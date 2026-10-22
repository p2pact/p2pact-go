package p2pact

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go/relay"
)

// relayWithStats is relayServer that also returns the server, to count who is connected.
func relayWithStats(t *testing.T) (RelayHint, *relay.Server) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := relay.NewServer()
	go srv.Serve(ln)
	sum := sha256.Sum256(der)
	return RelayHint{Addr: ln.Addr().String(), FP: hexs(sum[:])}, srv
}

// until waits for cond, without the node's lock.
func until(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; !cond(); i++ {
		if i > 500 {
			t.Fatal(what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sent counts every packet a node put on its roads.
func sent(n *Node, ble *fakeBLE) int64 {
	k := n.UDP().Stats().SentPackets
	if n.TCP() != nil {
		k += n.TCP().Stats().SentPackets
	}
	if ble != nil {
		k += ble.sent.Load()
	}
	return k
}

func relayChannels(n *Node) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	k := 0
	for _, r := range n.rel {
		r.mu.Lock()
		k += len(r.ch)
		r.mu.Unlock()
	}
	return k
}

func tcpConns(n *Node) int {
	t := n.TCP()
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.conns)
}

// A paused node is silent on every road over many keepalive intervals while the other device
// keeps talking to it; its relay channels and TCP connections are closed. After resume it
// speaks first: a call to it succeeds at once, and what it queued while paused is delivered.
func TestPauseSilent(t *testing.T) {
	old := keepaliveGap
	keepaliveGap = 100 * time.Millisecond
	defer func() { keepaliveGap = old }()
	rh, srv := relayWithStats(t)
	a, b := tcpNode(t, "Laptop", "127.0.0.1:0", true), tcpNode(t, "Phone", "127.0.0.1:0", true)
	defer a.Close()
	defer b.Close()
	a.SetRelay(rh)
	b.SetRelay(rh)
	pair(t, a, b)
	ab, _ := bleLink(t, a, b, true, time.Millisecond)
	echo(t, b, a, []byte("before"), 5*time.Second)
	until(t, "both on the pair's relay channel", func() bool { _, peers := srv.Stats(); return peers == 2 })
	// TCP: b talks to a over it once, so that a holds a connection
	_ = a.TCP().Send(b.TCP().LocalAddr(), []byte{0, 0, 0, 0, 0})
	until(t, "a TCP connection", func() bool { return tcpConns(a) > 0 })

	a.SetPaused(true)
	a.SetPaused(true) // twice: nothing more
	until(t, "a gone from the relay", func() bool { _, peers := srv.Stats(); return peers == 1 })
	if k := relayChannels(a); k != 0 {
		t.Fatalf("%d relay channels open while paused", k)
	}
	if k := tcpConns(a); k != 0 {
		t.Fatalf("%d TCP connections open while paused", k)
	}
	if c, err := net.Dial("tcp", a.TCP().LocalAddr()); err == nil { // the listener refuses
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("a TCP connection was served while paused")
		}
		c.Close()
	}

	before := sent(a, ab)
	got := make(chan string, 1)
	b.mu.Lock()
	b.OnEvent = func(_ string, _, _ int, args []cbor.RawMessage) {
		var s string
		_ = cbor.Unmarshal(args[0], &s)
		got <- s
	}
	b.mu.Unlock()
	if err := a.Event(b.ID.Addr(), 64, 1, "queued while paused"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	_, err := b.Call(ctx, a.ID.Addr(), 64, 1, []byte("anyone?"))
	cancel()
	if err == nil {
		t.Fatal("a paused node answered a call")
	}
	time.Sleep(10 * keepaliveGap)
	if d := sent(a, ab) - before; d != 0 {
		t.Fatalf("a paused node sent %d packets", d)
	}
	select {
	case s := <-got:
		t.Fatalf("an event left a paused node: %q", s)
	default:
	}

	start := time.Now()
	a.SetPaused(false)
	a.SetPaused(false)
	select {
	case s := <-got:
		if s != "queued while paused" {
			t.Fatal(s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the event queued during the pause did not arrive")
	}
	echo(t, b, a, []byte("after"), 2*time.Second)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("back after %v", d)
	}
	until(t, "a back on the relay", func() bool { _, peers := srv.Stats(); return peers == 2 })
}

// A device that slept long enough for the other one to give up its session: on resume the
// call it queued still gets through, over a new session.
func TestPauseLongSleep(t *testing.T) {
	a, b := node(t, "Laptop", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, a, b, []byte("before"), 5*time.Second)
	a.SetPaused(true)
	// b restarts its view of a: the session is gone, as after a long sleep
	b.mu.Lock()
	for idx, s := range b.sessions {
		delete(b.sessions, idx)
		delete(b.current, s.peer)
	}
	b.mu.Unlock()
	res := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := a.Call(ctx, b.ID.Addr(), 64, 1, []byte("queued"))
		res <- err
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	a.SetPaused(false)
	if err := <-res; err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the queued call took %v after resume", d)
	}
}

// Pause and resume from many goroutines, and Close in the middle: no race, no panic, and
// nothing reconnects after Close.
func TestPauseRacesClose(t *testing.T) {
	rh := relayServer(t)
	for i := 0; i < 5; i++ {
		a, b := tcpNode(t, "Laptop", "127.0.0.1:0", true), tcpNode(t, "Phone", "127.0.0.1:0", true)
		a.SetRelay(rh)
		b.SetRelay(rh)
		pair(t, a, b)
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for k := 0; k < 50; k++ {
					a.SetPaused((k+g)%2 == 0)
					_ = a.Event(b.ID.Addr(), 64, 1, "x")
				}
			}(g)
		}
		time.Sleep(time.Duration(i) * 5 * time.Millisecond)
		a.Close()
		wg.Wait()
		a.SetPaused(false)
		if k := relayChannels(a); k != 0 {
			t.Fatalf("%d relay channels after Close", k)
		}
		b.Close()
	}
}
