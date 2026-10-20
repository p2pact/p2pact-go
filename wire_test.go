package p2pact

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	mrand "math/rand"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go/relay"
)

// relayServer runs a relay on localhost with a self-signed certificate.
func relayServer(t *testing.T) RelayHint {
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
	go relay.NewServer().Serve(ln)
	sum := sha256.Sum256(der)
	return RelayHint{Addr: ln.Addr().String(), FP: hexs(sum[:])}
}

func node(t *testing.T, name string, udp bool, rh *RelayHint) *Node {
	t.Helper()
	return nodeIn(t, t.TempDir(), name, udp, rh)
}

func nodeIn(t *testing.T, dir, name string, udp bool, rh *RelayHint) *Node {
	t.Helper()
	n, err := NewNode(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	if udp {
		if err := n.ListenUDP("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
	}
	if rh != nil {
		n.SetRelay(*rh)
	}
	n.Handle(64, 1, func(_ string, args []cbor.RawMessage) ([]any, error) { // echo
		var b []byte
		if len(args) == 0 || cbor.Unmarshal(args[0], &b) != nil {
			return nil, &Error{Code: ErrBadArgs, Text: "no data"}
		}
		return []any{b}, nil
	})
	n.Start()
	return n
}

func pair(t *testing.T, a, b *Node) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv, err := ParseInvite(a.Invite(10 * time.Minute).String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := b.Join(ctx, inv)
	if err != nil {
		t.Fatalf("pairing: %v", err)
	}
	if p.Addr != a.ID.Addr() || p.Name != a.Name {
		t.Fatalf("paired with the wrong device: %+v", p)
	}
	for i := 0; a.Trust.Get(b.ID.Addr()) == nil; i++ {
		if i > 200 {
			t.Fatal("the invite owner did not remember the joiner")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func echo(t *testing.T, from, to *Node, data []byte, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := from.Call(ctx, to.ID.Addr(), 64, 1, data)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	var got []byte
	if len(res) != 1 || cbor.Unmarshal(res[0], &got) != nil || !bytes.Equal(got, data) {
		t.Fatalf("echo returned something else: %d bytes of %d", len(got), len(data))
	}
}

// Pairing and talking directly over UDP; method errors arrive with a code.
func TestPairAndCallUDP(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, b, a, []byte("hello"), 5*time.Second)
	echo(t, a, b, []byte("hello back"), 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.Call(ctx, b.ID.Addr(), 64, 9); err == nil {
		t.Fatal("a missing method answered")
	} else if e, ok := err.(*Error); !ok || e.Code != ErrNoMethod {
		t.Fatalf("error: %v", err)
	}
	got := make(chan string, 1)
	b.OnEvent = func(peer string, tool, ev int, args []cbor.RawMessage) {
		var s string
		_ = cbor.Unmarshal(args[0], &s)
		got <- s
	}
	_ = a.Event(b.ID.Addr(), 64, 1, "event")
	select {
	case s := <-got:
		if s != "event" {
			t.Fatal(s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event did not arrive")
	}
	if paths := a.Paths(b.ID.Addr()); len(paths) != 1 || paths[0] != "udp" {
		t.Fatalf("roads %v", paths)
	}
}

// Relay only: no direct road at all.
func TestPairAndCallRelayOnly(t *testing.T) {
	rh := relayServer(t)
	a, b := node(t, "Mac", false, &rh), node(t, "Phone", false, &rh)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, b, a, bytes.Repeat([]byte("relay "), 300), 10*time.Second)
	echo(t, a, b, []byte("back"), 10*time.Second)
}

// A third of packets are lost both ways; a long message still arrives whole.
func TestLossyLongMessage(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	r := mrand.New(mrand.NewSource(1))
	var mu atomic.Int32
	drop := func() bool { mu.Add(1); return r.Intn(3) == 0 }
	a.UDP().Drop, b.UDP().Drop = drop, drop
	data := make([]byte, 200<<10)
	_, _ = rand.Read(data)
	echo(t, a, b, data, 60*time.Second)
}

// UDP stops working; the conversation continues through the relay.
func TestFallbackToRelay(t *testing.T) {
	rh := relayServer(t)
	a, b := node(t, "Mac", true, &rh), node(t, "Phone", true, &rh)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, a, b, []byte("over udp"), 5*time.Second)
	for i := 0; ; i++ { // both keep the pair channel on the relay
		time.Sleep(100 * time.Millisecond)
		if i > 50 {
			break
		}
	}
	off := func() bool { return true }
	a.UDP().Drop, b.UDP().Drop = off, off
	echo(t, a, b, []byte("through the relay"), 20*time.Second)
}

// A device does not answer a stranger at all, even one that knows its key.
func TestStrangerIgnored(t *testing.T) {
	a, c := node(t, "Mac", true, nil), node(t, "Stranger", true, nil)
	defer a.Close()
	defer c.Close()
	c.Trust.Put(Peer{Addr: a.ID.Addr(), Key: a.ID.Key.Public, Name: "Mac", PairSecret: randBytes(32), Hints: Hints{UDP: a.udp.localAddrs()}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Call(ctx, a.ID.Addr(), 0, 1); err == nil {
		t.Fatal("a stranger got an answer")
	}
}

// An invite with a wrong secret fails; a used invite fails the second time.
func TestInviteSecret(t *testing.T) {
	a, b, c := node(t, "Mac", true, nil), node(t, "Phone", true, nil), node(t, "Other", true, nil)
	defer a.Close()
	defer b.Close()
	defer c.Close()
	inv := a.Invite(time.Minute)
	bad := *inv
	bad.Secret = randBytes(32)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.Join(ctx, &bad); err == nil {
		t.Fatal("pairing with a wrong secret succeeded")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := b.Join(ctx2, inv); err != nil {
		t.Fatal(err)
	}
	ctx3, cancel3 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel3()
	if _, err := c.Join(ctx3, inv); err == nil {
		t.Fatal("the invite worked twice")
	}
}

// A device restarts (same keys, no sessions); the conversation resumes by itself.
func TestPeerRestart(t *testing.T) {
	dir := t.TempDir()
	a, b := node(t, "Mac", true, nil), nodeIn(t, dir, "Phone", true, nil)
	defer a.Close()
	pair(t, a, b)
	echo(t, a, b, []byte("before"), 5*time.Second)
	addr := b.udp.conn.LocalAddr().String()
	b.Close()
	b2, err := NewNode(dir, "Phone")
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.ListenUDP(addr); err != nil {
		t.Fatal(err)
	}
	b2.Handle(64, 1, func(_ string, args []cbor.RawMessage) ([]any, error) {
		var x []byte
		_ = cbor.Unmarshal(args[0], &x)
		return []any{x}, nil
	})
	b2.Start()
	defer b2.Close()
	echo(t, a, b2, []byte("after"), 10*time.Second)
	echo(t, b2, a, []byte("and back"), 10*time.Second)
}

func TestWindow(t *testing.T) {
	var w window
	for _, c := range []struct {
		n  uint64
		ok bool
	}{{0, true}, {0, false}, {5, true}, {3, true}, {3, false}, {5000, true}, {5, false}, {4000, true}, {2000, false}} {
		if w.accept(c.n) != c.ok {
			t.Fatalf("number %d: want %v", c.n, c.ok)
		}
	}
}
