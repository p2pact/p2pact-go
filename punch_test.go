package p2pact

import (
	"bytes"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/p2pact/p2pact-go/relay"
)

// observingRelay is relayServer that also answers observe on UDP, on the port of its TLS
// listener (like cmd/p2pact-relay).
func observingRelay(t *testing.T) RelayHint {
	t.Helper()
	for range 20 {
		rh := relayServer(t)
		pc, err := net.ListenPacket("udp", rh.Addr)
		if err != nil {
			continue // the UDP port is taken: another one
		}
		t.Cleanup(func() { pc.Close() })
		go relay.NewServer().ServeUDP(pc)
		return rh
	}
	t.Fatal("no free UDP port next to the relay")
	return RelayHint{}
}

func (n *Node) udpHints() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.hintsLocked().UDP
}

// roadTo is the road the session with peer runs on ("" — none or several).
func (n *Node) roadTo(peer string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	ps := n.peers[peer]
	if ps == nil || n.current[peer] == nil {
		return ""
	}
	if !n.sessionDirectLocked(time.Now(), peer, ps) {
		return "relayed"
	}
	return n.candidatesLocked(peer, ps, time.Now(), false)[0].ep.Road.Name()
}

func within(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); !ok(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal(what)
		}
	}
}

// The node asks its relay where it is seen from, takes only the answer to its own request
// from the relay's address, adds it to its UDP hints and replaces it when it changes.
func TestObserveReflexive(t *testing.T) {
	old := observeEvery
	observeEvery = 1500 * time.Millisecond
	defer func() { observeEvery = old }()
	fake, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer fake.Close()
	other, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer other.Close()

	a := node(t, "Mac", true, &RelayHint{Addr: fake.LocalAddr().String()})
	defer a.Close()
	local := a.UDP().LocalAddr()
	request := func() ([]byte, *net.UDPAddr) {
		t.Helper()
		buf := make([]byte, 2048)
		_ = fake.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, from, err := fake.ReadFromUDP(buf)
		if err != nil {
			t.Fatal("no observe request:", err)
		}
		req := buf[:n]
		if len(req) != 36 || req[0] != pObserve || !bytes.Equal(req[17:], make([]byte, 19)) {
			t.Fatalf("request %x", req)
		}
		if from.String() != local {
			t.Fatalf("request from %v, not the node's UDP socket %v", from, local)
		}
		return req, from
	}
	reply := func(nonce []byte, ip net.IP, port int) []byte {
		b := append([]byte{pObserve}, nonce...)
		b = append(b, ip.To16()...)
		return append(b, byte(port>>8), byte(port))
	}

	req, from := request()
	pub := net.ParseIP("203.0.113.7")
	_, _ = fake.WriteToUDP(reply(make([]byte, 16), pub, 4000), from) // a nonce we did not send
	_, _ = other.WriteToUDP(reply(req[1:17], pub, 4000), from)       // not from the relay
	_, _ = fake.WriteToUDP(reply(req[1:17], pub, 4000)[:34], from)   // short
	time.Sleep(300 * time.Millisecond)
	if h := a.udpHints(); slices.Contains(h, "203.0.113.7:4000") {
		t.Fatalf("took a wrong answer: %v", h)
	}
	_, _ = fake.WriteToUDP(reply(req[1:17], pub, 4000), from)
	within(t, 3*time.Second, "the observed address is not in the hints", func() bool {
		h := a.udpHints()
		return slices.Contains(h, "203.0.113.7:4000") && slices.Contains(h, local)
	})

	req, from = request() // the next one, observeEvery later
	_, _ = fake.WriteToUDP(reply(req[1:17], net.ParseIP("203.0.113.8"), 4001), from)
	within(t, 3*time.Second, "the new observed address did not replace the old one", func() bool {
		h := a.udpHints()
		return slices.Contains(h, "203.0.113.8:4001") && !slices.Contains(h, "203.0.113.7:4000") && slices.Contains(h, local)
	})
}

// counter counts session packets (type 6) arriving at a UDP socket.
func counter(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	var got atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > 0 && buf[0] == pData {
				got.Add(1)
			}
		}
	}()
	return c.LocalAddr().String(), &got
}

// A punch burst (about 15 keepalives in 3 s to every UDP address of the device) goes when a
// session comes up over the relay, when the device's UDP addresses change, and when our own
// observed address changes; not while the session is on UDP.
func TestPunchBurst(t *testing.T) {
	old := probeEvery
	probeEvery = time.Hour // the bursts only
	defer func() { probeEvery = old }()
	rh := relayServer(t)
	sink1, got1 := counter(t)
	sink2, got2 := counter(t)
	a := node(t, "Mac", false, &rh) // no UDP of its own: it only announces the sinks
	a.SetAdvertise(&Hints{UDP: []string{sink1}})
	b := node(t, "Phone", true, &rh)
	defer a.Close()
	defer b.Close()
	burst := func(got *atomic.Int64, why string) {
		t.Helper()
		start := got.Load()
		time.Sleep(punchFor + 700*time.Millisecond)
		n := got.Load() - start
		if n < 10 || n > 20 {
			t.Fatalf("%s: %d keepalives in a burst", why, n)
		}
		time.Sleep(time.Second)
		if more := got.Load() - start - n; more > 2 {
			t.Fatalf("%s: the burst goes on: %d more", why, more)
		}
	}

	pair(t, a, b) // (c) the session is up over the relay
	burst(got1, "session over the relay")

	a.SetAdvertise(&Hints{UDP: []string{sink2}}) // (b) its addresses change: its hello says so
	within(t, 10*time.Second, "no burst to the new address", func() bool { return got2.Load() > 0 })
	burst(got2, "new addresses")

	b.mu.Lock() // (a) our observed address changes
	b.setReflexiveLocked(time.Now(), "198.51.100.1:5000")
	b.mu.Unlock()
	burst(got2, "our address changed")

	c, d := node(t, "Mac2", true, nil), node(t, "Phone2", true, nil)
	defer c.Close()
	defer d.Close()
	pair(t, c, d)
	echo(t, c, d, []byte("over udp"), 5*time.Second)
	c.mu.Lock()
	c.setReflexiveLocked(time.Now(), "198.51.100.2:5000")
	busy := !c.peers[d.ID.Addr()].punchUntil.IsZero()
	c.mu.Unlock()
	if busy {
		t.Fatal("a burst for a session on UDP")
	}
}

// Two devices that know nothing of each other's addresses but their relay learn from it
// where they are seen from, tell each other in their hellos, punch and move the session from
// the relay to UDP (on loopback, the observed address is the socket itself).
func TestPunchAcrossRelay(t *testing.T) {
	oldProbe, oldObserve := probeEvery, observeEvery
	probeEvery, observeEvery = time.Hour, 1500*time.Millisecond
	defer func() { probeEvery, observeEvery = oldProbe, oldObserve }()
	rh := observingRelay(t)
	off := func() bool { return true }
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	for _, n := range []*Node{a, b} {
		n.UDP().SetDrop(off) // nothing on UDP until the session runs over the relay
		n.SetAdvertise(&Hints{})
		n.SetRelay(rh)
	}
	pair(t, a, b)
	echo(t, a, b, []byte("over the relay"), 10*time.Second)
	if r := a.roadTo(b.ID.Addr()); r != "relayed" {
		t.Fatalf("road %q before observe", r)
	}
	if h := a.Trust.Get(b.ID.Addr()).Hints.UDP; len(h) != 0 {
		t.Fatalf("a knows b's UDP addresses already: %v", h)
	}

	start := time.Now()
	a.UDP().SetDrop(nil)
	b.UDP().SetDrop(nil)
	within(t, 15*time.Second, "b's observed address did not reach a", func() bool {
		return slices.Contains(a.Trust.Get(b.ID.Addr()).Hints.UDP, b.UDP().LocalAddr())
	})
	within(t, 15*time.Second, "the session stays on the relay", func() bool {
		return a.roadTo(b.ID.Addr()) == "udp" && b.roadTo(a.ID.Addr()) == "udp"
	})
	t.Logf("on UDP %v after UDP came up", time.Since(start).Round(time.Millisecond))
	before := a.UDP().Stats().SentPackets
	echo(t, a, b, randomBytes(20000), 10*time.Second)
	if sent := a.UDP().Stats().SentPackets - before; sent < 15 {
		t.Fatalf("%d UDP packets for 20 KB: not on UDP", sent)
	}
}
