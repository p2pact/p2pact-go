package p2pact

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// threeNodes: A and B trust each other but cannot reach each other — they know no address of
// the other and announce none — while both are paired with X over UDP.
func threeNodes(t *testing.T) (a, x, b *Node) {
	t.Helper()
	a, x, b = node(t, "A", true, nil), node(t, "X", true, nil), node(t, "B", true, nil)
	t.Cleanup(func() { a.Close(); x.Close(); b.Close() })
	a.SetAdvertise(&Hints{})
	b.SetAdvertise(&Hints{})
	pair(t, x, a)
	pair(t, x, b)
	if err := a.Befriend(Peer{Addr: b.ID.Addr(), Key: b.ID.Key.Public, Name: "B"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Befriend(Peer{Addr: a.ID.Addr(), Key: a.ID.Key.Public, Name: "A"}); err != nil {
		t.Fatal(err)
	}
	return a, x, b
}

// tap records what X forwards.
type tap struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (tp *tap) install(x *Node) {
	x.mu.Lock()
	x.forwardTap = func(_, _ string, pkt []byte) {
		tp.mu.Lock()
		tp.pkts = append(tp.pkts, append([]byte(nil), pkt...))
		tp.mu.Unlock()
	}
	x.mu.Unlock()
}

func (tp *tap) contains(b []byte) (seen int, found bool) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	for _, p := range tp.pkts {
		if bytes.Contains(p, b) {
			found = true
		}
	}
	return len(tp.pkts), found
}

// A and B, which cannot reach each other, set up a session through X and talk both ways —
// calls, events, a long message; X carries only ciphertext.
func TestForwardViaThirdDevice(t *testing.T) {
	a, x, b := threeNodes(t)
	var tp tap
	tp.install(x)
	if err := x.AllowForward(a.ID.Addr(), b.ID.Addr(), true); err != nil {
		t.Fatal(err)
	}
	if got := x.Forwards(a.ID.Addr()); !slices.Equal(got, []string{b.ID.Addr()}) {
		t.Fatalf("X forwards for A to %v", got)
	}
	eventually(t, "A hears X forwards to B", func() bool { return slices.Equal(a.Forwarders(b.ID.Addr()), []string{x.ID.Addr()}) })

	marker := []byte("plaintext-marker-that-X-must-never-see")
	msg := append(bytes.Repeat([]byte{'.'}, 100), marker...)
	echo(t, a, b, msg, 10*time.Second)
	echo(t, b, a, msg, 10*time.Second)
	if p := a.Paths(b.ID.Addr()); !slices.Equal(p, []string{"via:" + x.ID.Addr()}) {
		t.Fatalf("A's paths to B: %v", p)
	}
	if p := b.Paths(a.ID.Addr()); !slices.Equal(p, []string{"via:" + x.ID.Addr()}) {
		t.Fatalf("B's paths to A: %v", p)
	}

	long := randomBytes(40 << 10)
	echo(t, a, b, long, 20*time.Second)
	echo(t, b, a, long, 20*time.Second)

	got := make(chan string, 2)
	for _, n := range []*Node{a, b} {
		n.mu.Lock()
		n.OnEvent = func(peer string, tool, ev int, args []cbor.RawMessage) {
			var s string
			_ = cbor.Unmarshal(args[0], &s)
			got <- s
		}
		n.mu.Unlock()
	}
	if err := a.Event(b.ID.Addr(), 64, 3, "to B"); err != nil {
		t.Fatal(err)
	}
	if err := b.Event(a.ID.Addr(), 64, 3, "to A"); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 2 {
		select {
		case s := <-got:
			seen[s] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("events: %v", seen)
		}
	}
	if !seen["to A"] || !seen["to B"] {
		t.Fatalf("events: %v", seen)
	}

	n, found := tp.contains(marker)
	if n == 0 {
		t.Fatal("X forwarded nothing")
	}
	if found {
		t.Fatal("X saw the plaintext")
	}
	if fw, _ := x.ForwardStats(); fw == 0 {
		t.Fatal("no forwarded packets counted")
	}
	// the consent is kept with the trusted list
	if p := LoadTrust(x.dir).Get(a.ID.Addr()); p == nil || !slices.Equal(p.Forward, []string{b.ID.Addr()}) {
		t.Fatalf("consent not saved: %+v", p)
	}
}

// forge sends X an event 0.7 for B by hand.
func forge(t *testing.T, a, x, b *Node) {
	t.Helper()
	to, _ := addrBytes(b.ID.Addr())
	pkt := append([]byte{pInit}, randomBytes(200)...)
	if err := a.Event(x.ID.Addr(), 0, evForward, to, pkt); err != nil {
		t.Fatal(err)
	}
}

// X forwards nothing for a pair it was not opted in for, nor to a device it does not trust,
// and stops when it forgets one of the two.
func TestForwardRefused(t *testing.T) {
	a, x, b := threeNodes(t)
	var tp tap
	tp.install(x)

	// not opted in: no road via X, and a forged 0.7 is dropped
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := a.Call(ctx, b.ID.Addr(), 64, 1, []byte("hi")); err == nil {
		t.Fatal("A reached B with nobody forwarding")
	}
	forge(t, a, x, b)
	eventually(t, "X drops the forged packet", func() bool { _, d := x.ForwardStats(); return d > 0 })
	if n, _ := tp.contains(nil); n != 0 {
		t.Fatalf("X forwarded %d packets without consent", n)
	}

	// only between devices X trusts, never to itself
	stranger := node(t, "S", false, nil)
	defer stranger.Close()
	if err := x.AllowForward(a.ID.Addr(), stranger.ID.Addr(), true); err == nil {
		t.Fatal("X agreed to forward to a device it does not trust")
	}
	if err := x.AllowForward(a.ID.Addr(), x.ID.Addr(), true); err == nil {
		t.Fatal("X agreed to forward to itself")
	}

	// opted in, then X forgets B: A learns it, and X forwards nothing more
	if err := x.AllowForward(a.ID.Addr(), b.ID.Addr(), true); err != nil {
		t.Fatal(err)
	}
	echo(t, a, b, []byte("through X"), 10*time.Second)
	x.Forget(b.ID.Addr())
	eventually(t, "A hears X no longer forwards to B", func() bool { return len(a.Forwarders(b.ID.Addr())) == 0 })
	before, _ := tp.contains(nil)
	_, dropped := x.ForwardStats()
	forge(t, a, x, b)
	eventually(t, "X drops a packet for a device it forgot", func() bool { _, d := x.ForwardStats(); return d > dropped })
	if n, _ := tp.contains(nil); n != before {
		t.Fatal("X forwarded to a device it forgot")
	}
}

// Withdrawing the consent stops forwarding and tells both devices.
func TestForwardWithdrawn(t *testing.T) {
	a, x, b := threeNodes(t)
	if err := x.AllowForward(a.ID.Addr(), b.ID.Addr(), true); err != nil {
		t.Fatal(err)
	}
	echo(t, a, b, []byte("through X"), 10*time.Second)
	if err := x.AllowForward(b.ID.Addr(), a.ID.Addr(), false); err != nil {
		t.Fatal(err)
	}
	eventually(t, "both hear X no longer forwards", func() bool {
		return len(a.Forwarders(b.ID.Addr())) == 0 && len(b.Forwarders(a.ID.Addr())) == 0
	})
	_, dropped := x.ForwardStats()
	forge(t, a, x, b)
	eventually(t, "X drops the packet", func() bool { _, d := x.ForwardStats(); return d > dropped })
}

// The rate limit: a direction may send a burst, then only its rate; what is over the rate
// waits, up to a burst, and goes as the bucket refills; past that it is dropped.
func TestForwardBucket(t *testing.T) {
	n := &Node{ForwardRate: 1000, fwdBuckets: map[string]*fwdBucket{},
		peers: map[string]*peerState{"b": {addr: "b", st: newStream()}, "a": {addr: "a", st: newStream()}}}
	now := time.Now()
	p := func(to string) fwdPending { return fwdPending{to: to, msg: []byte{1}, stream: 1, size: 1000} }
	offered := 0
	for n.fwdOfferLocked("a>b", p("b"), now) {
		offered++
	}
	burst := forwardBurst / 1000
	if sent := n.fwdCount.Load(); sent != int64(burst) || offered != 2*burst {
		t.Fatalf("sent %d, offered %d; want %d and %d", sent, offered, burst, 2*burst)
	}
	n.fwdReleaseLocked(now.Add(400 * time.Millisecond)) // 536 left + 400: not enough
	if sent := n.fwdCount.Load(); sent != int64(burst) {
		t.Fatalf("more than the rate: %d", sent)
	}
	n.fwdReleaseLocked(now.Add(2100 * time.Millisecond))
	if sent := n.fwdCount.Load(); sent != int64(burst)+2 {
		t.Fatalf("the rate refills: %d sent", sent)
	}
	if !n.fwdOfferLocked("b>a", p("a"), now) || n.fwdCount.Load() != int64(burst)+3 {
		t.Fatal("the other direction has its own bucket")
	}
}

func TestAddrBytes(t *testing.T) {
	n := node(t, "A", false, nil)
	defer n.Close()
	b, ok := addrBytes(n.ID.Addr())
	if !ok || addrText(b) != n.ID.Addr() {
		t.Fatalf("%v %q", ok, addrText(b))
	}
	if _, ok := addrBytes("nonsense"); ok {
		t.Fatal("bad address taken")
	}
}

// One hop only: X reaches B only through Y, so it does not forward A's packets to B (no chains).
func TestForwardOneHop(t *testing.T) {
	a, x, y, b := node(t, "A", true, nil), node(t, "X", true, nil), node(t, "Y", true, nil), node(t, "B", true, nil)
	defer func() { a.Close(); x.Close(); y.Close(); b.Close() }()
	a.SetAdvertise(&Hints{})
	b.SetAdvertise(&Hints{})
	pair(t, y, x)
	pair(t, y, b)
	pair(t, x, a)
	x.SetAdvertise(&Hints{}) // Y and A know where X is; B never learns it
	friends := func(p, q *Node) {
		if err := p.Befriend(Peer{Addr: q.ID.Addr(), Key: q.ID.Key.Public, Name: q.Name}); err != nil {
			t.Fatal(err)
		}
		if err := q.Befriend(Peer{Addr: p.ID.Addr(), Key: p.ID.Key.Public, Name: p.Name}); err != nil {
			t.Fatal(err)
		}
	}
	friends(x, b)
	friends(a, b)
	if err := y.AllowForward(x.ID.Addr(), b.ID.Addr(), true); err != nil {
		t.Fatal(err)
	}
	echo(t, x, b, []byte("X to B through Y"), 10*time.Second)
	if err := x.AllowForward(a.ID.Addr(), b.ID.Addr(), true); err != nil {
		t.Fatal(err)
	}
	eventually(t, "A hears X forwards to B", func() bool { return len(a.Forwarders(b.ID.Addr())) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := a.Call(ctx, b.ID.Addr(), 64, 1, []byte("two hops")); err == nil {
		t.Fatal("A reached B over two forwarders")
	}
	if fw, d := x.ForwardStats(); fw != 0 || d == 0 {
		t.Fatalf("X forwarded %d, dropped %d", fw, d)
	}
}

// A road via a third device gives way to a direct one as soon as it answers (spec §7).
func TestForwardGivesWayToDirect(t *testing.T) {
	old := probeEvery
	probeEvery = 300 * time.Millisecond
	defer func() { probeEvery = old }()
	a, x, b := threeNodes(t)
	if err := x.AllowForward(a.ID.Addr(), b.ID.Addr(), true); err != nil {
		t.Fatal(err)
	}
	echo(t, a, b, []byte("through X"), 10*time.Second)
	a.SetAdvertise(nil) // A announces its UDP address again: B probes it
	eventually(t, "the session moves to UDP", func() bool {
		echo(t, b, a, []byte("ping"), 5*time.Second)
		p := b.Paths(a.ID.Addr())
		return slices.Contains(p, "udp")
	})
	fw, _ := x.ForwardStats()
	for range 20 {
		echo(t, a, b, []byte("direct"), 5*time.Second)
	}
	if now, _ := x.ForwardStats(); now-fw > 4 {
		t.Fatalf("X still carried %d packets after UDP came up", now-fw)
	}
}
