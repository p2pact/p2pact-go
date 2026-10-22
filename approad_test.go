package p2pact

import (
	"errors"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// fakeBLE is one direction of an in-memory Bluetooth LE link: writes of at most mtu bytes, rate
// bytes a second (a write waits for the link, as a GATT write waits for its acknowledgement),
// a one-way delay; it keeps order and loses nothing, as GATT does while connected.
type fakeBLE struct {
	mtu, rate int
	delay     time.Duration
	q         chan bleWrite
	free      time.Time // when the link is free again (only Send's goroutine touches it)
	sent      atomic.Int64
	tooBig    atomic.Bool
	conn      net.Conn    // instead of the delay: a local TCP connection (a pipe to another program)
	peer      net.Conn    // its other end
	loss      func() bool // a datagram is lost (a datagram road only)
}

type bleWrite struct {
	b   []byte
	due time.Time
}

func newFakeBLE(mtu, rate int, delay time.Duration) *fakeBLE {
	return &fakeBLE{mtu: mtu, rate: rate, delay: delay, q: make(chan bleWrite, 1<<16)}
}

func (f *fakeBLE) Send(b []byte) error {
	if len(b) > f.mtu {
		f.tooBig.Store(true)
		return errors.New("longer than the MTU")
	}
	now := time.Now()
	if f.free.Before(now.Add(-10 * time.Millisecond)) { // idle: the link starts now (an oversleep does not slow it)
		f.free = now
	}
	f.free = f.free.Add(time.Duration(len(b)) * time.Second / time.Duration(f.rate))
	if d := time.Until(f.free); d > 2*time.Millisecond {
		time.Sleep(d)
	}
	f.sent.Add(int64(len(b)))
	if f.loss != nil && f.loss() {
		return nil
	}
	if f.conn != nil {
		_, err := f.conn.Write(b)
		return err
	}
	f.q <- bleWrite{append([]byte(nil), b...), f.free.Add(f.delay)}
	return nil
}

// deliver hands what was written to the road at the other end, in order, after the delay.
func (f *fakeBLE) deliver(to *AttachedRoad) {
	if f.conn != nil {
		go func() { // the other end of the connection reads, at most an MTU at a time
			buf := make([]byte, f.mtu)
			for {
				k, err := f.peer.Read(buf)
				if err != nil {
					return
				}
				to.Receive(buf[:k])
			}
		}()
		return
	}
	go func() {
		for w := range f.q {
			time.Sleep(time.Until(w.due))
			to.Receive(w.b)
		}
	}()
}

const (
	bleMTU  = 20       // the smallest GATT write
	bleRate = 40 << 10 // a Bluetooth LE link under load
)

// bleLink attaches a Bluetooth LE link between a and b with a one-way delay, or over local TCP
// connections when delay < 0: bound to each other when bind is set, else learnt from what
// arrives.
func bleLink(t *testing.T, a, b *Node, bind bool, delay time.Duration) (ab, ba *fakeBLE) {
	t.Helper()
	ab, ba = newFakeBLE(bleMTU, bleRate, delay), newFakeBLE(bleMTU, bleRate, delay)
	if delay < 0 {
		ab.conn, ab.peer = tcpPair(t)
		ba.conn, ba.peer = tcpPair(t)
	}
	cfg := AppRoadConfig{Name: "ble", Stream: true, MTU: bleMTU, Rate: bleRate}
	pa, pb := "", ""
	if bind {
		pa, pb = b.ID.Addr(), a.ID.Addr()
	}
	// each side's deliverer starts before the other side may send
	ra, err := a.AttachRoad(pa, ab, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ba.deliver(ra)
	rb, err := b.AttachRoad(pb, ba, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ab.deliver(rb)
	t.Cleanup(func() { ra.Detach(); rb.Detach() })
	return ab, ba
}

// tcpPair is both ends of a local TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	d, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); d.Close() })
	return c, d
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	mrand.New(mrand.NewSource(int64(n))).Read(b)
	return b
}

// Two devices with nothing but a Bluetooth LE link (20-byte writes, 40 KB/s): they pair over it
// (the road is bound by the handshake), call both ways, and carry long messages without
// resending them — with the latency of a radio link, and over a local connection with none (a
// pipe to another program: a small packet's round trip is then no measure of the link at all).
func TestAppRoadBluetooth(t *testing.T) {
	for _, c := range []struct {
		name  string
		delay time.Duration
		sizes []int
	}{
		{"10ms", 10 * time.Millisecond, []int{13, 10000, 30 << 10, 13, 1800, 200 << 10, 13}},
		{"pipe", -1, []int{13, 10000, 30 << 10, 13, 1800, 64 << 10, 13}},
	} {
		t.Run(c.name, func(t *testing.T) { bluetooth(t, c.delay, c.sizes) })
	}
}

// quietNode is a node with no road of its own that trains no dictionary.
func quietNode(t *testing.T, name string) *Node {
	t.Helper()
	n, err := NewNode(t.TempDir(), name)
	if err != nil {
		t.Fatal(err)
	}
	n.NoLearning = true
	n.Handle(64, 1, func(_ string, args []cbor.RawMessage) ([]any, error) { return []any{args[0]}, nil })
	n.Start()
	return n
}

func bluetooth(t *testing.T, delay time.Duration, sizes []int) {
	// no dictionary of their own: its download would take the link from the messages timed here
	a, b := quietNode(t, "Mac"), quietNode(t, "Phone")
	defer a.Close()
	defer b.Close()
	ab, ba := bleLink(t, a, b, false, delay)
	pair(t, a, b)
	echo(t, b, a, []byte("hello over bluetooth"), 10*time.Second)
	if p := a.Paths(b.ID.Addr()); len(p) != 1 || p[0] != "app:ble" {
		t.Fatalf("paths %v, want [app:ble]", p)
	}
	for _, size := range sizes {
		for _, d := range [][2]*Node{{b, a}, {a, b}} {
			before := ab.sent.Load() + ba.sent.Load()
			start := time.Now()
			echo(t, d[0], d[1], randomBytes(size), 30*time.Second)
			took := time.Since(start)
			sent := ab.sent.Load() + ba.sent.Load() - before
			if size > 1000 {
				t.Logf("%d bytes there and back over 20-byte writes at 40 KB/s: %v, %d bytes on the link", size, took, sent)
			}
			// a short message right after a long one does not wait behind resent parts or a
			// backed-off timer
			if ideal := time.Duration(2*size) * time.Second / bleRate; took > ideal*5/4+300*time.Millisecond {
				t.Fatalf("%d bytes there and back took %v, the link needs %v", size, took, ideal)
			}
			// both ways, plus headers, acks and framing (about 4 %); resent parts would show here
			if limit := int64(2*size)*110/100 + 1000; sent > limit {
				t.Fatalf("%d bytes on the link for %d there and back: parts were resent", sent, size)
			}
		}
	}
	if ab.tooBig.Load() || ba.tooBig.Load() {
		t.Fatal("a write longer than the MTU")
	}
}

// Known devices that have only a Bluetooth link the application names: attaching it starts a
// session over it (a handshake with data in the first packet).
func TestAppRoadBoundHandshake(t *testing.T) {
	da, db := t.TempDir(), t.TempDir()
	a, b := nodeIn(t, da, "Mac", true, nil), nodeIn(t, db, "Phone", true, nil)
	pair(t, a, b)
	a.Close()
	b.Close()
	// the same devices again, now without UDP
	a, b = nodeIn(t, da, "Mac", false, nil), nodeIn(t, db, "Phone", false, nil)
	defer a.Close()
	defer b.Close()
	bleLink(t, a, b, true, 10*time.Millisecond)
	echo(t, a, b, []byte("first packet"), 10*time.Second)
	echo(t, b, a, randomBytes(5000), 10*time.Second)
	if h := a.handshakes.Load() + b.handshakes.Load(); h < 1 {
		t.Fatalf("%d handshakes", h)
	}
}

// A session moves from Bluetooth to UDP when UDP comes up, and back when it goes.
func TestAppRoadSwitch(t *testing.T) {
	old := probeEvery
	probeEvery = 300 * time.Millisecond
	defer func() { probeEvery = old }()
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, a, b, []byte("over udp"), 5*time.Second)

	down := func() bool { return true }
	a.UDP().SetDrop(down)
	b.UDP().SetDrop(down)
	ab, ba := bleLink(t, a, b, true, 10*time.Millisecond)
	ble := func() int64 { return ab.sent.Load() + ba.sent.Load() }
	carried := func(size int, timeout time.Duration) int64 {
		t.Helper()
		before := ble()
		echo(t, a, b, randomBytes(size), timeout)
		return ble() - before
	}
	if n := carried(8000, 15*time.Second); n < 16000 {
		t.Fatalf("UDP down: %d bytes over Bluetooth for 16000", n)
	}

	a.UDP().SetDrop(nil)
	b.UDP().SetDrop(nil)
	for i := 0; ; i++ {
		time.Sleep(200 * time.Millisecond)
		if n := carried(50000, 15*time.Second); n < 5000 {
			t.Logf("UDP took over after %d tries", i+1)
			break
		}
		if i == 20 {
			t.Fatal("the session stays on Bluetooth while UDP is up")
		}
	}

	a.UDP().SetDrop(down)
	b.UDP().SetDrop(down)
	start := time.Now()
	if n := carried(8000, 15*time.Second); n < 16000 {
		t.Fatalf("UDP down again: %d bytes over Bluetooth for 16000", n)
	}
	t.Logf("back on Bluetooth in %v", time.Since(start))
}

// A datagram road the application provides (a packet each, some lost): pairing, calls and a
// long message, the losses found as on UDP.
func TestAppRoadDatagram(t *testing.T) {
	a, b := quietNode(t, "Mac"), quietNode(t, "Phone")
	defer a.Close()
	defer b.Close()
	rnd := mrand.New(mrand.NewSource(7))
	var mu sync.Mutex
	loss := func() bool { mu.Lock(); defer mu.Unlock(); return rnd.Float64() < 0.02 }
	ab, ba := newFakeBLE(MaxRoadPacket, 100<<10, 5*time.Millisecond), newFakeBLE(MaxRoadPacket, 100<<10, 5*time.Millisecond)
	ab.loss, ba.loss = loss, loss
	cfg := AppRoadConfig{Name: "wifi-aware", MTU: MaxRoadPacket, Rate: 100 << 10}
	ra, err := a.AttachRoad("", ab, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ba.deliver(ra)
	rb, err := b.AttachRoad("", ba, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ab.deliver(rb)
	pair(t, a, b)
	echo(t, a, b, []byte("over datagrams"), 10*time.Second)
	if p := b.Paths(a.ID.Addr()); len(p) != 1 || p[0] != "app:wifi-aware" {
		t.Fatalf("paths %v", p)
	}
	before := ab.sent.Load() + ba.sent.Load()
	start := time.Now()
	size := 100 << 10
	echo(t, b, a, randomBytes(size), 30*time.Second)
	took, sent := time.Since(start), ab.sent.Load()+ba.sent.Load()-before
	t.Logf("100 KB there and back at 100 KB/s, 2 %% lost: %v, %d bytes on the link", took, sent)
	// headers about 4 %, the lost 2 % again; a lost part resent on every ack until its copy got
	// through the link's queue would show here
	if sent > int64(2*size)*110/100 {
		t.Fatalf("%d bytes on the link for %d: parts were resent needlessly", sent, 2*size)
	}
	if took > 4*time.Second {
		t.Fatalf("took %v, the link needs 2 s", took)
	}
}

// A datagram road must carry a whole packet; a stream road takes any MTU.
func TestAppRoadConfig(t *testing.T) {
	a := node(t, "Mac", false, nil)
	defer a.Close()
	if _, err := a.AttachRoad("", newFakeBLE(512, bleRate, 0), AppRoadConfig{MTU: 512}); err == nil {
		t.Fatal("a datagram road of 512 bytes was taken")
	}
	r, err := a.AttachRoad("", newFakeBLE(512, bleRate, 0), AppRoadConfig{Stream: true, MTU: 512})
	if err != nil {
		t.Fatal(err)
	}
	r.Detach()
	if r.Send("", []byte{1}) == nil {
		t.Fatal("a detached road takes packets")
	}
	if _, err := a.AttachRoad("nobody", newFakeBLE(512, bleRate, 0), AppRoadConfig{Stream: true, MTU: 512}); err == nil {
		t.Fatal("a road to an unknown device was taken")
	}
}
