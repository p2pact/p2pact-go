package p2pact

import (
	"bytes"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"
)

func TestStreamHalfLoss(t *testing.T) {
	a, b := newStream(), newStream()
	r := mrand.New(mrand.NewSource(2))
	data := make([]byte, 200<<10)
	r.Read(data)
	a.push(data, false, 0, false)
	var got []byte
	now := time.Unix(0, 0)
	for step := 0; step < 200000 && got == nil; step++ {
		now = now.Add(5 * time.Millisecond)
		for i := 0; i < 64; i++ {
			p, _ := a.nextPacket(now, false)
			if p == nil {
				break
			}
			if r.Intn(2) == 0 {
				_ = b.receive(now, p, func(m []byte, _ bool, _ uint64) { got = m })
			}
		}
		for i := 0; i < 64; i++ {
			p, _ := b.nextPacket(now, false)
			if p == nil {
				break
			}
			if r.Intn(2) == 0 {
				_ = a.receive(now, p, nil)
			}
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("not reassembled: recvAck=%d got=%d inflight=%d queue=%d", b.recvAck, len(b.got), len(a.inflight), len(a.queue))
	}
}

// Streams are independent: a message on one stream is delivered although an earlier part of
// another stream is lost; within a stream the order holds.
func TestStreamsIndependent(t *testing.T) {
	a, b := newStream(), newStream()
	a.push([]byte("s1 first"), false, 1, false)
	a.push([]byte("s2 only"), false, 2, false)
	a.push([]byte("s1 second"), false, 1, false)
	now := time.Now()
	var pkts [][]byte
	for {
		p, _ := a.nextPacket(now, false)
		if p == nil {
			break
		}
		pkts = append(pkts, p)
	}
	var got []string
	deliver := func(m []byte, _ bool, st uint64) { got = append(got, fmt.Sprintf("%d:%s", st, m)) }
	_ = b.receive(now, pkts[1], deliver) // s2 — part 1 (s1 first) is "lost"
	_ = b.receive(now, pkts[2], deliver) // s1 second must wait for s1 first
	if fmt.Sprint(got) != "[2:s2 only]" {
		t.Fatalf("after the loss: %v", got)
	}
	_ = b.receive(now, pkts[0], deliver)
	if fmt.Sprint(got) != "[2:s2 only 1:s1 first 1:s1 second]" {
		t.Fatalf("after the retransmission: %v", got)
	}
	ack, _ := b.nextPacket(now, true)
	if err := a.receive(now, ack, func([]byte, bool, uint64) {}); err != nil || len(a.inflight) != 0 {
		t.Fatalf("ack ranges: %v, %d still in flight", err, len(a.inflight))
	}
}

// A timeout fired by a queue, not a loss: the ack of the first copy comes just after the
// retransmission and must not mark the parts sent between the copies lost (spec §5).
func TestStreamSpuriousRetransmission(t *testing.T) {
	a, b := newStream(), newStream()
	t0 := time.Unix(0, 0)
	exchange := func(at time.Time, pkts ...[]byte) {
		for _, p := range pkts {
			_ = b.receive(at, p, func([]byte, bool, uint64) {})
		}
		ack, _ := b.nextPacket(at, true)
		_ = a.receive(at.Add(time.Millisecond), ack, nil)
	}
	a.push([]byte("first"), false, 1, false) // a round-trip sample: 60 ms
	p, _ := a.nextPacket(t0, false)
	exchange(t0.Add(59*time.Millisecond), p)
	sent := t0.Add(100 * time.Millisecond)
	var pkts [][]byte
	for i := 0; i < 5; i++ {
		a.push([]byte("queued"), false, 1, false)
		p, _ := a.nextPacket(sent, false)
		pkts = append(pkts, p)
	}
	at := sent.Add(a.timeout(a.inflight[2], 0))
	if _, retry := a.nextPacket(at, false); !retry {
		t.Fatal("no retransmission on timeout")
	}
	exchange(at.Add(time.Millisecond), pkts[0]) // the first copy, late behind a queue
	for seq, p := range a.inflight {
		if p.sent.IsZero() {
			t.Fatalf("part %d taken as lost", seq)
		}
	}
}

// The other device restarted: our unacknowledged calls go again, renumbered; replies to its
// old calls are dropped — they would answer its new calls with the same ids.
func TestStreamResetDropsReplies(t *testing.T) {
	a := newStream()
	a.push([]byte("call"), false, 1, false)
	a.push([]byte("reply"), false, 2, true)
	a.push([]byte("queued reply"), false, 2, true)
	_, _ = a.nextPacket(time.Now(), false)
	_, _ = a.nextPacket(time.Now(), false)
	a.reset()
	if len(a.queue) != 1 || string(a.queue[0].data) != "call" || a.queue[0].seq != 1 || a.next != 2 {
		t.Fatalf("after the restart: %d queued, next %d", len(a.queue), a.next)
	}
}

// A lost part with more than gotMax parts sent after it: the receiver must still take the
// part its gap waits for, and the sender must not run gotMax past it. Before, the receiver
// bounded the number of parts held above the gap: once gotMax arrived it dropped the missing
// part's every copy, and delivery stopped for good while the session stayed alive.
func TestStreamGapPastGotMax(t *testing.T) {
	a, b := newStream(), newStream()
	a.reliable = true // like TCP: no fast retransmit, the gap waits for the timer
	const n = gotMax + 2000
	for i := 0; i < n; i++ {
		a.push([]byte(fmt.Sprintf("m%d", i)), false, 0, false)
	}
	var got []string
	now := time.Unix(0, 0)
	dropped := false
	for step := 0; step < 20000 && len(got) < n; step++ {
		now = now.Add(5 * time.Millisecond)
		for i := 0; i < 256; i++ {
			p, _ := a.nextPacket(now, false)
			if p == nil {
				break
			}
			if !dropped { // the first copy of part 1 is lost
				dropped = true
				continue
			}
			_ = b.receive(now, p, func(m []byte, _ bool, _ uint64) { got = append(got, string(m)) })
			if len(b.got) > gotMax+1 {
				t.Fatalf("receiver holds %d parts", len(b.got))
			}
		}
		for {
			p, _ := b.nextPacket(now, true)
			if p == nil || len(p) <= 1 {
				break
			}
			_ = a.receive(now, p, nil)
			if !b.ackDue.IsZero() {
				continue
			}
			break
		}
	}
	if len(got) != n {
		t.Fatalf("delivered %d of %d: recvAck=%d got=%d inflight=%d queue=%d", len(got), n, b.recvAck, len(b.got), len(a.inflight), len(a.queue))
	}
	for i, m := range got {
		if m != fmt.Sprintf("m%d", i) {
			t.Fatalf("message %d is %q", i, m)
		}
	}
}

// The receiver alone (an old sender runs ahead): the part at recvAck is taken even with
// gotMax−1 parts held above it, and a part gotMax past it is dropped.
func TestStreamReceiveWindow(t *testing.T) {
	a, b := newStream(), newStream()
	a.reliable = true
	for i := 0; i < gotMax+1; i++ {
		a.push([]byte{byte(i)}, false, 0, false)
	}
	var pkts [][]byte
	now := time.Unix(0, 0)
	for len(pkts) < gotMax+1 {
		p, _ := a.nextPacket(now, false)
		if p == nil { // the window: let everything sent so far count as acked
			for seq := range a.inflight {
				delete(a.inflight, seq)
			}
			a.inflightBytes = 0
			continue
		}
		pkts = append(pkts, p)
	}
	n := 0
	deliver := func([]byte, bool, uint64) { n++ }
	for _, p := range pkts[1:] {
		_ = b.receive(now, p, deliver)
	}
	if len(b.got) != gotMax-1 || b.recvAck != 1 {
		t.Fatalf("held %d, recvAck %d", len(b.got), b.recvAck)
	}
	_ = b.receive(now, pkts[0], deliver)
	if b.recvAck != gotMax+1 || n != gotMax {
		t.Fatalf("after the gap: recvAck %d delivered %d", b.recvAck, n)
	}
}
