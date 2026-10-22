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
