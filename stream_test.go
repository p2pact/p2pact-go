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
	a.push(data, false, 0)
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
	a.push([]byte("s1 first"), false, 1)
	a.push([]byte("s2 only"), false, 2)
	a.push([]byte("s1 second"), false, 1)
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
