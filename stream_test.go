package p2pact

import (
	"bytes"
	mrand "math/rand"
	"testing"
	"time"
)

func TestStreamHalfLoss(t *testing.T) {
	a, b := newStream(), newStream()
	r := mrand.New(mrand.NewSource(2))
	data := make([]byte, 200<<10)
	r.Read(data)
	a.push(data, false)
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
				_ = b.receive(now, p, func(m []byte, _ bool) { got = m })
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
		t.Fatalf("not reassembled: recvNext=%d early=%d inflight=%d queue=%d", b.recvNext, len(b.early), len(a.inflight), len(a.queue))
	}
}
