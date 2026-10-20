package p2pact

import (
	"encoding/binary"
	"errors"
	"sort"
	"time"
)

// Delivery (spec §5). The decrypted content of a data packet:
//
//	flags (1) | [ack: varint "all up to N" + varint bitmap of the 32 parts after N+1] | [varint part number | part]
//
// A message is cut into packet-sized parts numbered consecutively; the receiver reassembles
// them in order. Anything unacknowledged is retransmitted while the session lives.
const (
	fAck  = 1  // carries an ack
	fMsg  = 2  // carries a message part
	fMore = 4  // more parts follow
	fZip  = 8  // compressed (compress.go); set on every part of a compressed message
	fOnce = 16 // do not ack (keepalive)
)

// maxPart is the message part per packet: 1200 − 9 (header) − 16 (tag) − 1 (flags) −
// up to 10 (ack) − up to 5 (number).
const maxPart = MaxPacket - dataHeader - 16 - 1 - 10 - 5

const (
	rtoStart  = 250 * time.Millisecond
	rtoMax    = time.Second
	ackDelay  = 40 * time.Millisecond
	inflightN = 32
	earlyMax  = 512
	msgMax    = 16 << 20 // longer messages abort reassembly
)

type part struct {
	seq   uint32
	data  []byte
	more  bool
	zip   bool
	first time.Time // first sent at (zero — not sent yet)
	sent  time.Time
	tries int
	rto   time.Duration
}

// stream is delivery to one device, both directions.
type stream struct {
	next     uint32 // number of our next part (from 1)
	inflight map[uint32]*part
	queue    []*part

	recvNext   uint32 // the number we expect next (from 1)
	early      map[uint32]*part
	assembling []byte
	zipped     bool      // the message being assembled is compressed
	ackDue     time.Time // when to ack (zero — nothing to ack)
}

func newStream() *stream {
	return &stream{next: 1, recvNext: 1, inflight: map[uint32]*part{}, early: map[uint32]*part{}}
}

// reset handles a restart of the other device: its receiving started from zero. Our
// unacknowledged parts are renumbered from 1; receiving restarts from 1 too.
func (s *stream) reset() {
	var pending []*part
	for _, p := range s.inflight {
		pending = append(pending, p)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].seq < pending[j].seq })
	pending = append(pending, s.queue...)
	s.next, s.inflight, s.queue = 1, map[uint32]*part{}, nil
	for _, p := range pending {
		p.seq, p.first, p.sent, p.tries = s.next, time.Time{}, time.Time{}, 0
		s.next++
		s.queue = append(s.queue, p)
	}
	s.recvNext, s.early, s.assembling, s.zipped, s.ackDue = 1, map[uint32]*part{}, nil, false, time.Time{}
}

// push queues a message in parts; zip marks it compressed.
func (s *stream) push(msg []byte, zip bool) {
	for {
		n := min(len(msg), maxPart)
		p := &part{seq: s.next, data: msg[:n], more: n < len(msg), zip: zip}
		s.next++
		s.queue = append(s.queue, p)
		msg = msg[n:]
		if len(msg) == 0 {
			return
		}
	}
}

// nextPacket builds the next packet content: an overdue retransmission, a new part, or just
// an ack; nil — nothing to send. forceAck asks for an ack now.
func (s *stream) nextPacket(now time.Time, forceAck bool) (plain []byte, retry bool) {
	var p *part
	for _, x := range s.inflight {
		if now.Sub(x.sent) >= x.rto && (p == nil || x.seq < p.seq) {
			p = x
		}
	}
	if p != nil {
		retry = true
	} else if len(s.queue) > 0 && len(s.inflight) < inflightN {
		p = s.queue[0]
		s.queue = s.queue[1:]
		s.inflight[p.seq] = p
	}
	ack := s.recvNext > 1 && (p != nil || forceAck || (!s.ackDue.IsZero() && !now.Before(s.ackDue)))
	if p == nil && !ack {
		return nil, false
	}
	flags := byte(0)
	b := []byte{0}
	if ack {
		flags |= fAck
		b = binary.AppendUvarint(b, uint64(s.recvNext-1))
		var bits uint64
		for i := uint32(0); i < 32; i++ {
			if s.early[s.recvNext+1+i] != nil {
				bits |= 1 << i
			}
		}
		b = binary.AppendUvarint(b, bits)
		s.ackDue = time.Time{}
	}
	if p != nil {
		flags |= fMsg
		if p.more {
			flags |= fMore
		}
		if p.zip {
			flags |= fZip
		}
		b = binary.AppendUvarint(b, uint64(p.seq))
		b = append(b, p.data...)
		if p.first.IsZero() {
			p.first, p.rto = now, rtoStart
		} else {
			p.rto = min(p.rto*2, rtoMax)
		}
		p.sent = now
		p.tries++
	}
	b[0] = flags
	return b, retry
}

// keepalive is a liveness packet: flags only, not acknowledged.
func keepalive() []byte { return []byte{fOnce} }

// receive handles packet content from the other device; deliver is called for every
// reassembled message, in order (zip — compressed).
func (s *stream) receive(now time.Time, b []byte, deliver func(msg []byte, zip bool)) error {
	if len(b) == 0 {
		return errors.New("empty packet")
	}
	flags, b := b[0], b[1:]
	if flags&fAck != 0 {
		upto, n := binary.Uvarint(b)
		if n <= 0 {
			return errShort
		}
		bits, m := binary.Uvarint(b[n:])
		if m <= 0 {
			return errShort
		}
		b = b[n+m:]
		for seq := range s.inflight {
			if uint64(seq) <= upto {
				delete(s.inflight, seq)
			}
		}
		for i := uint64(0); i < 32; i++ {
			if bits&(1<<i) != 0 {
				delete(s.inflight, uint32(upto+2+i))
			}
		}
		// fast retransmit: parts after the gap arrived, so resend the gap now, without the timer
		if bits != 0 {
			if p := s.inflight[uint32(upto+1)]; p != nil && now.Sub(p.sent) >= ackDelay*2 {
				p.sent = time.Time{}
			}
		}
	}
	if flags&fMsg == 0 {
		return nil
	}
	seq64, n := binary.Uvarint(b)
	if n <= 0 {
		return errShort
	}
	seq, data := uint32(seq64), b[n:]
	if s.ackDue.IsZero() {
		s.ackDue = now.Add(ackDelay)
	}
	switch {
	case seq < s.recvNext: // duplicate: already had it, just ack
		return nil
	case seq > s.recvNext:
		if len(s.early) < earlyMax {
			s.early[seq] = &part{seq: seq, data: append([]byte(nil), data...), more: flags&fMore != 0, zip: flags&fZip != 0}
		}
		return nil
	}
	s.take(data, flags&fMore != 0, flags&fZip != 0, deliver)
	for {
		p := s.early[s.recvNext]
		if p == nil {
			return nil
		}
		delete(s.early, s.recvNext)
		s.take(p.data, p.more, p.zip, deliver)
	}
}

func (s *stream) take(data []byte, more, zip bool, deliver func([]byte, bool)) {
	s.recvNext++
	if len(s.assembling) == 0 {
		s.zipped = zip
	}
	if len(s.assembling)+len(data) > msgMax {
		s.assembling = nil
		return
	}
	s.assembling = append(s.assembling, data...)
	if more {
		return
	}
	msg := s.assembling
	s.assembling = nil
	deliver(msg, s.zipped)
}

// idle reports that nothing waits to be sent or acknowledged.
func (s *stream) idle() bool { return len(s.inflight) == 0 && len(s.queue) == 0 }
