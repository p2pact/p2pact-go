package p2pact

import (
	"encoding/binary"
	"errors"
	mbits "math/bits"
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
	rtoStart  = 500 * time.Millisecond // before the first round-trip sample
	rtoMin    = 50 * time.Millisecond
	rtoMax    = 4 * time.Second
	ackDelay  = 40 * time.Millisecond
	cwndStart = 32   // parts in flight at first
	cwndMin   = 32   // never below (the old fixed window)
	cwndMax   = 4096 // ~4.5 MB in flight
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
	// bytes delivered when this part was sent: its ack gives a delivery-rate sample
	delivered int64
}

// stream is delivery to one device, both directions.
type stream struct {
	next     uint32 // number of our next part (from 1)
	inflight map[uint32]*part
	queue    []*part

	// congestion control, as in TCP NewReno: the window grows while acks arrive and halves
	// on a loss; the retransmission timer follows the measured round trip (RFC 6298)
	cwnd, ssthresh float64
	srtt, rttvar   time.Duration
	minRTT         time.Duration
	lastCut        time.Time
	// delivery rate, as in BBR: bytes acknowledged per second, the maximum of recent samples;
	// in flight we keep at most what the link delivers in two round trips
	delivered     int64
	inflightBytes int64
	reliable      bool // the current road is a reliable stream: no window of our own
	bw            float64
	bwAt          time.Time

	recvNext   uint32 // the number we expect next (from 1)
	early      map[uint32]*part
	assembling []byte
	zipped     bool      // the message being assembled is compressed
	ackDue     time.Time // when to ack (zero — nothing to ack)
	unacked    int       // parts received since our last ack
}

func newStream() *stream {
	return &stream{next: 1, recvNext: 1, inflight: map[uint32]*part{}, early: map[uint32]*part{},
		cwnd: cwndStart, ssthresh: cwndMax}
}

// rto is the retransmission timeout for a part sent for the first time.
func (s *stream) rto() time.Duration {
	if s.srtt == 0 {
		return rtoStart
	}
	return min(max(s.srtt+4*s.rttvar, rtoMin), rtoMax)
}

// rate takes a delivery-rate sample: the bandwidth estimate is the maximum of the samples
// of the last ~2 seconds (a slower link shows up once old samples age out).
func (s *stream) rate(now time.Time, r float64) {
	if r >= s.bw || now.Sub(s.bwAt) > 2*time.Second {
		s.bw, s.bwAt = r, now
	}
}

// canSend tells whether one more part may go: the congestion window, capped by twice the
// bandwidth-delay product while a queue is building (the round trip has grown well above
// its minimum). Without a queue the rate samples may come from small messages that never
// filled the link, so they must not hold it back.
func (s *stream) canSend() bool {
	if s.reliable { // the road (TCP, a relay over TLS) controls congestion itself
		return len(s.inflight) < cwndMax
	}
	if len(s.inflight) >= int(s.cwnd) {
		return false
	}
	queue := s.srtt > s.minRTT+max(s.minRTT/2, 10*time.Millisecond)
	if queue && s.bw > 0 && s.minRTT > 0 {
		// in bytes, not parts: under load parts are small
		return s.inflightBytes < int64(2*s.bw*s.minRTT.Seconds())+4*maxPart
	}
	return true
}

// timeout is when a part is due for retransmission: the current estimate (not the one at
// send time — a queue on a slow link stretches it) plus the time the link needs for the
// parts sent ahead of it, doubled for every retry.
func (s *stream) timeout(p *part, ahead int) time.Duration {
	t := s.rto()
	if s.bw > 0 {
		t += time.Duration(float64(ahead*maxPart) / s.bw * float64(time.Second))
	}
	for i := 1; i < p.tries && t < rtoMax; i++ {
		t *= 2
	}
	return min(t, rtoMax)
}

// sample takes a round-trip measurement (only from parts sent once — Karn's rule). A round
// trip well above the minimum means a queue is building: leave slow start (as HyStart does).
func (s *stream) sample(rtt time.Duration) {
	if s.minRTT == 0 || rtt < s.minRTT {
		s.minRTT = rtt
	}
	if s.cwnd < s.ssthresh && rtt > s.minRTT+max(s.minRTT/2, 4*time.Millisecond) {
		s.ssthresh = s.cwnd
	}
	if s.srtt == 0 {
		s.srtt, s.rttvar = rtt, rtt/2
		return
	}
	d := s.srtt - rtt
	if d < 0 {
		d = -d
	}
	s.rttvar = (3*s.rttvar + d) / 4
	s.srtt = (7*s.srtt + rtt) / 8
}

// acked grows the window for n newly acknowledged parts.
func (s *stream) acked(n int) {
	for i := 0; i < n; i++ {
		if s.cwnd < s.ssthresh {
			s.cwnd++ // slow start: doubles every round trip
		} else {
			s.cwnd += 1 / s.cwnd
		}
	}
	s.cwnd = min(s.cwnd, cwndMax)
}

// lost halves the window, at most once per round trip.
func (s *stream) lost(now time.Time) {
	if now.Sub(s.lastCut) < max(s.srtt, rtoMin) {
		return
	}
	s.lastCut = now
	s.ssthresh = max(s.cwnd/2, cwndMin)
	s.cwnd = s.ssthresh
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
	s.next, s.inflight, s.queue, s.inflightBytes = 1, map[uint32]*part{}, nil, 0
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
	lowest := uint32(0)
	for seq := range s.inflight {
		if lowest == 0 || seq < lowest {
			lowest = seq
		}
	}
	for _, x := range s.inflight {
		if now.Sub(x.sent) >= s.timeout(x, int(x.seq-lowest)) && (p == nil || x.seq < p.seq) {
			p = x
		}
	}
	if p != nil {
		retry = true
		s.lost(now)
	} else if len(s.queue) > 0 && s.canSend() {
		p = s.queue[0]
		s.queue = s.queue[1:]
		s.inflight[p.seq] = p
		s.inflightBytes += int64(len(p.data))
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
		s.ackDue, s.unacked = time.Time{}, 0
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
			p.first = now
		}
		p.delivered = s.delivered
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
		done := 0
		ack := func(seq uint32) {
			p := s.inflight[seq]
			if p == nil {
				return
			}
			s.delivered += int64(len(p.data))
			if p.tries == 1 {
				s.sample(now.Sub(p.sent))
				if dt := now.Sub(p.sent); dt > 0 {
					s.rate(now, float64(s.delivered-p.delivered)/dt.Seconds())
				}
			}
			delete(s.inflight, seq)
			s.inflightBytes -= int64(len(p.data))
			done++
		}
		for seq := range s.inflight {
			if uint64(seq) <= upto {
				ack(seq)
			}
		}
		for i := uint64(0); i < 32; i++ {
			if bits&(1<<i) != 0 {
				ack(uint32(upto + 2 + i))
			}
		}
		s.acked(done)
		// fast retransmit, as TCP after three duplicate acks: three parts after the gap arrived,
		// so the gap is lost — resend it now instead of waiting for the timer. Fewer than
		// three may be reordering: wait a quarter of a round trip.
		if bits != 0 {
			if p := s.inflight[uint32(upto+1)]; p != nil &&
				(mbits.OnesCount64(bits) >= 3 || now.Sub(p.sent) >= max(s.srtt/4, ackDelay)) {
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
	// like TCP: ack at once every second part, and on anything out of order (a gap tells the
	// sender to retransmit); a lone part waits ackDelay for a reply to ride on
	if s.unacked++; s.unacked >= 2 || seq != s.recvNext {
		s.ackDue = now
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
