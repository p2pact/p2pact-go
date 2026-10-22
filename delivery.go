package p2pact

import (
	"encoding/binary"
	"errors"
	"sort"
	"time"
)

// Delivery (spec §5). The decrypted content of a data packet:
//
//	flags (1) | [ack] | [varint part number | [varint stream | varint number in stream] | part]
//	ack = varint "all up to N" | varint count | count × (varint missing, varint received)
//
// A message is cut into packet-sized parts numbered consecutively. Messages on stream 0 are
// delivered in the order sent; a message on another stream (a chat, say) is delivered as soon
// as it is complete and its stream's earlier messages are delivered — a loss on one stream
// does not hold up the others. Anything unacknowledged is retransmitted while the session
// lives. The ack lists the ranges received above the first gap, so many messages in flight
// past a loss are all acknowledged.
const (
	fAck   = 1  // carries an ack
	fMsg   = 2  // carries a message part
	fMore  = 4  // more parts follow
	fZip   = 8  // compressed (compress.go); set on every part of a compressed message
	fOnce  = 16 // do not ack (keepalive)
	fFirst = 32 // the first part of a message on a stream: stream and its number follow
	fCont  = 64 // a further part of a message on a stream
)

// ackBudget is the room for an ack in a packet; ranges beyond it are left out.
const ackBudget = 60

// maxPart is the message part per packet: 1200 − 9 (header) − 16 (tag) − 1 (flags) −
// the ack − up to 5 (part number) − up to 20 (stream and number).
const maxPart = MaxPacket - dataHeader - 16 - 1 - ackBudget - 5 - 20

const (
	rtoStart  = 500 * time.Millisecond // before the first round-trip sample
	rtoMin    = 50 * time.Millisecond
	rtoMax    = 4 * time.Second
	ackDelay  = 40 * time.Millisecond
	cwndStart = 32       // parts in flight at first
	cwndMin   = 32       // never below (the old fixed window)
	cwndMax   = 4096     // ~4.5 MB in flight
	gotMax    = 8192     // parts held above the first gap
	msgMax    = 16 << 20 // longer messages abort reassembly
)

type part struct {
	seq    uint32
	data   []byte
	more   bool
	zip    bool
	stream uint64      // 0 — the ordered default stream
	num    uint64      // message number in its stream (from 1), on the first part
	first  bool        // first part of a message on a stream
	reply  bool        // part of a result or error: it answers a call of this boot only
	copies []time.Time // when each copy was sent
	timer  bool        // the last copy went because the timer ran out
	sent   time.Time
	tries  int
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

	snext map[uint64]uint64 // last message number sent per stream

	recvAck uint32            // the first part not received yet (all before it arrived)
	got     map[uint32]*rpart // parts received from recvAck on, and earlier ones not yet used
	next0   uint32            // the next part to take for stream 0
	asm0    []byte            // stream 0 message being assembled
	zip0    bool
	streams map[uint64]*rstream
	ackDue  time.Time // when to ack (zero — nothing to ack)
	unacked int       // parts received since our last ack
}

type rpart struct {
	data                       []byte
	more, zip, first, streamed bool
	used                       bool
	stream, num                uint64
}

// rstream holds complete messages of one stream until their turn.
type rstream struct {
	next  uint64
	ready map[uint64]readyMsg
}

type readyMsg struct {
	msg []byte
	zip bool
}

func newStream() *stream {
	s := &stream{next: 1, inflight: map[uint32]*part{}, cwnd: cwndStart, ssthresh: cwndMax}
	s.resetRecv()
	return s
}

func (s *stream) resetRecv() {
	s.snext = map[uint64]uint64{}
	s.recvAck, s.next0, s.got, s.asm0, s.zip0 = 1, 1, map[uint32]*rpart{}, nil, false
	s.streams = map[uint64]*rstream{}
	s.ackDue, s.unacked = time.Time{}, 0
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
	if s.queueing() && s.bw > 0 && s.minRTT > 0 {
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
	// back off only on signs of congestion, or after three tries in a row: a random loss
	// (radio, a busy Wi-Fi) does not mean the link needs a rest
	backoff := p.tries - 1
	if !s.queueing() {
		backoff = max(0, p.tries-3)
	}
	for i := 0; i < backoff && t < rtoMax; i++ {
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
	queue := s.queueing()
	for i := 0; i < n; i++ {
		if s.cwnd < s.ssthresh || !queue {
			s.cwnd++ // slow start, and while no queue builds (as BBR probes): doubles every round trip
		} else {
			s.cwnd += 1 / s.cwnd
		}
	}
	s.cwnd = min(s.cwnd, cwndMax)
}

// queueing reports that the round trip has grown well above its minimum: a queue is building
// somewhere on the path.
func (s *stream) queueing() bool {
	return s.srtt > s.minRTT+max(s.minRTT/2, 10*time.Millisecond)
}

// lost halves the window, at most once per round trip — but only when a queue builds: a loss
// without one is random (radio, a busy Wi-Fi) and says nothing about congestion.
func (s *stream) lost(now time.Time) {
	if now.Sub(s.lastCut) < max(s.srtt, rtoMin) || !s.queueing() {
		return
	}
	s.lastCut = now
	s.ssthresh = max(s.cwnd/2, cwndMin)
	s.cwnd = s.ssthresh
}

// reset handles a restart of the other device: its receiving started from zero. Our
// unacknowledged parts are renumbered from 1; receiving restarts from 1 too. Replies are
// dropped: the calls they answer ended with the restart, and the new call ids start from 1
// again, so a stale reply would answer a new call.
func (s *stream) reset() {
	var pending []*part
	for _, p := range s.inflight {
		pending = append(pending, p)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].seq < pending[j].seq })
	pending = append(pending, s.queue...)
	s.next, s.inflight, s.queue, s.inflightBytes = 1, map[uint32]*part{}, nil, 0
	s.resetRecv()
	// the path may be another one now: measure it afresh (a stale minimum round trip would
	// read every round trip as a queue, or every ack of a retransmission as a real one)
	s.cwnd, s.ssthresh, s.lastCut = cwndStart, cwndMax, time.Time{}
	s.srtt, s.rttvar, s.minRTT, s.bw, s.bwAt = 0, 0, 0, 0, time.Time{}
	for _, p := range pending {
		if p.reply {
			continue
		}
		p.seq, p.copies, p.sent, p.tries, p.timer = s.next, nil, time.Time{}, 0, false
		s.next++
		if p.first { // the other side expects each stream from message 1 again
			s.snext[p.stream]++
			p.num = s.snext[p.stream]
		}
		s.queue = append(s.queue, p)
	}
}

// push queues a message in parts on a stream (0 — the ordered default); zip marks it
// compressed, reply — a result or error.
func (s *stream) push(msg []byte, zip bool, stream uint64, reply bool) {
	var num uint64
	if stream != 0 {
		s.snext[stream]++
		num = s.snext[stream]
	}
	first := true
	for {
		n := min(len(msg), maxPart)
		p := &part{seq: s.next, data: msg[:n], more: n < len(msg), zip: zip, stream: stream, reply: reply}
		if stream != 0 && first {
			p.first, p.num = true, num
		}
		first = false
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
		p.timer = !p.sent.IsZero() // not taken as lost by an ack: the timer ran out
		s.lost(now)
	} else if len(s.queue) > 0 && s.canSend() {
		p = s.queue[0]
		s.queue = s.queue[1:]
		s.inflight[p.seq] = p
		s.inflightBytes += int64(len(p.data))
	}
	received := s.recvAck > 1 || len(s.got) > 0
	ack := received && (p != nil || forceAck || (!s.ackDue.IsZero() && !now.Before(s.ackDue)))
	if p == nil && !ack {
		return nil, false
	}
	flags := byte(0)
	b := []byte{0}
	if ack {
		flags |= fAck
		b = s.appendAck(b)
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
		switch {
		case p.first:
			flags |= fFirst
			b = binary.AppendUvarint(b, p.stream)
			b = binary.AppendUvarint(b, p.num)
		case p.stream != 0:
			flags |= fCont
		}
		b = append(b, p.data...)
		p.copies = append(p.copies, now)
		p.delivered = s.delivered
		p.sent = now
		p.tries++
	}
	b[0] = flags
	return b, retry
}

// appendAck writes the ack: all up to recvAck−1, then ranges received above the first gap as
// (missing, received) counts, as many as fit in ackBudget.
func (s *stream) appendAck(b []byte) []byte {
	b = binary.AppendUvarint(b, uint64(s.recvAck-1))
	var above []uint32
	for seq := range s.got {
		if seq > s.recvAck {
			above = append(above, seq)
		}
	}
	sort.Slice(above, func(i, j int) bool { return above[i] < above[j] })
	var ranges []byte
	count, cursor := 0, s.recvAck
	for i := 0; i < len(above); {
		j := i
		for j+1 < len(above) && above[j+1] == above[j]+1 {
			j++
		}
		r := binary.AppendUvarint(nil, uint64(above[i]-cursor))
		r = binary.AppendUvarint(r, uint64(j-i+1))
		if len(ranges)+len(r) > ackBudget-12 {
			break
		}
		ranges = append(ranges, r...)
		count++
		cursor = above[j] + 1
		i = j + 1
	}
	b = binary.AppendUvarint(b, uint64(count))
	return append(b, ranges...)
}

// keepalive is a liveness packet: flags only, not acknowledged.
func keepalive() []byte { return []byte{fOnce} }

// receive handles packet content from the other device; deliver is called for every
// message as it becomes deliverable (zip — compressed; stream — the stream it came on).
func (s *stream) receive(now time.Time, b []byte, deliver func(msg []byte, zip bool, stream uint64)) error {
	if len(b) == 0 {
		return errors.New("empty packet")
	}
	flags, b := b[0], b[1:]
	if flags&fAck != 0 {
		upto, n := binary.Uvarint(b)
		if n <= 0 {
			return errShort
		}
		b = b[n:]
		count, n := binary.Uvarint(b)
		if n <= 0 || count > 64 {
			return errShort
		}
		b = b[n:]
		done := 0
		var newest time.Time // the latest send time among the parts this ack covers
		ack := func(seq uint32) {
			p := s.inflight[seq]
			if p == nil {
				return
			}
			// an ack sooner than the minimum round trip after a timer's copy is for an earlier
			// copy: the timer fired on a queue, not a loss (RFC 8985 §6.2). The newest copy's
			// time would declare every part sent between the copies lost, and their copies
			// would fire the same way, again and again. The ack is not ambiguous, so it is a
			// round-trip sample (Karn's rule skips it otherwise): without one the timer
			// would stay shorter than the queue for good.
			sent := p.sent
			if p.timer && now.Sub(p.sent) < s.minRTT {
				for i, c := range p.copies {
					if i == 0 || now.Sub(c) >= s.minRTT {
						sent = c
					}
				}
				s.sample(now.Sub(sent))
			}
			if sent.After(newest) {
				newest = sent
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
		beyond, cursor := uint64(0), upto+1
		for i := uint64(0); i < count; i++ {
			gap, k := binary.Uvarint(b)
			if k <= 0 {
				return errShort
			}
			run, m := binary.Uvarint(b[k:])
			if m <= 0 || run > gotMax {
				return errShort
			}
			b = b[k+m:]
			start := cursor + gap
			for seq := start; seq < start+run; seq++ {
				ack(uint32(seq))
			}
			beyond += run
			cursor = start + run
		}
		s.acked(done)
		// time-based loss detection (RACK, RFC 8985): a part sent a quarter of a round trip
		// before one that arrived, and still not acknowledged, is lost — resend it now. A
		// reliable road loses nothing: there a late ack only means the road's own queue.
		if !newest.IsZero() && !s.reliable {
			reorder := max(s.srtt/4, time.Millisecond)
			lost := false
			for _, p := range s.inflight {
				if !p.sent.IsZero() && p.sent.Add(reorder).Before(newest) {
					p.sent, lost = time.Time{}, true
				}
			}
			if lost {
				s.lost(now)
			}
		}
		// fast retransmit, as TCP after three duplicate acks: three parts after the gap arrived,
		// so the gap is lost — resend it now instead of waiting for the timer. Fewer than
		// three may be reordering: wait a quarter of a round trip.
		if beyond > 0 && !s.reliable {
			if p := s.inflight[uint32(upto+1)]; p != nil &&
				(beyond >= 3 || now.Sub(p.sent) >= max(s.srtt/4, ackDelay)) {
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
	b = b[n:]
	r := &rpart{more: flags&fMore != 0, zip: flags&fZip != 0}
	if flags&fFirst != 0 {
		st, k := binary.Uvarint(b)
		if k <= 0 {
			return errShort
		}
		num, m := binary.Uvarint(b[k:])
		if m <= 0 {
			return errShort
		}
		b = b[k+m:]
		r.first, r.streamed, r.stream, r.num = true, true, st, num
	} else if flags&fCont != 0 {
		r.streamed = true
	}
	seq := uint32(seq64)
	if s.ackDue.IsZero() {
		s.ackDue = now.Add(ackDelay)
	}
	// like TCP: ack at once every second part, and on anything out of order (a gap tells the
	// sender to retransmit); a lone part waits ackDelay for a reply to ride on
	if s.unacked++; s.unacked >= 2 || seq != s.recvAck {
		s.ackDue = now
	}
	if seq < s.recvAck || s.got[seq] != nil || len(s.got) >= gotMax {
		return nil // duplicate (just ack), or too far ahead
	}
	r.data = append([]byte(nil), b...)
	s.got[seq] = r
	for s.got[s.recvAck] != nil {
		s.recvAck++
	}
	if r.streamed {
		s.assemble(seq, deliver)
	}
	s.take0(deliver)
	for seq, x := range s.got { // forget parts that are used and acknowledged
		if x.used && seq < s.recvAck && seq < s.next0 {
			delete(s.got, seq)
		}
	}
	return nil
}

// assemble completes the stream message part seq belongs to, if all its parts are here, and
// delivers what its stream allows.
func (s *stream) assemble(seq uint32, deliver func([]byte, bool, uint64)) {
	start := seq
	for {
		x := s.got[start]
		if x == nil || x.used {
			return
		}
		if x.first {
			break
		}
		if !x.streamed || start == 0 {
			return
		}
		start--
	}
	head := s.got[start]
	var msg []byte
	end := start
	for {
		x := s.got[end]
		if x == nil || !x.streamed || x.used || (end != start && x.first) {
			return // a part is still missing
		}
		if len(msg)+len(x.data) > msgMax {
			return
		}
		msg = append(msg, x.data...)
		if !x.more {
			break
		}
		end++
	}
	for k := start; k <= end; k++ {
		s.got[k].used = true
	}
	st := s.streams[head.stream]
	if st == nil {
		st = &rstream{next: 1, ready: map[uint64]readyMsg{}}
		s.streams[head.stream] = st
	}
	if head.num < st.next {
		return // a duplicate of a delivered message
	}
	st.ready[head.num] = readyMsg{msg, head.zip}
	for {
		m, ok := st.ready[st.next]
		if !ok {
			return
		}
		delete(st.ready, st.next)
		st.next++
		deliver(m.msg, m.zip, head.stream)
	}
}

// take0 delivers stream 0 messages in order; parts of stream messages are skipped.
func (s *stream) take0(deliver func([]byte, bool, uint64)) {
	for {
		x := s.got[s.next0]
		if x == nil {
			return
		}
		s.next0++
		if x.streamed {
			continue
		}
		x.used = true
		if len(s.asm0) == 0 {
			s.zip0 = x.zip
		}
		if len(s.asm0)+len(x.data) > msgMax {
			s.asm0 = nil
			continue
		}
		s.asm0 = append(s.asm0, x.data...)
		if x.more {
			continue
		}
		msg := s.asm0
		s.asm0 = nil
		deliver(msg, s.zip0, 0)
	}
}

// idle reports that nothing waits to be sent or acknowledged.
func (s *stream) idle() bool { return len(s.inflight) == 0 && len(s.queue) == 0 }
