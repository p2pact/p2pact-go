package p2pact

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Via a third device (spec §3): a device both trust carries a pair's packets inside its own
// sessions with each of them — event 0.7 forward [to, packet] to it, event 0.8 forwarded
// [from, packet] from it. The packets stay end-to-end encrypted: the forwarder sees what a relay
// sees. It forwards only for pairs its person opted it in for (AllowForward), one hop only,
// within a rate limit, and never ahead of its own traffic.

const (
	evForward   = 7 // event 0.7 forward [to, packet]: to a forwarder
	evForwarded = 8 // event 0.8 forwarded [from, packet]: from a forwarder

	// DefaultForwardRate is how many bytes a second a forwarder carries in one direction of a
	// pair, unless Node.ForwardRate says otherwise.
	DefaultForwardRate = 256 << 10
	forwardBurst       = 64 << 10 // bytes a direction may send at once above its rate
	// forwardQueue: past this many parts waiting to go to a device, packets to forward to it
	// (and our own packets for a forwarder) are dropped — our own traffic goes first
	forwardQueue = 128
)

var addrEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// addrBytes is an address as it goes on the wire: 16 bytes.
func addrBytes(addr string) ([]byte, bool) {
	b, err := addrEncoding.DecodeString(strings.ToUpper(addr))
	return b, err == nil && len(b) == 16
}

// addrText is an address from the wire.
func addrText(b []byte) string { return strings.ToLower(addrEncoding.EncodeToString(b)) }

// forwardStream is the stream forward events about a device go on: its address's first 8
// bytes, so a loss towards one device holds up nothing else.
func forwardStream(addr []byte) uint64 {
	s := binary.BigEndian.Uint64(addr[:8])
	if s == 0 {
		s = 1
	}
	return s
}

// viaRoad is the road to other devices through forwarder x: Send wraps a packet into event
// 0.7 to x; what x hands over (0.8) arrives on it. Addr is the device at the other end.
type viaRoad struct {
	n *Node
	x string
}

func (v *viaRoad) Name() string { return "via:" + v.x }

// Send is called under the node's lock, like every Road.Send of the node's own roads.
func (v *viaRoad) Send(to string, pkt []byte) error {
	n := v.n
	if len(pkt) > MaxRoadPacket {
		return errors.New("packet too big")
	}
	raw, ok := addrBytes(to)
	if !ok {
		return errors.New("bad address")
	}
	ps := n.peers[v.x]
	if ps == nil || !n.directLocked(ps, time.Now()) {
		return errors.New("no direct road to the forwarder")
	}
	if len(ps.st.queue) >= forwardQueue {
		return errors.New("forwarder queue full")
	}
	msg, _ := cbor.Marshal([]any{3, 0, evForward, raw, pkt})
	ps.st.push(msg, false, forwardStream(raw), false)
	n.wakeLocked()
	return nil
}

func isVia(r Road) bool {
	_, ok := r.(*viaRoad)
	return ok
}

// viaLocked is the road through forwarder x.
func (n *Node) viaLocked(x string) *viaRoad {
	v := n.vias[x]
	if v == nil {
		v = &viaRoad{n: n, x: x}
		n.vias[x] = v
	}
	return v
}

// directLocked: we are in session with the device and have a live road to it that is not via
// a third device. Forwarding takes one hop only — no chains, no loops.
func (n *Node) directLocked(ps *peerState, now time.Time) bool {
	if n.current[ps.addr] == nil {
		return false
	}
	for _, e := range ps.eps {
		if !isVia(e.ep.Road) && now.Sub(e.lastRecv) <= aliveFor {
			return true
		}
	}
	return false
}

// AllowForward opts this device in (on) or out as a forwarder between two devices it trusts
// (spec §3): one consent for both directions, kept with the trusted list. Both devices learn
// it from our hello, sent again to them at once.
func (n *Node) AllowForward(a, b string, on bool) error {
	if a == b || a == n.ID.Addr() || b == n.ID.Addr() {
		return errors.New("forwarding needs two other devices")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	pa, pb := n.Trust.Get(a), n.Trust.Get(b)
	if pa == nil || pb == nil {
		return errors.New("unknown device")
	}
	if pa.Kind == KindPlugin || pb.Kind == KindPlugin {
		return errors.New("a plugin is reachable over the local socket only")
	}
	set := func(p *Peer, other string) bool {
		list := slices.DeleteFunc(slices.Clone(p.Forward), func(s string) bool { return s == other })
		if on {
			list = append(list, other)
			slices.Sort(list)
		}
		if slices.Equal(list, p.Forward) {
			return false
		}
		n.Trust.SetForward(p.Addr, list)
		return true
	}
	if set(pa, b) {
		n.helloLocked(a)
	}
	if set(pb, a) {
		n.helloLocked(b)
	}
	return nil
}

// Forwards lists the devices we forward to for a known device (AllowForward).
func (n *Node) Forwards(peer string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.forwardsLocked(peer)
}

func (n *Node) forwardsLocked(peer string) []string {
	p := n.Trust.Get(peer)
	if p == nil {
		return nil
	}
	var out []string
	for _, a := range p.Forward {
		if q := n.Trust.Get(a); q != nil && a != peer {
			out = append(out, a)
		}
	}
	return out
}

// Forwarders lists the devices that forward for us to peer: their hellos list it.
func (n *Node) Forwarders(peer string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	for x, xs := range n.peers {
		if x != peer && slices.Contains(xs.forwards, peer) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

// helloLocked sends our hello again to a device in session (what we forward for it changed).
func (n *Node) helloLocked(peer string) {
	if n.current[peer] == nil {
		return
	}
	if ps := n.peerLocked(peer); ps != nil {
		msg, _ := cbor.Marshal(append([]any{3, 0, 2}, n.infoLocked(peer)...))
		n.pushLocked(ps, msg, 0, false, false)
	}
}

// forwardsWire is the hello's ninth element: what we forward to for peer; nil — none.
func (n *Node) forwardsWire(peer string) [][]byte {
	var out [][]byte
	for _, a := range n.forwardsLocked(peer) {
		if b, ok := addrBytes(a); ok {
			out = append(out, b)
		}
	}
	return out
}

// heardForwardsLocked takes the list a device's hello gave: the devices it forwards to for us.
// A device newly reachable through it gets a handshake at once.
func (n *Node) heardForwardsLocked(x string, ps *peerState, raw *cbor.RawMessage) {
	var list [][]byte
	if raw != nil {
		_ = cbor.Unmarshal(*raw, &list)
	}
	old := ps.forwards
	ps.forwards = nil
	for _, b := range list {
		if len(b) == 16 {
			if a := addrText(b); a != x && a != n.ID.Addr() { // trust is checked on use
				ps.forwards = append(ps.forwards, a)
			}
		}
	}
	now := time.Now()
	for _, a := range ps.forwards {
		if slices.Contains(old, a) || n.current[a] != nil {
			continue
		}
		if pa := n.peerLocked(a); pa != nil {
			pa.lastInit = time.Time{}
			var first []byte
			if !pa.st.idle() {
				first, _ = pa.st.nextPacket(now, false)
			}
			n.startInitLocked(now, a, pa, first)
		}
	}
}

// forwardLocked: device from asks us to carry a packet to another device (event 0.7).
// Anything we may not or cannot forward is dropped silently.
func (n *Node) forwardLocked(from string, args []cbor.RawMessage) {
	var to, pkt []byte
	if len(args) < 2 || cbor.Unmarshal(args[0], &to) != nil || cbor.Unmarshal(args[1], &pkt) != nil ||
		len(to) != 16 || len(pkt) < 5 || len(pkt) > MaxRoadPacket {
		n.fwdDropped.Add(1)
		return
	}
	now := time.Now()
	dest := addrText(to)
	pf := n.Trust.Get(from)
	if dest == from || dest == n.ID.Addr() || pf == nil || n.Trust.Get(dest) == nil || !slices.Contains(pf.Forward, dest) {
		n.fwdDropped.Add(1)
		return
	}
	pd, ps := n.peerLocked(dest), n.peers[from]
	if ps == nil || pd == nil || !n.directLocked(ps, now) || !n.directLocked(pd, now) || len(pd.st.queue) >= forwardQueue {
		n.fwdDropped.Add(1)
		return
	}
	src, _ := addrBytes(from)
	msg, _ := cbor.Marshal([]any{3, 0, evForwarded, src, pkt})
	if !n.fwdOfferLocked(from+">"+dest, fwdPending{to: dest, msg: msg, stream: forwardStream(src), size: len(pkt)}, now) {
		n.fwdDropped.Add(1)
		return
	}
	if tap := n.forwardTap; tap != nil {
		tap(from, dest, pkt)
	}
}

// fwdBucket shapes one forwarded direction: a token bucket of the forward rate with bursts of
// forwardBurst bytes. What comes over the rate waits, up to forwardBurst bytes, and goes as the
// bucket refills — the queue it builds tells the pair's congestion control to slow down; past
// that it is dropped.
type fwdBucket struct {
	tokens float64
	at     time.Time
	q      []fwdPending
	queued int // bytes waiting in q
}

type fwdPending struct {
	to     string
	msg    []byte
	stream uint64
	size   int // the forwarded packet's bytes
}

func (n *Node) fwdRefill(b *fwdBucket, now time.Time) {
	rate := float64(n.ForwardRate)
	if rate <= 0 {
		rate = DefaultForwardRate
	}
	if !now.After(b.at) {
		return
	}
	b.tokens = min(forwardBurst, b.tokens+rate*now.Sub(b.at).Seconds())
	b.at = now
}

// fwdOfferLocked forwards p now, or queues it behind its direction's rate; false — dropped.
func (n *Node) fwdOfferLocked(dir string, p fwdPending, now time.Time) bool {
	b := n.fwdBuckets[dir]
	if b == nil {
		b = &fwdBucket{tokens: forwardBurst, at: now}
		n.fwdBuckets[dir] = b
	}
	n.fwdRefill(b, now)
	if len(b.q) == 0 && b.tokens >= float64(p.size) {
		b.tokens -= float64(p.size)
		n.fwdSendLocked(p)
		return true
	}
	if b.queued+p.size > forwardBurst {
		return false
	}
	b.q = append(b.q, p)
	b.queued += p.size
	return true
}

// fwdReleaseLocked forwards what waited for its direction's rate (called with every pump).
func (n *Node) fwdReleaseLocked(now time.Time) {
	for dir, b := range n.fwdBuckets {
		if len(b.q) == 0 {
			if now.Sub(b.at) > time.Minute {
				delete(n.fwdBuckets, dir) // full again long ago
			}
			continue
		}
		n.fwdRefill(b, now)
		for len(b.q) > 0 && b.tokens >= float64(b.q[0].size) {
			p := b.q[0]
			b.q, b.queued, b.tokens = b.q[1:], b.queued-p.size, b.tokens-float64(p.size)
			n.fwdSendLocked(p)
		}
	}
}

func (n *Node) fwdSendLocked(p fwdPending) {
	pd := n.peers[p.to]
	if pd == nil {
		return
	}
	pd.st.push(p.msg, false, p.stream, false)
	n.fwdCount.Add(1)
	n.wakeLocked()
}

// forwardedLocked: forwarder x hands over a packet another device sent us through it (event
// 0.8). It is handled as arriving on the road via x — only from a device x told us it forwards
// to, and only over a road to x that is not via a third device.
func (n *Node) forwardedLocked(x string, args []cbor.RawMessage) {
	var src, pkt []byte
	if len(args) < 2 || cbor.Unmarshal(args[0], &src) != nil || cbor.Unmarshal(args[1], &pkt) != nil ||
		len(src) != 16 || len(pkt) < 5 || len(pkt) > MaxRoadPacket {
		return
	}
	from := addrText(src)
	xs := n.peers[x]
	if from == x || from == n.ID.Addr() || xs == nil || !slices.Contains(xs.forwards, from) ||
		n.Trust.Get(from) == nil || !n.directLocked(xs, time.Now()) {
		return
	}
	n.receiveLocked(pkt, Endpoint{Road: n.viaLocked(x), Addr: from})
}

// ForwardStats: packets this device forwarded for others, and those it dropped.
func (n *Node) ForwardStats() (forwarded, dropped int64) {
	return n.fwdCount.Load(), n.fwdDropped.Load()
}

// forwardMsg reports events 0.7 and 0.8: never compressed, run out of order (spec §3).
func forwardMsg(msg []byte) bool {
	return len(msg) > 3 && msg[1] == 3 && msg[2] == 0 && (msg[3] == evForward || msg[3] == evForwarded)
}
