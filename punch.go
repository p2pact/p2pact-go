package p2pact

import (
	"encoding/binary"
	"net"
	"net/netip"
	"slices"
	"time"
)

// Direct across the internet (spec §7). Our relay tells us, over UDP, the address our UDP
// socket is seen from (observe, packet type 8, spec §4.1): behind NAT it is the mapping our
// peers must hit. It goes into our hints next to the local addresses, and the hello carries it
// to the devices. When a device's addresses or ours change while its session runs over a
// relay or an application road, both sides send a burst of keepalives to every UDP address of
// the other (a punch): each opens its own NAT towards the other, and once a keepalive gets
// through and is answered, the session moves to UDP. A symmetric or carrier NAT does not punch;
// the relay goes on carrying the session.

const (
	observeReqLen   = 36 // [8][nonce 16][zero 19]
	observeReplyLen = 35 // [8][nonce 16][ip 16][port 2]
)

// observeEvery is how often we ask our relay where we are seen from (it also keeps the NAT
// mapping alive); punchFor and punchGap shape a punch burst. Tests shorten them.
var (
	observeEvery = 25 * time.Second
	punchFor     = 3 * time.Second
	punchGap     = 200 * time.Millisecond
)

type observeReq struct {
	to netip.AddrPort
	at time.Time
}

// observeLocked sends an observe request to our relay over our UDP socket: when its time has
// come, or now (force) when the relay road came up or our socket changed — but not more than
// once a second: a forced request that comes too soon waits for maintainLocked, it is not lost.
func (n *Node) observeLocked(now time.Time, force bool) {
	if force {
		n.obsForce = true
	}
	if n.paused || n.udp == nil || n.own == nil || n.stoppedLocked() {
		return
	}
	if gap := now.Sub(n.obsAt); gap < time.Second || (!n.obsForce && gap < observeEvery) {
		return
	}
	// a relay that stopped answering (another network, an old relay): its last answer is stale
	if n.reflexive != "" && now.Sub(n.obsGot) > 3*observeEvery+5*time.Second {
		n.setReflexiveLocked(now, "")
	}
	if n.obsFor != n.own.Addr || !n.obsTo.IsValid() {
		if !n.obsResolving { // a host name: resolve it off the lock
			n.obsResolving = true
			host := n.own.Addr
			n.goLocked(func() {
				a, err := net.ResolveUDPAddr("udp", host)
				n.mu.Lock()
				defer n.mu.Unlock()
				n.obsResolving = false
				if err == nil && n.own != nil && n.own.Addr == host {
					n.obsFor, n.obsTo = host, a.AddrPort()
					n.observeLocked(time.Now(), true)
				}
			})
		}
		return
	}
	n.obsAt, n.obsForce = now, false
	for k, r := range n.obsSent {
		if now.Sub(r.at) > 2*observeEvery || r.to != n.obsTo {
			delete(n.obsSent, k)
		}
	}
	if n.obsSent == nil {
		n.obsSent = map[[16]byte]observeReq{}
	}
	var nonce [16]byte
	copy(nonce[:], randBytes(16))
	n.obsSent[nonce] = observeReq{to: n.obsTo, at: now}
	pkt := make([]byte, observeReqLen)
	pkt[0] = pObserve
	copy(pkt[1:17], nonce[:])
	_ = n.udp.Send(n.obsTo.String(), pkt)
}

// relayUp: a channel of relay r is open. If it is our relay, ask it where we are seen from
// now (resolving its address again: it may have moved).
func (n *Node) relayUp(r *RelayRoad) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.own != nil && n.own.Addr == r.hint.Addr && n.udp != nil {
		n.obsTo = netip.AddrPort{}
		n.observeLocked(time.Now(), true)
	}
}

// onObserveLocked takes the relay's answer: only for a request we sent, from the address we
// sent it to.
func (n *Node) onObserveLocked(now time.Time, pkt []byte, from Endpoint) {
	if len(pkt) != observeReplyLen || n.udp == nil || from.Road != Road(n.udp) {
		return
	}
	var nonce [16]byte
	copy(nonce[:], pkt[1:17])
	req, ok := n.obsSent[nonce]
	src, err := netip.ParseAddrPort(from.Addr)
	if !ok || err != nil || src.Addr().Unmap() != req.to.Addr().Unmap() || src.Port() != req.to.Port() {
		return
	}
	delete(n.obsSent, nonce)
	ip := netip.AddrFrom16([16]byte(pkt[17:33])).Unmap()
	port := binary.BigEndian.Uint16(pkt[33:35])
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || port == 0 {
		return
	}
	n.obsGot = now
	n.setReflexiveLocked(now, netip.AddrPortFrom(ip, port).String())
}

// setReflexiveLocked records our address as the relay sees it ("" — forget it). A change goes
// to the devices in session at once (their hello), and those not on a direct road get a punch.
func (n *Node) setReflexiveLocked(now time.Time, addr string) {
	if addr == n.reflexive {
		return
	}
	n.reflexive = addr
	n.hintsAt = time.Time{} // announce now, not in up to 5 s
	n.reannounceLocked(now)
	if addr == "" {
		return
	}
	for peer := range n.current {
		if ps := n.peers[peer]; ps != nil {
			n.punchLocked(now, peer, ps)
		}
	}
}

// withReflexive adds our observed address to UDP addresses (a copy) unless it is there.
func (n *Node) withReflexive(udp []string) []string {
	if n.reflexive == "" || n.udp == nil || slices.Contains(udp, n.reflexive) {
		return udp
	}
	return append(slices.Clone(udp), n.reflexive)
}

// sessionDirectLocked: the session with peer runs on a live UDP or TCP road (its current road,
// unlike directLocked, which asks for any live road not via a third device).
func (n *Node) sessionDirectLocked(now time.Time, peer string, ps *peerState) bool {
	c := n.candidatesLocked(peer, ps, now, false)
	return len(c) == 1 && roadRank(c[0].ep.Road) < 2 && now.Sub(c[0].lastRecv) <= aliveFor
}

// punchLocked starts a punch burst to peer, unless its session already runs on a direct road.
func (n *Node) punchLocked(now time.Time, peer string, ps *peerState) {
	if n.udp == nil || n.current[peer] == nil || n.sessionDirectLocked(now, peer, ps) {
		return
	}
	ps.punchUntil, ps.punchAt = now.Add(punchFor), time.Time{}
	n.wakeLocked()
}

// punchIfRelayedLocked: a session came up on from; over a relay, an application road or a
// road via a third device, punch (the burst itself goes over UDP only).
func (n *Node) punchIfRelayedLocked(now time.Time, peer string, ps *peerState, from Endpoint) {
	if ps != nil && roadRank(from.Road) >= 2 {
		n.punchLocked(now, peer, ps)
	}
}

// punchStepLocked sends the next keepalive of a burst to every UDP address of the device
// (from pumpLocked); the burst ends early once the session is on a direct road.
func (n *Node) punchStepLocked(now time.Time, peer string, ps *peerState, s *session) {
	if ps.punchUntil.IsZero() || n.udp == nil {
		return
	}
	if !now.Before(ps.punchUntil) || n.sessionDirectLocked(now, peer, ps) {
		ps.punchUntil = time.Time{}
		return
	}
	if now.Sub(ps.punchAt) < punchGap {
		return
	}
	ps.punchAt = now
	p := n.Trust.Get(peer)
	if p == nil {
		return
	}
	for _, a := range p.Hints.UDP {
		ep := Endpoint{Road: n.udp, Addr: a}
		e := ps.eps[ep.key()]
		if e == nil {
			e = &epState{ep: ep}
			ps.eps[ep.key()] = e
		}
		n.sealToLocked(s, e, now, keepalive())
	}
}
