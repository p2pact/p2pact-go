package p2pact

import (
	"net"
	"net/netip"
	"strings"
	"time"
)

// RouteInfo is what the application may plan a heavy stream (video) by: the road the session to
// a device runs on now and how much it carries.
type RouteInfo struct {
	// Kind: "lan" — a device on the same network (a loopback, private or link-local address, the
	// local socket); "direct" — UDP or TCP over the internet or a VPN (100.64.0.0/10 included);
	// "relay" — through a relay; "app" — a road the application provides (Bluetooth); "via" —
	// through a third device. "" — no road is alive.
	Kind string
	// RTT is the smoothed round trip, MinRTT the smallest seen on this session (0 — not measured).
	RTT, MinRTT time.Duration
	// Rate is the delivery rate in bytes a second as measured (the maximum of the last ~2 s of
	// samples), else what an application road declares; 0 — not known yet. A stream that sends
	// little shows a rate of what it sent, not what the road could carry.
	Rate float64
	// MTU is the biggest packet on the road, bytes.
	MTU int
}

// Backlog is what waits to be sent to a device: the parts and bytes queued behind the
// congestion window (not what is already in flight). A sender of video keeps it short: it does
// not feed the encoder a new frame while Backlog is more than about 150 ms of Route's Rate.
func (n *Node) Backlog(peer string) (parts, bytes int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ps := n.peers[peer]
	if ps == nil {
		return 0, 0
	}
	for _, p := range ps.st.queue {
		parts++
		bytes += len(p.data)
	}
	return parts, bytes
}

// Route describes the road the session to a device runs on (RouteInfo).
func (n *Node) Route(peer string) RouteInfo {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.routeLocked(peer, time.Now())
}

func (n *Node) routeLocked(peer string, now time.Time) RouteInfo {
	ps := n.peers[peer]
	if ps == nil {
		return RouteInfo{}
	}
	var best *epState
	if n.current[peer] != nil {
		if c := n.candidatesLocked(peer, ps, now, false); len(c) == 1 && now.Sub(c[0].lastRecv) <= aliveFor {
			best = c[0]
		}
	}
	if best == nil {
		return RouteInfo{}
	}
	return RouteInfo{Kind: roadKind(best.ep), RTT: ps.st.srtt, MinRTT: ps.st.minRTT,
		Rate: ps.st.linkRate(), MTU: MaxPacket}
}

// roadKind names the kind of an endpoint for RouteInfo.Kind.
func roadKind(ep Endpoint) string {
	switch r := ep.Road.(type) {
	case *AttachedRoad:
		if r.cfg.Direct {
			return "direct"
		}
		return "app"
	case *viaRoad:
		return "via"
	}
	name := ep.Road.Name()
	switch {
	case name == "local":
		return "lan"
	case strings.HasPrefix(name, "relay:"):
		return "relay"
	}
	host, _, err := net.SplitHostPort(ep.Addr)
	if err != nil {
		host = ep.Addr
	}
	if a, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")); err == nil {
		a = a.Unmap()
		if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() {
			return "lan"
		}
	}
	return "direct" // the internet, or a VPN such as 100.64.0.0/10: a direct road either way
}

// OnRoute sets f to be called, on a goroutine of its own, when the kind of the road to a device
// changes (checked every second and after ProbeNow); nil — none. It is called with the new
// RouteInfo, whose Kind may be "" when no road is alive.
func (n *Node) OnRoute(f func(peer string, r RouteInfo)) {
	n.mu.Lock()
	n.onRoute = f
	n.mu.Unlock()
}

// ProbeNow tries the direct roads to a device at once, while the session runs over a relay or a
// road of the application (what happens every 30 s anyway, spec §7): a stream that wants the
// shortest road does not wait for the timer. A better road that answers takes over, and
// OnRoute tells.
func (n *Node) ProbeNow(peer string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ps, s := n.peers[peer], n.current[peer]
	if ps == nil || s == nil {
		return
	}
	ps.lastProbe = time.Time{}
	n.probeLocked(time.Now(), peer, ps, s)
}

// routesLocked runs every second: tells the application where a road's kind changed.
func (n *Node) routesLocked(now time.Time) {
	if n.onRoute == nil {
		return
	}
	for peer, ps := range n.peers {
		r := n.routeLocked(peer, now)
		if r.Kind == ps.lastKind {
			continue
		}
		ps.lastKind = r.Kind
		f := n.onRoute
		n.goLocked(func() { f(peer, r) })
	}
}
