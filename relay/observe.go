package relay

import (
	"errors"
	"net"
	"net/netip"
	"time"
)

// Observe (spec §4.1, type 8): over UDP, on the port of the TLS listener, the relay tells a
// device the address its datagrams come from (its address as seen from the internet, behind
// NAT). Devices put it into their hints, so their peers can try the direct road (spec §7).
//
//	→ [8][nonce 16][zero 19]                  36 bytes
//	← [8][nonce 16][ip 16][port 2]           35 bytes: IPv4 as ::ffff:a.b.c.d, port big-endian
//
// The reply is never larger than the request, so the relay cannot amplify a spoofed source.
// Anything else is ignored, and so is more than observeRate requests a second from one IP.
const (
	observeType     = 8
	observeReqLen   = 36
	observeReplyLen = 35
	observeRate     = 10 // requests a second per source IP
	observeMaxIPs   = 1 << 16
)

// ServeUDP answers observe requests on pc until it is closed. Run it next to Serve, on the
// same port number as the TLS listener (devices send to the relay's hint address).
func (s *Server) ServeUDP(pc net.PacketConn) error {
	buf := make([]byte, 2048)
	var window time.Time
	seen := map[netip.Addr]int{}
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		if n < observeReqLen || buf[0] != observeType {
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := ua.AddrPort()
		now := s.now()
		if now.Sub(window) >= time.Second { // a fixed one-second window: the map stays small
			window = now
			clear(seen)
		}
		ip := ap.Addr().Unmap()
		if seen[ip] >= observeRate || (seen[ip] == 0 && len(seen) >= observeMaxIPs) {
			continue
		}
		seen[ip]++
		_, _ = pc.WriteTo(observeReply(buf[1:17], ap), from)
	}
}

// observeReply builds the answer for a request with nonce from address ap.
func observeReply(nonce []byte, ap netip.AddrPort) []byte {
	out := make([]byte, 0, observeReplyLen)
	out = append(out, observeType)
	out = append(out, nonce[:16]...)
	ip16 := ap.Addr().Unmap().As16() // IPv4 comes out as ::ffff:a.b.c.d
	out = append(out, ip16[:]...)
	return append(out, byte(ap.Port()>>8), byte(ap.Port()))
}
