package p2pact

import (
	"encoding/binary"
	"errors"
	"strconv"
	"sync"
	"time"
)

// AppRoad is a road the application provides (spec §3): Bluetooth LE GATT, a serial line, a
// pipe to another program — anything the node cannot open by itself. The node calls Send from
// one goroutine of its own, never under its lock, one call at a time: Send may block until the
// link has taken the bytes (a GATT write waits for its acknowledgement, a notification for its
// turn). What arrives the application hands to [AttachedRoad.Receive].
type AppRoad interface {
	// Send carries one unit of at most MTU bytes: a packet on a datagram road, a piece of the
	// byte stream on a stream road. An error on a stream road detaches it: the stream is broken
	// mid-packet, so the application attaches the link again once it is back.
	Send(b []byte) error
}

// AppRoadConfig describes an application road.
type AppRoadConfig struct {
	// Name is the kind of road, shown by Paths as "app:<name>" ("ble").
	Name string
	// Stream: the link keeps order and loses nothing while it is up (GATT writes and
	// notifications, a serial line, a pipe). Packets are framed as on TCP — a 2-byte length,
	// then the packet — and the frames are cut into pieces of at most MTU bytes, so any MTU
	// works. Otherwise the road carries datagrams that may be lost or reordered, one packet each,
	// and must take any packet whole: MTU at least MaxRoadPacket.
	Stream bool
	// MTU is the largest unit Send takes (a GATT link: the negotiated ATT MTU minus 3).
	MTU int
	// Rate is what the link carries, bytes per second, if the application knows it; 0 —
	// DefaultAppRate until the node has measured it. It sets how much the node keeps in flight
	// on the road before the first measurement, so a slow link does not get a window meant for
	// a fast one and its timers do not fire on its queue.
	Rate int
}

// MaxRoadPacket is the largest packet a road must carry: MaxPacket, and a handshake start with
// data in it may be up to 64 bytes longer (the TCP road's frame takes the same).
const MaxRoadPacket = MaxPacket + 64

// DefaultAppRate is the rate assumed for an application road that does not declare one:
// Bluetooth LE carries tens of kilobytes a second.
const DefaultAppRate = 16 << 10

// appQueue is how many packets wait for an application road's Send: past it they are dropped,
// as a full network queue drops them, and delivery resends them.
const appQueue = 256

// AttachedRoad is an application road attached to a node.
type AttachedRoad struct {
	n    *Node
	app  AppRoad
	cfg  AppRoadConfig
	id   string
	peer string // the device it reaches, as the application told us ("" — learnt from packets)
	out  chan []byte
	stop chan struct{}
	once sync.Once

	mu  sync.Mutex // Receive: the stream being reassembled
	buf []byte
}

var appRoadSeq struct {
	sync.Mutex
	n int
}

// AttachRoad attaches a road the application provides. peer is the device it reaches, when the
// application knows it (it found that device's Bluetooth advertisement, say): the node sends
// to it on this road like on its hints, and starts a session over it at once if it has none.
// With peer "" the road is bound by what arrives on it: a handshake or session packet names
// the device, and the answers go back the same way; until then it is offered for pairing
// (Join). The road ranks below UDP, TCP and a relay: it carries the session while nothing
// better is up, and the session moves to a better road as soon as one answers (spec §7).
func (n *Node) AttachRoad(peer string, r AppRoad, cfg AppRoadConfig) (*AttachedRoad, error) {
	if r == nil || cfg.MTU < 1 {
		return nil, errors.New("an application road needs Send and an MTU")
	}
	if !cfg.Stream && cfg.MTU < MaxRoadPacket {
		return nil, errors.New("a datagram road must carry " + strconv.Itoa(MaxRoadPacket) + " bytes; a smaller link that keeps order is a stream road")
	}
	if cfg.Name == "" {
		cfg.Name = "app"
	}
	appRoadSeq.Lock()
	appRoadSeq.n++
	id := "#" + strconv.Itoa(appRoadSeq.n)
	appRoadSeq.Unlock()
	a := &AttachedRoad{n: n, app: r, cfg: cfg, id: id, peer: peer, out: make(chan []byte, appQueue), stop: make(chan struct{})}
	n.mu.Lock()
	if peer != "" && n.Trust.Get(peer) == nil {
		n.mu.Unlock()
		return nil, errors.New("unknown device")
	}
	n.apps[a] = true
	n.mu.Unlock()
	go a.write() // not waited for by Close: the application's Send may hang on a dead link
	if peer != "" {
		n.mu.Lock()
		n.appAttachedLocked(time.Now(), a)
		n.mu.Unlock()
	}
	return a, nil
}

// Name is "app:<name>": the road's kind, as Paths shows it.
func (a *AttachedRoad) Name() string { return "app:" + a.cfg.Name }

// Send queues a packet for the application's Send (the node's Road interface; addr is the
// attachment's own).
func (a *AttachedRoad) Send(_ string, pkt []byte) error {
	if len(pkt) > MaxRoadPacket {
		return errors.New("packet too big")
	}
	b := pkt
	if a.cfg.Stream {
		b = binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(pkt)), uint16(len(pkt)))
		b = append(b, pkt...)
	} else {
		b = append([]byte(nil), pkt...)
	}
	select {
	case <-a.stop:
		return errors.New("road detached")
	default:
	}
	select {
	case a.out <- b:
		return nil
	default:
		return errors.New("road queue full")
	}
}

// write hands queued packets to the application, a stream road's in pieces of at most MTU.
func (a *AttachedRoad) write() {
	for {
		select {
		case <-a.stop:
			return
		case b := <-a.out:
			if !a.cfg.Stream {
				_ = a.app.Send(b)
				continue
			}
			for len(b) > 0 {
				k := min(len(b), a.cfg.MTU)
				if err := a.app.Send(b[:k]); err != nil {
					go a.Detach() // the stream is broken mid-packet
					return
				}
				b = b[k:]
			}
		}
	}
}

// Receive hands the node what arrived on the road: a datagram, or the next piece of the byte
// stream (pieces may be of any size). Call it from one goroutine at a time, in the order the
// bytes came.
func (a *AttachedRoad) Receive(b []byte) {
	select {
	case <-a.stop:
		return
	default:
	}
	ep := Endpoint{Road: a, Addr: a.id}
	if !a.cfg.Stream {
		if len(b) <= MaxRoadPacket {
			a.n.receive(append([]byte(nil), b...), ep)
		}
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.buf = append(a.buf, b...)
	for len(a.buf) >= 2 {
		k := int(binary.BigEndian.Uint16(a.buf))
		if k > MaxRoadPacket {
			a.buf = nil // not a frame: the stream is damaged, and nothing tells where the next one starts
			return
		}
		if len(a.buf) < 2+k {
			break
		}
		pkt := append([]byte(nil), a.buf[2:2+k]...)
		a.buf = a.buf[2+k:]
		a.n.receive(pkt, ep)
	}
	if len(a.buf) == 0 {
		a.buf = nil
	}
}

// drop discards what waits for the application's Send (the node pauses): it would go out
// while the device sleeps, and delivery sends it again after resume.
func (a *AttachedRoad) drop() {
	for {
		select {
		case <-a.out:
		default:
			return
		}
	}
}

// Detach stops using the road: the link is gone. The session goes on over the other roads.
func (a *AttachedRoad) Detach() {
	a.once.Do(func() {
		close(a.stop)
		n := a.n
		n.mu.Lock()
		delete(n.apps, a)
		for _, ps := range n.peers {
			for k, e := range ps.eps {
				if e.ep.Road == Road(a) {
					delete(ps.eps, k)
				}
			}
		}
		n.mu.Unlock()
	})
}

// rate is the link rate to plan with before one is measured.
func (a *AttachedRoad) rate() float64 {
	if a.cfg.Rate > 0 {
		return float64(a.cfg.Rate)
	}
	return DefaultAppRate
}

// appAttachedLocked starts using a road the application attached for a device: a keepalive
// over it when there is a session (so the other side binds it too), a handshake when not.
func (n *Node) appAttachedLocked(now time.Time, a *AttachedRoad) {
	if n.paused { // it is offered on resume, with the other roads
		return
	}
	ps := n.peerLocked(a.peer)
	if ps == nil {
		return
	}
	ep := Endpoint{Road: a, Addr: a.id}
	if ps.eps[ep.key()] == nil {
		ps.eps[ep.key()] = &epState{ep: ep}
	}
	if s := n.current[a.peer]; s != nil {
		n.sealToLocked(s, ps.eps[ep.key()], now, keepalive())
		return
	}
	ps.lastInit = time.Time{}
	var first []byte
	if !ps.st.idle() {
		first, _ = ps.st.nextPacket(now, false)
	}
	n.startInitLocked(now, a.peer, ps, first)
}

// sealToLocked sends packet content on one endpoint only (a keepalive, a probe).
func (n *Node) sealToLocked(s *session, e *epState, now time.Time, plain []byte) {
	if n.paused {
		return
	}
	hdr := put32(put32([]byte{pData}, s.remote), uint32(s.sendN))
	pkt := s.send.Encrypt(append([]byte(nil), hdr...), s.sendN, hdr, plain)
	s.sendN++
	if e.ep.Road.Send(e.ep.Addr, pkt) == nil {
		e.lastSend = now
	}
}
