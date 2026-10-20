package p2pact

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/fxamacker/cbor/v2"
)

const (
	tsSkew       = 2 * time.Minute  // an older handshake start is a replay: drop it
	initEvery    = time.Second      // handshake retry while unanswered
	autoConnect  = 30 * time.Second // how often to try known devices without a session
	aliveFor     = 60 * time.Second // a road is alive if something arrived on it within this time
	keepaliveGap = 25 * time.Second
	sessionIdle  = 3 * time.Minute
)

// Handler is a tool method: arguments → result (or *Error).
type Handler func(peer string, args []cbor.RawMessage) ([]any, error)

// Error is a call error (spec §6): a code and a text.
type Error struct {
	Code int
	Text string
}

func (e *Error) Error() string { return e.Text }

// Error codes (spec §6).
const (
	ErrNoMethod   = 1
	ErrBadArgs    = 2
	ErrNotFound   = 3
	ErrForbidden  = 4
	ErrFailed     = 5
	ErrNotDeliver = 6
)

type session struct {
	peer          string
	local, remote uint32
	send, recv    noise.Cipher
	sendN         uint64
	win           window
	lastRecv      time.Time
}

type handshake struct {
	pair   bool
	hs     *noise.HandshakeState
	peer   string  // known device: to whom
	invite *Invite // pairing: their invite (we join) or ours (they join)
	done   chan error
	at     time.Time
	// data that overtook the handshake reply (reordering): run once the session is up
	early []earlyPacket
	// pairing, we respond: the joiner's index from its first packet
	remoteIdx uint32
}

type earlyPacket struct {
	pkt  []byte
	from Endpoint
}

type epState struct {
	ep                 Endpoint
	lastRecv, lastSend time.Time
}

type peerState struct {
	st       *stream
	eps      map[string]*epState
	lastTS   uint64 // timestamp of the last accepted handshake start
	boot     uint32 // the other device's boot id (from the handshake)
	lastInit time.Time
	calls    map[uint64]chan callResult
	callID   uint64
	dicts    [][]byte  // its dictionaries (ids), newest first — from its hello and 0.5
	lacks    [][]byte  // it asked us for these, so it lacks them until it announces again
	waiting  []inbound // waiting for a dictionary (spec §5): run in order once it arrives
	fetching bool
}

type inbound struct {
	msg []byte
	zip bool
}

type callResult struct {
	res []cbor.RawMessage
	err error
}

// Node is a device in the protocol network.
type Node struct {
	ID    *Identity
	Trust *Trust
	Name  string
	// OnEvent receives tool events (except tool 0) from known devices.
	OnEvent func(peer string, tool, event int, args []cbor.RawMessage)
	// OnPaired is called after pairing (on either side).
	OnPaired func(p Peer)
	// OnHello is called when a known device sends its hello (new session or pairing).
	OnHello func(peer string)
	// NoCompression turns compression off for what we send (benchmarks, debugging).
	NoCompression bool
	// AllowDict decides whether a known device may fetch a dictionary (0.5); nil — all may.
	AllowDict func(peer string, id []byte) bool

	boot uint32
	mu   sync.Mutex
	udp  *UDPRoad
	tcp  *TCPRoad
	own  *RelayHint
	rel  map[string]*RelayRoad // by server address

	sessions map[uint32]*session // by our index
	current  map[string]*session // the best session with a device
	hs       map[uint32]*handshake
	invites  map[string]*Invite // our invites by id (hex)
	peers    map[string]*peerState
	handlers map[[2]int]Handler
	resetAt  map[string]time.Time
	dicts    *dictStore

	stop chan struct{}
	kick chan struct{} // something was queued: send now, not on the next tick
	wg   sync.WaitGroup
	// handshakes counts sessions set up (for tests: a network change needs no new one)
	handshakes atomic.Int64
}

// NewNode creates a device with keys and known devices from dir.
func NewNode(dir, name string) (*Node, error) {
	id, err := LoadIdentity(dir)
	if err != nil {
		return nil, err
	}
	n := &Node{ID: id, Trust: LoadTrust(dir), Name: name, boot: binary.BigEndian.Uint32(randBytes(4)),
		rel: map[string]*RelayRoad{}, sessions: map[uint32]*session{}, current: map[string]*session{},
		hs: map[uint32]*handshake{}, invites: map[string]*Invite{}, peers: map[string]*peerState{},
		handlers: map[[2]int]Handler{}, resetAt: map[string]time.Time{}, dicts: loadDicts(dir), stop: make(chan struct{}),
		kick: make(chan struct{}, 1)}
	n.Handle(0, 1, func(string, []cbor.RawMessage) ([]any, error) { return []any{}, nil }) // ping
	n.Handle(0, 2, func(string, []cbor.RawMessage) ([]any, error) { return n.info(), nil })
	n.Handle(0, 5, n.dictHandler)
	return n, nil
}

// ListenUDP opens the main road on an address (":48730", "127.0.0.1:0").
func (n *Node) ListenUDP(addr string) error {
	u, err := listenUDP(addr)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.udp = u
	n.mu.Unlock()
	n.wg.Add(1)
	go func() { defer n.wg.Done(); u.run(n.receive) }()
	return nil
}

// RebindUDP handles a network change (new address or port): listen again and tell known
// devices at once. Sessions stay; no new handshakes (§4.1: a packet finds its session by
// number).
func (n *Node) RebindUDP(addr string) error {
	u, err := listenUDP(addr)
	if err != nil {
		return err
	}
	n.mu.Lock()
	old := n.udp
	n.udp = u
	now := time.Now()
	for peer, ps := range n.peers {
		for k, e := range ps.eps {
			if old != nil && e.ep.Road == Road(old) {
				delete(ps.eps, k)
				ne := &epState{ep: Endpoint{Road: u, Addr: e.ep.Addr}, lastRecv: e.lastRecv}
				ps.eps[ne.ep.key()] = ne
			}
		}
		if s := n.current[peer]; s != nil {
			n.sendLocked(now, peer, ps, s, keepalive(), true)
		}
	}
	n.mu.Unlock()
	if old != nil {
		old.close()
	}
	n.wg.Add(1)
	go func() { defer n.wg.Done(); u.run(n.receive) }()
	return nil
}

// ListenTCP opens the fallback TCP road on an address; "" — dial only, no listener (a
// phone behind a carrier NAT can still reach a computer).
func (n *Node) ListenTCP(addr string) error {
	t, err := listenTCP(addr, n.receive)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.tcp = t
	n.mu.Unlock()
	return nil
}

// TCP returns the TCP road (nil if not opened).
func (n *Node) TCP() *TCPRoad { return n.tcp }

// UDP returns the UDP road (for tests: loss).
func (n *Node) UDP() *UDPRoad { return n.udp }

// SetRelay sets our relay: used for pairing and pair channels.
func (n *Node) SetRelay(h RelayHint) {
	n.mu.Lock()
	n.own = &h
	n.mu.Unlock()
}

// Start runs the service loop: delivery, retransmission, keepalives, connecting to known
// devices.
func (n *Node) Start() {
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		slow := time.Now()
		for {
			select {
			case <-n.stop:
				return
			case <-n.kick:
				n.mu.Lock()
				n.pumpLocked(time.Now())
				n.mu.Unlock()
			case now := <-t.C:
				n.mu.Lock()
				n.pumpLocked(now)
				if now.Sub(slow) >= time.Second {
					slow = now
					n.maintainLocked(now)
				}
				n.mu.Unlock()
			}
		}
	}()
}

func (n *Node) Close() {
	close(n.stop)
	n.mu.Lock()
	if n.udp != nil {
		n.udp.close()
	}
	if n.tcp != nil {
		n.tcp.close()
	}
	for _, r := range n.rel {
		r.close()
	}
	n.mu.Unlock()
	n.wg.Wait()
}

// Handle registers method tool.method.
func (n *Node) Handle(tool, method int, h Handler) {
	n.mu.Lock()
	n.handlers[[2]int{tool, method}] = h
	n.mu.Unlock()
}

// --- pairing ---

// Invite creates an invite valid for ttl; pairing is accepted on all our roads.
func (n *Node) Invite(ttl time.Duration) *Invite {
	n.mu.Lock()
	defer n.mu.Unlock()
	inv := &Invite{Key: n.ID.Key.Public, Name: n.Name, Secret: randBytes(32), Exp: time.Now().Add(ttl), Hints: n.hintsLocked()}
	n.invites[hexs(inv.ID())] = inv
	if n.own != nil {
		n.relayLocked(*n.own).join(hexs(inv.ID()), "a")
	}
	return inv
}

// Join pairs using an invite, trying all its hints until one answers.
func (n *Node) Join(ctx context.Context, inv *Invite) (Peer, error) {
	addr := Address(inv.Key)
	var eps []Endpoint
	n.mu.Lock()
	if n.udp != nil {
		for _, a := range inv.Hints.UDP {
			eps = append(eps, Endpoint{Road: n.udp, Addr: a})
		}
	}
	if n.tcp != nil {
		for _, a := range inv.Hints.TCP {
			eps = append(eps, Endpoint{Road: n.tcp, Addr: a})
		}
	}
	if inv.Hints.Relay != nil {
		r := n.relayLocked(*inv.Hints.Relay)
		r.join(hexs(inv.ID()), "b")
		defer r.leave(hexs(inv.ID()))
		eps = append(eps, Endpoint{Road: r, Addr: hexs(inv.ID())})
	}
	n.mu.Unlock()
	if len(eps) == 0 {
		return Peer{}, errors.New("the invite has no road we can use")
	}
	done := make(chan error, 1)
	t := time.NewTicker(initEvery)
	defer t.Stop()
	var local uint32
	for {
		n.mu.Lock()
		delete(n.hs, local)
		hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeXX, Initiator: true,
			Prologue: []byte(Prologue), StaticKeypair: n.ID.Key, PresharedKey: inv.Secret, PresharedKeyPlacement: 2})
		if err != nil {
			n.mu.Unlock()
			return Peer{}, err
		}
		msg1, _, _, _ := hs.WriteMessage(nil, nil)
		local = n.newIndexLocked()
		n.hs[local] = &handshake{pair: true, hs: hs, invite: inv, done: done, at: time.Now()}
		pkt := append([]byte{pPair1}, inv.ID()...)
		pkt = append(put32(pkt, local), msg1...)
		for _, e := range eps {
			_ = e.Road.Send(e.Addr, pkt)
		}
		n.mu.Unlock()
		select {
		case err := <-done:
			if err != nil {
				return Peer{}, err
			}
			if p := n.Trust.Get(addr); p != nil {
				return *p, nil
			}
			return Peer{}, errors.New("pairing was not saved")
		case <-ctx.Done():
			n.mu.Lock()
			delete(n.hs, local)
			n.mu.Unlock()
			return Peer{}, ctx.Err()
		case <-t.C:
		}
	}
}

// pairPayload is [name, boot, hints, signing key, os] in the pairing handshake.
type pairPayload struct {
	_       struct{} `cbor:",toarray"`
	Name    string
	Boot    uint32
	Hints   hintsWire
	SignKey []byte
	OS      string
}

func (n *Node) pairPayloadLocked() []byte {
	b, _ := cbor.Marshal(pairPayload{Name: n.Name, Boot: n.boot, Hints: toWire(n.hintsLocked()), SignKey: n.ID.SignPublic(), OS: runtime.GOOS})
	return b
}

// Befriend adds a known device without a pairing handshake: its key comes from the family
// book; the pair secret comes from both permanent keys (Identity.Shared).
func (n *Node) Befriend(p Peer) error {
	if len(p.Key) != 32 || Address(p.Key) != p.Addr {
		return errors.New("key does not match address")
	}
	if old := n.Trust.Get(p.Addr); old != nil {
		old.Name, old.SignKey, old.OS = p.Name, p.SignKey, p.OS
		n.Trust.Put(*old)
		return nil
	}
	sec, err := n.ID.Shared(p.Key, "family-pair")
	if err != nil {
		return err
	}
	p.PairSecret = sec
	n.Trust.Put(p)
	return nil
}

// Forget drops a known device: we stop answering it (removed from the family).
func (n *Node) Forget(addr string) {
	n.mu.Lock()
	delete(n.peers, addr)
	if s := n.current[addr]; s != nil {
		delete(n.current, addr)
		delete(n.sessions, s.local)
	}
	n.mu.Unlock()
	n.Trust.Remove(addr)
}

// --- calls and events ---

// Call invokes tool.method on a known device and returns the result elements.
func (n *Node) Call(ctx context.Context, peer string, tool, method int, args ...any) ([]cbor.RawMessage, error) {
	n.mu.Lock()
	ps := n.peerLocked(peer)
	if ps == nil {
		n.mu.Unlock()
		return nil, errors.New("unknown device")
	}
	ps.callID++
	id := ps.callID
	ch := make(chan callResult, 1)
	ps.calls[id] = ch
	msg, err := cbor.Marshal(append([]any{0, id, tool, method}, args...))
	if err == nil {
		n.pushLocked(ps, msg)
	}
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		n.mu.Lock()
		delete(ps.calls, id)
		n.mu.Unlock()
	}()
	select {
	case r := <-ch:
		return r.res, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Event sends event tool.event to a known device (delivered in order, like calls).
func (n *Node) Event(peer string, tool, event int, args ...any) error {
	msg, err := cbor.Marshal(append([]any{3, tool, event}, args...))
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	ps := n.peerLocked(peer)
	if ps == nil {
		return errors.New("unknown device")
	}
	n.pushLocked(ps, msg)
	return nil
}

// Paths lists live roads to a known device: udp, relay:<address>.
func (n *Node) Paths(peer string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	ps := n.peers[peer]
	if ps == nil {
		return nil
	}
	now := time.Now()
	var out []string
	seen := map[string]bool{}
	for _, e := range ps.eps {
		name := e.ep.Road.Name()
		if now.Sub(e.lastRecv) <= aliveFor && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// info is the hello (spec §6, 0.2): [name, os, implementation, {tool: version}, [dictionaries], hints].
func (n *Node) info() []any {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.infoLocked()
}

func (n *Node) infoLocked() []any {
	tools := map[int]int{}
	for k := range n.handlers {
		if k[0] != 0 {
			tools[k[0]] = 1
		}
	}
	return []any{n.Name, runtime.GOOS, "p2pact-go", tools, n.dicts.ids(), toWire(n.hintsLocked())}
}

func (n *Node) hintsLocked() Hints {
	var h Hints
	if n.udp != nil {
		h.UDP = n.udp.localAddrs()
	}
	if n.tcp != nil {
		h.TCP = n.tcp.localAddrs()
	}
	if n.own != nil {
		cp := *n.own
		h.Relay = &cp
	}
	return h
}

// --- receiving ---

func (n *Node) receive(pkt []byte, from Endpoint) {
	if len(pkt) < 5 {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	switch pkt[0] {
	case pData:
		n.onDataLocked(now, pkt, from)
	case pInit:
		n.onInitLocked(now, pkt, from)
	case pResp:
		n.onRespLocked(now, pkt, from)
	case pPair1:
		n.onPair1Locked(now, pkt, from)
	case pPair2:
		n.onPair2Locked(now, pkt, from)
	case pPair3:
		n.onPair3Locked(now, pkt, from)
	case pReset:
		idx := u32(pkt[1:5])
		for _, s := range n.sessions {
			if s.remote == idx {
				delete(n.sessions, s.local)
				if n.current[s.peer] == s {
					delete(n.current, s.peer)
				}
			}
		}
	}
}

func (n *Node) onDataLocked(now time.Time, pkt []byte, from Endpoint) {
	if len(pkt) < dataHeader+16 {
		return
	}
	s := n.sessions[u32(pkt[1:5])]
	if s == nil {
		// our handshake is still waiting for its reply, and data from the new session
		// overtook it: hold the data instead of resetting the session
		if h := n.hs[u32(pkt[1:5])]; h != nil && !h.pair && len(h.early) < 16 {
			h.early = append(h.early, earlyPacket{append([]byte(nil), pkt...), from})
			return
		}
		k := from.key()
		if now.Sub(n.resetAt[k]) >= 5*time.Second {
			n.resetAt[k] = now
			_ = from.Road.Send(from.Addr, put32([]byte{pReset}, u32(pkt[1:5])))
		}
		return
	}
	cnt := uint64(u32(pkt[5:9]))
	plain, err := s.recv.Decrypt(nil, cnt, pkt[:dataHeader], pkt[dataHeader:])
	if err != nil || !s.win.accept(cnt) {
		return
	}
	s.lastRecv = now
	if n.current[s.peer] == nil {
		n.current[s.peer] = s
	}
	ps := n.peerLocked(s.peer)
	n.seenLocked(ps, from, now)
	_ = ps.st.receive(now, plain, func(msg []byte, zip bool) { n.inboundLocked(s.peer, msg, zip) })
}

// onInitLocked: a known device starts a session (Noise_IK) with data in the first packet.
func (n *Node) onInitLocked(now time.Time, pkt []byte, from Endpoint) {
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeIK,
		Prologue: []byte(Prologue), StaticKeypair: n.ID.Key})
	if err != nil {
		return
	}
	payload, _, _, err := hs.ReadMessage(nil, pkt[5:])
	if err != nil || len(payload) < 12 {
		return
	}
	peer := Address(hs.PeerStatic())
	if n.Trust.Get(peer) == nil {
		return // silence to strangers (spec §4.2)
	}
	ps := n.peerLocked(peer)
	ts := binary.BigEndian.Uint64(payload[:8])
	age := now.Sub(time.Unix(0, int64(ts)))
	if ts <= ps.lastTS || age > tsSkew || age < -tsSkew {
		return // replay of an old start
	}
	ps.lastTS = ts
	local := n.newIndexLocked()
	resp, cs1, cs2, err := hs.WriteMessage(nil, binary.BigEndian.AppendUint32(nil, n.boot))
	if err != nil || cs1 == nil {
		return
	}
	s := &session{peer: peer, local: local, remote: u32(pkt[1:5]), send: cs2.Cipher(), recv: cs1.Cipher(), lastRecv: now}
	n.sessions[local] = s
	n.current[peer] = s
	n.handshakes.Add(1)
	n.seenLocked(ps, from, now)
	n.bootLocked(ps, binary.BigEndian.Uint32(payload[8:12]))
	out := put32(put32([]byte{pResp}, s.remote), local)
	_ = from.Road.Send(from.Addr, append(out, resp...))
	if len(payload) > 12 { // data in the first packet
		_ = ps.st.receive(now, payload[12:], func(msg []byte, zip bool) { n.inboundLocked(peer, msg, zip) })
	}
	n.sendInfoLocked(peer)
}

func (n *Node) onRespLocked(now time.Time, pkt []byte, from Endpoint) {
	if len(pkt) < 9 {
		return
	}
	local := u32(pkt[1:5])
	h := n.hs[local]
	if h == nil || h.pair {
		return
	}
	payload, cs1, cs2, err := h.hs.ReadMessage(nil, pkt[9:])
	if err != nil || cs1 == nil || len(payload) < 4 {
		return
	}
	delete(n.hs, local)
	s := &session{peer: h.peer, local: local, remote: u32(pkt[5:9]), send: cs1.Cipher(), recv: cs2.Cipher(), lastRecv: now}
	n.sessions[local] = s
	n.current[h.peer] = s
	n.handshakes.Add(1)
	ps := n.peerLocked(h.peer)
	n.seenLocked(ps, from, now)
	n.bootLocked(ps, binary.BigEndian.Uint32(payload[:4]))
	n.sendInfoLocked(h.peer)
	for _, e := range h.early {
		n.onDataLocked(now, e.pkt, e.from)
	}
}

// onPair1Locked: someone joins with our invite (Noise_XXpsk2, we respond).
func (n *Node) onPair1Locked(now time.Time, pkt []byte, from Endpoint) {
	if len(pkt) < 21 {
		return
	}
	inv := n.invites[hexs(pkt[1:17])]
	if inv == nil || now.After(inv.Exp) {
		return
	}
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeXX,
		Prologue: []byte(Prologue), StaticKeypair: n.ID.Key, PresharedKey: inv.Secret, PresharedKeyPlacement: 2})
	if err != nil {
		return
	}
	if _, _, _, err := hs.ReadMessage(nil, pkt[21:]); err != nil {
		return
	}
	msg2, _, _, err := hs.WriteMessage(nil, n.pairPayloadLocked())
	if err != nil {
		return
	}
	local := n.newIndexLocked()
	n.hs[local] = &handshake{pair: true, hs: hs, invite: inv, at: now, remoteIdx: u32(pkt[17:21])}
	out := put32(put32([]byte{pPair2}, u32(pkt[17:21])), local)
	_ = from.Road.Send(from.Addr, append(out, msg2...))
}

// onPair2Locked: we are joining; the invite owner answered.
func (n *Node) onPair2Locked(now time.Time, pkt []byte, from Endpoint) {
	if len(pkt) < 9 {
		return
	}
	local := u32(pkt[1:5])
	h := n.hs[local]
	if h == nil || !h.pair || h.done == nil {
		return
	}
	payload, _, _, err := h.hs.ReadMessage(nil, pkt[9:])
	if err != nil {
		return // wrong secret or a stranger
	}
	if hexs(h.hs.PeerStatic()) != hexs(h.invite.Key) {
		h.done <- errors.New("device key does not match the invite")
		delete(n.hs, local)
		return
	}
	var pp pairPayload
	_ = cbor.Unmarshal(payload, &pp)
	msg3, cs1, cs2, err := h.hs.WriteMessage(nil, n.pairPayloadLocked())
	if err != nil || cs1 == nil {
		return
	}
	delete(n.hs, local)
	peer := Address(h.invite.Key)
	hints := fromWire(pp.Hints)
	if len(hints.UDP) == 0 {
		hints.UDP = h.invite.Hints.UDP
	}
	if len(hints.TCP) == 0 {
		hints.TCP = h.invite.Hints.TCP
	}
	if hints.Relay == nil {
		hints.Relay = h.invite.Hints.Relay
	}
	p := Peer{Addr: peer, Key: h.invite.Key, Name: pp.Name, PairSecret: h.invite.Secret, Hints: hints, SignKey: pp.SignKey, OS: pp.OS}
	n.Trust.Put(p)
	s := &session{peer: peer, local: local, remote: u32(pkt[5:9]), send: cs1.Cipher(), recv: cs2.Cipher(), lastRecv: now}
	n.sessions[local] = s
	n.current[peer] = s
	ps := n.peerLocked(peer)
	n.seenLocked(ps, from, now)
	n.bootLocked(ps, pp.Boot)
	_ = from.Road.Send(from.Addr, append(put32([]byte{pPair3}, s.remote), msg3...))
	n.pairedLocked(p)
	h.done <- nil
}

// onPair3Locked: the joiner confirmed; pairing is complete.
func (n *Node) onPair3Locked(now time.Time, pkt []byte, from Endpoint) {
	local := u32(pkt[1:5])
	h := n.hs[local]
	if h == nil || !h.pair || h.done != nil {
		return
	}
	payload, cs1, cs2, err := h.hs.ReadMessage(nil, pkt[5:])
	if err != nil || cs1 == nil {
		return
	}
	delete(n.hs, local)
	delete(n.invites, hexs(h.invite.ID())) // single use
	if n.own != nil {
		n.relayLocked(*n.own).leave(hexs(h.invite.ID()))
	}
	key := h.hs.PeerStatic()
	peer := Address(key)
	var pp pairPayload
	_ = cbor.Unmarshal(payload, &pp)
	p := Peer{Addr: peer, Key: append([]byte(nil), key...), Name: pp.Name, PairSecret: h.invite.Secret, Hints: fromWire(pp.Hints),
		SignKey: pp.SignKey, OS: pp.OS, Via: hexs(h.invite.ID())}
	n.Trust.Put(p)
	// the joiner was the initiator; we are the responder
	s := &session{peer: peer, local: local, remote: h.remoteIdx, send: cs2.Cipher(), recv: cs1.Cipher(), lastRecv: now}
	n.sessions[local] = s
	n.current[peer] = s
	ps := n.peerLocked(peer)
	n.seenLocked(ps, from, now)
	n.bootLocked(ps, pp.Boot)
	n.pairedLocked(p)
}

func (n *Node) pairedLocked(p Peer) {
	n.sendInfoLocked(p.Addr)
	if n.OnPaired != nil {
		go n.OnPaired(p)
	}
}

// bootLocked records the other device's boot id; a change means its receiving restarted.
func (n *Node) bootLocked(ps *peerState, boot uint32) {
	if ps.boot != 0 && ps.boot != boot {
		ps.st.reset()
	}
	ps.boot = boot
}

// sendInfoLocked sends our hello: name and where to find us (event 0.2).
func (n *Node) sendInfoLocked(peer string) {
	msg, _ := cbor.Marshal(append([]any{3, 0, 2}, n.infoLocked()...))
	n.pushLocked(n.peerLocked(peer), msg)
}

// messageLocked handles a reassembled message (spec §6).
func (n *Node) messageLocked(peer string, msg []byte) {
	var a []cbor.RawMessage
	if cbor.Unmarshal(msg, &a) != nil || len(a) < 2 {
		return
	}
	var kind int
	if cbor.Unmarshal(a[0], &kind) != nil {
		return
	}
	ps := n.peerLocked(peer)
	switch kind {
	case 0: // call
		if len(a) < 4 {
			return
		}
		var id uint64
		var tool, method int
		if cbor.Unmarshal(a[1], &id) != nil || cbor.Unmarshal(a[2], &tool) != nil || cbor.Unmarshal(a[3], &method) != nil {
			return
		}
		h := n.handlers[[2]int{tool, method}]
		args := a[4:]
		go func() {
			var out []any
			if h == nil {
				out = []any{2, id, ErrNoMethod, "no such method"}
			} else if res, err := h(peer, args); err != nil {
				var e *Error
				if !errors.As(err, &e) {
					e = &Error{Code: ErrFailed, Text: err.Error()}
				}
				out = []any{2, id, e.Code, e.Text}
			} else {
				out = append([]any{1, id}, res...)
			}
			b, _ := cbor.Marshal(out)
			n.mu.Lock()
			if ps := n.peerLocked(peer); ps != nil {
				n.pushLocked(ps, b)
			}
			n.mu.Unlock()
		}()
	case 1, 2: // result, error
		var id uint64
		if cbor.Unmarshal(a[1], &id) != nil {
			return
		}
		ch := ps.calls[id]
		if ch == nil {
			return
		}
		if kind == 1 {
			ch <- callResult{res: a[2:]}
			return
		}
		e := &Error{Code: ErrFailed}
		if len(a) > 3 {
			_ = cbor.Unmarshal(a[2], &e.Code)
			_ = cbor.Unmarshal(a[3], &e.Text)
		}
		ch <- callResult{err: e}
	case 3: // event
		if len(a) < 3 {
			return
		}
		var tool, ev int
		if cbor.Unmarshal(a[1], &tool) != nil || cbor.Unmarshal(a[2], &ev) != nil {
			return
		}
		if tool == 0 && ev == 2 && len(a) >= 9 { // hello: name and hints
			var name, goos string
			var hw hintsWire
			_ = cbor.Unmarshal(a[3], &name)
			_ = cbor.Unmarshal(a[4], &goos)
			_ = cbor.Unmarshal(a[8], &hw)
			n.Trust.SetHints(peer, name, goos, fromWire(hw))
			if n.OnHello != nil {
				go n.OnHello(peer)
			}
			ps.dicts, ps.lacks = nil, nil
			_ = cbor.Unmarshal(a[7], &ps.dicts)
			n.drainLocked(peer, ps)
			return
		}
		if tool == 0 && ev == 5 && len(a) >= 4 { // the dictionary list changed
			ps.dicts, ps.lacks = nil, nil
			_ = cbor.Unmarshal(a[3], &ps.dicts)
			n.drainLocked(peer, ps)
			return
		}
		if n.OnEvent != nil {
			args := a[3:]
			go n.OnEvent(peer, tool, ev, args)
		}
	}
}

// --- sending ---

func (n *Node) peerLocked(peer string) *peerState {
	ps := n.peers[peer]
	if ps == nil {
		if n.Trust.Get(peer) == nil {
			return nil
		}
		ps = &peerState{st: newStream(), eps: map[string]*epState{}, calls: map[uint64]chan callResult{}}
		n.peers[peer] = ps
	}
	return ps
}

func (n *Node) seenLocked(ps *peerState, from Endpoint, now time.Time) {
	k := from.key()
	e := ps.eps[k]
	if e == nil {
		e = &epState{ep: from}
		ps.eps[k] = e
	}
	e.lastRecv = now
}

// candidatesLocked picks where to send: live roads; with none alive or on retransmission,
// all hints as well (blindly).
func (n *Node) candidatesLocked(peer string, ps *peerState, now time.Time, all bool) []*epState {
	var alive []*epState
	for _, e := range ps.eps {
		if now.Sub(e.lastRecv) <= aliveFor {
			alive = append(alive, e)
		}
	}
	if len(alive) > 0 && !all {
		rank := func(e *epState) int { // UDP, then TCP, then relay
			switch e.ep.Road.Name() {
			case "udp":
				return 0
			case "tcp":
				return 1
			}
			return 2
		}
		best := alive[0]
		for _, e := range alive[1:] {
			if rank(e) < rank(best) {
				best = e
			}
		}
		return []*epState{best}
	}
	out := alive
	p := n.Trust.Get(peer)
	if p == nil {
		return out
	}
	add := func(ep Endpoint) {
		k := ep.key()
		if ps.eps[k] == nil {
			ps.eps[k] = &epState{ep: ep}
		}
		for _, e := range out {
			if e == ps.eps[k] {
				return
			}
		}
		out = append(out, ps.eps[k])
	}
	if n.udp != nil {
		for _, a := range p.Hints.UDP {
			add(Endpoint{Road: n.udp, Addr: a})
		}
	}
	if n.tcp != nil {
		for _, a := range p.Hints.TCP {
			add(Endpoint{Road: n.tcp, Addr: a})
		}
	}
	if r := n.pairRelayLocked(p); r != nil {
		add(Endpoint{Road: r, Addr: p.relayChannel()})
	}
	return out
}

// pairRelayLocked picks the pair's relay: the one of the lower address, else the other's.
func (n *Node) pairRelayLocked(p *Peer) *RelayRoad {
	mine, theirs := n.own, p.Hints.Relay
	first, second := mine, theirs
	if p.Addr < n.ID.Addr() {
		first, second = theirs, mine
	}
	h := first
	if h == nil {
		h = second
	}
	if h == nil {
		return nil
	}
	return n.relayLocked(*h)
}

func (n *Node) relayLocked(h RelayHint) *RelayRoad {
	r := n.rel[h.Addr]
	if r == nil {
		r = newRelayRoad(h, n.receive)
		n.rel[h.Addr] = r
	}
	return r
}

// sendLocked sends data packet content: on the best road, or on all when retransmitting.
func (n *Node) sendLocked(now time.Time, peer string, ps *peerState, s *session, plain []byte, all bool) {
	hdr := put32(put32([]byte{pData}, s.remote), uint32(s.sendN))
	pkt := s.send.Encrypt(append([]byte(nil), hdr...), s.sendN, hdr, plain)
	s.sendN++
	for _, e := range n.candidatesLocked(peer, ps, now, all) {
		if e.ep.Road.Send(e.ep.Addr, pkt) == nil {
			e.lastSend = now
		}
	}
}

// startInitLocked starts a session with a known device (Noise_IK); first is first-packet data.
func (n *Node) startInitLocked(now time.Time, peer string, ps *peerState, first []byte) {
	p := n.Trust.Get(peer)
	if p == nil || now.Sub(ps.lastInit) < initEvery {
		return
	}
	ps.lastInit = now
	for idx, h := range n.hs { // forget earlier unanswered starts to this device
		if !h.pair && h.peer == peer {
			delete(n.hs, idx)
		}
	}
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeIK, Initiator: true,
		Prologue: []byte(Prologue), StaticKeypair: n.ID.Key, PeerStatic: p.Key})
	if err != nil {
		return
	}
	payload := binary.BigEndian.AppendUint64(nil, uint64(now.UnixNano()))
	payload = binary.BigEndian.AppendUint32(payload, n.boot)
	payload = append(payload, first...)
	msg1, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		return
	}
	local := n.newIndexLocked()
	n.hs[local] = &handshake{hs: hs, peer: peer, at: now}
	pkt := append(put32([]byte{pInit}, local), msg1...)
	for _, e := range n.candidatesLocked(peer, ps, now, true) {
		if e.ep.Road.Send(e.ep.Addr, pkt) == nil {
			e.lastSend = now
		}
	}
}

// pumpLocked sends what is queued and what is due for retransmission.
func (n *Node) pumpLocked(now time.Time) {
	for peer, ps := range n.peers {
		s := n.current[peer]
		if s == nil {
			// take a part for the first packet only when a handshake really goes out:
			// otherwise it would count as sent and wait for its retransmission timer
			if !ps.st.idle() && now.Sub(ps.lastInit) >= initEvery && n.Trust.Get(peer) != nil {
				first, _ := ps.st.nextPacket(now, false)
				n.startInitLocked(now, peer, ps, first)
			}
			continue
		}
		// nothing for 10 s while retransmitting: the session looks dead, start a new one
		if !ps.st.idle() && now.Sub(s.lastRecv) > 10*time.Second && n.stuckLocked(ps) {
			delete(n.current, peer)
			continue
		}
		for i := 0; i < 64; i++ {
			plain, retry := ps.st.nextPacket(now, false)
			if plain == nil {
				break
			}
			n.sendLocked(now, peer, ps, s, plain, retry)
		}
		for _, e := range ps.eps { // keepalive on every quiet road
			if now.Sub(e.lastRecv) <= aliveFor && now.Sub(e.lastSend) >= keepaliveGap {
				hdr := put32(put32([]byte{pData}, s.remote), uint32(s.sendN))
				pkt := s.send.Encrypt(append([]byte(nil), hdr...), s.sendN, hdr, keepalive())
				s.sendN++
				if e.ep.Road.Send(e.ep.Addr, pkt) == nil {
					e.lastSend = now
				}
			}
		}
	}
}

func (n *Node) stuckLocked(ps *peerState) bool {
	for _, p := range ps.st.inflight {
		if p.tries >= 4 {
			return true
		}
	}
	return false
}

// maintainLocked runs every second: connect to known devices, keep channels, clean up.
func (n *Node) maintainLocked(now time.Time) {
	for _, p := range n.Trust.List() {
		ps := n.peerLocked(p.Addr)
		if ps == nil {
			continue
		}
		if r := n.pairRelayLocked(&p); r != nil {
			role := "a"
			if p.Addr < n.ID.Addr() {
				role = "b"
			}
			r.join(p.relayChannel(), role)
		}
		s := n.current[p.Addr]
		if s == nil && now.Sub(ps.lastInit) >= autoConnect {
			n.startInitLocked(now, p.Addr, ps, nil)
		}
	}
	for idx, s := range n.sessions {
		if n.current[s.peer] != s && now.Sub(s.lastRecv) > sessionIdle {
			delete(n.sessions, idx)
		}
	}
	for idx, h := range n.hs {
		if now.Sub(h.at) > time.Minute {
			delete(n.hs, idx)
		}
	}
	for id, inv := range n.invites {
		if now.After(inv.Exp) {
			delete(n.invites, id)
			if n.own != nil {
				n.relayLocked(*n.own).leave(id)
			}
		}
	}
}

func (n *Node) newIndexLocked() uint32 {
	for {
		i := binary.BigEndian.Uint32(randBytes(4))
		if i != 0 && n.sessions[i] == nil && n.hs[i] == nil {
			return i
		}
	}
}

// wakeLocked asks the service loop to send what was just queued.
func (n *Node) wakeLocked() {
	select {
	case n.kick <- struct{}{}:
	default:
	}
}

// --- compression (spec §5) ---

// pushLocked queues a message, compressed with the newest common dictionary when worth it.
// The slot refers to our list at send time: the list changes only through event 0.5, which
// travels in the same order as messages.
func (n *Node) pushLocked(ps *peerState, msg []byte) {
	defer n.wakeLocked()
	d, slot := n.dicts.pick(ps.dicts, ps.lacks)
	if n.NoCompression {
		ps.st.push(msg, false)
		return
	}
	if z := compress(msg, d, slot); z != nil {
		ps.st.push(z, true)
		return
	}
	ps.st.push(msg, false)
}

// inboundLocked decompresses a reassembled message and runs it in order. A missing
// dictionary is not an error: we hold the message and everything after it and ask the sender
// for the dictionary; if we do not know the sender's list yet (it restarted), we wait for its
// hello. While waiting, only replies to our calls (the dictionary among them), hellos and
// dictionary lists run out of order: nothing depends on their order.
func (n *Node) inboundLocked(peer string, msg []byte, zip bool) {
	ps := n.peerLocked(peer)
	if ps == nil {
		return
	}
	if len(ps.waiting) > 0 {
		if plain, err := n.unzipLocked(ps, msg, zip); err == nil && outOfOrder(plain) {
			n.messageLocked(peer, plain)
			n.drainLocked(peer, ps)
			return
		}
	}
	ps.waiting = append(ps.waiting, inbound{msg, zip})
	n.drainLocked(peer, ps)
}

// drainLocked runs waiting messages in order until one cannot be decoded yet.
func (n *Node) drainLocked(peer string, ps *peerState) {
	for len(ps.waiting) > 0 {
		w := ps.waiting[0]
		plain, err := n.unzipLocked(ps, w.msg, w.zip)
		switch {
		case errors.Is(err, errNoDict):
			n.fetchDictLocked(peer, ps, ps.dicts[int(w.msg[0])-1])
			return
		case errors.Is(err, errNoList):
			return // wait for a hello or 0.5
		}
		ps.waiting = ps.waiting[1:]
		if err == nil {
			n.messageLocked(peer, plain)
		}
	}
	ps.waiting = nil
}

var errNoList = errors.New("sender dictionary list not received yet")

// unzipLocked decompresses a message; errNoDict — we lack the dictionary in that slot,
// errNoList — the slot is beyond the list we know.
func (n *Node) unzipLocked(ps *peerState, msg []byte, zip bool) ([]byte, error) {
	if !zip {
		return msg, nil
	}
	if len(msg) < 1 {
		return nil, errShort
	}
	var d *Dict
	if slot := int(msg[0]); slot > 0 {
		if slot > len(ps.dicts) {
			return nil, errNoList
		}
		if d = n.dicts.get(ps.dicts[slot-1]); d == nil {
			return nil, errNoDict
		}
	}
	return decompress(msg, d)
}

// outOfOrder reports messages that may run out of order: a result or error for our call
// ([1|2, …]), a hello or a dictionary list ([3, 0, 2|5, …]).
func outOfOrder(msg []byte) bool {
	if len(msg) < 2 {
		return false
	}
	return msg[1] == 1 || msg[1] == 2 || (len(msg) > 3 && msg[1] == 3 && msg[2] == 0 && (msg[3] == 2 || msg[3] == 5))
}

// fetchDictLocked asks the sender for dictionary id (it compressed with it, so it has it).
func (n *Node) fetchDictLocked(peer string, ps *peerState, id []byte) {
	if ps.fetching {
		return
	}
	ps.fetching = true
	go func() {
		var d *Dict
		for try := 0; try < 3 && d == nil; try++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			res, err := n.Call(ctx, peer, 0, 5, id)
			cancel()
			var raw []byte
			if err != nil || len(res) == 0 || cbor.Unmarshal(res[0], &raw) != nil || !bytes.Equal(DictID(raw), id) {
				continue
			}
			d, _ = NewDict(raw)
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		ps.fetching = false
		if d != nil {
			_ = n.addDictLocked(d)
		} else if len(ps.waiting) > 0 {
			ps.waiting = ps.waiting[1:] // the dictionary is unreachable: this message is lost
		}
		n.drainLocked(peer, ps)
	}()
}

// dictHandler serves 0.5 dict [id] → dictionary bytes. A device that asks lacks it, so we
// stop compressing with it for that device (this reply included) until it announces again.
func (n *Node) dictHandler(peer string, args []cbor.RawMessage) ([]any, error) {
	var id []byte
	if len(args) < 1 || cbor.Unmarshal(args[0], &id) != nil {
		return nil, &Error{Code: ErrBadArgs, Text: "dictionary id required"}
	}
	if n.AllowDict != nil && !n.AllowDict(peer, id) {
		return nil, &Error{Code: ErrForbidden, Text: "dictionary is for the family only"}
	}
	n.mu.Lock()
	if ps := n.peers[peer]; ps != nil {
		ps.lacks = append(ps.lacks, id)
	}
	d := n.dicts.get(id)
	n.mu.Unlock()
	if d == nil {
		return nil, &Error{Code: ErrNotFound, Text: "no such dictionary"}
	}
	return []any{d.Raw}, nil
}

// AddDict stores a new (newest) dictionary and announces it to all known devices (event 0.5).
func (n *Node) AddDict(raw []byte) error {
	d, err := NewDict(raw)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.addDictLocked(d)
}

func (n *Node) addDictLocked(d *Dict) error {
	if err := n.dicts.add(d); err != nil {
		return err
	}
	msg, _ := cbor.Marshal([]any{3, 0, 5, n.dicts.ids()})
	for _, p := range n.Trust.List() {
		if ps := n.peerLocked(p.Addr); ps != nil {
			ps.st.push(msg, false)
		}
	}
	n.wakeLocked()
	return nil
}

// Dicts lists our dictionary ids, newest first.
func (n *Node) Dicts() [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dicts.ids()
}
