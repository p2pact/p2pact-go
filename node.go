package p2pact

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"sort"
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
	session            uint32 // our index of the session its last packet belonged to
}

type peerState struct {
	addr     string
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
	tried    [][]byte        // dictionaries of its list we asked it for and did not get
	hist     *history        // what we sent it and got from it, to train our dictionary for it
	sysCalls map[uint64]bool // our calls of tool 0: their results are not conversation
	queue    []pending       // conversation messages waiting to be learnt (learn.go)
	queued   int
	lastTalk time.Time
}

type inbound struct {
	msg    []byte
	zip    bool
	stream uint64
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
	dir   string
	// OnEvent receives tool events (except tool 0) from known devices.
	OnEvent func(peer string, tool, event int, args []cbor.RawMessage)
	// OnPaired is called after pairing (on either side).
	OnPaired func(p Peer)
	// OnHello is called when a known device sends its hello (new session or pairing).
	OnHello func(peer string)
	// NoCompression turns compression off for what we send (benchmarks, debugging).
	NoCompression bool
	// NoLearning: do not train our own dictionaries on what we send (spec §5).
	NoLearning bool

	advertise *Hints // announced instead of our own addresses (SetAdvertise)
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

	stop  chan struct{}
	kick  chan struct{} // something was queued: send now, not on the next tick
	train chan struct{} // one dictionary is trained at a time
	wg    sync.WaitGroup
	// handshakes counts sessions set up (for tests: a network change needs no new one)
	handshakes atomic.Int64
}

// NewNode creates a device with keys and known devices from dir.
func NewNode(dir, name string) (*Node, error) {
	id, err := LoadIdentity(dir)
	if err != nil {
		return nil, err
	}
	n := &Node{ID: id, Trust: LoadTrust(dir), Name: name, dir: dir, boot: binary.BigEndian.Uint32(randBytes(4)),
		rel: map[string]*RelayRoad{}, sessions: map[uint32]*session{}, current: map[string]*session{},
		hs: map[uint32]*handshake{}, invites: map[string]*Invite{}, peers: map[string]*peerState{},
		handlers: map[[2]int]Handler{}, resetAt: map[string]time.Time{}, dicts: loadDicts(dir), stop: make(chan struct{}),
		kick: make(chan struct{}, 1), train: make(chan struct{}, 1)}
	n.Handle(0, 1, func(string, []cbor.RawMessage) ([]any, error) { return []any{}, nil }) // ping
	n.Handle(0, 2, func(peer string, _ []cbor.RawMessage) ([]any, error) { return n.info(peer), nil })
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
	go n.learnLoop()
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

// Forget drops a known device: we stop answering it (removed from the family). Our
// conversation's dictionaries and history go too.
func (n *Node) Forget(addr string) {
	n.mu.Lock()
	n.dicts.forget(addr)
	if ps := n.peers[addr]; ps != nil && ps.hist != nil {
		ps.hist.gone = true
	}
	_ = os.Remove(historyPath(n.dir, addr))
	delete(n.peers, addr)
	if s := n.current[addr]; s != nil {
		delete(n.current, addr)
		delete(n.sessions, s.local)
	}
	n.mu.Unlock()
	n.Trust.Remove(addr)
}

// --- calls and events ---

// Call invokes tool.method on a known device and returns the result elements. It goes on
// stream 0: in order with every other stream-0 message.
func (n *Node) Call(ctx context.Context, peer string, tool, method int, args ...any) ([]cbor.RawMessage, error) {
	return n.CallOn(ctx, peer, 0, tool, method, args...)
}

// CallOn is Call on a stream: in order with the stream's other messages, independent of
// other streams (a loss on one does not hold up the rest). One stream per chat is natural.
// The result comes back on the same stream.
func (n *Node) CallOn(ctx context.Context, peer string, stream uint64, tool, method int, args ...any) ([]cbor.RawMessage, error) {
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
	if tool == 0 {
		ps.sysCalls[id] = true
	}
	msg, err := cbor.Marshal(append([]any{0, id, tool, method}, args...))
	if err == nil {
		n.pushLocked(ps, msg, stream, tool != 0)
	}
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		n.mu.Lock()
		delete(ps.calls, id)
		delete(ps.sysCalls, id)
		n.mu.Unlock()
	}()
	select {
	case r := <-ch:
		return r.res, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Event sends event tool.event to a known device on stream 0 (in order, like calls).
func (n *Node) Event(peer string, tool, event int, args ...any) error {
	return n.EventOn(peer, 0, tool, event, args...)
}

// EventOn is Event on a stream (see CallOn).
func (n *Node) EventOn(peer string, stream uint64, tool, event int, args ...any) error {
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
	n.pushLocked(ps, msg, stream, tool != 0)
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
// The dictionaries are those peer may see.
func (n *Node) info(peer string) []any {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.infoLocked(peer)
}

func (n *Node) infoLocked(peer string) []any {
	tools := map[int]int{}
	for k := range n.handlers {
		if k[0] != 0 {
			tools[k[0]] = 1
		}
	}
	return []any{n.Name, runtime.GOOS, "p2pact-go", tools, n.dicts.ids(peer), toWire(n.hintsLocked())}
}

// SetAdvertise announces these addresses instead of our own in invites and hellos: behind
// port forwarding, a known public address, or a proxy. nil — our own addresses again.
func (n *Node) SetAdvertise(h *Hints) {
	n.mu.Lock()
	n.advertise = h
	n.mu.Unlock()
}

func (n *Node) hintsLocked() Hints {
	if n.advertise != nil {
		h := *n.advertise
		if h.Relay == nil && n.own != nil {
			cp := *n.own
			h.Relay = &cp
		}
		return h
	}
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
	n.seenLocked(ps, from, now, s.local)
	_ = ps.st.receive(now, plain, func(msg []byte, zip bool, st uint64) { n.inboundLocked(s.peer, msg, zip, st) })
	if !ps.st.ackDue.IsZero() && !now.Before(ps.st.ackDue) {
		n.wakeLocked() // an ack is due now
	}
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
	n.seenLocked(ps, from, now, s.local)
	n.bootLocked(ps, binary.BigEndian.Uint32(payload[8:12]))
	out := put32(put32([]byte{pResp}, s.remote), local)
	_ = from.Road.Send(from.Addr, append(out, resp...))
	if len(payload) > 12 { // data in the first packet
		_ = ps.st.receive(now, payload[12:], func(msg []byte, zip bool, st uint64) { n.inboundLocked(peer, msg, zip, st) })
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
	n.seenLocked(ps, from, now, s.local)
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
	n.seenLocked(ps, from, now, s.local)
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
	n.seenLocked(ps, from, now, s.local)
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
	msg, _ := cbor.Marshal(append([]any{3, 0, 2}, n.infoLocked(peer)...))
	n.pushLocked(n.peerLocked(peer), msg, 0, false)
}

// messageLocked handles a reassembled message (spec §6).
func (n *Node) messageLocked(peer string, msg []byte, stream uint64) {
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
		if tool != 0 {
			n.hearLocked(ps, msg)
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
				n.pushLocked(ps, b, stream, tool != 0) // the result goes back on the call's stream
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
		if !ps.sysCalls[id] {
			n.hearLocked(ps, msg)
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
			ps.dicts, ps.lacks, ps.tried = nil, nil, nil
			_ = cbor.Unmarshal(a[7], &ps.dicts)
			n.fetchNewLocked(peer, ps)
			n.drainLocked(peer, ps)
			return
		}
		if tool == 0 && ev == 5 && len(a) >= 4 { // the dictionary list changed
			ps.dicts, ps.lacks, ps.tried = nil, nil, nil
			_ = cbor.Unmarshal(a[3], &ps.dicts)
			n.fetchNewLocked(peer, ps)
			n.drainLocked(peer, ps)
			return
		}
		if tool != 0 {
			n.hearLocked(ps, msg)
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
		ps = &peerState{addr: peer, st: newStream(), eps: map[string]*epState{}, calls: map[uint64]chan callResult{},
			sysCalls: map[uint64]bool{}}
		n.peers[peer] = ps
	}
	return ps
}

func (n *Node) seenLocked(ps *peerState, from Endpoint, now time.Time, session uint32) {
	k := from.key()
	e := ps.eps[k]
	if e == nil {
		e = &epState{ep: from}
		ps.eps[k] = e
	}
	e.lastRecv, e.session = now, session
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
	// prefer roads the current session was heard on: earlier sessions (the device before a
	// restart, another program with the same keys) may have used roads that are gone now
	if s := n.current[peer]; s != nil && !all {
		var cur []*epState
		for _, e := range alive {
			if e.session == s.local {
				cur = append(cur, e)
			}
		}
		if len(cur) > 0 {
			alive = cur
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
		// the road heard from last: a device that reconnected (a new TCP connection, a new
		// port behind NAT, UDP blocked so it moved to TCP) leaves its old endpoint "alive"
		// for a while, but it is dead. A better kind of road wins only if it was heard from
		// within half a second of it (a working UDP road hears something all the time).
		best := alive[0]
		for _, e := range alive[1:] {
			if e.lastRecv.After(best.lastRecv) {
				best = e
			}
		}
		for _, e := range alive {
			if rank(e) < rank(best) && best.lastRecv.Sub(e.lastRecv) < 500*time.Millisecond {
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
	if p == nil || now.Sub(ps.lastInit) < ps.initGap() {
		return
	}
	ps.lastInit = now
	// keep the last few unanswered starts: a reply to any of them opens the session (on a
	// slow link the reply to an earlier one may come after we retried)
	var pending []uint32
	for idx, h := range n.hs {
		if !h.pair && h.peer == peer {
			pending = append(pending, idx)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return n.hs[pending[i]].at.Before(n.hs[pending[j]].at) })
	for len(pending) >= 3 {
		delete(n.hs, pending[0])
		pending = pending[1:]
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
			if !ps.st.idle() && now.Sub(ps.lastInit) >= ps.initGap() && n.Trust.Get(peer) != nil {
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
		if c := n.candidatesLocked(peer, ps, now, false); len(c) == 1 {
			ps.st.reliable = c[0].ep.Road.Name() != "udp"
		}
		for i := 0; ; i++ {
			if i == 256 { // a burst at a time; the rest on the next wake
				n.wakeLocked()
				break
			}
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

// initGap is how long to wait for a handshake reply before retrying: three round trips as
// last measured with this device (250 ms – 2 s), a second when unknown (like TCP and QUIC).
func (ps *peerState) initGap() time.Duration {
	if ps.st.srtt == 0 {
		return initEvery
	}
	return min(max(3*ps.st.srtt, 250*time.Millisecond), 2*time.Second)
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

// pushLocked queues a message, compressed when worth it: with our dictionary for this device,
// else the newest one it also has. The slot refers to our list at send time: the list changes
// only through event 0.5, which travels in the same order as messages.
// talk: the message is conversation (not tool 0), so it goes to the history (learn.go).
func (n *Node) pushLocked(ps *peerState, msg []byte, stream uint64, talk bool) {
	defer n.wakeLocked()
	if n.NoCompression {
		ps.st.push(msg, false, stream)
		return
	}
	d, slot := n.dicts.pick(ps.addr, ps.dicts, ps.lacks)
	z := compress(msg, d, slot)
	if talk {
		n.learnLocked(ps, msg, d, z)
	}
	if z != nil {
		ps.st.push(z, true, stream)
		return
	}
	ps.st.push(msg, false, stream)
}

// inboundLocked decompresses a reassembled message and runs it in order. A missing
// dictionary is not an error: we hold the message and everything after it and ask the sender
// for the dictionary; if we do not know the sender's list yet (it restarted), we wait for its
// hello. While waiting, only replies to our calls (the dictionary among them), hellos and
// dictionary lists run out of order: nothing depends on their order.
func (n *Node) inboundLocked(peer string, msg []byte, zip bool, stream uint64) {
	ps := n.peerLocked(peer)
	if ps == nil {
		return
	}
	if len(ps.waiting) > 0 {
		if plain, err := n.unzipLocked(ps, msg, zip); err == nil && outOfOrder(plain) {
			n.messageLocked(peer, plain, stream)
			n.drainLocked(peer, ps)
			return
		}
	}
	ps.waiting = append(ps.waiting, inbound{msg, zip, stream})
	n.drainLocked(peer, ps)
}

// drainLocked runs waiting messages in order until one cannot be decoded yet.
func (n *Node) drainLocked(peer string, ps *peerState) {
	for len(ps.waiting) > 0 {
		w := ps.waiting[0]
		plain, err := n.unzipLocked(ps, w.msg, w.zip)
		switch {
		case errors.Is(err, errNoDict):
			if id := ps.dicts[int(w.msg[0])-1]; len(id) > 0 {
				n.fetchDictLocked(peer, ps, id, true)
				return
			} // a free slot: the message is damaged
			ps.waiting = ps.waiting[1:]
			continue
		case errors.Is(err, errNoList):
			return // wait for a hello or 0.5
		}
		ps.waiting = ps.waiting[1:]
		if err == nil {
			n.messageLocked(peer, plain, w.stream)
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
		if d = n.dicts.get(ps.dicts[slot-1], ps.addr); d == nil {
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

// fetchNewLocked asks the device for the newest dictionary in its list that we lack: so it
// can compress with it (only a dictionary both have is used). One at a time; one we could not
// get (the family's, say) is not asked for again.
func (n *Node) fetchNewLocked(peer string, ps *peerState) {
	for _, id := range ps.dicts {
		if len(id) > 0 && n.dicts.get(id, peer) == nil && !has(ps.tried, id) {
			n.fetchDictLocked(peer, ps, id, false)
			return
		}
	}
}

// fetchDictLocked asks the device for dictionary id: one it compressed a waiting message
// with (it has it), or a new one in its list. What we get belongs to the pair with it.
func (n *Node) fetchDictLocked(peer string, ps *peerState, id []byte, waiting bool) {
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
			d.peer = peer
			if n.addDictLocked(d) != nil { // could not store it: do not ask again and again
				d = nil
			}
		}
		switch {
		case d != nil:
		case waiting && len(ps.waiting) > 0:
			ps.waiting = ps.waiting[1:] // the dictionary is unreachable: this message is lost
		default:
			ps.tried = append(ps.tried, id)
		}
		n.drainLocked(peer, ps)
		n.fetchNewLocked(peer, ps)
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
	d := n.dicts.get(id, peer)
	n.mu.Unlock()
	if d == nil {
		return nil, &Error{Code: ErrNotFound, Text: "no such dictionary"}
	}
	return []any{d.Raw}, nil
}

// AddDict stores a new (newest) common dictionary and announces it to all known devices
// (event 0.5).
func (n *Node) AddDict(raw []byte) error {
	d, err := NewDict(raw)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.addDictLocked(d)
}

// addDictLocked stores a dictionary and announces the new list to the devices that see it:
// all for a common one, the pair's device for its own. Only over a live session: a new one
// starts with our hello, which carries the list, and a queued announcement would open it
// early, without the message the session is for.
func (n *Node) addDictLocked(d *Dict) error {
	if err := n.dicts.add(d); err != nil {
		return err
	}
	for _, p := range n.Trust.List() {
		if !d.visible(p.Addr) || n.current[p.Addr] == nil {
			continue
		}
		if ps := n.peerLocked(p.Addr); ps != nil {
			msg, _ := cbor.Marshal([]any{3, 0, 5, n.dicts.ids(p.Addr)})
			ps.st.push(msg, false, 0)
		}
	}
	n.wakeLocked()
	return nil
}

// Dicts lists the dictionary ids peer sees, newest first.
func (n *Node) Dicts(peer string) [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dicts.ids(peer)
}
