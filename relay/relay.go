// Package relay is the P2PACT relay server (spec §3): it joins the two devices of a channel
// when they cannot reach each other directly.
//
// Both devices connect to it over TLS, name a channel and their side (a | b), and it forwards
// lines from one to the other. Channels are derived from the pair secret, so only the two
// devices know them; packets are already encrypted end to end, so the relay sees only the
// channel and packet sizes. While the other side is away it holds up to maxQueue lines
// (maxQueueBytes) for at most queueTTL. Limits: maxPerIP connections per address, maxChannels
// channels, lines up to maxServerLine.
//
// The protocol is newline-terminated JSON lines:
//
//	→ {"relay":1,"channel":"<32 hex>","role":"a"}   first line
//	← {"ok":true}                                    or {"error":"…"} and close
//	→ "p"                                            keepalive, answered with "P" (not forwarded)
//	→ any other line                                 forwarded to the other side of the channel
package relay

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	maxServerLine = 256 << 10 // longer lines close the connection
	maxQueue      = 256       // lines queued per channel side
	maxQueueBytes = 4 << 20   // bytes queued per channel side
	maxChannels   = 2000
	maxPerIP      = 16 // concurrent connections per address
	queueTTL      = 10 * time.Minute
	idle          = 90 * time.Second // silent longer: the connection is dead
)

type hello struct {
	Relay   int    `json:"relay"`
	Channel string `json:"channel"`
	Role    string `json:"role"`
}

type queued struct {
	at   time.Time
	line []byte
}

type peer struct {
	conn     net.Conn
	mu       sync.Mutex // guards writes
	draining bool       // draining the queue: new lines are queued behind it
}

func (p *peer) write(line []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_ = p.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := p.conn.Write(line)
	return err
}

type channel struct {
	peers map[string]*peer    // side → connection
	queue map[string][]queued // receiving side → queued lines
	bytes map[string]int      // receiving side → queued bytes
	seen  time.Time
}

// push queues a line for to within the limits (the oldest drop first).
func (ch *channel) push(to string, q queued) {
	ch.queue[to] = append(ch.queue[to], q)
	ch.bytes[to] += len(q.line)
	for len(ch.queue[to]) > 0 && (len(ch.queue[to]) > maxQueue || ch.bytes[to] > maxQueueBytes) {
		ch.bytes[to] -= len(ch.queue[to][0].line)
		ch.queue[to] = ch.queue[to][1:]
	}
}

// take removes and returns the whole queue for to.
func (ch *channel) take(to string) []queued {
	q := ch.queue[to]
	delete(ch.queue, to)
	delete(ch.bytes, to)
	return q
}

// prune drops lines older than queueTTL.
func (ch *channel) prune(now time.Time) {
	for to, q := range ch.queue {
		i := 0
		for i < len(q) && now.Sub(q[i].at) >= queueTTL {
			ch.bytes[to] -= len(q[i].line)
			i++
		}
		if i == len(q) {
			delete(ch.queue, to)
			delete(ch.bytes, to)
		} else {
			ch.queue[to] = q[i:]
		}
	}
}

// Server is a relay. Channels live in memory; after a restart devices reconnect by themselves.
type Server struct {
	mu       sync.Mutex
	channels map[string]*channel
	perIP    map[string]int
	now      func() time.Time
}

func NewServer() *Server {
	return &Server{channels: map[string]*channel{}, perIP: map[string]int{}, now: time.Now}
}

// Serve accepts connections until ln is closed (ln is already TLS).
func (s *Server) Serve(ln net.Listener) error {
	stop := make(chan struct{})
	defer close(stop)
	go s.sweep(stop)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.serve(c)
	}
}

// Stats reports open channels and connected devices (for logs).
func (s *Server) Stats() (channels, peers int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.channels {
		channels++
		peers += len(ch.peers)
	}
	return
}

func hostOf(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	ip := hostOf(c)
	s.mu.Lock()
	if s.perIP[ip] >= maxPerIP {
		s.mu.Unlock()
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte(`{"error":"too many connections"}` + "\n"))
		return
	}
	s.perIP[ip]++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.perIP[ip]--; s.perIP[ip] <= 0 {
			delete(s.perIP, ip)
		}
		s.mu.Unlock()
	}()

	r := bufio.NewReaderSize(c, 64<<10)
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	line, err := readLimited(r, maxServerLine)
	if err != nil {
		return
	}
	var h hello
	if json.Unmarshal(line, &h) != nil || h.Relay != 1 || !validChannel(h.Channel) || (h.Role != "a" && h.Role != "b") {
		_, _ = c.Write([]byte(`{"error":"bad hello"}` + "\n"))
		return
	}
	me := &peer{conn: c, draining: true}
	other := "b"
	if h.Role == "b" {
		other = "a"
	}

	s.mu.Lock()
	ch := s.channels[h.Channel]
	if ch == nil {
		if len(s.channels) >= maxChannels {
			s.mu.Unlock()
			_, _ = c.Write([]byte(`{"error":"too many channels"}` + "\n"))
			return
		}
		ch = &channel{peers: map[string]*peer{}, queue: map[string][]queued{}, bytes: map[string]int{}}
		s.channels[h.Channel] = ch
	}
	if old := ch.peers[h.Role]; old != nil {
		old.conn.Close() // the same side reconnected: the old connection is dead
	}
	ch.peers[h.Role] = me
	ch.seen = s.now()
	s.mu.Unlock()
	// leave the channel on any exit, including a failed drain
	defer s.leave(ch, h.Role, me)

	if err := me.write([]byte(`{"ok":true}` + "\n")); err != nil {
		return
	}
	if !s.drain(ch, h.Role, me) {
		return
	}

	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		line, err := readLimited(r, maxServerLine)
		if err != nil {
			return
		}
		if len(line) == 2 && line[0] == 'p' { // "p\n" is a keepalive
			if me.write([]byte("P\n")) != nil {
				return
			}
			continue
		}
		s.forward(h.Channel, other, line)
	}
}

// drain hands the queue to a new connection; lines arriving meanwhile queue behind it, so
// order is kept. false — a write failed (the rest went back to the queue).
func (s *Server) drain(ch *channel, role string, me *peer) bool {
	for {
		s.mu.Lock()
		if ch.peers[role] != me {
			s.mu.Unlock()
			return false
		}
		ch.prune(s.now())
		pending := ch.take(role)
		if len(pending) == 0 {
			me.draining = false
			s.mu.Unlock()
			return true
		}
		s.mu.Unlock()
		for i, q := range pending {
			if me.write(q.line) != nil {
				s.mu.Lock()
				rest := append(pending[i:], ch.take(role)...)
				for _, r := range rest {
					ch.push(role, r)
				}
				s.mu.Unlock()
				return false
			}
		}
	}
}

// leave removes the connection from the channel (unless a newer one replaced it).
func (s *Server) leave(ch *channel, role string, me *peer) {
	s.mu.Lock()
	if ch.peers[role] == me {
		delete(ch.peers, role)
	}
	ch.seen = s.now()
	s.mu.Unlock()
	me.conn.Close()
}

// forward hands a line to the other side, or queues it if that side is away or draining.
// A failed write means a dead connection: drop it and queue the line.
func (s *Server) forward(id, to string, line []byte) {
	s.mu.Lock()
	ch := s.channels[id]
	if ch == nil {
		s.mu.Unlock()
		return
	}
	ch.seen = s.now()
	p := ch.peers[to]
	if p == nil || p.draining {
		ch.push(to, queued{at: s.now(), line: line})
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if err := p.write(line); err != nil {
		s.mu.Lock()
		if ch.peers[to] == p {
			delete(ch.peers, to)
		}
		ch.push(to, queued{at: s.now(), line: line})
		s.mu.Unlock()
		p.conn.Close()
	}
}

// sweep runs every minute: expires queues and removes long-empty channels.
func (s *Server) sweep(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		s.mu.Lock()
		now := s.now()
		for id, ch := range s.channels {
			ch.prune(now)
			for role, p := range ch.peers { // a stale queue for a connected side is no longer needed
				if !p.draining && len(ch.queue[role]) > 0 {
					ch.take(role)
				}
			}
			if len(ch.peers) == 0 && len(ch.queue) == 0 && now.Sub(ch.seen) > queueTTL {
				delete(s.channels, id)
			}
		}
		s.mu.Unlock()
		if c, p := s.Stats(); c > 0 {
			slog.Info("relay", "channels", c, "peers", p)
		}
	}
}

func validChannel(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16
}

// readLimited reads a '\n'-terminated line of at most max bytes.
func readLimited(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		chunk, err := r.ReadSlice('\n')
		out = append(out, chunk...)
		if len(out) > max {
			return nil, errors.New("line too long")
		}
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}
