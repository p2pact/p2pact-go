package p2pact

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Road carries packets (spec §3). It encrypts nothing and trusts nothing; it may lose,
// duplicate and reorder packets.
type Road interface {
	Name() string
	Send(addr string, pkt []byte) error
}

// Endpoint is where to send on a road: a UDP address or a relay channel.
type Endpoint struct {
	Road Road
	Addr string
}

func (e Endpoint) key() string { return e.Road.Name() + "|" + e.Addr }

// --- UDP ---

// UDPRoad is the main road: one packet is one datagram.
type UDPRoad struct {
	conn *net.UDPConn
	mu   sync.Mutex
	addr map[string]*net.UDPAddr
	// Drop is for tests: the packet is lost (network loss).
	Drop func() bool
	// Delay is for tests: one-way packet delay (a distant network).
	Delay time.Duration
	// Rate is for tests: link speed in bytes per second (0 — unlimited); packets queue
	// behind each other like on a slow link.
	Rate int

	free                   time.Time // when the emulated link is free again
	sentBytes, sentPackets atomic.Int64
	recvBytes, recvPackets atomic.Int64
}

// RoadStats counts UDP payload bytes and datagrams (add 28 bytes of IP and UDP headers per
// datagram for bytes on the wire).
type RoadStats struct {
	SentBytes, SentPackets, RecvBytes, RecvPackets int64
}

// Stats returns the counters since the road was opened.
func (u *UDPRoad) Stats() RoadStats {
	return RoadStats{u.sentBytes.Load(), u.sentPackets.Load(), u.recvBytes.Load(), u.recvPackets.Load()}
}

func listenUDP(addr string) (*UDPRoad, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, err
	}
	// a burst of retransmissions must not overflow the receive queue (~40 KB by default on macOS)
	_ = c.SetReadBuffer(1 << 20)
	_ = c.SetWriteBuffer(1 << 20)
	return &UDPRoad{conn: c, addr: map[string]*net.UDPAddr{}}, nil
}

func (u *UDPRoad) Name() string { return "udp" }

// LocalAddr is the address the road listens on.
func (u *UDPRoad) LocalAddr() string { return u.conn.LocalAddr().String() }

func (u *UDPRoad) Send(addr string, pkt []byte) error {
	u.sentBytes.Add(int64(len(pkt)))
	u.sentPackets.Add(1)
	if u.Drop != nil && u.Drop() {
		return nil
	}
	u.mu.Lock()
	a := u.addr[addr]
	u.mu.Unlock()
	if a == nil {
		var err error
		if a, err = net.ResolveUDPAddr("udp", addr); err != nil {
			return err
		}
		u.mu.Lock()
		u.addr[addr] = a
		u.mu.Unlock()
	}
	if u.Delay > 0 || u.Rate > 0 {
		wait := u.Delay
		if u.Rate > 0 {
			u.mu.Lock()
			now := time.Now()
			if u.free.Before(now) {
				u.free = now
			}
			u.free = u.free.Add(time.Duration(len(pkt)+28) * time.Second / time.Duration(u.Rate))
			wait += u.free.Sub(now)
			u.mu.Unlock()
		}
		cp := append([]byte(nil), pkt...)
		time.AfterFunc(wait, func() { _, _ = u.conn.WriteToUDP(cp, a) })
		return nil
	}
	_, err := u.conn.WriteToUDP(pkt, a)
	return err
}

func (u *UDPRoad) run(recv func([]byte, Endpoint)) {
	buf := make([]byte, 2048)
	for {
		n, from, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		u.recvBytes.Add(int64(n))
		u.recvPackets.Add(1)
		if u.Drop != nil && u.Drop() {
			continue
		}
		recv(append([]byte(nil), buf[:n]...), Endpoint{Road: u, Addr: from.String()})
	}
}

// localAddrs lists our addresses for hints: the listen address, or every network address
// when listening on all of them.
func (u *UDPRoad) localAddrs() []string {
	la := u.conn.LocalAddr().(*net.UDPAddr)
	port := strconv.Itoa(la.Port)
	if !la.IP.IsUnspecified() {
		return []string{net.JoinHostPort(la.IP.String(), port)}
	}
	var out []string
	ifs, _ := net.InterfaceAddrs()
	for _, a := range ifs {
		ip, ok := a.(*net.IPNet)
		if !ok || ip.IP.IsLoopback() || ip.IP.To4() == nil || ip.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, net.JoinHostPort(ip.IP.String(), port))
	}
	return out
}

func (u *UDPRoad) close() { _ = u.conn.Close() }

// --- relay ---

// RelayRoad is the relay road (spec §3): one channel per pair, a packet is a base64 line.
// The server is the relay package (cmd/p2pact-relay).
type RelayRoad struct {
	hint RelayHint
	recv func([]byte, Endpoint)
	mu   sync.Mutex
	ch   map[string]*relayChan
}

type relayChan struct {
	role string
	out  chan []byte
	stop chan struct{}
}

func newRelayRoad(h RelayHint, recv func([]byte, Endpoint)) *RelayRoad {
	return &RelayRoad{hint: h, recv: recv, ch: map[string]*relayChan{}}
}

func (r *RelayRoad) Name() string { return "relay:" + r.hint.Addr }

// Send puts a packet into a channel; an unknown (not joined) channel is an error.
func (r *RelayRoad) Send(channel string, pkt []byte) error {
	r.mu.Lock()
	c := r.ch[channel]
	r.mu.Unlock()
	if c == nil {
		return errors.New("relay channel not open")
	}
	select {
	case c.out <- pkt:
		return nil
	default:
		return errors.New("relay queue full")
	}
}

// join keeps a channel open, reconnecting until leave.
func (r *RelayRoad) join(channel, role string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ch[channel] != nil {
		return
	}
	c := &relayChan{role: role, out: make(chan []byte, 256), stop: make(chan struct{})}
	r.ch[channel] = c
	go r.keep(channel, c)
}

func (r *RelayRoad) leave(channel string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c := r.ch[channel]; c != nil {
		close(c.stop)
		delete(r.ch, channel)
	}
}

func (r *RelayRoad) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, c := range r.ch {
		close(c.stop)
		delete(r.ch, k)
	}
}

func (r *RelayRoad) keep(channel string, c *relayChan) {
	backoff := 500 * time.Millisecond
	for {
		err := r.session(channel, c)
		select {
		case <-c.stop:
			return
		case <-time.After(backoff):
		}
		if err != nil {
			backoff = min(backoff*2, 30*time.Second)
		} else {
			backoff = 500 * time.Millisecond
		}
	}
}

func (r *RelayRoad) dial() (net.Conn, error) {
	host, _, err := net.SplitHostPort(r.hint.Addr)
	if err != nil {
		return nil, err
	}
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if r.hint.FP != "" {
		want := strings.ToLower(r.hint.FP)
		tc.InsecureSkipVerify = true // verified below, by fingerprint
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no certificate")
			}
			if sum := sha256.Sum256(raw[0]); hexs(sum[:]) != want {
				return errors.New("relay certificate does not match the fingerprint")
			}
			return nil
		}
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", r.hint.Addr, tc)
}

func (r *RelayRoad) session(channel string, c *relayChan) error {
	conn, err := r.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	h, _ := json.Marshal(map[string]any{"relay": 1, "channel": channel, "role": c.role})
	if _, err := conn.Write(append(h, '\n')); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(conn, 64<<10)
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	line, err := rd.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, `"ok":true`) {
		return errors.New("relay refused: " + strings.TrimSpace(line))
	}
	done := make(chan struct{})
	defer close(done)
	go func() { // writer: packets, and a keepalive to the server every 25 s
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			var b []byte
			select {
			case <-done:
				return
			case <-c.stop:
				conn.Close()
				return
			case <-t.C:
				b = []byte("p\n")
			case pkt := <-c.out:
				b = append([]byte(base64.StdEncoding.EncodeToString(pkt)), '\n')
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(b); err != nil {
				conn.Close()
				return
			}
		}
	}()
	ep := Endpoint{Road: r, Addr: channel}
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		line, err := rd.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "P" || line == "" {
			continue
		}
		pkt, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(pkt) > MaxPacket+64 {
			continue
		}
		r.recv(pkt, ep)
	}
}
