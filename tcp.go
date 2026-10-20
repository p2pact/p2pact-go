package p2pact

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// TCPRoad is the fallback road where UDP is blocked (spec §3): a 2-byte length, then the
// packet. Connections are made on demand and reused both ways; sessions do not depend on them,
// so a dropped connection costs nothing but a reconnect.
type TCPRoad struct {
	ln    net.Listener
	recv  func([]byte, Endpoint)
	mu    sync.Mutex
	conns map[string]*tcpConn // by remote address as we know it

	// Delay and Rate are for tests, as on UDPRoad.
	Delay time.Duration
	Rate  int
	free  time.Time

	sentBytes, sentPackets atomic.Int64
	recvBytes, recvPackets atomic.Int64
}

type tcpConn struct {
	out  chan tcpOut
	once sync.Once
	stop chan struct{}
}

type tcpOut struct {
	b   []byte
	due time.Time
}

// listenTCP opens the TCP road; addr "" — dial only, no listener.
func listenTCP(addr string, recv func([]byte, Endpoint)) (*TCPRoad, error) {
	t := &TCPRoad{recv: recv, conns: map[string]*tcpConn{}}
	if addr == "" {
		return t, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	t.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := t.newConn(c.RemoteAddr().String())
			go t.serve(c, c.RemoteAddr().String(), tc)
		}
	}()
	return t, nil
}

func (t *TCPRoad) Name() string { return "tcp" }

// Stats returns the counters (frame bytes, without TCP/IP headers).
func (t *TCPRoad) Stats() RoadStats {
	return RoadStats{t.sentBytes.Load(), t.sentPackets.Load(), t.recvBytes.Load(), t.recvPackets.Load()}
}

func (t *TCPRoad) newConn(addr string) *tcpConn {
	tc := &tcpConn{out: make(chan tcpOut, 1024), stop: make(chan struct{})}
	t.mu.Lock()
	if old := t.conns[addr]; old != nil {
		old.close()
	}
	t.conns[addr] = tc
	t.mu.Unlock()
	return tc
}

func (tc *tcpConn) close() { tc.once.Do(func() { close(tc.stop) }) }

// Send queues a packet to addr, dialing in the background if there is no connection: the
// node's lock is never held over a dial.
func (t *TCPRoad) Send(addr string, pkt []byte) error {
	if len(pkt) > MaxPacket+64 {
		return errors.New("packet too big")
	}
	t.mu.Lock()
	tc := t.conns[addr]
	if tc == nil {
		tc = &tcpConn{out: make(chan tcpOut, 1024), stop: make(chan struct{})}
		t.conns[addr] = tc
		go t.dial(addr, tc)
	}
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(pkt)), uint16(len(pkt)))
	frame = append(frame, pkt...)
	due := time.Now()
	if t.Rate > 0 {
		if t.free.Before(due) {
			t.free = due
		}
		t.free = t.free.Add(time.Duration(len(frame)) * time.Second / time.Duration(t.Rate))
		due = t.free
	}
	t.mu.Unlock()
	select {
	case tc.out <- tcpOut{frame, due.Add(t.Delay)}:
		t.sentBytes.Add(int64(len(frame)))
		t.sentPackets.Add(1)
		return nil
	default:
		return errors.New("tcp queue full")
	}
}

func (t *TCPRoad) dial(addr string, tc *tcpConn) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.drop(addr, tc)
		return
	}
	t.serve(c, addr, tc)
}

// serve runs one connection: a writer that keeps the emulated timing and a reader of frames.
func (t *TCPRoad) serve(c net.Conn, addr string, tc *tcpConn) {
	defer t.drop(addr, tc)
	defer c.Close()
	if tcp, ok := c.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	go func() {
		for {
			select {
			case <-tc.stop:
				c.Close()
				return
			case o := <-tc.out:
				time.Sleep(time.Until(o.due))
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := c.Write(o.b); err != nil {
					c.Close()
					return
				}
			}
		}
	}()
	ep := Endpoint{Road: t, Addr: addr}
	var hdr [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Minute))
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n > MaxPacket+64 {
			return
		}
		pkt := make([]byte, n)
		if _, err := io.ReadFull(c, pkt); err != nil {
			return
		}
		t.recvBytes.Add(int64(2 + n))
		t.recvPackets.Add(1)
		t.recv(pkt, ep)
	}
}

func (t *TCPRoad) drop(addr string, tc *tcpConn) {
	tc.close()
	t.mu.Lock()
	if t.conns[addr] == tc {
		delete(t.conns, addr)
	}
	t.mu.Unlock()
}

// localAddrs lists our TCP addresses for hints.
func (t *TCPRoad) localAddrs() []string {
	if t.ln == nil {
		return nil
	}
	la := t.ln.Addr().(*net.TCPAddr)
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

// LocalAddr is the listen address ("" — dial only).
func (t *TCPRoad) LocalAddr() string {
	if t.ln == nil {
		return ""
	}
	return t.ln.Addr().String()
}

func (t *TCPRoad) close() {
	if t.ln != nil {
		_ = t.ln.Close()
	}
	t.mu.Lock()
	for k, tc := range t.conns {
		tc.close()
		delete(t.conns, k)
	}
	t.mu.Unlock()
}
