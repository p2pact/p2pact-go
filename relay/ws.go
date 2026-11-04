package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// WebSocket side of the relay (spec §3): the same line protocol, one WebSocket message is one
// line (the trailing newline is optional), and the connection joins the same hub of channels
// as the TLS listener, so a browser on wss:// and a device on TLS reach each other.

// wsMaxMessage bounds a message; the hub drops longer lines anyway (maxServerLine).
const wsMaxMessage = maxServerLine

// Handler serves WebSocket connections (any path). Origin is not checked: the relay is public
// and the channel name is the only credential.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
		if err != nil {
			return
		}
		c.SetReadLimit(wsMaxMessage)
		wc := newWSConn(c, s.clientHost(r))
		s.serve(wc) // closes the connection
	})
}

// ServeWS serves WebSocket connections on ln (already TLS for wss) until it is closed. Run it
// next to Serve: the sweeper of expired queues is Serve's.
func (s *Server) ServeWS(ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 15 * time.Second}
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// TrustProxy makes the WebSocket handler take the client address from X-Forwarded-For (last
// entry, as a trusted proxy appends it) or X-Real-IP, but only when the TCP peer is loopback.
// Use it behind a local reverse proxy; the proxy must overwrite client-supplied values.
func (s *Server) TrustProxy() { s.trustProxy = true }

func (s *Server) clientHost(r *http.Request) string {
	peer := remoteHost(r)
	if !s.trustProxy {
		return peer
	}
	if ip := net.ParseIP(peer); ip == nil || !ip.IsLoopback() {
		return peer
	}
	if xs := r.Header.Values("X-Forwarded-For"); len(xs) > 0 {
		parts := strings.Split(xs[len(xs)-1], ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); ip != nil {
		return ip.String()
	}
	return peer
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IsLoopbackAddr says whether a listen address ("127.0.0.1:8080", "[::1]:8080",
// "localhost:8080") is on the loopback interface only.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// wsConn presents a WebSocket as the net.Conn the line protocol reads: each message comes out
// as a line ending in "\n", each Write (always one whole line) goes out as one message without it.
type wsConn struct {
	c      *websocket.Conn
	host   string
	rbuf   []byte
	mu     sync.Mutex
	rd, wd time.Time
	closed bool
}

func newWSConn(c *websocket.Conn, host string) *wsConn { return &wsConn{c: c, host: host} }

type hostAddr string

func (a hostAddr) Network() string { return "ws" }
func (a hostAddr) String() string  { return string(a) + ":0" }

func (w *wsConn) deadline(d time.Time) (context.Context, context.CancelFunc) {
	if d.IsZero() {
		return context.WithCancel(context.Background())
	}
	return context.WithDeadline(context.Background(), d)
}

func (w *wsConn) Read(p []byte) (int, error) {
	if len(w.rbuf) == 0 {
		w.mu.Lock()
		d := w.rd
		w.mu.Unlock()
		ctx, cancel := w.deadline(d)
		_, msg, err := w.c.Read(ctx)
		cancel()
		if err != nil {
			if websocket.CloseStatus(err) != -1 {
				return 0, io.EOF
			}
			return 0, err
		}
		if len(msg) == 0 || msg[len(msg)-1] != '\n' {
			msg = append(msg, '\n')
		}
		w.rbuf = msg
	}
	n := copy(p, w.rbuf)
	w.rbuf = w.rbuf[n:]
	return n, nil
}

func (w *wsConn) Write(b []byte) (int, error) {
	w.mu.Lock()
	d := w.wd
	w.mu.Unlock()
	ctx, cancel := w.deadline(d)
	defer cancel()
	if err := w.c.Write(ctx, websocket.MessageText, []byte(strings.TrimSuffix(string(b), "\n"))); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConn) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	w.mu.Unlock()
	return w.c.Close(websocket.StatusNormalClosure, "")
}

func (w *wsConn) LocalAddr() net.Addr  { return hostAddr("relay") }
func (w *wsConn) RemoteAddr() net.Addr { return hostAddr(w.host) }
func (w *wsConn) SetDeadline(t time.Time) error {
	w.mu.Lock()
	w.rd, w.wd = t, t
	w.mu.Unlock()
	return nil
}
func (w *wsConn) SetReadDeadline(t time.Time) error {
	w.mu.Lock()
	w.rd = t
	w.mu.Unlock()
	return nil
}
func (w *wsConn) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.wd = t
	w.mu.Unlock()
	return nil
}
