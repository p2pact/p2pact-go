package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

const testChannel = "00112233445566778899aabbccddeeff"

func wsDial(t *testing.T, url, role string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	wsSend(t, c, `{"relay":1,"channel":"`+testChannel+`","role":"`+role+`"}`)
	if got := wsRecv(t, c); got != `{"ok":true}` {
		t.Fatalf("hello answer %q", got)
	}
	return c
}

func wsSend(t *testing.T, c *websocket.Conn, s string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Write(ctx, websocket.MessageText, []byte(s)); err != nil {
		t.Fatal(err)
	}
}

func wsRecv(t *testing.T, c *websocket.Conn) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Two WebSocket devices on one channel: one message is one line, keepalives are answered.
func TestWSRelay(t *testing.T) {
	ts := httptest.NewServer(NewServer().Handler())
	defer ts.Close()
	url := "ws" + strings.TrimPrefix(ts.URL, "http")
	a, b := wsDial(t, url, "a"), wsDial(t, url, "b")
	wsSend(t, a, "AAAA")
	if got := wsRecv(t, b); got != "AAAA" {
		t.Fatalf("b got %q", got)
	}
	wsSend(t, b, "BBBB\n") // a trailing newline is accepted too
	if got := wsRecv(t, a); got != "BBBB" {
		t.Fatalf("a got %q", got)
	}
	wsSend(t, a, "p")
	if got := wsRecv(t, a); got != "P" {
		t.Fatalf("keepalive answer %q", got)
	}
	wsSend(t, a, "bad") // nothing comes back for a forwarded line
	wsSend(t, a, "C")
	if wsRecv(t, b) != "bad" || wsRecv(t, b) != "C" {
		t.Fatal("order")
	}
}

// A bad hello is refused and closed.
func TestWSRelayBadHello(t *testing.T) {
	ts := httptest.NewServer(NewServer().Handler())
	defer ts.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	wsSend(t, c, `{"relay":2}`)
	if got := wsRecv(t, c); !strings.Contains(got, "bad hello") {
		t.Fatalf("answer %q", got)
	}
}

// A browser on WebSocket and a device on TLS share the hub: the line goes both ways.
func TestWSAndTLSShareHub(t *testing.T) {
	srv := NewServer()
	ws := httptest.NewServer(srv.Handler())
	defer ws.Close()
	cert, err := LoadOrMakeCert(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	go srv.Serve(tl)
	defer ln.Close()

	b := wsDial(t, "ws"+strings.TrimPrefix(ws.URL, "http"), "b")
	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	conn.Write([]byte(`{"relay":1,"channel":"` + testChannel + `","role":"a"}` + "\n"))
	if l, _ := r.ReadString('\n'); l != `{"ok":true}`+"\n" {
		t.Fatalf("tls hello answer %q", l)
	}
	conn.Write([]byte("from-tls\n"))
	if got := wsRecv(t, b); got != "from-tls" {
		t.Fatalf("ws got %q", got)
	}
	wsSend(t, b, "from-ws")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if l, err := r.ReadString('\n'); err != nil || l != "from-ws\n" {
		t.Fatalf("tls got %q %v", l, err)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{"127.0.0.1:80": true, "[::1]:80": true, "localhost:80": true, ":443": false, "0.0.0.0:80": false, "10.0.0.1:80": false, "bad": false} {
		if IsLoopbackAddr(addr) != want {
			t.Errorf("%s: want %v", addr, want)
		}
	}
}
