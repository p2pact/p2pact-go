package p2pact

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Comparisons with JSON lines over TLS/TCP and JSON-RPC over HTTPS. The numbers are printed
// to the test log (go test -v -run Compare).

// tlsOverhead is a TLS 1.3 record: 5 bytes of header, 1 type byte, a 16-byte tag.
const tlsOverhead = 22

// ourBytes is the size of a P2PACT packet carrying msg (with a piggybacked ack).
func ourBytes(msg []any) int {
	b, _ := cbor.Marshal(msg)
	s := newStream()
	s.recvNext = 2 // something to ack, as in a live conversation
	s.push(b, false)
	plain, _ := s.nextPacket(time.Now(), false)
	return dataHeader + len(plain) + 16
}

func jsonTLS(v any) int {
	b, _ := json.Marshal(v)
	return len(b) + 1 + tlsOverhead
}

func httpsJSON(path string, v any) int {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": path, "params": v})
	head := fmt.Sprintf("POST /rpc HTTP/1.1\r\nHost: 192.168.1.5:48725\r\nContent-Type: application/json\r\n"+
		"Authorization: Bearer %s\r\nContent-Length: %d\r\n\r\n", strings.Repeat("a", 64), len(body))
	return len(head) + len(body) + tlsOverhead
}

func TestCompareBytes(t *testing.T) {
	chat := "62b7b92a-252b-43a2-971a-ec011b3c299c"
	at := time.Now().UnixMilli()
	cases := []struct {
		name     string
		ours     []any
		json     any
		httpPath string
	}{
		{"keepalive", nil, map[string]any{"cmd": "ping", "at": at}, "net/ping"},
		{"new chat message \"ok\"", []any{3, 1, 1, 1, 58, 0, "ok"},
			map[string]any{"cmd": "messages", "chat": chat, "messages": []any{map[string]any{"seq": 58, "role": "user", "text": "ok"}}}, "chat/changed"},
		{"human reply to a chat", []any{0, 12, 2, 2, 1, "open a PR"},
			map[string]any{"cmd": "reply", "chat": chat, "text": "open a PR", "at": at, "mid": "3f9a1c2b7d4e5f60"}, "chat/send"},
		{"history search", []any{0, 7, 1, 3, "relay", 5},
			map[string]any{"cmd": "search", "query": "relay", "limit": 5, "at": at}, "history/search"},
	}
	for _, c := range cases {
		ours := dataHeader + 1 + 16 // a keepalive is a flags-only packet
		if c.ours != nil {
			ours = ourBytes(c.ours)
		}
		js, rpc := jsonTLS(c.json), httpsJSON(c.httpPath, c.json)
		t.Logf("%-28s p2pact %4d B · JSON over TLS %4d B · JSON-RPC over HTTPS %4d B", c.name, ours, js, rpc)
		if ours >= js {
			t.Errorf("%s: p2pact is not smaller", c.name)
		}
	}

	// a chat list: a polling client gets the whole list every 1.5 s; P2PACT sends only changes
	var list []any
	for i := 0; i < 12; i++ {
		list = append(list, map[string]any{"id": fmt.Sprintf("%08x-252b-43a2-971a-ec011b3c299c", i), "agent": "claude",
			"title": "Fix flaky delivery test", "cwd": "/home/user/projects/app", "project": "app",
			"state": "waiting", "updated": time.Now().Format(time.RFC3339Nano),
			"last": strings.Repeat("Review is still running: waiting for the tests. ", 3)})
	}
	full := jsonTLS(map[string]any{"cmd": "chats", "list": list})
	perMinPoll := full * 40                        // every 1.5 s
	change := ourBytes([]any{3, 2, 1, 3, 1})       // "chat 3 is now working"
	perMinOurs := change*4 + (dataHeader+1+16)*2*2 // 4 changes a minute plus keepalives on two roads
	t.Logf("chat list: polling %d B every 1.5 s = %d KB a minute; p2pact changes: %d B per event, ~%d B a minute",
		full, perMinPoll/1024, change, perMinOurs)
}

// delayProxy is a TCP proxy that delays every chunk by d one way.
func delayProxy(t *testing.T, target string, d time.Duration) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				time.Sleep(d)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				dst.Close()
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go pipe(s, c)
			go pipe(c, s)
		}
	}()
	return ln.Addr().String()
}

// First answer on a new connection with 50 ms one-way delay (a cross-town network): TLS over
// TCP needs the TCP handshake and the TLS handshake before the request; P2PACT sends the request
// in the first packet.
func TestCompareFirstAnswer(t *testing.T) {
	const oneWay = 50 * time.Millisecond

	// baseline: TLS 1.3 over TCP, one request line, one reply line
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				line, _ := r.ReadString('\n')
				_, _ = io.WriteString(c, line)
			}()
		}
	}()
	px := delayProxy(t, ln.Addr().String(), oneWay)
	start := time.Now()
	c, err := tls.Dial("tcp", px, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, `{"cmd":"ping"}`+"\n")
	if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	tlsTook := time.Since(start)
	c.Close()

	// p2pact: paired, but no session (the other device has just started)
	dir := t.TempDir()
	a, b := node(t, "Mac", true, nil), nodeIn(t, dir, "Phone", true, nil)
	defer a.Close()
	pair(t, a, b)
	baddr := b.udp.conn.LocalAddr().String()
	b.Close()
	b2, _ := NewNode(dir, "Phone")
	_ = b2.ListenUDP(baddr)
	b2.Start()
	defer b2.Close()
	a.mu.Lock()
	delete(a.current, b.ID.Addr()) // and the first forgets the old session: an honest cold start
	a.mu.Unlock()
	a.UDP().Delay, b2.UDP().Delay = oneWay, oneWay
	start = time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := b2.Call(ctx, a.ID.Addr(), 0, 1); err != nil {
		t.Fatal(err)
	}
	oursTook := time.Since(start)
	t.Logf("first answer on a new connection, %v one-way delay: TLS+TCP %v, p2pact %v",
		oneWay, tlsTook.Round(time.Millisecond), oursTook.Round(time.Millisecond))
	if oursTook >= tlsTook {
		t.Errorf("p2pact is not faster: %v vs %v", oursTook, tlsTook)
	}
}

// The network changes mid-conversation (new address and port): the session survives with no
// new handshake, where a TCP connection would break and reconnect.
func TestCompareNetworkChange(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, a, b, []byte("before the network change"), 5*time.Second)
	before := a.handshakes.Load() + b.handshakes.Load()
	if err := b.RebindUDP("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	echo(t, a, b, []byte("after the network change"), 5*time.Second)
	took := time.Since(start)
	after := a.handshakes.Load() + b.handshakes.Load()
	t.Logf("network change: %d new handshakes, first answer after %v", after-before, took.Round(time.Millisecond))
	if after != before {
		t.Errorf("a new handshake was needed")
	}
}
