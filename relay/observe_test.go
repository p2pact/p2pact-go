package relay

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func observeServer(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go NewServer().ServeUDP(pc)
	c, err := net.DialUDP("udp", nil, pc.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func observeReq(nonce byte) []byte {
	b := make([]byte, observeReqLen)
	b[0] = observeType
	for i := 1; i <= 16; i++ {
		b[i] = nonce
	}
	return b
}

// read returns the next datagram, nil after wait.
func read(c *net.UDPConn, wait time.Duration) []byte {
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(wait))
	n, err := c.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// The reply carries the nonce and the address the request came from, and is never longer
// than the request.
func TestObserveReply(t *testing.T) {
	c := observeServer(t)
	if _, err := c.Write(observeReq(7)); err != nil {
		t.Fatal(err)
	}
	got := read(c, 2*time.Second)
	if len(got) != observeReplyLen || got[0] != observeType {
		t.Fatalf("reply %x", got)
	}
	if !bytes.Equal(got[1:17], observeReq(7)[1:17]) {
		t.Fatalf("nonce %x", got[1:17])
	}
	me := c.LocalAddr().(*net.UDPAddr)
	ip := net.IP(got[17:33])
	if !bytes.Equal(got[17:29], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}) || !ip.Equal(me.IP) {
		t.Fatalf("ip %v (%x), want %v as IPv4-mapped", ip, got[17:33], me.IP)
	}
	if port := binary.BigEndian.Uint16(got[33:35]); int(port) != me.Port {
		t.Fatalf("port %d, want %d", port, me.Port)
	}
}

// Short datagrams (a reply among them) and other types are not answered.
func TestObserveIgnores(t *testing.T) {
	c := observeServer(t)
	other := observeReq(1)
	other[0] = 6
	for _, b := range [][]byte{observeReq(1)[:observeReqLen-1], observeReq(1)[:observeReplyLen], other, {observeType}} {
		if _, err := c.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if got := read(c, 300*time.Millisecond); got != nil {
		t.Fatalf("answered %x", got)
	}
	// a longer request is fine: only the first 36 bytes count
	if _, err := c.Write(append(observeReq(2), 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if got := read(c, 2*time.Second); len(got) != observeReplyLen {
		t.Fatalf("longer request: reply %x", got)
	}
}

// More than observeRate requests a second from one IP: the excess is dropped.
func TestObserveRateLimit(t *testing.T) {
	c := observeServer(t)
	for i := 0; i < 3*observeRate; i++ {
		if _, err := c.Write(observeReq(byte(i))); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	for read(c, 300*time.Millisecond) != nil {
		got++
	}
	if got == 0 || got > observeRate {
		t.Fatalf("%d replies to %d requests in a burst (limit %d)", got, 3*observeRate, observeRate)
	}
	time.Sleep(1100 * time.Millisecond) // the next second
	if _, err := c.Write(observeReq(99)); err != nil {
		t.Fatal(err)
	}
	if read(c, 2*time.Second) == nil {
		t.Fatal("no reply in the next second")
	}
}
