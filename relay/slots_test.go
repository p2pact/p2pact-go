package relay

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	testSlot = "00112233445566778899aabbccddeeff"
	testTok  = "ffeeddccbbaa99887766554433221100"
	testTok2 = "0f0e0d0c0b0a09080706050403020100"
)

func TestSlotPutGetDel(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newSlots(func() time.Time { return now })
	if r := s.handle("1.1.1.1", slotReq{Op: "get", Slot: testSlot}); r.Error != "not found" {
		t.Fatalf("get of an empty slot: %+v", r)
	}
	if r := s.handle("1.1.1.1", slotReq{Op: "put", Slot: testSlot, Box: "abc", TTL: 60, Tok: testTok}); !r.OK {
		t.Fatalf("put: %+v", r)
	}
	if r := s.handle("2.2.2.2", slotReq{Op: "put", Slot: testSlot, Box: "xyz", TTL: 60, Tok: testTok2}); r.Error != "taken" {
		t.Fatalf("put over another's slot: %+v", r)
	}
	if r := s.handle("1.1.1.1", slotReq{Op: "put", Slot: testSlot, Box: "abd", TTL: 60, Tok: testTok}); !r.OK {
		t.Fatalf("put again with own tok: %+v", r)
	}
	if r := s.handle("2.2.2.2", slotReq{Op: "get", Slot: testSlot}); !r.OK || r.Box != "abd" {
		t.Fatalf("get: %+v", r)
	}
	// del with a wrong tok does nothing
	s.handle("2.2.2.2", slotReq{Op: "del", Slot: testSlot, Tok: testTok2})
	if r := s.handle("2.2.2.2", slotReq{Op: "get", Slot: testSlot}); !r.OK {
		t.Fatalf("slot gone after a foreign del: %+v", r)
	}
	s.handle("1.1.1.1", slotReq{Op: "del", Slot: testSlot, Tok: testTok})
	if r := s.handle("2.2.2.2", slotReq{Op: "get", Slot: testSlot}); r.Error != "not found" {
		t.Fatalf("slot after del: %+v", r)
	}
}

func TestSlotExpiresAndBurns(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newSlots(func() time.Time { return now })
	s.handle("1.1.1.1", slotReq{Op: "put", Slot: testSlot, Box: "abc", TTL: 3600, Tok: testTok})
	now = now.Add(maxSlotTTL) // the ttl is capped
	if r := s.handle("2.2.2.2", slotReq{Op: "get", Slot: testSlot}); r.Error != "not found" {
		t.Fatalf("get after max ttl: %+v", r)
	}
	s.handle("1.1.1.1", slotReq{Op: "put", Slot: testSlot, Box: "abc", TTL: 60, Tok: testTok})
	for i := 0; i < maxSlotReads; i++ {
		if r := s.handle("2.2.2.2", slotReq{Op: "get", Slot: testSlot}); !r.OK {
			t.Fatalf("read %d: %+v", i, r)
		}
	}
	if r := s.handle("2.2.2.2", slotReq{Op: "get", Slot: testSlot}); r.Error != "not found" {
		t.Fatalf("read past the limit: %+v", r)
	}
}

func TestSlotRateLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	s := newSlots(func() time.Time { return now })
	for i := 0; i < getsPerMin; i++ {
		if r := s.handle("2001:db8::1", slotReq{Op: "get", Slot: testSlot}); r.Error != "not found" {
			t.Fatalf("get %d: %+v", i, r)
		}
	}
	// another address of the same /64 shares the limit
	if r := s.handle("2001:db8::2", slotReq{Op: "get", Slot: testSlot}); r.Error != "slow down" {
		t.Fatalf("over the limit: %+v", r)
	}
	if r := s.handle("2001:db9::1", slotReq{Op: "get", Slot: testSlot}); r.Error != "not found" {
		t.Fatalf("another network: %+v", r)
	}
	now = now.Add(time.Minute)
	if r := s.handle("2001:db8::2", slotReq{Op: "get", Slot: testSlot}); r.Error != "not found" {
		t.Fatalf("next minute: %+v", r)
	}
}

func TestSlotBadRequests(t *testing.T) {
	s := newSlots(time.Now)
	for _, r := range []slotReq{
		{Op: "get", Slot: "zz"},
		{Op: "put", Slot: testSlot, Box: "abc", Tok: "short"},
		{Op: "put", Slot: testSlot, Box: "not base64!", Tok: testTok},
		{Op: "put", Slot: testSlot, Box: strings.Repeat("a", maxBox+1), Tok: testTok},
		{Op: "nope", Slot: testSlot},
	} {
		if got := s.handle("1.1.1.1", r); got.Error != "bad request" {
			t.Fatalf("%+v: %+v", r, got)
		}
	}
}

// Over the wire: a slot request is answered once and the connection closes; channels still work.
func TestSlotOverTLS(t *testing.T) {
	srv := NewServer()
	cert, err := LoadOrMakeCert(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}}))
	ask := func(line string) (string, bool) {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.Write([]byte(line + "\n"))
		r := bufio.NewReader(c)
		ans, _ := r.ReadString('\n')
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = r.ReadByte()
		return ans, err != nil && !isTimeout(err)
	}
	if a, closed := ask(`{"relay":1,"op":"put","slot":"` + testSlot + `","box":"abc","ttl":60,"tok":"` + testTok + `"}`); a != `{"ok":true}`+"\n" || !closed {
		t.Fatalf("put: %q closed=%v", a, closed)
	}
	if a, _ := ask(`{"relay":1,"op":"get","slot":"` + testSlot + `"}`); a != `{"ok":true,"box":"abc"}`+"\n" {
		t.Fatalf("get: %q", a)
	}
	if a, _ := ask(`{"relay":1,"channel":"` + testSlot + `","role":"a"}`); a != `{"ok":true}`+"\n" {
		t.Fatalf("channel hello: %q", a)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
