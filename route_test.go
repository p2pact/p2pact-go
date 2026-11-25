package p2pact

import (
	"bytes"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestScreenToolNumber(t *testing.T) {
	if num, ok := FixedTool("p2pact.screen"); !ok || num != 6 {
		t.Fatalf("p2pact.screen: %d %v", num, ok)
	}
}

// A Raw event goes as it is: compressible bytes are not shrunk, nothing is queued for the
// dictionary's history, and the receiver gets the bytes intact. The same event without Raw is
// compressed.
func TestEventRawNotCompressed(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	got := make(chan []byte, 4)
	b.mu.Lock()
	b.OnEvent = func(_ string, _, _ int, args []cbor.RawMessage) {
		var d []byte
		_ = cbor.Unmarshal(args[0], &d)
		got <- d
	}
	b.mu.Unlock()
	data := bytes.Repeat([]byte("frame-"), 20000) // 120 KB, zstd takes it to almost nothing
	send := func(o SendOpts) (int64, []byte) {
		before := a.UDP().Stats().SentBytes
		if err := a.EventOpts(b.ID.Addr(), 77, 64, 1, o, data); err != nil {
			t.Fatal(err)
		}
		select {
		case d := <-got:
			return a.UDP().Stats().SentBytes - before, d
		case <-time.After(5 * time.Second):
			t.Fatal("the event did not arrive")
		}
		return 0, nil
	}
	rawBytes, d := send(SendOpts{Raw: true})
	if !bytes.Equal(d, data) {
		t.Fatal("raw bytes changed on the way")
	}
	a.mu.Lock()
	queued := a.peers[b.ID.Addr()].queued
	a.mu.Unlock()
	if queued != 0 {
		t.Errorf("a raw event went into the learning queue: %d", queued)
	}
	zipBytes, d := send(SendOpts{})
	if !bytes.Equal(d, data) {
		t.Fatal("compressed bytes changed on the way")
	}
	if rawBytes < int64(len(data)) || zipBytes*4 > rawBytes {
		t.Errorf("raw sent %d bytes, compressed %d for %d: raw is not raw, or the control is not compressed", rawBytes, zipBytes, len(data))
	}
}

func TestRoadKind(t *testing.T) {
	udp := &UDPRoad{}
	for addr, want := range map[string]string{
		"127.0.0.1:5000": "lan", "192.168.1.5:1": "lan", "10.0.0.2:1": "lan", "172.16.4.4:1": "lan",
		"169.254.1.1:1": "lan", "[::1]:1": "lan", "[fd00::1]:1": "lan", "[fe80::1]:1": "lan",
		"100.64.0.7:1": "direct", "100.127.255.1:1": "direct", "8.8.8.8:1": "direct", "[2001:db8::1]:1": "direct",
	} {
		if got := roadKind(Endpoint{Road: udp, Addr: addr}); got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
	rel := &RelayRoad{hint: RelayHint{Addr: "relay.example:1"}}
	if got := roadKind(Endpoint{Road: rel, Addr: "ab"}); got != "relay" {
		t.Errorf("relay: %s", got)
	}
	if got := roadKind(Endpoint{Road: &AttachedRoad{cfg: AppRoadConfig{Name: "ble"}}}); got != "app" {
		t.Errorf("app: %s", got)
	}
	if got := roadKind(Endpoint{Road: &AttachedRoad{cfg: AppRoadConfig{Name: "rtc", Direct: true}}}); got != "direct" {
		t.Errorf("app direct: %s", got)
	}
	if got := roadKind(Endpoint{Road: &viaRoad{x: "x"}}); got != "via" {
		t.Errorf("via: %s", got)
	}
}

// Route on two nodes of one machine is "lan" with a round trip and an MTU; OnRoute tells
// when the kind appears; Backlog counts what waits behind the window and ProbeNow is harmless.
func TestRouteBacklogOnRoute(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	if r := a.Route("nobody"); r.Kind != "" {
		t.Fatalf("a stranger has a road: %+v", r)
	}
	if p, by := a.Backlog("nobody"); p != 0 || by != 0 {
		t.Fatal("a stranger has a backlog")
	}
	seen := make(chan RouteInfo, 8)
	a.OnRoute(func(peer string, r RouteInfo) {
		if peer == b.ID.Addr() {
			seen <- r
		}
	})
	pair(t, a, b)
	echo(t, a, b, []byte("hi"), 5*time.Second)
	eventually(t, "lan road", func() bool { return a.Route(b.ID.Addr()).Kind == "lan" })
	r := a.Route(b.ID.Addr())
	if r.MTU != MaxPacket {
		t.Errorf("MTU %d", r.MTU)
	}
	select {
	case r := <-seen:
		if r.Kind != "lan" {
			t.Errorf("OnRoute told %q", r.Kind)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnRoute did not tell")
	}
	a.ProbeNow(b.ID.Addr())
	a.ProbeNow("nobody")
	// stop the pump by pausing, then queue: everything waits
	a.SetPaused(true)
	_ = a.EventOpts(b.ID.Addr(), 5, 64, 1, SendOpts{Raw: true}, bytes.Repeat([]byte{7}, 5000))
	parts, bytes_ := a.Backlog(b.ID.Addr())
	if parts < 4 || bytes_ < 5000 {
		t.Errorf("backlog %d parts %d bytes", parts, bytes_)
	}
	a.SetPaused(false)
	eventually(t, "backlog drained", func() bool { p, _ := a.Backlog(b.ID.Addr()); return p == 0 })
}

// Unanswered is 0 while nothing waits for an acknowledgement or the device answers, and grows
// once the device is silent while data to it is unacknowledged.
func TestUnanswered(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	stopB := stopper(t, b)
	if d := a.Unanswered("nobody"); d != 0 {
		t.Fatalf("a stranger: %v", d)
	}
	pair(t, a, b)
	echo(t, a, b, []byte("hi"), 5*time.Second)
	for i := 0; i < 20; i++ {
		_ = a.EventOpts(b.ID.Addr(), 5, 64, 1, SendOpts{Raw: true}, bytes.Repeat([]byte{7}, 3000))
		time.Sleep(50 * time.Millisecond)
		if d := a.Unanswered(b.ID.Addr()); d > time.Second {
			t.Fatalf("a live device unanswered for %v", d)
		}
	}
	eventually(t, "all acknowledged", func() bool { p, _ := a.Backlog(b.ID.Addr()); return p == 0 && a.Unanswered(b.ID.Addr()) == 0 })
	stopB()
	_ = a.EventOpts(b.ID.Addr(), 5, 64, 1, SendOpts{Raw: true}, bytes.Repeat([]byte{7}, 3000))
	time.Sleep(1500 * time.Millisecond)
	if d := a.Unanswered(b.ID.Addr()); d < time.Second || d > 3*time.Second {
		t.Fatalf("a vanished device unanswered for %v, want about 1.5 s", d)
	}
}
