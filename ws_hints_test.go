package p2pact

import (
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// The ws hint is a fourth element of the hints; without it the wire form is the old three.
func TestWSHints(t *testing.T) {
	h := Hints{UDP: []string{"1.2.3.4:5"}, Relay: &RelayHint{Addr: "r:1", FP: "ab"}, WS: []string{"wss://r.example/"}}
	b, err := cbor.Marshal(toWire(h))
	if err != nil {
		t.Fatal(err)
	}
	var raw []any
	if err := cbor.Unmarshal(b, &raw); err != nil || len(raw) != 4 {
		t.Fatalf("want 4 elements, got %v (%v)", raw, err)
	}
	var w hintsWire
	if err := cbor.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	if got := fromWire(w); !reflect.DeepEqual(got, h) {
		t.Fatalf("roundtrip: %+v != %+v", got, h)
	}

	// no ws: three elements, as older devices write and read
	b, _ = cbor.Marshal(toWire(Hints{UDP: []string{"1.2.3.4:5"}}))
	raw = nil
	if err := cbor.Unmarshal(b, &raw); err != nil || len(raw) != 3 {
		t.Fatalf("want 3 elements, got %v (%v)", raw, err)
	}
	// an old three-element array and an empty hints array decode
	old, _ := cbor.Marshal([]any{[]string{"1.2.3.4:5"}, []string{"r:1", "ab"}, []string{"1.2.3.4:6"}})
	w = hintsWire{}
	if err := cbor.Unmarshal(old, &w); err != nil || fromWire(w).Relay == nil || len(w.WS) != 0 {
		t.Fatalf("old hints: %+v %v", w, err)
	}
	// a future fifth element is ignored
	fut, _ := cbor.Marshal([]any{nil, nil, nil, []string{"ws://x/"}, "later"})
	w = hintsWire{}
	if err := cbor.Unmarshal(fut, &w); err != nil || len(w.WS) != 1 {
		t.Fatalf("future hints: %+v %v", w, err)
	}
}

// An invite carries the ws hint, and pairing keeps it in trust.
func TestWSHintsInInvite(t *testing.T) {
	inv := &Invite{Key: make([]byte, 32), Name: "A", Secret: make([]byte, 32), Exp: time.Now().Add(time.Minute), Hints: Hints{WS: []string{"wss://r.example/"}}}
	got, err := ParseInvite(inv.String())
	if err != nil || !reflect.DeepEqual(got.Hints.WS, inv.Hints.WS) {
		t.Fatalf("invite: %+v %v", got, err)
	}
}

// A road the application declares direct ranks with TCP, above a relay; others stay below.
func TestAppRoadRank(t *testing.T) {
	plain := &AttachedRoad{cfg: AppRoadConfig{Name: "ble"}}
	direct := &AttachedRoad{cfg: AppRoadConfig{Name: "webrtc", Direct: true}}
	relay := &RelayRoad{hint: RelayHint{Addr: "r:1"}}
	if !(roadRank(direct) < roadRank(relay) && roadRank(relay) < roadRank(plain)) {
		t.Fatalf("ranks: direct %d relay %d app %d", roadRank(direct), roadRank(relay), roadRank(plain))
	}
}

// SetRelayWS puts the relay's WebSocket URLs into our invites and hellos.
func TestSetRelayWS(t *testing.T) {
	a := node(t, "Mac", false, nil)
	defer a.Close()
	a.SetRelay(RelayHint{Addr: "r.example:8443", FP: "ab"})
	a.SetRelayWS("wss://r.example/")
	inv, err := ParseInvite(a.Invite(time.Minute).String())
	if err != nil || !reflect.DeepEqual(inv.Hints.WS, []string{"wss://r.example/"}) || inv.Hints.Relay == nil {
		t.Fatalf("invite hints: %+v %v", inv, err)
	}
}
