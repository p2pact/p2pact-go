package p2pact

import (
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func setKind(n *Node, kind int) {
	n.mu.Lock()
	n.Kind = kind
	n.mu.Unlock()
}

// eventually polls until cond holds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; !cond(); i++ {
		if i > 500 {
			t.Fatalf("timeout: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The kind goes in the pairing payload and the hello, and is stored in trust on both sides.
func TestKindInPairingAndHello(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	setKind(a, KindComputer)
	setKind(b, KindClient)
	pair(t, a, b)
	eventually(t, "kinds in trust", func() bool {
		pa, pb := a.Trust.Get(b.ID.Addr()), b.Trust.Get(a.ID.Addr())
		return pa != nil && pb != nil && pa.Kind == KindClient && pb.Kind == KindComputer
	})
	// a later change of kind arrives with the next hello
	setKind(b, KindPlugin)
	a.mu.Lock()
	b.mu.Lock()
	b.sendInfoLocked(a.ID.Addr())
	b.mu.Unlock()
	a.mu.Unlock()
	eventually(t, "kind from a new hello", func() bool { return a.Trust.Get(b.ID.Addr()).Kind == KindPlugin })
}

// Older devices send a payload and a hello without the kind: they keep working, kind 0.
func TestKindOldPeer(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Old", true, nil)
	defer a.Close()
	defer b.Close()
	old, _ := cbor.Marshal([]any{"Old", uint32(7), toWire(Hints{UDP: []string{"1.2.3.4:5"}}), []byte{1}, "linux"})
	if pi := parsePair(old); pi.Name != "Old" || pi.Boot != 7 || pi.OS != "linux" || pi.Kind != KindUnknown || len(pi.Hints.UDP) != 1 {
		t.Fatalf("old payload: %+v", pi)
	}
	// a newer payload with fields we do not know yet is read too
	newer, _ := cbor.Marshal([]any{"New", uint32(7), toWire(Hints{}), []byte{1}, "linux", KindClient, []any{[]any{"*", 1}}, "future"})
	if pi := parsePair(newer); pi.Kind != KindClient || pi.Name != "New" {
		t.Fatalf("newer payload: %+v", pi)
	}
	// a node that does not say its kind sends the old payload
	var pl []cbor.RawMessage
	a.mu.Lock()
	b2 := a.pairPayloadLocked(nil)
	a.mu.Unlock()
	if cbor.Unmarshal(b2, &pl) != nil || len(pl) != 5 {
		t.Fatalf("a device with no kind sends %d fields", len(pl))
	}
	setKind(b, KindClient)
	pair(t, a, b)
	eventually(t, "kind", func() bool { return a.Trust.Get(b.ID.Addr()).Kind == KindClient })
	// an old hello (six fields, no kind) changes nothing but the usual
	hello, _ := cbor.Marshal([]any{3, 0, 2, "Old", "linux", "old-impl", map[int]int{}, [][]byte{}, toWire(Hints{})})
	a.mu.Lock()
	a.messageLocked(b.ID.Addr(), hello, 0)
	a.mu.Unlock()
	if p := a.Trust.Get(b.ID.Addr()); p.Name != "Old" || p.Kind != KindClient {
		t.Fatalf("after an old hello: %+v", p)
	}
	echo(t, a, b, []byte("still works"), 5*time.Second)
}
