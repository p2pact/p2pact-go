package p2pact

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/klauspost/compress/dict"
)

// testDict trains a dictionary on chat-like phrases.
func testDict(t *testing.T, seed int) []byte {
	t.Helper()
	phrases := []string{"let's do it", "do the messages go through the server or not?", "why is it so slow",
		"run the tests and commit", "the agent finished the task", "messages do not reach the phone",
		"Done. Tests pass, changes are in the repository.", "Checked the logs: a delivery bug, fixed."}
	var in [][]byte
	for i := range 400 {
		in = append(in, fmt.Appendf(nil, "%s %d — %s, %s", phrases[(i+seed)%len(phrases)], i, phrases[(i*3)%len(phrases)], phrases[(i*5+seed)%len(phrases)]))
	}
	raw, err := dict.BuildZstdDict(in, dict.Options{MaxDictSize: 8 << 10, HashBytes: 6})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var longText = []byte("do the messages go through the server or not? run the tests and commit, the agent finished the task")

// Compress and back, with and without a dictionary; the zstd magic and dictionary id are not sent.
func TestCompressRoundTrip(t *testing.T) {
	d, err := NewDict(testDict(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, dd := range []*Dict{d, nil} {
		slot := 0
		if dd != nil {
			slot = 3
		}
		z := compress(longText, dd, slot)
		if z == nil || int(z[0]) != slot {
			t.Fatalf("dictionary %v: not compressed", dd != nil)
		}
		got, err := decompress(z, dd)
		if err != nil || !bytes.Equal(got, longText) {
			t.Fatalf("dictionary %v: wrong result: %v", dd != nil, err)
		}
		t.Logf("dictionary %v: %d → %d bytes", dd != nil, len(longText), len(z))
	}
	if z := compress(longText, d, 1); len(z) >= len(compress(longText, nil, 0)) {
		t.Fatal("with a dictionary it must be shorter than without")
	}
	if compress([]byte("short"), d, 1) != nil {
		t.Fatal("messages under 64 bytes are not compressed")
	}
	if _, err := decompress(compress(longText, d, 1), nil); err == nil {
		t.Fatal("decompression without the right dictionary must fail")
	}
}

// The newest dictionary both sides have is picked; the slot is in our own list.
func TestDictPick(t *testing.T) {
	s := loadDicts(t.TempDir())
	old, _ := NewDict(testDict(t, 0))
	fresh, _ := NewDict(testDict(t, 1))
	for _, d := range []*Dict{old, fresh} {
		if err := s.add(d); err != nil {
			t.Fatal(err)
		}
	}
	if d, slot := s.pick([][]byte{old.ID, fresh.ID}, nil); d != fresh || slot != 1 {
		t.Fatalf("newest common is fresh in slot 1, got slot %d", slot)
	}
	if d, slot := s.pick([][]byte{old.ID}, nil); d != old || slot != 2 {
		t.Fatalf("the other has only old, slot 2, got %d", slot)
	}
	if d, slot := s.pick(nil, nil); d != nil || slot != 0 {
		t.Fatal("nothing in common: no dictionary")
	}
	if d, _ := s.pick([][]byte{old.ID, fresh.ID}, [][]byte{fresh.ID}); d != old {
		t.Fatal("do not use a dictionary the other side lost")
	}
	again := loadDicts(s.dir[:len(s.dir)-len("/net-dicts")])
	if len(again.dicts) != 2 || !bytes.Equal(again.dicts[0].ID, fresh.ID) {
		t.Fatal("dictionaries and their order were not saved")
	}
}

// waitDicts waits until a knows b's dictionary list.
func waitDicts(t *testing.T, a, b *Node, want int) {
	t.Helper()
	for i := 0; ; i++ {
		a.mu.Lock()
		ps := a.peers[b.ID.Addr()]
		got := ps != nil && len(ps.dicts) == want
		a.mu.Unlock()
		if got {
			return
		}
		if i > 300 {
			t.Fatalf("%s did not learn the dictionaries of %s", a.Name, b.Name)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A dictionary added after pairing is announced, and messages go compressed.
func TestCompressedCall(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Laptop", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	raw := testDict(t, 0)
	for _, n := range []*Node{a, b} {
		if err := n.AddDict(raw); err != nil {
			t.Fatal(err)
		}
	}
	waitDicts(t, a, b, 1)
	waitDicts(t, b, a, 1)
	echo(t, a, b, longText, 5*time.Second)
	echo(t, b, a, bytes.Repeat(longText, 50), 5*time.Second) // long: in parts
}

// The receiver lacks the dictionary a message is compressed with: it asks the sender and runs
// the message without losing anything.
func TestMissingDictFetched(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Laptop", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	raw := testDict(t, 0)
	_ = a.AddDict(raw)
	_ = b.AddDict(raw)
	waitDicts(t, a, b, 1)
	waitDicts(t, b, a, 1)
	b.mu.Lock()
	b.dicts.dicts = nil // b lost the dictionary and a does not know
	b.mu.Unlock()
	for range 3 {
		echo(t, a, b, longText, 10*time.Second)
	}
	if len(b.Dicts()) != 1 || !bytes.Equal(b.Dicts()[0], DictID(raw)) {
		t.Fatal("b should have got the dictionary from a")
	}
}
