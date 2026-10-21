package p2pact

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func chatLine(i int) []byte {
	words := []string{"the agent", "finished", "the task", "run the tests", "and commit", "messages do not reach",
		"the phone", "why is it so slow", "checked the logs", "a delivery bug", "fixed it", "pushed to the branch"}
	var b bytes.Buffer
	fmt.Fprintf(&b, "step %d: ", i)
	for j := range 12 {
		b.WriteString(words[(i*7+j*j)%len(words)])
		b.WriteString(", ")
	}
	return b.Bytes()
}

// waitFor polls cond under the node's lock.
func waitFor(t *testing.T, n *Node, what string, cond func() bool) {
	t.Helper()
	for i := 0; ; i++ {
		n.mu.Lock()
		ok := cond()
		n.mu.Unlock()
		if ok {
			return
		}
		if i > 1000 {
			t.Fatal(what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A device trains its own dictionary for the device it talks to; that device fetches it, and
// then messages go compressed with it. A third device neither sees nor gets it, from either.
func TestOwnDictionary(t *testing.T) {
	a, b, c := node(t, "Mac", true, nil), node(t, "Phone", true, nil), node(t, "Laptop", true, nil)
	defer a.Close()
	defer b.Close()
	defer c.Close()
	pair(t, a, b)
	pair(t, a, c)
	pair(t, b, c)
	for i := range 300 {
		echo(t, a, b, chatLine(i), 5*time.Second)
	}
	var own *Dict
	waitFor(t, a, "a did not train a dictionary for b", func() bool { own = a.dicts.own(b.ID.Addr()); return own != nil })
	waitFor(t, a, "b did not take a's dictionary", func() bool {
		ps := a.peers[b.ID.Addr()]
		d, _ := a.dicts.pick(b.ID.Addr(), ps.dicts, ps.lacks)
		return d == own
	})
	echo(t, a, b, chatLine(1000), 5*time.Second)
	if z, plain := compress(chatLine(1000), own, 1), compress(chatLine(1000), nil, 0); len(z) >= len(plain) {
		t.Fatalf("own dictionary: %d bytes, without: %d", len(z), len(plain))
	}

	for _, x := range c.Dicts(a.ID.Addr()) {
		if bytes.Equal(x, own.ID) {
			t.Fatal("c sees a's dictionary for b")
		}
	}
	for _, x := range a.Dicts(c.ID.Addr()) {
		if bytes.Equal(x, own.ID) {
			t.Fatal("a lists its dictionary for b to c")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, from := range []*Node{a, b} {
		if _, err := c.Call(ctx, from.ID.Addr(), 0, 5, own.ID); err == nil {
			t.Fatalf("%s gave c the dictionary of a and b", from.Name)
		}
	}

	// it survives a restart: the history and the dictionary are on disk
	var ownSize int
	waitFor(t, a, "the history was not written", func() bool {
		h := a.peers[b.ID.Addr()].hist
		ownSize = h.ownSize
		return !h.flushing
	})
	again := loadDicts(a.dir)
	if d := again.own(b.ID.Addr()); d == nil || !bytes.Equal(d.ID, own.ID) {
		t.Fatal("the own dictionary was not saved")
	}
	n2 := &Node{dir: a.dir, dicts: again}
	if h := n2.historyLocked(&peerState{addr: b.ID.Addr()}); h.ownSize != ownSize || h.heardSize == 0 {
		t.Fatalf("history after restart: %d sent of %d, %d received", h.ownSize, ownSize, h.heardSize)
	}
}

// The trainer finds the repeated content: a dictionary from it compresses new lines better than
// none, and it is a valid zstd dictionary.
func TestTrainDict(t *testing.T) {
	var train, test [][]byte
	for i := range 400 {
		train = append(train, chatLine(i))
	}
	for i := 400; i < 450; i++ {
		test = append(test, chatLine(i))
	}
	raw, err := trainDict(train, test, 8<<10)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDict(raw)
	if err != nil {
		t.Fatal(err)
	}
	with, without := 0, 0
	for _, m := range test {
		z := compress(m, d, 1)
		got, err := decompress(z, d)
		if err != nil || !bytes.Equal(got, m) {
			t.Fatal("round trip failed")
		}
		with += len(z)
		without += len(compress(m, nil, 0))
	}
	t.Logf("%d lines: %d bytes with the dictionary, %d without", len(test), with, without)
	if with*2 > without {
		t.Fatal("the dictionary should at least halve these lines")
	}
}

// A dictionary keeps its slot while listed: a message compressed with it may arrive after the
// new list, on another stream. A dropped one leaves a free slot; new ones go to the end.
func TestDictSlotsStay(t *testing.T) {
	s := loadDicts(t.TempDir())
	var ds []*Dict
	for i := range 6 {
		d, _ := NewDict(testDict(t, i))
		d.peer, d.own = "b", true
		ds = append(ds, d)
	}
	_ = s.add(ds[0])
	_ = s.add(ds[1])
	first := s.ids("b")
	_ = s.add(ds[2])
	if got := s.ids("b"); !bytes.Equal(got[0], first[0]) || !bytes.Equal(got[1], first[1]) || !bytes.Equal(got[2], ds[2].ID) {
		t.Fatal("a new dictionary moved the others")
	}
	for _, d := range ds[3:] { // 6 own ones: the 2 oldest are dropped (4 kept)
		_ = s.add(d)
	}
	got := s.ids("b")
	if len(got) != 6 || len(got[0]) != 0 || len(got[1]) != 0 || !bytes.Equal(got[5], ds[5].ID) {
		t.Fatalf("dropped ones should leave free slots: %x", got)
	}
	if _, slot := s.pick("b", [][]byte{ds[5].ID}, nil); slot != 6 {
		t.Fatalf("the newest is in slot 6, got %d", slot)
	}
	if ids := s.ids("c"); len(ids) != 0 {
		t.Fatal("another device sees b's dictionaries")
	}
}

// A damaged line in the order file never makes a pair's dictionary a common one.
func TestDictOrderDamaged(t *testing.T) {
	dir := t.TempDir()
	s := loadDicts(dir)
	d, _ := NewDict(testDict(t, 0))
	d.peer, d.own = "b", true
	_ = s.add(d)
	_ = os.WriteFile(filepath.Join(s.dir, "order"), []byte(hexs(d.ID)+" b\n"), 0o600)
	if again := loadDicts(dir); len(again.ids("c")) != 0 {
		t.Fatal("a damaged line made b's dictionary visible to c")
	}
}

// Forgetting a device drops the pair's dictionaries and history.
func TestForgetDropsDicts(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	for i := range 300 {
		echo(t, a, b, chatLine(i), 5*time.Second)
	}
	waitFor(t, a, "a did not train a dictionary for b", func() bool {
		h := a.peers[b.ID.Addr()].hist
		return a.dicts.own(b.ID.Addr()) != nil && !h.flushing
	})
	a.Forget(b.ID.Addr())
	if a.dicts.own(b.ID.Addr()) != nil {
		t.Fatal("the dictionary for b is still there")
	}
	if _, err := os.Stat(historyPath(a.dir, b.ID.Addr())); err == nil {
		t.Fatal("the history with b is still there")
	}
}

// Training waits for a lull: while the conversation goes on, no dictionary is trained; once it
// pauses, one is.
func TestTrainInLull(t *testing.T) {
	lull, wait := learnLull, learnWait
	learnLull, learnWait = 1500*time.Millisecond, time.Hour
	defer func() { learnLull, learnWait = lull, wait }()
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	until := time.Now().Add(4 * time.Second)
	for i := 0; time.Now().Before(until); i++ { // 32 KB in the first second, then on and on
		echo(t, a, b, chatLine(i), 5*time.Second)
		if i > 250 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	a.mu.Lock()
	own := a.dicts.own(b.ID.Addr())
	a.mu.Unlock()
	if own != nil {
		t.Fatal("a trained in the middle of the conversation")
	}
	waitFor(t, a, "a did not train in the lull", func() bool { return a.dicts.own(b.ID.Addr()) != nil })
}
