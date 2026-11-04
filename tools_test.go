package p2pact

import (
	"context"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestValidToolName(t *testing.T) {
	for name, want := range map[string]bool{"com.example.jira": true, "org.a-b.c1": true, "jira": false, "": false,
		"Com.example": false, "com..x": false, "p2pact.chat": false, "com.-x": false} {
		if ValidToolName(name) != want {
			t.Errorf("%q: want %v", name, want)
		}
	}
}

// A name gets a number of the device's own, from 64 up, not one a tool already has; the same name
// on another device may have another number, and callers resolve it by name.
func TestNamedToolsNumberedPerDevice(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil) // both have the echo at 64
	defer a.Close()
	defer b.Close()
	reg := func(n *Node, name string) {
		num, err := n.RegisterTool(name, 3)
		if err != nil || num < FirstNamedTool || num == 64 {
			t.Fatalf("%s: %d %v", name, num, err)
		}
		if again, _ := n.RegisterTool(name, 3); again != num {
			t.Fatalf("the number changed: %d -> %d", num, again)
		}
		who := n.Name
		if err := n.HandleTool(name, 1, func(string, []cbor.RawMessage) ([]any, error) { return []any{who + ":" + name}, nil }); err != nil {
			t.Fatal(err)
		}
	}
	reg(a, "com.acme.one")
	reg(a, "com.acme.two")
	reg(b, "com.acme.two")
	reg(b, "com.acme.one")
	if _, err := a.RegisterTool("jira", 1); err == nil {
		t.Fatal("a bad name was taken")
	}
	if _, err := a.RegisterTool("p2pact.chat", 1); err == nil {
		t.Fatal("a name of the spec was taken")
	}
	pair(t, a, b)
	eventually(t, "hellos", func() bool {
		_, x := a.ToolNumber(b.ID.Addr(), "com.acme.one")
		_, y := b.ToolNumber(a.ID.Addr(), "com.acme.one")
		return x && y
	})
	na, _ := a.ToolNumber(b.ID.Addr(), "com.acme.one") // b's number
	nb, _ := b.ToolNumber(a.ID.Addr(), "com.acme.one") // a's number
	if na == nb {
		t.Fatalf("the numbers should differ per device: %d %d", na, nb)
	}
	if n1, _ := a.ToolNumber(b.ID.Addr(), "p2pact.chat"); n1 != 1 {
		t.Fatalf("a tool of the spec: %d", n1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, c := range []struct {
		from, to *Node
		name     string
	}{{a, b, "com.acme.one"}, {a, b, "com.acme.two"}, {b, a, "com.acme.one"}} {
		res, err := c.from.CallTool(ctx, c.to.ID.Addr(), c.name, 1)
		var s string
		if err != nil || len(res) != 1 || cbor.Unmarshal(res[0], &s) != nil || s != c.to.Name+":"+c.name {
			t.Fatalf("%s -> %s %s: %q %v", c.from.Name, c.to.Name, c.name, s, err)
		}
	}
	if got := a.PeerToolName(b.ID.Addr(), na); got != "com.acme.one" {
		t.Fatalf("name by number: %q", got)
	}
	if _, err := a.CallTool(ctx, b.ID.Addr(), "com.acme.none", 1); err == nil {
		t.Fatal("an unannounced tool was called")
	}
	// a tool registered after the session is up reaches the other side at once
	if _, err := a.RegisterTool("com.acme.late", 1); err != nil {
		t.Fatal(err)
	}
	eventually(t, "late tool", func() bool { _, ok := b.ToolNumber(a.ID.Addr(), "com.acme.late"); return ok })
}

// A hello without the named map (an older device) names nothing; its numbered tools work as before.
func TestNamedToolsOldHello(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Old", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	hello, _ := cbor.Marshal([]any{3, 0, 2, "Old", "linux", "old-impl", map[int]int{64: 1}, [][]byte{}, toWire(Hints{})})
	a.mu.Lock()
	a.messageLocked(b.ID.Addr(), hello, 0)
	a.mu.Unlock()
	if _, ok := a.ToolNumber(b.ID.Addr(), "com.acme.one"); ok {
		t.Fatal("an old hello named a tool")
	}
	echo(t, a, b, []byte("numbered"), 5*time.Second)
}

// A hosted tool: one handler for all methods, the node requires read, the handler decides the
// rest; the tool leaves the hello when unregistered; PeerTools lists what a device announced.
func TestHandleToolAll(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	err := a.HandleToolAll("com.acme.host", func(_ string, level, method int, _ []cbor.RawMessage) ([]any, error) {
		if method >= 10 && level < LevelWrite {
			return nil, &Error{Code: ErrForbidden, Text: "read only"}
		}
		return []any{method}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pair(t, a, b)
	eventually(t, "hello", func() bool { _, ok := b.ToolNumber(a.ID.Addr(), "com.acme.host"); return ok })
	if got := b.PeerTools(a.ID.Addr()); len(got) != 1 || got[0] != "com.acme.host" {
		t.Fatalf("PeerTools: %v", got)
	}
	if err := a.SetGrants(b.ID.Addr(), []Grant{{"com.acme.host", LevelRead}}); err != nil {
		t.Fatal(err)
	}
	call := func(m int) error {
		_, err := b.CallTool(ctx5(t), a.ID.Addr(), "com.acme.host", m)
		return err
	}
	if err := call(3); err != nil {
		t.Errorf("read method: %v", err)
	}
	if callCode(call(12)) != ErrForbidden {
		t.Error("write method at read")
	}
	_ = a.SetGrants(b.ID.Addr(), []Grant{{"com.acme.host", LevelWrite}})
	if err := call(12); err != nil {
		t.Errorf("write method: %v", err)
	}
	_ = a.SetGrants(b.ID.Addr(), []Grant{})
	if callCode(call(3)) != ErrForbidden {
		t.Error("no grant")
	}
	a.UnregisterTool("com.acme.host")
	eventually(t, "gone from hello", func() bool { return len(b.PeerTools(a.ID.Addr())) == 0 })
}

// A tool of the spec served by the application: "p2pact.term" with one handler under its fixed
// number 5, announced in {tool: version}; the node checks read, the handler the rest; it leaves
// the hello when taken back; its name stays the spec's (RegisterTool refuses it).
func TestFixedToolServedByApp(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	if num, ok := FixedTool("p2pact.term"); !ok || num != 5 {
		t.Fatalf("p2pact.term: %d %v", num, ok)
	}
	if _, err := a.RegisterTool("p2pact.term", 1); err == nil {
		t.Fatal("a name of the spec was registered as a named tool")
	}
	pair(t, a, b)
	addr, me := a.ID.Addr(), b.ID.Addr()
	err := a.HandleToolAll("p2pact.term", func(_ string, level, method int, _ []cbor.RawMessage) ([]any, error) {
		if method != 1 && level < LevelWrite {
			return nil, &Error{Code: ErrForbidden, Text: "read only"}
		}
		return []any{"term", method}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "term in the hello", func() bool { return b.PeerHasTool(addr, "p2pact.term") })
	if got := b.PeerTools(addr); len(got) != 0 {
		t.Fatalf("a tool of the spec went into the named map: %v", got)
	}
	if num, called, ok := b.ResolveTool(addr, "p2pact.term"); !ok || num != 5 || called != "p2pact.term" {
		t.Fatalf("resolve: %d %q %v", num, called, ok)
	}
	call := func(m int) error {
		res, err := b.CallTool(ctx5(t), addr, "p2pact.term", m)
		var s string
		if err == nil && (len(res) != 2 || cbor.Unmarshal(res[0], &s) != nil || s != "term") {
			t.Fatalf("result %v", res)
		}
		return err
	}
	if err := call(1); err != nil {
		t.Fatal(err)
	}
	_ = a.SetGrants(me, []Grant{{"p2pact.term", LevelRead}})
	if err := call(1); err != nil {
		t.Errorf("read: %v", err)
	}
	if callCode(call(2)) != ErrForbidden {
		t.Error("write at read")
	}
	_ = a.SetGrants(me, []Grant{{"p2pact.chat", LevelWrite}})
	if callCode(call(1)) != ErrForbidden {
		t.Error("no grant on term")
	}
	a.UnregisterTool("p2pact.term")
	eventually(t, "term gone from the hello", func() bool { return !b.PeerHasTool(addr, "p2pact.term") })
}

// An alias (spec §8.1): one tool under the spec's name and a former one. Grants on either name
// count for both — the highest level wins — for calls and for events; each name answers under
// its own number.
func TestAliasRights(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	if err := a.AliasTool("p2pact.chat", "p2pact.term"); err == nil {
		t.Fatal("a name of the spec taken as an alias")
	}
	if err := a.AliasTool("com.example.term", "com.example.term"); err == nil {
		t.Fatal("a tool its own alias")
	}
	if err := a.AliasTool("com.example.term", "p2pact.term"); err != nil {
		t.Fatal(err)
	}
	served := func(name string) ToolHandler {
		return func(_ string, level, method int, _ []cbor.RawMessage) ([]any, error) {
			if method != 1 && level < LevelWrite {
				return nil, &Error{Code: ErrForbidden, Text: "read only"}
			}
			return []any{name}, nil
		}
	}
	if err := a.HandleToolAll("p2pact.term", served("p2pact.term")); err != nil {
		t.Fatal(err)
	}
	if err := a.HandleToolAll("com.example.term", served("com.example.term")); err != nil {
		t.Fatal(err)
	}
	events := make(chan int, 8)
	b.mu.Lock()
	b.OnEvent = func(_ string, tool, _ int, _ []cbor.RawMessage) { events <- tool }
	b.mu.Unlock()
	pair(t, a, b)
	addr, me := a.ID.Addr(), b.ID.Addr()
	eventually(t, "both names", func() bool {
		return b.PeerHasTool(addr, "p2pact.term") && b.PeerHasTool(addr, "com.example.term")
	})
	alias, _ := b.ToolNumber(addr, "com.example.term")
	call := func(name string, m int) error {
		res, err := b.CallTool(ctx5(t), addr, name, m)
		var s string
		if err == nil && (len(res) != 1 || cbor.Unmarshal(res[0], &s) != nil || s != name) {
			t.Fatalf("%s answered %q", name, s)
		}
		return err
	}
	for _, c := range []struct {
		grants []Grant
		level  int
	}{
		{[]Grant{{"com.example.term", LevelWrite}}, LevelWrite},
		{[]Grant{{"p2pact.term", LevelWrite}}, LevelWrite},
		{[]Grant{{"p2pact.term", LevelRead}, {"com.example.term", LevelWrite}}, LevelWrite},
		{[]Grant{{"com.example.term", LevelRead}}, LevelRead},
		{[]Grant{{"p2pact.chat", LevelWrite}}, 0},
	} {
		_ = a.SetGrants(me, c.grants)
		for _, name := range []string{"p2pact.term", "com.example.term"} {
			if got := a.Level(me, name); got != c.level {
				t.Fatalf("%v: level on %s %d, want %d", c.grants, name, got, c.level)
			}
			if err := call(name, 1); (err == nil) != (c.level >= LevelRead) {
				t.Fatalf("%v: read on %s: %v", c.grants, name, err)
			}
			if err := call(name, 2); (err == nil) != (c.level >= LevelWrite) {
				t.Fatalf("%v: write on %s: %v", c.grants, name, err)
			}
		}
		// events of either number reach a device with read on either name
		_ = a.Event(me, 5, 3)
		_ = a.Event(me, alias, 3)
		var got []int
		for wait := time.After(time.Second); len(got) < 2; {
			select {
			case tool := <-events:
				got = append(got, tool)
				continue
			case <-wait:
			}
			break
		}
		if want := c.level >= LevelRead; (len(got) == 2) != want || (want && (got[0] != 5 || got[1] != alias)) {
			t.Fatalf("%v: events %v", c.grants, got)
		}
	}
}

// A device that knows the terminal only by its former name and one that serves p2pact.term
// talk both ways: a new caller reaches the old device by the alias, an old caller reaches the
// new device by the former name with grants on p2pact.term, a new one goes to 5.
func TestAliasOldAndNewDevices(t *testing.T) {
	old, nw, phone := node(t, "Old", true, nil), node(t, "New", true, nil), node(t, "Phone", true, nil)
	defer old.Close()
	defer nw.Close()
	defer phone.Close()
	answer := func(who string) ToolHandler {
		return func(string, int, int, []cbor.RawMessage) ([]any, error) { return []any{who}, nil }
	}
	if err := old.HandleToolAll("com.example.term", answer("old")); err != nil { // before p2pact.term
		t.Fatal(err)
	}
	if err := nw.AliasTool("com.example.term", "p2pact.term"); err != nil {
		t.Fatal(err)
	}
	if err := nw.HandleToolAll("p2pact.term", answer("new:5")); err != nil {
		t.Fatal(err)
	}
	if err := nw.HandleToolAll("com.example.term", answer("new:alias")); err != nil {
		t.Fatal(err)
	}
	if err := phone.AliasTool("com.example.term", "p2pact.term"); err != nil { // a new caller
		t.Fatal(err)
	}
	pair(t, nw, old)
	pair(t, phone, old)
	pair(t, phone, nw)
	oldAddr, nwAddr, phoneAddr := old.ID.Addr(), nw.ID.Addr(), phone.ID.Addr()
	eventually(t, "hellos", func() bool {
		return phone.PeerHasTool(oldAddr, "com.example.term") && phone.PeerHasTool(nwAddr, "p2pact.term") &&
			old.PeerHasTool(nwAddr, "com.example.term") && nw.PeerHasTool(oldAddr, "com.example.term")
	})
	if phone.PeerHasTool(oldAddr, "p2pact.term") {
		t.Fatal("the old device announced 5")
	}
	if num, called, ok := phone.ResolveTool(oldAddr, "p2pact.term"); !ok || num < FirstNamedTool || called != "com.example.term" {
		t.Fatalf("new -> old: %d %q %v", num, called, ok)
	}
	if num, called, ok := phone.ResolveTool(nwAddr, "p2pact.term"); !ok || num != 5 || called != "p2pact.term" {
		t.Fatalf("new -> new: %d %q %v", num, called, ok)
	}
	if num, called, ok := phone.ResolveTool(nwAddr, "com.example.term"); !ok || num < FirstNamedTool || called != "com.example.term" {
		t.Fatalf("by the alias itself: %d %q %v", num, called, ok)
	}
	_ = nw.SetGrants(oldAddr, []Grant{{"p2pact.term", LevelWrite}}) // an old caller, granted the new name
	for _, c := range []struct {
		from     *Node
		to, name string
		want     string
	}{
		{phone, oldAddr, "p2pact.term", "old"},
		{phone, nwAddr, "p2pact.term", "new:5"},
		{nw, oldAddr, "p2pact.term", "old"},
		{old, nwAddr, "com.example.term", "new:alias"},
	} {
		res, err := c.from.CallTool(ctx5(t), c.to, c.name, 1)
		var s string
		if err != nil || len(res) != 1 || cbor.Unmarshal(res[0], &s) != nil || s != c.want {
			t.Fatalf("%s -> %s %s: %q %v", c.from.Name, c.to, c.name, s, err)
		}
	}
	// without the alias declared, the old device has no p2pact.term to a caller
	if _, err := old.CallTool(ctx5(t), phoneAddr, "com.example.none", 1); callCode(err) != ErrNoMethod {
		t.Fatalf("unknown tool: %v", err)
	}
}
