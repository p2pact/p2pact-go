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
