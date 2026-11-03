package p2pact

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func callCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return -1
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestGrantLevel(t *testing.T) {
	g := []Grant{{"com.a.x", LevelRead}, {"com.a.y", LevelWrite}}
	for tool, want := range map[string]int{"com.a.x": 1, "com.a.y": 2, "com.a.z": 0, "": 0} {
		if got := GrantLevel(g, tool); got != want {
			t.Errorf("%q: %d want %d", tool, got, want)
		}
	}
	if GrantLevel(nil, "any") != LevelWrite || GrantLevel([]Grant{}, "any") != 0 {
		t.Error("nil is the default, an empty list grants nothing")
	}
	if GrantLevel([]Grant{{AllTools, LevelRead}, {"com.a.x", LevelWrite}}, "com.a.x") != LevelWrite {
		t.Error("the highest entry wins")
	}
}

// Devices whose grants were never set (every device paired before grants) use everything.
func TestGrantsDefault(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	if g := a.Grants(b.ID.Addr()); !reflect.DeepEqual(g, DefaultGrants()) {
		t.Fatalf("default grants: %v", g)
	}
	echo(t, b, a, []byte("as before"), 5*time.Second)
	// a trust file from before grants has no such field
	dir := t.TempDir()
	var list []map[string]any
	for _, p := range a.Trust.List() {
		b, _ := json.Marshal(p)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		delete(m, "grants")
		delete(m, "granted")
		list = append(list, m)
	}
	raw, _ := json.Marshal(list)
	if err := os.WriteFile(filepath.Join(dir, "net-peers.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if p := LoadTrust(dir).Get(b.ID.Addr()); p == nil || p.Grants != nil || !reflect.DeepEqual(p.Allowed(), DefaultGrants()) {
		t.Fatalf("old trust file: %+v", p)
	}
}

func TestGrantsPersist(t *testing.T) {
	dir := t.TempDir()
	a, b := nodeIn(t, dir, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	want := []Grant{{"com.a.x", LevelRead}}
	if err := a.SetGrants(b.ID.Addr(), want); err != nil {
		t.Fatal(err)
	}
	if got := LoadTrust(dir).Get(b.ID.Addr()).Allowed(); !reflect.DeepEqual(got, want) {
		t.Fatalf("saved: %v", got)
	}
	if err := a.RevokeGrants(b.ID.Addr()); err != nil {
		t.Fatal(err)
	}
	if p := LoadTrust(dir).Get(b.ID.Addr()); p.Grants == nil || len(p.Allowed()) != 0 {
		t.Fatalf("revoked grants come back as the default: %+v", p.Grants)
	}
	if err := a.SetGrants("nobody", want); err == nil {
		t.Fatal("grants for a stranger")
	}
}

// A call outside the grants is error 4; read methods need read, the rest write; tool 0 is always allowed.
func TestGrantsEnforced(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	ok := func(string, []cbor.RawMessage) ([]any, error) { return []any{"ok"}, nil }
	if err := a.HandleTool("com.acme.notes", 1, ok); err != nil { // write
		t.Fatal(err)
	}
	_ = a.HandleTool("com.acme.notes", 2, ok) // read
	_ = a.HandleTool("com.acme.mail", 1, ok)
	num, _ := a.RegisterTool("com.acme.notes", 1)
	a.MarkRead(num, 2)
	pair(t, a, b)
	addr, me := a.ID.Addr(), b.ID.Addr()
	call := func(tool string, method int) int {
		_, err := b.CallTool(ctx5(t), addr, tool, method)
		return callCode(err)
	}
	eventually(t, "hello", func() bool { _, ok := b.ToolNumber(addr, "com.acme.notes"); return ok })
	if call("com.acme.notes", 1) != 0 || call("com.acme.mail", 1) != 0 {
		t.Fatal("the default does not allow everything")
	}
	if err := a.SetGrants(me, []Grant{{"com.acme.notes", LevelRead}}); err != nil {
		t.Fatal(err)
	}
	if c := call("com.acme.notes", 2); c != 0 {
		t.Errorf("read method at read: %d", c)
	}
	if c := call("com.acme.notes", 1); c != ErrForbidden {
		t.Errorf("write method at read: %d", c)
	}
	if c := call("com.acme.mail", 1); c != ErrForbidden {
		t.Errorf("a tool outside the grants: %d", c)
	}
	if _, err := b.Call(ctx5(t), addr, 64, 1, []byte("x")); callCode(err) != ErrForbidden { // the echo has no name
		t.Errorf("an unnamed tool without *: %v", err)
	}
	if _, err := b.Call(ctx5(t), addr, 0, 1); err != nil {
		t.Errorf("ping: %v", err)
	}
	if err := a.Grant(me, "com.acme.notes", LevelWrite); err != nil {
		t.Fatal(err)
	}
	if c := call("com.acme.notes", 1); c != 0 {
		t.Errorf("write after widening: %d", c)
	}
	if err := a.RevokeGrants(me); err != nil {
		t.Fatal(err)
	}
	if c := call("com.acme.notes", 2); c != ErrForbidden {
		t.Errorf("after revoking: %d", c)
	}
	if err := a.SetGrants(me, []Grant{{AllTools, LevelRead}}); err != nil {
		t.Fatal(err)
	}
	if c, d := call("com.acme.mail", 1), call("com.acme.notes", 2); c != ErrForbidden || d != 0 {
		t.Errorf("* at read: %d %d", c, d)
	}
}

// A tool whose one method carries many checks the level itself.
func TestGrantsLevelHandler(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	a.HandleLevel(1, 1, func(_ string, level int, args []cbor.RawMessage) ([]any, error) {
		var m string
		_ = cbor.Unmarshal(args[0], &m)
		if m != "session/list" && level < LevelWrite {
			return nil, &Error{Code: ErrForbidden, Text: "read only"}
		}
		return []any{m}, nil
	})
	pair(t, a, b)
	if err := a.SetGrants(b.ID.Addr(), []Grant{{"p2pact.chat", LevelRead}}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Call(ctx5(t), a.ID.Addr(), 1, 1, "session/list"); err != nil {
		t.Errorf("read: %v", err)
	}
	if _, err := b.Call(ctx5(t), a.ID.Addr(), 1, 1, "session/prompt"); callCode(err) != ErrForbidden {
		t.Errorf("write at read: %v", err)
	}
	_ = a.SetGrants(b.ID.Addr(), []Grant{{"p2pact.chat", LevelWrite}})
	if _, err := b.Call(ctx5(t), a.ID.Addr(), 1, 1, "session/prompt"); err != nil {
		t.Errorf("write: %v", err)
	}
	_ = a.SetGrants(b.ID.Addr(), []Grant{})
	if _, err := b.Call(ctx5(t), a.ID.Addr(), 1, 1, "session/list"); callCode(err) != ErrForbidden {
		t.Errorf("no grant: %v", err)
	}
}

// Events of a tool go only to devices with at least read on it; the device is told its grants (0.6).
func TestGrantsEventsAndTell(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	events := make(chan string, 8)
	told := make(chan []Grant, 8)
	b.mu.Lock()
	b.OnEvent = func(_ string, tool, ev int, args []cbor.RawMessage) {
		var s string
		_ = cbor.Unmarshal(args[0], &s)
		events <- s
	}
	b.OnGranted = func(_ string, g []Grant) { told <- g }
	b.mu.Unlock()
	if _, err := a.RegisterTool("com.acme.feed", 1); err != nil {
		t.Fatal(err)
	}
	num := a.names["com.acme.feed"]
	pair(t, a, b)
	addr, me := a.ID.Addr(), b.ID.Addr()
	expect := func(want string) {
		t.Helper()
		select {
		case s := <-events:
			if s != want {
				t.Fatalf("event %q, want %q", s, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no event %q", want)
		}
	}
	_ = a.Event(me, num, 1, "everyone")
	expect("everyone")
	_ = a.SetGrants(me, []Grant{{"com.acme.other", LevelWrite}})
	select {
	case g := <-told:
		if !reflect.DeepEqual(g, []Grant{{"com.acme.other", LevelWrite}}) {
			t.Fatalf("told %v", g)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("event 0.6 did not arrive")
	}
	if got := b.GrantedBy(addr); !reflect.DeepEqual(got, []Grant{{"com.acme.other", LevelWrite}}) {
		t.Fatalf("granted by: %v", got)
	}
	_ = a.Event(me, num, 1, "hidden") // no read: not sent
	time.Sleep(300 * time.Millisecond)
	_ = a.Grant(me, "com.acme.feed", LevelRead)
	_ = a.Event(me, num, 1, "visible")
	expect("visible") // "hidden" never came
	// method 0.6: what the caller may use
	res, err := b.Call(ctx5(t), addr, 0, 6)
	if err != nil || len(res) != 1 {
		t.Fatalf("0.6: %v %d", err, len(res))
	}
	if g, _ := parseGrants(res[0]); !reflect.DeepEqual(g, []Grant{{"com.acme.other", LevelWrite}, {"com.acme.feed", LevelRead}}) {
		t.Fatalf("0.6 returned %v", g)
	}
}
