package client

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/p2pact/p2pact-go"
)

const fleetID = "0b7c2e64-1d2a-4f5e-9a10-6c3b8d7e9f01"

func TestFleetReadMethods(t *testing.T) {
	v := connect(t, nil, nil)
	f, ctx := v.computer.Fleet(), ctx5(t)
	hello, err := f.Hello(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hello.Protocol != "0.2" || hello.Node.Name != "MacBook Pro" || hello.Node.OS != "darwin" || len(hello.Node.Agents) != 1 || hello.Node.Agents[0].ID != "claude" {
		t.Fatalf("%+v", hello)
	}
	var status map[string]any
	_ = json.Unmarshal(hello.Node.Status, &status)
	if status["working"] != float64(1) {
		t.Fatalf("%s", hello.Node.Status)
	}
	if n, err := f.Node(ctx); err != nil || n.Name != "MacBook Pro" {
		t.Fatalf("%v %v", n, err)
	}

	list, err := f.Sessions(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	s := list[0]
	if s.ID != fleetID || s.Agent != "claude" || s.Dir != "/Users/me/app" || s.Phase != "working" || s.Title != "Починить вход" || s.Updated != "2026-10-27T10:00:00Z" {
		t.Fatalf("%+v", s)
	}
	var raw struct {
		Status struct{ Owner struct{ Node string } }
	}
	_ = json.Unmarshal(s.Raw, &raw)
	if raw.Status.Owner.Node != "3f2a9c01d4e5b6a7" {
		t.Fatalf("%s", s.Raw)
	}
	if got, err := f.Session(ctx, fleetID); err != nil || got.ID != fleetID {
		t.Fatalf("%v %v", got, err)
	}
	v.assertSent(2, "session/get", "p2pact.fleet", "session-get.request")

	after := int64(2)
	m, err := f.Messages(ctx, fleetID, &after, nil)
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(2, "session/messages", "p2pact.fleet", "session-messages.request")
	if m.Last != 3 || !m.Older || len(m.Messages) != 1 || m.Messages[0].Text != "Готово" || m.Messages[0].Role != "assistant" {
		t.Fatalf("%+v", m)
	}
}

func TestFleetWatchDeliversEventsInOrder(t *testing.T) {
	v := connect(t, nil, nil)
	f, ctx := v.computer.Fleet(), ctx5(t)
	events, cancel := f.Events.Chan()
	defer cancel()
	watch, err := f.Watch(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(2, "fleet/watch", "p2pact.fleet", "watch.request")
	if len(watch.Sessions) != 1 || watch.Sessions[0].ID != fleetID {
		t.Fatalf("%+v", watch.Sessions)
	}
	for _, n := range []string{"notify-session-changed", "notify-session-messages", "notify-notify"} {
		v.engine.notify(2, fixture(t, "p2pact.fleet", n))
	}
	// the three go on different streams (the messages ride their session's): the order is kept
	// within a stream only
	got := map[FleetEventType]FleetEvent{}
	var order []FleetEventType
	for range 3 {
		e := next(t, events)
		got[e.Type] = e
		order = append(order, e.Type)
	}
	if e := got[FleetSessionsChanged]; len(e.Sessions) != 1 || e.Sessions[0].Phase != "working" {
		t.Fatalf("%+v", e)
	}
	if e := got[FleetSessionMessages]; e.ID != fleetID || len(e.Messages) != 1 || e.Messages[0].Seq != 4 || e.Messages[0].Text != "Продолжай" {
		t.Fatalf("%+v", e)
	}
	if e := got[FleetNotify]; e.Text != "Агент ждёт ответа" {
		t.Fatalf("%+v", e)
	}
	idx := func(ty FleetEventType) int {
		for i, o := range order {
			if o == ty {
				return i
			}
		}
		return -1
	}
	if idx(FleetSessionsChanged) > idx(FleetNotify) {
		t.Fatalf("events of one stream out of order: %v", order)
	}
	v.engine.notify(2, map[string]any{"jsonrpc": "2.0", "method": "session/resync", "params": map[string]any{"id": fleetID}})
	if e := next(t, events); e.Type != FleetResync || e.ID != fleetID {
		t.Fatalf("%+v", e)
	}
	v.engine.notify(2, map[string]any{"jsonrpc": "2.0", "method": "something/new", "params": map[string]any{"k": 1}})
	if e := next(t, events); e.Type != FleetOther || e.Method != "something/new" {
		t.Fatalf("%+v", e)
	}
	if err := watch.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.engine.last(2, "fleet/unwatch"); !ok {
		t.Fatal("the unwatch did not reach the engine")
	}
}

func TestFleetWriteMethods(t *testing.T) {
	v := connect(t, nil, nil)
	f, ctx := v.computer.Fleet(), ctx5(t)
	s, err := f.Create(ctx, SessionSpec{Agent: "claude", Dir: "/Users/me/app", Perms: "ask"}, "Почини вход")
	if err != nil || s.Phase != "starting" {
		t.Fatalf("%v %+v", err, s)
	}
	v.assertSent(2, "session/create", "p2pact.fleet", "session-create.request")

	if err := f.Send(ctx, fleetID, "Продолжай"); err != nil {
		t.Fatal(err)
	}
	v.assertSent(2, "session/send", "p2pact.fleet", "session-send.request")

	err = f.Send(ctx, "нет", "?")
	var rpc *RPCError
	if !errors.As(err, &rpc) || !rpc.IsNoSuchResource() || rpc.Code != -32004 {
		t.Fatalf("%v", err)
	}

	got, err := f.SetSettings(ctx, map[string]any{"sleep_after": 15})
	if err != nil || !reflect.DeepEqual(norm(json.RawMessage(got)), map[string]any{"sleep_after": float64(15)}) {
		t.Fatalf("%v %s", err, got)
	}
	v.assertSent(2, "settings/set", "p2pact.fleet", "settings-set.request")

	if err := f.Answer(ctx, fleetID, "w1", map[string]string{"Q": "A"}, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := v.engine.last(2, "session/answer"); !reflect.DeepEqual(norm(c.params), map[string]any{"id": fleetID, "waitId": "w1", "answers": map[string]any{"Q": "A"}}) {
		t.Fatalf("%v", c.params)
	}
	if err := f.Interrupt(ctx, fleetID); err != nil {
		t.Fatal(err)
	}
	if r, err := f.Close(ctx, fleetID); err != nil || r.Warning != "" {
		t.Fatalf("%v %+v", err, r)
	}
	if err := f.SetKeep(ctx, fleetID, true); err != nil {
		t.Fatal(err)
	}
	if c, _ := v.engine.last(2, "session/setKeep"); !reflect.DeepEqual(norm(c.params), map[string]any{"id": fleetID, "on": true}) {
		t.Fatalf("%v", c.params)
	}
}

func TestFleetReadOnly(t *testing.T) {
	v := connect(t, nil, func([]p2pact.Grant) []p2pact.Grant { return []p2pact.Grant{{Tool: ToolFleet, Level: p2pact.LevelRead}} })
	f, ctx := v.computer.Fleet(), ctx5(t)
	if l, err := f.Sessions(ctx); err != nil || len(l) != 1 {
		t.Fatalf("%v %v", l, err)
	}
	for name, w := range map[string]func() error{
		"send":      func() error { return f.Send(ctx, fleetID, "x") },
		"create":    func() error { _, err := f.Create(ctx, SessionSpec{Agent: "claude"}, ""); return err },
		"interrupt": func() error { return f.Interrupt(ctx, fleetID) },
	} {
		if err := w(); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// no grant on the chat at all: even reading is refused
	if _, err := v.computer.Chat().ListSessions(ctx, "", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("%v", err)
	}
}

func TestPluginsListLogGrants(t *testing.T) {
	wants := append(append([]p2pact.Grant(nil), DefaultWants...), p2pact.Grant{Tool: "com.example.hello", Level: p2pact.LevelWrite})
	v := connect(t, wants, nil)
	p, ctx := v.computer.Plugins(), ctx5(t)
	list, err := p.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("%v %v", list, err)
	}
	i := list[0]
	if i.Name != "com.example.hello" || i.Status != PluginRunning || !i.Enabled || i.PID != 4242 ||
		!reflect.DeepEqual(i.Announced, []string{"com.example.hello"}) || !reflect.DeepEqual(i.Needs, []string{"p2pact.chat:read"}) {
		t.Fatalf("%+v", i)
	}
	if log, err := p.Log(ctx, "com.example.hello", 2); err != nil || log != "started\nready\n" {
		t.Fatalf("%v %q", err, log)
	}
	v.assertSent(4, "plugins/log", "p2pact.plugins", "plugins.log.request")

	g, err := p.Grants(ctx, "com.example.hello")
	if err != nil || !reflect.DeepEqual(g.Grants, []p2pact.Grant{{Tool: "p2pact.chat", Level: p2pact.LevelRead}}) || !reflect.DeepEqual(g.Read, map[string][]int{"com.example.hello": {2}}) {
		t.Fatalf("%v %+v", err, g)
	}
	// plugins are asked for with read only: writing needs the person to widen it
	if err := p.Enable(ctx, "com.example.hello"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("%v", err)
	}
}

func TestPluginsEnableDisableWithWrite(t *testing.T) {
	wants := []p2pact.Grant{{Tool: ToolChat, Level: p2pact.LevelWrite}, {Tool: ToolFleet, Level: p2pact.LevelWrite}, {Tool: ToolPlugins, Level: p2pact.LevelWrite}}
	v := connect(t, wants, nil)
	p, ctx := v.computer.Plugins(), ctx5(t)
	if err := p.Enable(ctx, "com.example.hello"); err != nil {
		t.Fatal(err)
	}
	v.assertSent(4, "plugins/enable", "p2pact.plugins", "plugins.enable.request")
	if err := p.Disable(ctx, "com.example.hello"); err != nil {
		t.Fatal(err)
	}
	v.assertSent(4, "plugins/disable", "p2pact.plugins", "plugins.disable.request")
}

func TestCallsPluginToolByName(t *testing.T) {
	wants := append(append([]p2pact.Grant(nil), DefaultWants...), p2pact.Grant{Tool: "com.example.hello", Level: p2pact.LevelWrite})
	v := connect(t, wants, nil)
	c, ctx := v.computer, ctx5(t)
	if n, ok := c.ToolNumber("com.example.hello"); !ok || n < p2pact.FirstNamedTool {
		t.Fatalf("a number from 64 up, the computer's own: %d %v", n, ok)
	}
	res, err := c.Plugins().CallTool(ctx, "com.example.hello", 1, "world")
	var s string
	if err != nil || len(res) != 1 || cborString(res[0], &s) != nil || s != "hello world" {
		t.Fatalf("%v %v", res, err)
	}
	// a tool the computer does not announce
	if _, err := c.Plugins().CallTool(ctx, "com.example.nothing", 1); !errors.Is(err, ErrNoMethod) {
		t.Fatalf("%v", err)
	}
}

func TestToolGrantIsNeeded(t *testing.T) {
	v := connect(t, nil, nil) // no grant on the hosted tool
	if _, err := v.computer.CallTool(ctx5(t), "com.example.hello", 1, "x"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("%v", err)
	}
}

func TestWaitUntilNotOnline(t *testing.T) {
	// WhenOnline honours the context
	v := connect(t, nil, nil)
	other := newComputer(v.client, "nobody")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := other.WhenOnline(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}
