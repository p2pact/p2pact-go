package client

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go"
)

// fixture reads a reference message (contract/tools of the engine repository, copied to
// testdata) as a JSON tree.
func fixture(t testing.TB, dir, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile("testdata/" + dir + "/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v map[string]any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func fixtureExists(dir, name string) bool {
	_, err := os.Stat("testdata/" + dir + "/" + name + ".json")
	return err == nil
}

// fixtureParams is the `params` of a request fixture.
func fixtureParams(t testing.TB, dir, name string) any {
	t.Helper()
	p, _ := fixture(t, dir, name)["params"].(map[string]any)
	if p == nil {
		p = map[string]any{}
	}
	return norm(p)
}

// norm makes a JSON tree comparable: numbers are float64, whatever they were.
func norm(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }

type seenCall struct {
	tool   int
	method string
	params map[string]any
	level  int
}

var (
	chatRead    = set("initialize", "session/list", "session/load", "_p2pact/older", "_p2pact/commands", "_p2pact/files", "_p2pact/history", "_p2pact/projects", "_p2pact/agents", "_p2pact/image", "_p2pact/diff")
	fleetRead   = set("fleet/hello", "node/get", "session/list", "session/get", "session/messages", "fleet/watch", "fleet/unwatch")
	pluginsRead = set("plugins/list", "plugins/log", "plugins/grants")
)

func set(s ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range s {
		m[x] = true
	}
	return m
}

// fakeEngine is a computer built from the library alone: it serves tools 1, 2 and 4 and a
// hosted tool, and answers with the messages of the contract fixtures.
type fakeEngine struct {
	t    *testing.T
	node *p2pact.Node

	mu   sync.Mutex
	seen []seenCall
	// decide is what the person grants a newcomer that asked for wants; by default what it asked.
	decide func([]p2pact.Grant) []p2pact.Grant
	// overrides answer a method ("1:session/list") in place of the fixture.
	overrides map[string]func(map[string]any) map[string]any

	fromClient chan map[string]any
	paired     chan string
	watchers   chan bool
	clientAddr string
}

func newFakeEngine(t *testing.T) *fakeEngine {
	t.Helper()
	n, err := p2pact.NewNode(t.TempDir(), "MacBook Pro")
	if err != nil {
		t.Fatal(err)
	}
	e := &fakeEngine{t: t, node: n, decide: func(w []p2pact.Grant) []p2pact.Grant { return w },
		overrides:  map[string]func(map[string]any) map[string]any{},
		fromClient: make(chan map[string]any, 16), paired: make(chan string, 4), watchers: make(chan bool, 16)}
	n.Kind = p2pact.KindComputer
	if err := n.ListenUDP("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	n.OnWants = func(_ p2pact.Peer, wants []p2pact.Grant) ([]p2pact.Grant, bool) {
		e.mu.Lock()
		d := e.decide
		e.mu.Unlock()
		return d(wants), true
	}
	n.OnPaired = func(p p2pact.Peer) {
		e.mu.Lock()
		e.clientAddr = p.Addr
		e.mu.Unlock()
		e.paired <- p.Addr
	}
	n.OnEvent = func(_ string, tool, ev int, args []cbor.RawMessage) {
		if tool == 1 && ev == 1 && len(args) > 0 {
			var m map[string]any
			_ = json.Unmarshal(toJSON(args[0]), &m)
			e.fromClient <- m
		}
	}
	n.HandleLevel(1, 1, func(_ string, level int, args []cbor.RawMessage) ([]any, error) {
		return e.rpc(1, level, args, chatRead)
	})
	n.HandleLevel(2, 1, func(_ string, level int, args []cbor.RawMessage) ([]any, error) {
		return e.rpc(2, level, args, fleetRead)
	})
	n.HandleLevel(4, 1, func(_ string, level int, args []cbor.RawMessage) ([]any, error) {
		return e.rpc(4, level, args, pluginsRead)
	})
	if err := n.HandleTool("com.example.hello", 1, func(_ string, args []cbor.RawMessage) ([]any, error) {
		var name string
		_ = cbor.Unmarshal(args[0], &name)
		return []any{"hello " + name}, nil
	}); err != nil {
		t.Fatal(err)
	}
	n.Start()
	t.Cleanup(n.Close)
	return e
}

func (e *fakeEngine) invite() string { return e.node.Invite(time.Minute).String() }

func (e *fakeEngine) addr() string {
	e.t.Helper()
	select {
	case a := <-e.paired:
		e.paired <- a
		return a
	case <-time.After(10 * time.Second):
		e.t.Fatal("the engine saw no pairing")
		return ""
	}
}

func (e *fakeEngine) calls() []seenCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]seenCall(nil), e.seen...)
}

func (e *fakeEngine) methods() []string {
	var out []string
	for _, s := range e.calls() {
		out = append(out, s.method)
	}
	return out
}

func (e *fakeEngine) last(tool int, method string) (seenCall, bool) {
	c := e.calls()
	for i := len(c) - 1; i >= 0; i-- {
		if c[i].tool == tool && c[i].method == method {
			return c[i], true
		}
	}
	return seenCall{}, false
}

func (e *fakeEngine) rpc(tool, level int, args []cbor.RawMessage, reads map[string]bool) ([]any, error) {
	var req struct {
		Method string         `json:"method"`
		Params map[string]any `json:"params"`
	}
	if len(args) == 0 || json.Unmarshal(toJSON(args[0]), &req) != nil || req.Method == "" {
		return nil, &p2pact.Error{Code: p2pact.ErrBadArgs, Text: "no request"}
	}
	if req.Params == nil {
		req.Params = map[string]any{}
	}
	e.mu.Lock()
	e.seen = append(e.seen, seenCall{tool, req.Method, req.Params, level})
	ov := e.overrides[strings.Join([]string{string(rune('0' + tool)), req.Method}, ":")]
	e.mu.Unlock()
	// one P2PACT method carries all of the tool: the level is checked on the JSON-RPC method (chat spec §6)
	if !reads[req.Method] && level < p2pact.LevelWrite {
		return nil, &p2pact.Error{Code: p2pact.ErrForbidden, Text: "forbidden"}
	}
	var resp map[string]any
	switch {
	case ov != nil:
		resp = ov(req.Params)
	case tool == 1:
		resp = e.chat(req.Method)
	case tool == 2:
		resp = e.fleet(req.Method, req.Params)
	default:
		resp = e.plugins(req.Method)
	}
	return []any{wire(resp)}, nil
}

func (e *fakeEngine) chat(method string) map[string]any {
	if method == "session/load" {
		for _, n := range []string{"session.update.user_message", "session.update.agent_message", "session.update.tool_call"} {
			e.notify(1, fixture(e.t, "p2pact.chat", n+".notification"))
		}
		return map[string]any{"jsonrpc": "2.0", "result": map[string]any{"_meta": map[string]any{"p2pact": map[string]any{"older": true}}}}
	}
	stem := strings.ReplaceAll(method, "/", ".")
	if fixtureExists("p2pact.chat", stem+".response") {
		return fixture(e.t, "p2pact.chat", stem+".response")
	}
	return map[string]any{"jsonrpc": "2.0", "result": map[string]any{}}
}

func (e *fakeEngine) fleet(method string, params map[string]any) map[string]any {
	stem := ""
	switch method {
	case "fleet/hello":
		stem = "hello"
	case "session/list":
		stem = "session-list"
	case "session/get":
		stem = "session-get"
	case "session/messages":
		stem = "session-messages"
	case "fleet/watch":
		p, _ := params["partial"].(bool)
		e.watchers <- p
		stem = "watch"
	case "fleet/unwatch":
		stem = "unwatch"
	case "session/create":
		stem = "session-create"
	case "session/send":
		stem = "session-send"
		if params["id"] == "нет" {
			stem = "session-send-unknown"
		}
	case "settings/set":
		stem = "settings-set"
	case "node/get":
		hello := asMap(fixture(e.t, "p2pact.fleet", "hello.response")["result"])
		return map[string]any{"jsonrpc": "2.0", "result": hello["node"]}
	}
	if stem != "" {
		return fixture(e.t, "p2pact.fleet", stem+".response")
	}
	return map[string]any{"jsonrpc": "2.0", "result": map[string]any{"ok": true}}
}

func (e *fakeEngine) plugins(method string) map[string]any {
	stem := strings.ReplaceAll(method, "/", ".")
	if fixtureExists("p2pact.plugins", stem+".response") {
		return fixture(e.t, "p2pact.plugins", stem+".response")
	}
	return map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": -32601, "message": "no method " + method}}
}

// notify sends a JSON-RPC notification as the tool's event, on the stream of its session or id.
func (e *fakeEngine) notify(tool int, msg map[string]any) {
	p := asMap(msg["params"])
	id, _ := p["sessionId"].(string)
	if id == "" {
		id, _ = p["id"].(string)
	}
	e.mu.Lock()
	addr := e.clientAddr
	e.mu.Unlock()
	if addr == "" {
		addr = e.addr()
	}
	if err := e.node.EventOn(addr, StreamOf(id), tool, 1, wire(msg)); err != nil {
		e.t.Fatal(err)
	}
}

// ask makes a request of the client, as the agent device does (permissions, questions).
func (e *fakeEngine) ask(tool int, msg map[string]any, sessionID string) <-chan map[string]any {
	out := make(chan map[string]any, 1)
	addr := e.addr()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, err := e.node.CallOn(ctx, addr, StreamOf(sessionID), tool, 1, wire(msg))
		if err != nil || len(res) == 0 {
			out <- map[string]any{"transport_error": err}
			return
		}
		var m map[string]any
		_ = json.Unmarshal(toJSON(res[0]), &m)
		out <- m
	}()
	return out
}

// --- the application's side ---

type env struct {
	t        *testing.T
	engine   *fakeEngine
	client   *Client
	computer *Computer
}

func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	end := time.Now().Add(10 * time.Second)
	for time.Now().Before(end) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", what)
}

func ctx5(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// connect starts the engine and the client, pairs with wants and waits until the computer's
// hello came and it told the grants.
func connect(t *testing.T, wants []p2pact.Grant, decide func([]p2pact.Grant) []p2pact.Grant) *env {
	t.Helper()
	if wants == nil {
		wants = DefaultWants
	}
	e := newFakeEngine(t)
	if decide != nil {
		e.decide = decide
	}
	c, err := New(t.TempDir(), "Test app", &Config{UDP: "127.0.0.1:0", NoTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	comp, err := c.Pair(ctx5(t), e.invite(), wants)
	if err != nil {
		t.Fatal(err)
	}
	if err := comp.WhenOnline(ctx5(t)); err != nil {
		t.Fatal(err)
	}
	// wait for the first 0.6: until it comes a newcomer that asked may use nothing
	want := e.decide(wants)
	eventually(t, "grants told", func() bool { return reflect.DeepEqual(comp.Grants(), want) })
	return &env{t, e, c, comp}
}

// next waits for a value on a channel.
func next[T any](t testing.TB, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("no event within 10 s")
		panic("unreachable")
	}
}

func (v *env) assertSent(tool int, method, dir, name string) {
	v.t.Helper()
	s, ok := v.engine.last(tool, method)
	if !ok {
		v.t.Fatalf("%s was not called", method)
	}
	if want := fixtureParams(v.t, dir, name); !reflect.DeepEqual(want, norm(s.params)) {
		v.t.Fatalf("%s: sent %v, fixture %v", method, norm(s.params), want)
	}
}

func cborString(raw cbor.RawMessage, s *string) error { return cbor.Unmarshal(raw, s) }
