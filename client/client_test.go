package client

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go"
)

func TestPairingGrantsAndState(t *testing.T) {
	v := connect(t, nil, nil)
	c := v.computer
	if got := v.client.Computers(); len(got) != 1 || got[0].ID() != c.ID() {
		t.Fatalf("computers: %v", got)
	}
	if c.Name() != "MacBook Pro" || c.State() != Online {
		t.Fatalf("%q %v", c.Name(), c.State())
	}
	if !reflect.DeepEqual(c.Grants(), DefaultWants) {
		t.Fatalf("grants %v", c.Grants())
	}
	if c.Level(ToolChat) != p2pact.LevelWrite || c.Level(ToolPlugins) != p2pact.LevelRead || c.CanWrite(ToolPlugins) {
		t.Fatal("levels")
	}
	// the engine knows us as a client
	if p := v.engine.node.Trust.Get(v.engine.addr()); p == nil || p.Kind != p2pact.KindClient {
		t.Fatalf("kind: %+v", p)
	}
}

func TestInitializeAndList(t *testing.T) {
	v := connect(t, nil, nil)
	chat, ctx := v.computer.Chat(), ctx5(t)
	info, err := chat.Initialize(ctx)
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(1, "initialize", "p2pact.chat", "initialize.request")
	if len(info.Agents) != 1 || info.Agents[0].ID != "claude" || info.Agents[0].Name != "Claude Code" || !info.LoadSession || !info.Extensions || info.AgentTitle != "MacBook Pro" {
		t.Fatalf("%+v", info)
	}
	list, err := chat.ListSessions(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(1, "session/list", "p2pact.chat", "session.list.request")
	s := list.Sessions[0]
	if len(list.Sessions) != 1 || s.ID != "s1" || s.CWD != "/w/proj" || s.Agent != "claude" || s.State != StateWorking || s.UpdatedAt != "2026-11-03T10:00:00Z" || list.NextCursor != "" {
		t.Fatalf("%+v", s)
	}
	var raw map[string]any
	_ = json.Unmarshal(s.Raw, &raw) // the raw JSON stays reachable
	if raw["sessionId"] != "s1" {
		t.Fatalf("raw: %s", s.Raw)
	}
	if got := chat.Sessions(); len(got) != 1 || got[0].ID != "s1" {
		t.Fatalf("known: %v", got)
	}
}

func TestCallsInitializeFirstByThemselves(t *testing.T) {
	v := connect(t, nil, nil)
	if _, err := v.computer.Chat().ListAllSessions(ctx5(t), ""); err != nil {
		t.Fatal(err)
	}
	if got := v.engine.methods(); !reflect.DeepEqual(got, []string{"initialize", "session/list"}) {
		t.Fatalf("%v", got)
	}
}

func TestNewPromptCancel(t *testing.T) {
	v := connect(t, nil, nil)
	chat, ctx := v.computer.Chat(), ctx5(t)
	created, err := chat.NewSession(ctx, NewSessionOptions{CWD: "/w/app", Agent: "codex", Model: "gpt-5", Text: "собери проект", Perms: "ask", MID: "n1"})
	if err != nil || created.SessionID != "nomad-1" {
		t.Fatalf("%v %+v", err, created)
	}
	v.assertSent(1, "session/new", "p2pact.chat", "session.new.request")

	res, err := chat.PromptBlocks(ctx, "s1", "m1", TextBlock("запусти тесты"))
	if err != nil || res.StopReason != "end_turn" || res.Duplicate {
		t.Fatalf("%v %+v", err, res)
	}
	v.assertSent(1, "session/prompt", "p2pact.chat", "session.prompt.request")

	if err := chat.Cancel("s1"); err != nil {
		t.Fatal(err)
	}
	n := next(t, v.engine.fromClient)
	if n["method"] != "session/cancel" || asMap(n["params"])["sessionId"] != "s1" {
		t.Fatalf("%v", n)
	}
}

func TestLoadGivesTheWholeHistory(t *testing.T) {
	v := connect(t, nil, nil)
	chat := v.computer.Chat()
	live, cancel := chat.Updates.Chan()
	defer cancel()
	loaded, err := chat.LoadSession(ctx5(t), "s1", "/w/proj")
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(1, "session/load", "p2pact.chat", "session.load.request")
	if !loaded.Older {
		t.Fatal("older")
	}
	// all three replayed messages are in the result, in order, though the answer may come first
	u := loaded.Updates
	if len(u) != 3 {
		t.Fatalf("%d updates", len(u))
	}
	if u[0].Type != UpdateUserMessage || u[0].Text() != "привет" || u[0].Seq != 1 {
		t.Fatalf("%+v", u[0])
	}
	if u[1].Type != UpdateAgentMessage || u[1].Text() != "Привет! Чем помочь?" || u[1].Seq != 2 || u[1].Time != "2026-11-03T10:00:01Z" {
		t.Fatalf("%+v", u[1])
	}
	if c := u[2].Call; u[2].Type != UpdateToolCall || c == nil || c.ID != "m3" || c.Title != "Bash: go test" || c.Kind != "execute" || c.Status != "completed" {
		t.Fatalf("%+v", u[2])
	}
	for range 3 { // and they went to the listeners too
		next(t, live)
	}
}

func TestLiveUpdatesAndChanges(t *testing.T) {
	v := connect(t, nil, nil)
	chat := v.computer.Chat()
	updates, c1 := chat.Updates.Chan()
	changes, c2 := chat.SessionChanges.Chan()
	defer c1()
	defer c2()
	v.engine.notify(1, fixture(t, "p2pact.chat", "session.update.agent_message.notification"))
	v.engine.notify(1, fixture(t, "p2pact.chat", "_p2pact.session_changed.notification"))
	u := next(t, updates)
	if u.Type != UpdateAgentMessage || u.SessionID != "s1" || u.Text() != "Привет! Чем помочь?" {
		t.Fatalf("%+v", u)
	}
	s := next(t, changes)
	if s.ID != "s1" || s.State != StateIdle || s.Agent != "claude" || s.Title != "proj" {
		t.Fatalf("%+v", s)
	}
	if got := chat.Sessions(); len(got) != 1 {
		t.Fatalf("%v", got)
	}
	// closing removes it from the known chats
	v.engine.notify(1, map[string]any{"jsonrpc": "2.0", "method": "_p2pact/session_changed",
		"params": map[string]any{"sessionId": "s1", "_meta": map[string]any{"p2pact": map[string]any{"state": "closed"}}}})
	if s := next(t, changes); s.State != StateClosed {
		t.Fatalf("%+v", s)
	}
	if len(chat.Sessions()) != 0 {
		t.Fatal("closed chat is still known")
	}
}

func TestUnknownUpdatesAreKeptRaw(t *testing.T) {
	v := connect(t, nil, nil)
	updates, cancel := v.computer.Chat().Updates.Chan()
	defer cancel()
	v.engine.notify(1, map[string]any{"jsonrpc": "2.0", "method": "session/update", "params": map[string]any{
		"sessionId": "s1", "update": map[string]any{"sessionUpdate": "brand_new", "x": 1, "extra": []any{"y"}}}})
	u := next(t, updates)
	var raw map[string]any
	_ = json.Unmarshal(u.Raw, &raw)
	if u.Type != "brand_new" || raw["x"] != float64(1) {
		t.Fatalf("%+v %s", u, u.Raw)
	}
}

func TestPermissionRequestAnswered(t *testing.T) {
	v := connect(t, nil, nil)
	seen := make(chan *PermissionRequest, 1)
	v.computer.Chat().SetPermissionHandler(func(_ context.Context, r *PermissionRequest) (PermissionOutcome, error) {
		seen <- r
		return r.Allow(), nil
	})
	res := <-v.engine.ask(1, fixture(t, "p2pact.chat", "session.request_permission.request"), "s1")
	if !reflect.DeepEqual(res, norm(fixture(t, "p2pact.chat", "session.request_permission.response"))) {
		t.Fatalf("%v", res)
	}
	r := next(t, seen)
	if r.ToolCall.Title != "Bash: rm -rf build" || len(r.Options) != 3 || r.Options[0].ID != "allow" || r.Options[2].ID != "deny" {
		t.Fatalf("%+v", r)
	}
	if got := r.Deny(); got.OptionID != "deny" || got.Cancelled {
		t.Fatalf("%+v", got)
	}
}

func TestQuestionAnswered(t *testing.T) {
	v := connect(t, nil, nil)
	v.computer.Chat().SetQuestionHandler(func(_ context.Context, q *QuestionRequest) (map[string]string, error) {
		if len(q.Questions) != 2 || q.Questions[0].Header != "База" || !q.Questions[1].Multi ||
			len(q.Questions[0].Options) != 2 || q.Questions[0].Options[0] != (QuestionOption{"Postgres", "основная"}) || q.Questions[0].Options[1].Label != "SQLite" {
			t.Errorf("%+v", q)
		}
		return map[string]string{"База?": "SQLite", "Что проверить?": JoinLabels("Тесты")}, nil
	})
	res := <-v.engine.ask(1, fixture(t, "p2pact.chat", "_p2pact.question.request"), "s1")
	if !reflect.DeepEqual(res, norm(fixture(t, "p2pact.chat", "_p2pact.question.response"))) {
		t.Fatalf("%v", res)
	}
}

func TestRequestAnsweredElsewhere(t *testing.T) {
	v := connect(t, nil, nil)
	chat := v.computer.Chat()
	type shown struct {
		r   *PermissionRequest
		ctx context.Context
	}
	ch := make(chan shown, 1)
	// the person never decides here
	chat.SetPermissionHandler(func(ctx context.Context, r *PermissionRequest) (PermissionOutcome, error) {
		ch <- shown{r, ctx}
		<-ctx.Done()
		return Cancelled, ctx.Err()
	})
	answered, cancel := chat.RequestAnswered.Chan()
	defer cancel()
	res := v.engine.ask(1, fixture(t, "p2pact.chat", "session.request_permission.request"), "s1")
	s := next(t, ch)
	v.engine.notify(1, fixture(t, "p2pact.chat", "_p2pact.request_answered.notification"))
	if a := next(t, answered); a.ToolCallID != "w1" {
		t.Fatalf("%+v", a)
	}
	select {
	case <-s.ctx.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the request was not ended")
	}
	// the call does not hang: the computer got an error answer
	if asMap(next(t, res)["error"]) == nil {
		t.Fatal("no error answer")
	}
}

func TestWithoutHandlerTheComputerHearsNoSuchMethod(t *testing.T) {
	v := connect(t, nil, nil)
	res := <-v.engine.ask(1, fixture(t, "p2pact.chat", "session.request_permission.request"), "s1")
	if asMap(res["error"])["code"] != float64(-32601) {
		t.Fatalf("%v", res)
	}
	fs := <-v.engine.ask(1, map[string]any{"jsonrpc": "2.0", "method": "fs/read_text_file", "params": map[string]any{"sessionId": "s1"}}, "s1")
	if asMap(fs["error"])["code"] != float64(-32601) {
		t.Fatalf("%v", fs)
	}
}

func TestExtensions(t *testing.T) {
	v := connect(t, nil, nil)
	chat, ctx := v.computer.Chat(), ctx5(t)
	if _, err := chat.Close(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	v.assertSent(1, "_p2pact/close", "p2pact.chat", "_p2pact.close.request")
	if _, err := chat.Restart(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := chat.Hide(ctx, "s1", true); err != nil {
		t.Fatal(err)
	}
	if s, _ := v.engine.last(1, "_p2pact/hide"); !reflect.DeepEqual(norm(s.params), norm(map[string]any{"sessionId": "s1", "on": true})) {
		t.Fatalf("%v", s.params)
	}

	page, err := chat.Older(ctx, "s1", 3)
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(1, "_p2pact/older", "p2pact.chat", "_p2pact.older.request")
	if len(page.Messages) != 1 || page.Messages[0].Seq != 1 || page.Messages[0].Role != "user" || page.Messages[0].Text != "привет" || page.More {
		t.Fatalf("%+v", page)
	}

	diff, err := chat.Diff(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(1, "_p2pact/diff", "p2pact.chat", "_p2pact.diff.request")
	if len(diff.Files) != 1 || diff.Files[0].Path != "a.go" || diff.Files[0].Added != 3 || diff.Patch != "diff --git a/a.go b/a.go\n" || diff.Truncated {
		t.Fatalf("%+v", diff)
	}

	img, err := chat.Image(ctx, "s1", "/w/proj/shot.png")
	if err != nil {
		t.Fatal(err)
	}
	v.assertSent(1, "_p2pact/image", "p2pact.chat", "_p2pact.image.request")
	if img.Error != "not_found" || img.Data != "" {
		t.Fatalf("%+v", img)
	}
}

func TestLateReports(t *testing.T) {
	v := connect(t, nil, nil)
	reports, cancel := v.computer.Chat().Reports.Chan()
	defer cancel()
	v.engine.notify(1, fixture(t, "p2pact.chat", "_p2pact.report.notification"))
	var l struct{ Cmd string }
	_ = json.Unmarshal(next(t, reports), &l)
	if l.Cmd != "diff_more" {
		t.Fatalf("%+v", l)
	}
}

func TestEventsSubscribeAndUnsubscribe(t *testing.T) {
	var e Events[int]
	got := make(chan int, 4)
	cancel := e.Subscribe(func(v int) { got <- v })
	e.Subscribe(func(int) { panic("a listener that panics is skipped") })
	e.emit(1)
	cancel()
	e.emit(2)
	if v := next(t, got); v != 1 {
		t.Fatal(v)
	}
	select {
	case v := <-got:
		t.Fatalf("after unsubscribe: %d", v)
	default:
	}
}

func TestReadOnlyGrantRefusesWrites(t *testing.T) {
	v := connect(t, nil, func([]p2pact.Grant) []p2pact.Grant {
		return []p2pact.Grant{{Tool: ToolChat, Level: p2pact.LevelRead}, {Tool: ToolFleet, Level: p2pact.LevelRead}}
	})
	c, ctx := v.computer, ctx5(t)
	chat := c.Chat()
	if c.Level(ToolChat) != p2pact.LevelRead || c.CanWrite(ToolChat) {
		t.Fatal("level")
	}
	// reading works
	if l, err := chat.ListAllSessions(ctx, ""); err != nil || len(l) != 1 {
		t.Fatalf("%v %v", l, err)
	}
	if _, err := chat.LoadSession(ctx, "s1", "/w/proj"); err != nil {
		t.Fatal(err)
	}
	// writing is the P2PACT error 4, not a JSON-RPC error
	writes := map[string]func() error{
		"new":    func() error { _, err := chat.NewSession(ctx, NewSessionOptions{CWD: "/w/app"}); return err },
		"prompt": func() error { _, err := chat.Prompt(ctx, "s1", "x"); return err },
		"close":  func() error { _, err := chat.Close(ctx, "s1"); return err },
		"send":   func() error { return c.Fleet().Send(ctx, "x", "y") },
	}
	for name, w := range writes {
		err := w()
		var e *Error
		if !errors.Is(err, ErrForbidden) || !errors.As(err, &e) || e.Code != 4 {
			t.Fatalf("%s: expected Forbidden, got %v", name, err)
		}
		if errors.Is(err, ErrFailed) {
			t.Fatalf("%s: matched the wrong code", name)
		}
	}
	// the refused calls did not reach the tool's handler as writes
	for _, s := range v.engine.calls() {
		if s.method == "session/prompt" && s.level >= p2pact.LevelWrite {
			t.Fatal("prompt reached the handler as a write")
		}
	}
}

func TestErrorCodesAreTyped(t *testing.T) {
	for code, want := range map[int]*Error{1: ErrNoMethod, 2: ErrBadArgs, 3: ErrNotFound, 4: ErrForbidden, 5: ErrFailed, 6: ErrNotDelivered} {
		err := typed(&p2pact.Error{Code: code, Text: "x"})
		var e *Error
		if !errors.Is(err, want) || !errors.As(err, &e) || e.Code != code || e.Text != "x" {
			t.Fatalf("code %d: %v", code, err)
		}
	}
	var e *Error
	if err := typed(&p2pact.Error{Code: 99, Text: "?"}); !errors.As(err, &e) || e.Code != 99 {
		t.Fatal(err)
	}
	if plain := errors.New("plain"); typed(plain) != plain {
		t.Fatal("other errors stay as they are")
	}
}

func TestJSONRPCErrorsAreRPCErrors(t *testing.T) {
	v := connect(t, nil, nil)
	v.engine.mu.Lock()
	v.engine.overrides["1:session/list"] = func(map[string]any) map[string]any {
		return map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": -32601, "message": "nope", "data": "d"}}
	}
	v.engine.mu.Unlock()
	_, err := v.computer.Chat().ListAllSessions(ctx5(t), "")
	var e *RPCError
	if !errors.As(err, &e) || !e.IsMethodNotFound() || e.Message != "nope" || string(e.Data) != `"d"` {
		t.Fatalf("%v", err)
	}
	if errors.Is(err, ErrForbidden) {
		t.Fatal("an RPC error is not a P2PACT error")
	}
}

func TestCallTimeoutAndContext(t *testing.T) {
	v := connect(t, nil, nil)
	v.engine.mu.Lock()
	v.engine.overrides["1:session/list"] = func(map[string]any) map[string]any {
		time.Sleep(300 * time.Millisecond)
		return map[string]any{"result": map[string]any{}}
	}
	v.engine.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := v.computer.Chat().ListSessions(ctx, "", ""); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestStreamOf(t *testing.T) {
	if StreamOf("") != 0 || StreamOf("s1") == 0 || StreamOf("s1") == StreamOf("s2") || StreamOf("s1") != StreamOf("s1") {
		t.Fatal("stream numbers")
	}
}

// The client over a node the application runs itself: it owns the pairing and the callbacks,
// the SDK serves the chat.
func TestWrappedNode(t *testing.T) {
	engine := newFakeEngine(t)
	node, err := p2pact.NewNode(t.TempDir(), "Phone app")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.Close)
	if err := node.ListenUDP("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	c := Wrap(node, nil)
	hellos := make(chan string, 4)
	node.OnHello = func(peer string) { c.Hello(peer); hellos <- peer }
	node.OnEvent = c.Event
	node.Start()

	inv, err := p2pact.ParseInvite(engine.invite())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := node.Join(ctx5(t), inv)
	if err != nil {
		t.Fatal(err)
	}
	if got := next(t, hellos); got != peer.Addr {
		t.Fatal(got)
	}
	comp := c.Computer(peer.Addr)
	if comp == nil || comp.State() != Online {
		t.Fatalf("%v", comp)
	}
	list, err := comp.Chat().ListAllSessions(ctx5(t), "")
	if err != nil || len(list) != 1 || list[0].ID != "s1" {
		t.Fatalf("%v %v", list, err)
	}
	// a request on a stream of the application's choice (0: the computer's own)
	if _, err := comp.Chat().RequestOn(ctx5(t), 0, "session/list", map[string]any{"sessionId": "s1"}); err != nil {
		t.Fatal(err)
	}
	if got := engine.methods(); !reflect.DeepEqual(got, []string{"initialize", "session/list", "session/list"}) {
		t.Fatalf("%v", got)
	}
	// closing the client leaves the application's node alone
	c.Close()
	if len(node.Paths(peer.Addr)) == 0 {
		t.Fatal("the node was closed")
	}
}

func TestToolEventsOfUntypedTools(t *testing.T) {
	v := connect(t, []p2pact.Grant{{Tool: "com.example.hello", Level: p2pact.LevelWrite}}, nil)
	events, cancel := v.client.ToolEvents.Chan()
	defer cancel()
	addr := v.engine.addr()
	num, _ := v.engine.node.RegisterTool("com.example.hello", 1)
	if err := v.engine.node.Event(addr, num, 7, "tick", 3); err != nil {
		t.Fatal(err)
	}
	e := next(t, events)
	var s string
	_ = cbor.Unmarshal(e.Args[0], &s)
	if e.Event != 7 || e.ToolNumber != num || s != "tick" || e.Computer.ID() != v.computer.ID() {
		t.Fatalf("%+v", e)
	}
}
