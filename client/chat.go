package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go"
)

// PermissionHandler answers `session/request_permission`: it blocks until the person decided.
// ctx ends when another client answered first ([ChatClient.RequestAnswered]): stop showing the
// request. An error answers the computer with an error (the request stays open there).
type PermissionHandler func(ctx context.Context, r *PermissionRequest) (PermissionOutcome, error)

// QuestionHandler answers `_p2pact/question`: {question text → label} (see [JoinLabels]). ctx
// and errors are as in [PermissionHandler].
type QuestionHandler func(ctx context.Context, r *QuestionRequest) (map[string]string, error)

// ChatClient is tool 1 `p2pact.chat` of one computer: ACP over P2PACT with the `_p2pact/<name>`
// extensions (chat spec). Methods that read need level 1 on the tool, the others level 2; a
// method the grants refuse fails with [ErrForbidden].
//
// `initialize` goes first by itself (and again after the computer's hello comes anew). All
// calls about one session ride the session's own stream, as the spec says.
type ChatClient struct {
	computer *Computer

	// Updates: live messages of chats (and the history while a session is loaded).
	Updates Events[ChatUpdate]
	// SessionChanges: a chat appeared, changed state or title, or closed (`_p2pact/session_changed`).
	SessionChanges Events[ChatSession]
	// RequestAnswered: another client answered a request: stop showing it.
	RequestAnswered Events[RequestAnswered]
	// Reports: late lines of extension commands (`_p2pact/report`): JSON objects with `cmd`.
	Reports Events[json.RawMessage]

	mu         sync.Mutex
	permission PermissionHandler
	question   QuestionHandler
	known      map[string]ChatSession
	collectors []*collector
	pending    map[string]context.CancelFunc
	initMu     sync.Mutex
	init       *InitializeResult
}

type collector struct {
	session string
	mu      sync.Mutex
	got     []ChatUpdate
}

// SetPermissionHandler sets who answers `session/request_permission`. Without one the computer
// gets "method not found" and asks elsewhere.
func (c *ChatClient) SetPermissionHandler(h PermissionHandler) {
	c.mu.Lock()
	c.permission = h
	c.mu.Unlock()
}

// SetQuestionHandler sets who answers `_p2pact/question`.
func (c *ChatClient) SetQuestionHandler(h QuestionHandler) {
	c.mu.Lock()
	c.question = h
	c.mu.Unlock()
}

// Sessions are the chats seen so far (from lists and changes), without the closed.
func (c *ChatClient) Sessions() []ChatSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]ChatSession, 0, len(c.known))
	for _, s := range c.known {
		out = append(out, s)
	}
	return out
}

// Info is what `initialize` said, once it has (nil before).
func (c *ChatClient) Info() *InitializeResult {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	return c.init
}

// --- connection ---

// Initialize says hello to the computer's chat: capabilities, the agents it offers. It also
// asks for the extension notifications (`_meta.p2pact.ext: 1`). The other calls do it for you.
func (c *ChatClient) Initialize(ctx context.Context) (*InitializeResult, error) {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	return c.initializeLocked(ctx)
}

func (c *ChatClient) initializeLocked(ctx context.Context) (*InitializeResult, error) {
	params := map[string]any{
		"protocolVersion":    1,
		"clientCapabilities": map[string]any{},
		"_meta":              map[string]any{"p2pact": map[string]any{"ext": 1, "v": 2}},
	}
	r, err := c.computer.rpc(ctx, numChat, "initialize", params, 0, false)
	if err != nil {
		return nil, err
	}
	c.init = parseInitialize(r)
	return c.init, nil
}

func (c *ChatClient) reconnected() {
	c.initMu.Lock()
	c.init = nil
	c.initMu.Unlock()
}

func (c *ChatClient) ensureInit(ctx context.Context) error {
	c.initMu.Lock()
	defer c.initMu.Unlock()
	if c.init != nil {
		return nil
	}
	_, err := c.initializeLocked(ctx)
	return err
}

func (c *ChatClient) call(ctx context.Context, method string, params map[string]any, stream uint64, noTimeout bool) (json.RawMessage, error) {
	if err := c.ensureInit(ctx); err != nil {
		return nil, err
	}
	return c.computer.rpc(ctx, numChat, method, params, stream, noTimeout)
}

// callSettled is call, then waits for the events queued on the stream before the result (a
// result may come ahead of them).
func (c *ChatClient) callSettled(ctx context.Context, method string, params map[string]any, stream uint64) (json.RawMessage, error) {
	r, err := c.call(ctx, method, params, stream, false)
	if err != nil {
		return nil, err
	}
	if err := c.computer.owner.node.AfterEvents(ctx, c.computer.id, stream); err != nil {
		return nil, err
	}
	return r, nil
}

// --- chats ---

// ListSessions is `session/list`: one page. cwd and cursor are optional ("").
func (c *ChatClient) ListSessions(ctx context.Context, cwd, cursor string) (*SessionList, error) {
	p := map[string]any{}
	if cwd != "" {
		p["cwd"] = cwd
	}
	if cursor != "" {
		p["cursor"] = cursor
	}
	r, err := c.call(ctx, "session/list", p, 0, false)
	if err != nil {
		return nil, err
	}
	var w struct {
		Sessions   json.RawMessage `json:"sessions"`
		NextCursor string          `json:"nextCursor"`
	}
	decode(r, &w)
	list := parseAll(w.Sessions, parseSession)
	for _, s := range list {
		c.remember(s)
	}
	return &SessionList{list, w.NextCursor, r}, nil
}

// ListAllSessions follows the cursor to the end.
func (c *ChatClient) ListAllSessions(ctx context.Context, cwd string) ([]ChatSession, error) {
	var all []ChatSession
	cursor := ""
	for {
		l, err := c.ListSessions(ctx, cwd, cursor)
		if err != nil {
			return nil, err
		}
		all = append(all, l.Sessions...)
		if l.NextCursor == "" || len(l.Sessions) == 0 {
			return all, nil
		}
		cursor = l.NextCursor
	}
}

// NewSession is `session/new`.
func (c *ChatClient) NewSession(ctx context.Context, o NewSessionOptions) (*NewSession, error) {
	meta := map[string]any{}
	if o.Agent != "" {
		meta["agent"] = o.Agent
	}
	if o.MID == "" {
		o.MID = NewMID()
	}
	meta["mid"] = o.MID
	if o.Model != "" {
		meta["model"] = o.Model
	}
	if o.Text != "" {
		meta["text"] = o.Text
	}
	if o.Perms != "" {
		meta["perms"] = o.Perms
	}
	params := map[string]any{"cwd": o.CWD, "mcpServers": []any{}, "_meta": map[string]any{"p2pact": meta}}
	r, err := c.call(ctx, "session/new", params, 0, false)
	if err != nil {
		return nil, err
	}
	var w struct {
		SessionID string `json:"sessionId"`
	}
	decode(r, &w)
	if w.SessionID == "" {
		return nil, &Error{Code: p2pact.ErrFailed, Text: "no sessionId in the answer"}
	}
	return &NewSession{w.SessionID, r}, nil
}

// LoadSession is `session/load`: the chat's history comes as updates (also to Updates) and is
// in the result when it returns. A long chat comes as its tail: [LoadedSession.Older];
// [ChatClient.Older] fetches the earlier part.
func (c *ChatClient) LoadSession(ctx context.Context, sessionID, cwd string) (*LoadedSession, error) {
	col := &collector{session: sessionID}
	c.mu.Lock()
	c.collectors = append(c.collectors, col)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		for i, x := range c.collectors {
			if x == col {
				c.collectors = append(c.collectors[:i], c.collectors[i+1:]...)
				break
			}
		}
		c.mu.Unlock()
	}()
	params := map[string]any{"sessionId": sessionID, "cwd": cwd, "mcpServers": []any{}}
	r, err := c.callSettled(ctx, "session/load", params, StreamOf(sessionID))
	if err != nil {
		return nil, err
	}
	var m struct {
		Older bool `json:"older"`
	}
	decode(metaOf(r), &m)
	col.mu.Lock()
	defer col.mu.Unlock()
	return &LoadedSession{sessionID, append([]ChatUpdate(nil), col.got...), m.Older, r}, nil
}

// Prompt is `session/prompt` with a text: it returns when the agent's turn ends (minutes, no
// timeout but ctx); the reply comes as Updates meanwhile.
func (c *ChatClient) Prompt(ctx context.Context, sessionID, text string) (*PromptResult, error) {
	return c.PromptBlocks(ctx, sessionID, "", TextBlock(text))
}

// PromptBlocks is Prompt with content blocks ([TextBlock], [ImageBlock]). mid is kept for
// repeats: send the same one if you do not know whether the first went ("" — a fresh one).
func (c *ChatClient) PromptBlocks(ctx context.Context, sessionID, mid string, blocks ...map[string]any) (*PromptResult, error) {
	if mid == "" {
		mid = NewMID()
	}
	params := map[string]any{"sessionId": sessionID, "prompt": blocks, "_meta": map[string]any{"p2pact": map[string]any{"mid": mid}}}
	r, err := c.call(ctx, "session/prompt", params, StreamOf(sessionID), true)
	if err != nil {
		return nil, err
	}
	var w struct {
		StopReason string `json:"stopReason"`
	}
	decode(r, &w)
	var m struct {
		Duplicate bool `json:"duplicate"`
	}
	decode(r, &m)
	if !m.Duplicate {
		decode(metaOf(r), &m)
	}
	return &PromptResult{w.StopReason, m.Duplicate, r}, nil
}

// Cancel is the notification `session/cancel`: the agent stops the turn.
func (c *ChatClient) Cancel(sessionID string) error {
	return c.computer.notify(numChat, "session/cancel", map[string]any{"sessionId": sessionID}, StreamOf(sessionID))
}

func (c *ChatClient) SetMode(ctx context.Context, sessionID, modeID string) (json.RawMessage, error) {
	return c.call(ctx, "session/set_mode", map[string]any{"sessionId": sessionID, "modeId": modeID}, StreamOf(sessionID), false)
}

func (c *ChatClient) SetModel(ctx context.Context, sessionID, modelID string) (json.RawMessage, error) {
	return c.call(ctx, "session/set_model", map[string]any{"sessionId": sessionID, "modelId": modelID}, StreamOf(sessionID), false)
}

// Request is any ACP or extension method that has no typed call: the `result` object. It rides
// the stream of the params' `sessionId` (0 — the computer's own). Like [ChatClient.LoadSession],
// it returns after the events the computer sent before the result have been handled.
func (c *ChatClient) Request(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	sid, _ := params["sessionId"].(string)
	return c.RequestOn(ctx, StreamOf(sid), method, params)
}

// RequestOn is Request on a stream of the application's choice.
func (c *ChatClient) RequestOn(ctx context.Context, stream uint64, method string, params map[string]any) (json.RawMessage, error) {
	if params != nil {
		params = wire(params).(map[string]any)
	}
	return c.callSettled(ctx, method, params, stream)
}

// --- extensions (chat spec §10) ---

// Command calls `_p2pact/<name>` and gives its lines (§9.3): JSON objects with `cmd`. Lines
// that come later arrive in Reports. A failure the person should see is the line
// `{"cmd":"alert"}`.
func (c *ChatClient) Command(ctx context.Context, name string, params map[string]any) ([]json.RawMessage, error) {
	_, lines, err := c.extension(ctx, name, params)
	return lines, err
}

// extension calls `_p2pact/<name>` and gives the whole result (typed fields, §9.3) and its lines.
func (c *ChatClient) extension(ctx context.Context, name string, params map[string]any) (json.RawMessage, []json.RawMessage, error) {
	if params == nil {
		params = map[string]any{}
	}
	sid, _ := params["sessionId"].(string)
	r, err := c.callSettled(ctx, "_p2pact/"+name, wire(params).(map[string]any), StreamOf(sid))
	if err != nil {
		return nil, nil, err
	}
	var w struct {
		Lines json.RawMessage `json:"lines"`
	}
	decode(r, &w)
	return r, rawList(w.Lines), nil
}

// pickResult picks where a method's answer is read from: the result itself when it carries the typed
// field `key` (engine speaking §9.3), else the line `cmd` of `lines` (an older engine). A late
// line of an older engine (commands, agents, history without `v: 2`) is not waited for here: it
// arrives in Reports, and the typed call gives what was ready.
func pickResult(res json.RawMessage, lines []json.RawMessage, key, cmd string) json.RawMessage {
	var m map[string]json.RawMessage
	decode(res, &m)
	if _, ok := m[key]; ok {
		return res
	}
	return commandLine(lines, cmd)
}

// okResult reads `{"ok": ...}` of a write method; an older engine gave only lines, no `ok` then
// means success unless an `alert` line says otherwise.
func okResult(res json.RawMessage, lines []json.RawMessage) *OKResult {
	var w struct {
		OK    *bool  `json:"ok"`
		Error string `json:"error"`
	}
	decode(res, &w)
	r := &OKResult{Raw: clone(res)}
	switch {
	case w.OK != nil:
		r.OK, r.Error = *w.OK, w.Error
	default:
		r.OK = true
		var a struct{ Text string }
		if l := commandLine(lines, "alert"); len(l) > 2 {
			decode(l, &a)
			r.OK, r.Error = false, a.Text
		}
	}
	return r
}

// CloseChat is [ChatClient.Close] with the typed result `{ok, error}`.
func (c *ChatClient) CloseChat(ctx context.Context, sessionID string) (*OKResult, error) {
	return c.write(ctx, "close", map[string]any{"sessionId": sessionID})
}

// RestartChat is [ChatClient.Restart] with the typed result.
func (c *ChatClient) RestartChat(ctx context.Context, sessionID string) (*OKResult, error) {
	return c.write(ctx, "restart", map[string]any{"sessionId": sessionID})
}

// HideChat is [ChatClient.Hide] with the typed result.
func (c *ChatClient) HideChat(ctx context.Context, sessionID string, on bool) (*OKResult, error) {
	return c.write(ctx, "hide", map[string]any{"sessionId": sessionID, "on": on})
}

// HistoryOpen is `_p2pact/history_open`: bring a closed conversation (the id of a
// [HistoryItem]) back into the list as closed, so it can be loaded and continued.
func (c *ChatClient) HistoryOpen(ctx context.Context, historyID string) (*OKResult, error) {
	return c.write(ctx, "history_open", map[string]any{"sessionId": historyID})
}

func (c *ChatClient) write(ctx context.Context, name string, params map[string]any) (*OKResult, error) {
	res, lines, err := c.extension(ctx, name, params)
	if err != nil {
		return nil, err
	}
	return okResult(res, lines), nil
}

// Close closes the chat: it leaves the list.
func (c *ChatClient) Close(ctx context.Context, sessionID string) ([]json.RawMessage, error) {
	return c.Command(ctx, "close", map[string]any{"sessionId": sessionID})
}

// Restart starts the agent of a chat again.
func (c *ChatClient) Restart(ctx context.Context, sessionID string) ([]json.RawMessage, error) {
	return c.Command(ctx, "restart", map[string]any{"sessionId": sessionID})
}

// Hide hides a chat from the list (on) or shows it again.
func (c *ChatClient) Hide(ctx context.Context, sessionID string, on bool) ([]json.RawMessage, error) {
	return c.Command(ctx, "hide", map[string]any{"sessionId": sessionID, "on": on})
}

// commandLine finds the line with the given `cmd` among the lines of a command.
func commandLine(lines []json.RawMessage, cmd string) json.RawMessage {
	for _, l := range lines {
		var w struct {
			Cmd string `json:"cmd"`
		}
		decode(l, &w)
		if w.Cmd == cmd {
			return l
		}
	}
	return json.RawMessage("{}")
}

// NewMID is a fresh message id for [ChatClient.PromptBlocks] and [ChatClient.NewSession].
func NewMID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// --- from the computer ---

func (c *ChatClient) remember(s ChatSession) {
	if s.ID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s.State == StateClosed {
		delete(c.known, s.ID)
	} else {
		c.known[s.ID] = s
	}
}

// notified handles a `notify` event (`session/update`, `_p2pact/…`).
func (c *ChatClient) notified(args []cbor.RawMessage) {
	if len(args) == 0 {
		return
	}
	var msg struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	decode(toJSON(args[0]), &msg)
	switch msg.Method {
	case "session/update":
		var p struct {
			SessionID string          `json:"sessionId"`
			Update    json.RawMessage `json:"update"`
		}
		decode(msg.Params, &p)
		if p.SessionID == "" || len(p.Update) == 0 {
			return
		}
		u := parseUpdate(p.SessionID, p.Update)
		c.mu.Lock()
		cols := append([]*collector(nil), c.collectors...)
		c.mu.Unlock()
		for _, col := range cols {
			if col.session == p.SessionID {
				col.mu.Lock()
				col.got = append(col.got, u)
				col.mu.Unlock()
			}
		}
		c.Updates.emit(u)
	case "_p2pact/session_changed":
		s := parseSession(msg.Params)
		c.remember(s)
		c.SessionChanges.emit(s)
	case "_p2pact/request_answered":
		var p struct{ SessionID, ToolCallID string }
		decode(msg.Params, &p)
		if p.SessionID == "" || p.ToolCallID == "" {
			return
		}
		c.mu.Lock()
		cancel := c.pending[p.SessionID+"/"+p.ToolCallID]
		c.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		c.RequestAnswered.emit(RequestAnswered{p.SessionID, p.ToolCallID})
	case "_p2pact/report", "_nomad/report": // _nomad/…: an engine older than the ext flag
		var p struct {
			Line json.RawMessage `json:"line"`
		}
		decode(msg.Params, &p)
		if len(p.Line) > 0 {
			c.Reports.emit(p.Line)
		}
	}
}

// incoming handles a request of the computer (`1.1 rpc`). It registers what must be known
// before the stream goes on, and returns the function that waits for the person and builds
// the answer, a JSON-RPC message.
func (c *ChatClient) incoming(args []cbor.RawMessage) func() []any {
	var req struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if len(args) == 0 {
		return reply(rpcErr(RPCInvalidParams, "bad request"))
	}
	decode(toJSON(args[0]), &req)
	c.mu.Lock()
	ph, qh := c.permission, c.question
	c.mu.Unlock()
	switch req.Method {
	case "session/request_permission":
		if ph == nil {
			return reply(rpcErr(RPCMethodNotFound, "method not found"))
		}
		var p struct {
			SessionID string          `json:"sessionId"`
			ToolCall  json.RawMessage `json:"toolCall"`
			Options   json.RawMessage `json:"options"`
		}
		decode(req.Params, &p)
		r := &PermissionRequest{SessionID: p.SessionID, ToolCall: parseToolCall(p.ToolCall), Raw: clone(req.Params)}
		r.Options = parseAll(p.Options, func(o json.RawMessage) PermissionOption {
			var w struct{ OptionID, Name, Kind string }
			decode(o, &w)
			var m struct{ Description string }
			decode(metaOf(o), &m)
			return PermissionOption{w.OptionID, w.Name, w.Kind, m.Description, clone(o)}
		})
		ctx := c.track(p.SessionID + "/" + r.ToolCall.ID)
		return func() []any {
			defer c.untrack(p.SessionID + "/" + r.ToolCall.ID)
			out, err := ask(ctx, func() (PermissionOutcome, error) { return ph(ctx, r) })
			if err != nil {
				return reply(rpcErr(RPCFailed, err.Error()))()
			}
			if out.Cancelled {
				return reply(rpcResult2(map[string]any{"outcome": map[string]any{"outcome": "cancelled"}}))()
			}
			return reply(rpcResult2(map[string]any{"outcome": map[string]any{"outcome": "selected", "optionId": out.OptionID}}))()
		}
	case "_p2pact/question", "_nomad/question": // _nomad/…: an engine older than the ext flag
		if qh == nil {
			return reply(rpcErr(RPCMethodNotFound, "method not found"))
		}
		var p struct {
			SessionID  string          `json:"sessionId"`
			ToolCallID string          `json:"toolCallId"`
			Questions  json.RawMessage `json:"questions"`
		}
		decode(req.Params, &p)
		r := &QuestionRequest{SessionID: p.SessionID, ToolCallID: p.ToolCallID, Raw: clone(req.Params)}
		r.Questions = parseAll(p.Questions, func(q json.RawMessage) Question {
			var w struct {
				Question, Header string
				Multi            bool
				Options          []QuestionOption
			}
			decode(q, &w)
			return Question{w.Question, w.Header, w.Multi, w.Options}
		})
		ctx := c.track(p.SessionID + "/" + p.ToolCallID)
		return func() []any {
			defer c.untrack(p.SessionID + "/" + p.ToolCallID)
			answers, err := ask(ctx, func() (map[string]string, error) { return qh(ctx, r) })
			if err != nil {
				return reply(rpcErr(RPCFailed, err.Error()))()
			}
			return reply(rpcResult2(map[string]any{"answers": answers}))()
		}
	}
	// fs and terminal methods: the agent device does not use our files (chat spec §7)
	return reply(rpcErr(RPCMethodNotFound, "method not found"))
}

// track makes the context of a request: another client's answer cancels it.
func (c *ChatClient) track(key string) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.pending[key] = cancel
	c.mu.Unlock()
	return ctx
}

func (c *ChatClient) untrack(key string) {
	c.mu.Lock()
	if cancel := c.pending[key]; cancel != nil {
		cancel()
		delete(c.pending, key)
	}
	c.mu.Unlock()
}

var errAnsweredElsewhere = errors.New("answered elsewhere")

// ask runs the application's handler; it ends when the handler answers or ctx does (another
// client answered first: our reply is not needed, but the stream must go on).
func ask[T any](ctx context.Context, run func() (T, error)) (T, error) {
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				var zero T
				ch <- res{zero, errors.New("handler failed")}
			}
		}()
		v, err := run()
		ch <- res{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, errAnsweredElsewhere
	}
}

func rpcResult2(r any) map[string]any { return map[string]any{"jsonrpc": "2.0", "result": r} }

func rpcErr(code int, message string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "error": map[string]any{"code": code, "message": message}}
}

func reply(msg map[string]any) func() []any { return func() []any { return []any{wire(msg)} } }
