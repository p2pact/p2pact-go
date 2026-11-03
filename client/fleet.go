package client

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Tool 2 `p2pact.fleet` (fleet spec): the computer and its agent sessions. JSON-RPC over `2.1 rpc`.

// FleetNode is the computer as the fleet describes it (`Node`).
type FleetNode struct {
	ID, Name, OS string
	// Status: online, lid, battery, temperature, working… as the computer reports.
	Status       json.RawMessage
	Agents       []AgentInfo
	Capabilities json.RawMessage
	Raw          json.RawMessage
}

func parseNode(raw json.RawMessage) FleetNode {
	var w struct {
		ID, Name, OS string
		Status       json.RawMessage
		Capabilities json.RawMessage
	}
	decode(raw, &w)
	var caps struct{ Agents json.RawMessage }
	decode(w.Capabilities, &caps)
	return FleetNode{w.ID, w.Name, w.OS, w.Status, parseAll(caps.Agents, parseAgent), w.Capabilities, clone(raw)}
}

// FleetHello is the answer to `fleet/hello`.
type FleetHello struct {
	Protocol string
	Node     FleetNode
	Raw      json.RawMessage
}

// FleetSession is an agent session of the fleet: the same id as the chat's.
type FleetSession struct {
	ID    string
	Agent string
	Model string
	Dir   string
	Keep  *bool
	Perms string
	// Phase: starting, working, waiting, idle… as the computer says.
	Phase string
	Title string
	// Updated is RFC 3339.
	Updated string
	// Ask is the `ask` of the status, if the agent waits for the person.
	Ask json.RawMessage
	Raw json.RawMessage
}

func parseFleetSession(raw json.RawMessage) FleetSession {
	var w struct {
		ID   string
		Spec struct {
			Agent, Model, Dir, Perms string
			Keep                     *bool
		}
		Status struct {
			Phase, Title, Updated string
			Ask                   json.RawMessage
		}
	}
	decode(raw, &w)
	return FleetSession{w.ID, w.Spec.Agent, w.Spec.Model, w.Spec.Dir, w.Spec.Keep, w.Spec.Perms,
		w.Status.Phase, w.Status.Title, w.Status.Updated, w.Status.Ask, clone(raw)}
}

// SessionSpec is what `session/create` starts. Extra is added as it is, for fields this SDK
// does not know.
type SessionSpec struct {
	Agent, Dir, Model string
	Keep              *bool
	Perms             string
	Extra             map[string]any
}

func (s SessionSpec) toMap() map[string]any {
	m := map[string]any{}
	if s.Agent != "" {
		m["agent"] = s.Agent
	}
	if s.Dir != "" {
		m["dir"] = s.Dir
	}
	if s.Model != "" {
		m["model"] = s.Model
	}
	if s.Keep != nil {
		m["keep"] = *s.Keep
	}
	if s.Perms != "" {
		m["perms"] = s.Perms
	}
	for k, v := range s.Extra {
		m[k] = wire(v)
	}
	return m
}

// FleetMessage is a reply of a session.
type FleetMessage struct {
	Seq  int64
	Role string
	Text string
	Time string
	Raw  json.RawMessage
}

func parseFleetMessage(raw json.RawMessage) FleetMessage {
	var w struct {
		Seq  int64
		Role string
		Text string
		Time string
	}
	decode(raw, &w)
	return FleetMessage{w.Seq, w.Role, w.Text, w.Time, clone(raw)}
}

// FleetMessages is `session/messages`: the replies after a number; Older — there are earlier ones.
type FleetMessages struct {
	Messages []FleetMessage
	Last     int64
	Older    bool
	Raw      json.RawMessage
}

// CloseResult is the answer to `session/close`.
type CloseResult struct {
	OK bool
	// Warning: done, but not smoothly.
	Warning string
	Raw     json.RawMessage
}

// FleetEventType tells which change a [FleetEvent] is.
type FleetEventType int

const (
	// FleetSessionsChanged: the whole list, at every change (Sessions).
	FleetSessionsChanged FleetEventType = iota + 1
	// FleetSessionMessages: new replies of a session (ID, Messages).
	FleetSessionMessages
	// FleetResync: replies of ID were lost: read Messages(ID, after) again.
	FleetResync
	// FleetPartial: the agent's text while it is written (ID, Message); only if the watch
	// asked for partial.
	FleetPartial
	// FleetNotify: what the computer would show as a notification (Text).
	FleetNotify
	// FleetOther: an event this SDK has no type for (Method, Params).
	FleetOther
)

// FleetEvent is an event of a watch (fleet spec §4); which fields are set depends on Type.
type FleetEvent struct {
	Type     FleetEventType
	Sessions []FleetSession
	ID       string
	Messages []FleetMessage
	Message  json.RawMessage
	Text     string
	Method   string
	Params   json.RawMessage
}

// FleetWatch is an active watch: Close it to unsubscribe.
type FleetWatch struct {
	// Sessions at the start.
	Sessions []FleetSession
	c        *FleetClient
}

// Close unsubscribes.
func (w *FleetWatch) Close(ctx context.Context) error {
	w.c.mu.Lock()
	w.c.watching = nil
	w.c.mu.Unlock()
	_, err := w.c.call(ctx, "fleet/unwatch", nil)
	return err
}

// FleetClient is tool 2 `p2pact.fleet` of one computer.
type FleetClient struct {
	computer *Computer

	// Events of the watch ([FleetClient.Watch]); also after the computer restarted (the watch
	// is repeated).
	Events Events[FleetEvent]

	mu       sync.Mutex
	watching *bool // partial, or nil — not watching
}

func (f *FleetClient) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	id, _ := params["id"].(string)
	return f.computer.rpc(ctx, numFleet, method, params, StreamOf(id), false)
}

// writeCall is call on stream 0: writes are not tied to a session's stream.
func (f *FleetClient) writeCall(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	return f.computer.rpc(ctx, numFleet, method, params, 0, false)
}

// --- read ---

// Hello is `fleet/hello`.
func (f *FleetClient) Hello(ctx context.Context) (*FleetHello, error) {
	r, err := f.call(ctx, "fleet/hello", nil)
	if err != nil {
		return nil, err
	}
	var w struct {
		Protocol string
		Node     json.RawMessage
	}
	decode(r, &w)
	return &FleetHello{w.Protocol, parseNode(w.Node), r}, nil
}

// Node is `node/get`.
func (f *FleetClient) Node(ctx context.Context) (*FleetNode, error) {
	r, err := f.call(ctx, "node/get", nil)
	if err != nil {
		return nil, err
	}
	n := parseNode(r)
	return &n, nil
}

// Sessions is `session/list`.
func (f *FleetClient) Sessions(ctx context.Context) ([]FleetSession, error) {
	r, err := f.call(ctx, "session/list", nil)
	if err != nil {
		return nil, err
	}
	var w struct{ Sessions json.RawMessage }
	decode(r, &w)
	return parseAll(w.Sessions, parseFleetSession), nil
}

// Session is `session/get`; no such session — [RPCError] -32004.
func (f *FleetClient) Session(ctx context.Context, id string) (*FleetSession, error) {
	r, err := f.call(ctx, "session/get", map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	s := parseFleetSession(r)
	return &s, nil
}

// Messages is `session/messages`: the replies after number after (nil — the last limit ones;
// limit nil — the computer's choice).
func (f *FleetClient) Messages(ctx context.Context, id string, after, limit *int64) (*FleetMessages, error) {
	p := map[string]any{"id": id}
	if after != nil {
		p["after"] = *after
	}
	if limit != nil {
		p["limit"] = *limit
	}
	r, err := f.call(ctx, "session/messages", p)
	if err != nil {
		return nil, err
	}
	var w struct {
		Messages json.RawMessage
		Last     int64
		Older    bool
	}
	decode(r, &w)
	return &FleetMessages{parseAll(w.Messages, parseFleetMessage), w.Last, w.Older, r}, nil
}

// Watch subscribes to the fleet: Events get the changes. Close the result to stop. With
// partial the agent's text comes while it is written.
func (f *FleetClient) Watch(ctx context.Context, partial bool) (*FleetWatch, error) {
	f.mu.Lock()
	f.watching = &partial
	f.mu.Unlock()
	r, err := f.call(ctx, "fleet/watch", map[string]any{"partial": partial})
	if err != nil {
		f.mu.Lock()
		f.watching = nil
		f.mu.Unlock()
		return nil, err
	}
	var w struct{ Sessions json.RawMessage }
	decode(r, &w)
	return &FleetWatch{Sessions: parseAll(w.Sessions, parseFleetSession), c: f}, nil
}

// --- write ---

// Create is `session/create`: starts an agent session, with a first text if given.
func (f *FleetClient) Create(ctx context.Context, spec SessionSpec, text string) (*FleetSession, error) {
	p := map[string]any{"spec": spec.toMap()}
	if text != "" {
		p["text"] = text
	}
	r, err := f.writeCall(ctx, "session/create", p)
	if err != nil {
		return nil, err
	}
	s := parseFleetSession(r)
	return &s, nil
}

// Send puts a message into the session.
func (f *FleetClient) Send(ctx context.Context, id, text string) error {
	_, err := f.writeCall(ctx, "session/send", map[string]any{"id": id, "text": text})
	return err
}

// Answer answers an agent's question (answers: question → label) or permission (allow).
// waitID names the wait, if the computer gave one.
func (f *FleetClient) Answer(ctx context.Context, id, waitID string, answers map[string]string, allow *bool) error {
	p := map[string]any{"id": id}
	if waitID != "" {
		p["waitId"] = waitID
	}
	if answers != nil {
		p["answers"] = answers
	}
	if allow != nil {
		p["allow"] = *allow
	}
	_, err := f.writeCall(ctx, "session/answer", p)
	return err
}

// Interrupt stops the agent's turn.
func (f *FleetClient) Interrupt(ctx context.Context, id string) error {
	_, err := f.writeCall(ctx, "session/interrupt", map[string]any{"id": id})
	return err
}

// Close is `session/close`.
func (f *FleetClient) Close(ctx context.Context, id string) (*CloseResult, error) {
	r, err := f.writeCall(ctx, "session/close", map[string]any{"id": id})
	if err != nil {
		return nil, err
	}
	w := struct {
		OK      bool
		Warning string
	}{OK: true}
	decode(r, &w)
	return &CloseResult{w.OK, w.Warning, r}, nil
}

// SetKeep keeps the agent running (on) or lets it stop.
func (f *FleetClient) SetKeep(ctx context.Context, id string, on bool) error {
	_, err := f.writeCall(ctx, "session/setKeep", map[string]any{"id": id, "on": on})
	return err
}

// Status is `engine/status`: version, mode, link, clients, peers (write: it names the device's
// data directory).
func (f *FleetClient) Status(ctx context.Context) (json.RawMessage, error) {
	return f.call(ctx, "engine/status", nil)
}

// Settings is `settings/get`.
func (f *FleetClient) Settings(ctx context.Context) (json.RawMessage, error) {
	return f.call(ctx, "settings/get", nil)
}

// SetSettings changes settings and gives them as they are after; an invalid patch —
// [RPCError] -32602.
func (f *FleetClient) SetSettings(ctx context.Context, patch map[string]any) (json.RawMessage, error) {
	return f.call(ctx, "settings/set", map[string]any{"patch": wire(patch)})
}

// Request is any other method of the fleet.
func (f *FleetClient) Request(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	if params != nil {
		params = wire(params).(map[string]any)
	}
	return f.call(ctx, method, params)
}

// --- events ---

func (f *FleetClient) reconnected() {
	// the device forgot the subscription with its restart (fleet spec §4)
	f.mu.Lock()
	partial := f.watching
	f.mu.Unlock()
	if partial == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = f.call(ctx, "fleet/watch", map[string]any{"partial": *partial})
	}()
}

func (f *FleetClient) notified(args []cbor.RawMessage) {
	if len(args) == 0 {
		return
	}
	var msg struct {
		Method string
		Params json.RawMessage
	}
	decode(toJSON(args[0]), &msg)
	if msg.Method == "" {
		return
	}
	var p struct {
		Sessions json.RawMessage
		ID       string
		Messages json.RawMessage
		Message  json.RawMessage
		Text     string
	}
	decode(msg.Params, &p)
	e := FleetEvent{ID: p.ID, Text: p.Text, Message: p.Message}
	switch msg.Method {
	case "session/changed":
		e.Type, e.Sessions = FleetSessionsChanged, parseAll(p.Sessions, parseFleetSession)
	case "session/messages":
		e.Type, e.Messages = FleetSessionMessages, parseAll(p.Messages, parseFleetMessage)
	case "session/resync":
		e.Type = FleetResync
	case "session/partial":
		e.Type = FleetPartial
	case "notify":
		e.Type = FleetNotify
	default:
		e.Type, e.Method, e.Params = FleetOther, msg.Method, clone(msg.Params)
	}
	f.Events.emit(e)
}
