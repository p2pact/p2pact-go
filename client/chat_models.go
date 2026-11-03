package client

import (
	"encoding/json"
	"strings"
)

// Types of tool 1 `p2pact.chat` (chat spec): ACP with `_meta.p2pact`. Unknown fields are
// ignored; every type keeps the JSON it was read from in Raw. Absent strings are "".

// AgentInfo is an agent the computer can start.
type AgentInfo struct {
	ID      string
	Name    string
	Version string
	Raw     json.RawMessage
}

func parseAgent(raw json.RawMessage) AgentInfo {
	var w struct {
		ID, Name, Version string
	}
	decode(raw, &w)
	if w.Name == "" {
		w.Name = w.ID
	}
	return AgentInfo{w.ID, w.Name, w.Version, clone(raw)}
}

// InitializeResult is the answer to `initialize`: what the computer's chat offers.
type InitializeResult struct {
	ProtocolVersion int
	AgentName       string
	AgentTitle      string
	AgentVersion    string
	// LoadSession: `session/load` works.
	LoadSession bool
	// Agents the computer can start (`_meta.p2pact.agents`); the first is the default.
	Agents []AgentInfo
	// Extensions: the computer speaks the `_p2pact/<name>` extensions.
	Extensions bool
	Raw        json.RawMessage
}

func parseInitialize(raw json.RawMessage) *InitializeResult {
	var w struct {
		ProtocolVersion int `json:"protocolVersion"`
		AgentInfo       struct {
			Name, Title, Version string
		} `json:"agentInfo"`
		AgentCapabilities struct {
			LoadSession bool `json:"loadSession"`
		} `json:"agentCapabilities"`
	}
	decode(raw, &w)
	var meta struct {
		Agents json.RawMessage `json:"agents"`
		Ext    int             `json:"ext"`
	}
	decode(metaOf(raw), &meta)
	if w.ProtocolVersion == 0 {
		w.ProtocolVersion = 1
	}
	return &InitializeResult{w.ProtocolVersion, w.AgentInfo.Name, w.AgentInfo.Title, w.AgentInfo.Version,
		w.AgentCapabilities.LoadSession, parseAll(meta.Agents, parseAgent), meta.Ext >= 1, clone(raw)}
}

// SessionState of a chat. Values the SDK does not know are kept as they came.
type SessionState string

const (
	StateWorking SessionState = "working"
	// StateWaiting: waits for the person.
	StateWaiting SessionState = "waiting"
	StateIdle    SessionState = "idle"
	StateClosed  SessionState = "closed"
)

// ChatSession is a chat of a computer: an entry of `session/list` or `_p2pact/session_changed`.
type ChatSession struct {
	ID    string
	CWD   string
	Title string
	Agent string
	State SessionState
	// UpdatedAt is RFC 3339.
	UpdatedAt string
	Raw       json.RawMessage
}

func parseSession(raw json.RawMessage) ChatSession {
	var w struct {
		SessionID string `json:"sessionId"`
		CWD       string `json:"cwd"`
		Title     string `json:"title"`
		UpdatedAt string `json:"updatedAt"`
	}
	decode(raw, &w)
	var m struct {
		Title     string `json:"title"`
		Agent     string `json:"agent"`
		State     string `json:"state"`
		UpdatedAt string `json:"updatedAt"`
	}
	decode(metaOf(raw), &m)
	return ChatSession{ID: w.SessionID, CWD: w.CWD, Title: first(m.Title, w.Title), Agent: m.Agent,
		State: SessionState(m.State), UpdatedAt: first(m.UpdatedAt, w.UpdatedAt), Raw: clone(raw)}
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// SessionList is one page of `session/list`.
type SessionList struct {
	Sessions   []ChatSession
	NextCursor string
	Raw        json.RawMessage
}

// ContentBlock is an ACP content block: text, image, resource_link…
type ContentBlock struct {
	Type string
	Text string
	Raw  json.RawMessage
}

func parseBlock(raw json.RawMessage) ContentBlock {
	var w struct{ Type, Text string }
	decode(raw, &w)
	return ContentBlock{w.Type, w.Text, clone(raw)}
}

// TextBlock makes a text content block for a prompt.
func TextBlock(text string) map[string]any { return map[string]any{"type": "text", "text": text} }

// ImageBlock makes an image content block for a prompt (base64 data).
func ImageBlock(mimeType, base64 string) map[string]any {
	return map[string]any{"type": "image", "mimeType": mimeType, "data": base64}
}

// ToolCall is a tool call of an agent (`tool_call`, `tool_call_update` and the `toolCall` of a
// permission request).
type ToolCall struct {
	ID    string
	Title string
	// Kind is ACP's: execute, read, edit…
	Kind string
	// Status: pending, in_progress, completed, failed.
	Status string
	Raw    json.RawMessage
}

func parseToolCall(raw json.RawMessage) ToolCall {
	var w struct {
		ToolCallID, Title, Kind, Status string
	}
	decode(raw, &w)
	return ToolCall{w.ToolCallID, w.Title, w.Kind, w.Status, clone(raw)}
}

// PlanEntry is a line of an agent's plan.
type PlanEntry struct {
	Content, Priority, Status string
	Raw                       json.RawMessage
}

// Types of ChatUpdate.Type (ACP's `sessionUpdate`).
const (
	UpdateUserMessage  = "user_message_chunk"
	UpdateAgentMessage = "agent_message_chunk"
	UpdateAgentThought = "agent_thought_chunk"
	UpdateToolCall     = "tool_call"
	UpdateToolCallDone = "tool_call_update"
	UpdatePlan         = "plan"
	UpdateMode         = "current_mode_update"
)

// ChatUpdate is a `session/update`: a live message of a chat or a replayed one
// (`session/load`). Seq numbers the messages of a session (0 — none): a client that loads a
// session again skips what it has shown (chat spec §8); the pieces of a streamed agent message
// carry no Seq but the first. Which fields are set depends on Type; Raw is the `update` object.
type ChatUpdate struct {
	SessionID string
	Type      string
	Seq       int64
	// Time is RFC 3339.
	Time string
	// Content is set for the user and agent message and thought chunks.
	Content ContentBlock
	// Call is set for UpdateToolCall and UpdateToolCallDone.
	Call *ToolCall
	// Plan is set for UpdatePlan.
	Plan []PlanEntry
	// ModeID is set for UpdateMode.
	ModeID string
	Raw    json.RawMessage
}

// Text is the text of the content block ("" if there is none).
func (u ChatUpdate) Text() string { return u.Content.Text }

func parseUpdate(sessionID string, raw json.RawMessage) ChatUpdate {
	var w struct {
		SessionUpdate string          `json:"sessionUpdate"`
		Content       json.RawMessage `json:"content"`
		Entries       json.RawMessage `json:"entries"`
		CurrentModeID string          `json:"currentModeId"`
	}
	decode(raw, &w)
	var m struct {
		Seq  int64  `json:"seq"`
		Time string `json:"time"`
	}
	decode(metaOf(raw), &m)
	u := ChatUpdate{SessionID: sessionID, Type: w.SessionUpdate, Seq: m.Seq, Time: m.Time, Raw: clone(raw)}
	switch w.SessionUpdate {
	case UpdateUserMessage, UpdateAgentMessage, UpdateAgentThought:
		u.Content = parseBlock(w.Content)
	case UpdateToolCall, UpdateToolCallDone:
		c := parseToolCall(raw)
		u.Call = &c
	case UpdatePlan:
		u.Plan = parseAll(w.Entries, func(r json.RawMessage) PlanEntry {
			var e struct{ Content, Priority, Status string }
			decode(r, &e)
			return PlanEntry{e.Content, e.Priority, e.Status, clone(r)}
		})
	case UpdateMode:
		u.ModeID = w.CurrentModeID
	}
	return u
}

// NewSession is the answer to `session/new`.
type NewSession struct {
	SessionID string
	Raw       json.RawMessage
}

// NewSessionOptions are the arguments of [ChatClient.NewSession].
type NewSessionOptions struct {
	CWD string
	// Agent is one of [InitializeResult.Agents] (default: the first), Model one of the agent's models.
	Agent, Model string
	// Text is the first task, sent at once.
	Text string
	// Perms is "skip" or "ask".
	Perms string
	// MID makes a repeat after a restart harmless; "" — a fresh one.
	MID string
}

// LoadedSession is what `session/load` gave: the replayed Updates (all of them have come when
// it returns).
type LoadedSession struct {
	SessionID string
	Updates   []ChatUpdate
	// Older: the history is the chat's tail; [ChatClient.Older] fetches the earlier part.
	Older bool
	Raw   json.RawMessage
}

// PromptResult is the answer to `session/prompt`.
type PromptResult struct {
	StopReason string
	// Duplicate: the mid was already executed; nothing was sent again.
	Duplicate bool
	Raw       json.RawMessage
}

// ChatMessage is a message of a conversation, as `_p2pact/older` gives it.
type ChatMessage struct {
	Seq    int64
	Role   string
	Text   string
	Time   string
	Images []string
	Raw    json.RawMessage
}

// OlderPage is `_p2pact/older`: messages just before one you have.
type OlderPage struct {
	SessionID string
	Messages  []ChatMessage
	More      bool
	Raw       json.RawMessage
}

type DiffFile struct {
	Path           string
	Added, Removed int
	Status         string
}

// DiffResult is `_p2pact/diff`: the changes in the chat's folder (git).
type DiffResult struct {
	Files     []DiffFile
	Patch     string
	Truncated bool
	// Error is "not_found", "not_git" or text.
	Error string
	Raw   json.RawMessage
}

// ImageResult is `_p2pact/image`.
type ImageResult struct {
	// Data is base64.
	Data string
	// Error is "not_found", "no_file", "too_big" or "bad_image".
	Error string
	Raw   json.RawMessage
}

// RequestAnswered is `_p2pact/request_answered`: another client answered; stop showing the request.
type RequestAnswered struct {
	SessionID, ToolCallID string
}

// --- the computer asks, the application answers ---

// PermissionOption is one answer a permission request offers.
type PermissionOption struct {
	ID   string
	Name string
	// Kind: allow_once, allow_always, reject_once, reject_always.
	Kind        string
	Description string
	Raw         json.RawMessage
}

// PermissionOutcome is the answer to a permission request: an option, or cancelled.
type PermissionOutcome struct {
	OptionID  string
	Cancelled bool
}

// Cancelled is the outcome of a request nobody answered.
var Cancelled = PermissionOutcome{Cancelled: true}

// PermissionRequest is `session/request_permission` (chat spec §6): the agent asks the person
// to allow something. It is also how an agent asks a single question: ToolCall.Title is the
// question and the options are the answers (§9.1).
type PermissionRequest struct {
	SessionID string
	ToolCall  ToolCall
	Options   []PermissionOption
	Raw       json.RawMessage
}

// Allow is the first option that allows, once before always; Cancelled if there is none.
func (r *PermissionRequest) Allow() PermissionOutcome { return r.pick("allow_once", "allow_always") }

// Deny is the first option that rejects.
func (r *PermissionRequest) Deny() PermissionOutcome { return r.pick("reject_once", "reject_always") }

// Select answers with an option.
func (r *PermissionRequest) Select(o PermissionOption) PermissionOutcome {
	return PermissionOutcome{OptionID: o.ID}
}

func (r *PermissionRequest) pick(kinds ...string) PermissionOutcome {
	for _, k := range kinds {
		for _, o := range r.Options {
			if o.Kind == k {
				return r.Select(o)
			}
		}
	}
	return Cancelled
}

type QuestionOption struct{ Label, Description string }

type Question struct {
	Question string
	Header   string
	// Multi: the answer may take several options.
	Multi   bool
	Options []QuestionOption
}

// QuestionRequest is `_p2pact/question`: several questions, or answers that may take several
// options (§9.1).
type QuestionRequest struct {
	SessionID, ToolCallID string
	Questions             []Question
	Raw                   json.RawMessage
}

// JoinLabels is the answer to a Multi question: the labels joined by ", ".
func JoinLabels(labels ...string) string { return strings.Join(labels, ", ") }
