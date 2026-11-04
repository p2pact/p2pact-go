package client

import (
	"context"
	"encoding/json"
)

// Typed calls of the chat extensions (chat spec §9.3, §10). Each reads the typed fields of the
// result first; against an older engine, which answers with `lines` only, it reads the line of
// the command, as before.

// Older is `_p2pact/older`: the page of messages just before `before` (the `seq` of the oldest
// you have).
func (c *ChatClient) Older(ctx context.Context, sessionID string, before int64) (*OlderPage, error) {
	res, lines, err := c.extension(ctx, "older", map[string]any{"sessionId": sessionID, "before": before})
	if err != nil {
		return nil, err
	}
	l := pickResult(res, lines, "messages", "older")
	var w struct {
		Messages json.RawMessage `json:"messages"`
		More     bool            `json:"more"`
		Run      string          `json:"run"`
	}
	decode(l, &w)
	msgs := parseAll(w.Messages, func(r json.RawMessage) ChatMessage {
		var m struct {
			Seq    int64
			Role   string
			Text   string
			Time   string
			Images []string
		}
		decode(r, &m)
		return ChatMessage{m.Seq, m.Role, m.Text, m.Time, m.Images, clone(r)}
	})
	return &OlderPage{sessionID, msgs, w.More, clone(l), w.Run}, nil
}

// Commands is `_p2pact/commands`: the agent's slash commands of this chat, for completion.
func (c *ChatClient) Commands(ctx context.Context, sessionID string) ([]SlashCommand, error) {
	res, lines, err := c.extension(ctx, "commands", map[string]any{"sessionId": sessionID})
	if err != nil {
		return nil, err
	}
	l := pickResult(res, lines, "commands", "commands")
	var w struct{ Commands, List json.RawMessage } // List: the line of an older engine
	decode(l, &w)
	if w.Commands == nil {
		w.Commands = w.List
	}
	return parseAll(w.Commands, func(r json.RawMessage) SlashCommand {
		var s struct {
			Name, Desc, Hint string
			Args             []struct{ Value, Desc string }
		}
		decode(r, &s)
		cmd := SlashCommand{Name: s.Name, Desc: s.Desc, Hint: s.Hint, Raw: clone(r)}
		for _, a := range s.Args {
			cmd.Args = append(cmd.Args, SlashArg{a.Value, a.Desc})
		}
		return cmd
	}), nil
}

// Files is `_p2pact/files`: files of the chat's folder matching the query (for `@file`
// completion), relative paths, up to 50.
func (c *ChatClient) Files(ctx context.Context, sessionID, query string) ([]string, error) {
	res, lines, err := c.extension(ctx, "files", map[string]any{"sessionId": sessionID, "query": query})
	if err != nil {
		return nil, err
	}
	l := pickResult(res, lines, "files", "files")
	var w struct{ Files, List []string }
	decode(l, &w)
	if w.Files == nil {
		w.Files = w.List
	}
	return w.Files, nil
}

// History is `_p2pact/history`: closed conversations of the agents on the device, newest first.
// query is a text search (empty — all), offset the start (0 — first page, then
// [HistoryPage.Cursor]).
func (c *ChatClient) History(ctx context.Context, query string, offset int) (*HistoryPage, error) {
	res, lines, err := c.extension(ctx, "history", map[string]any{"query": query, "offset": offset})
	if err != nil {
		return nil, err
	}
	l := pickResult(res, lines, "items", "history")
	var w struct {
		Items, List json.RawMessage
		Query       string
		From, Total int
		Cursor      *int
		Partial     bool
	}
	decode(l, &w)
	if w.Items == nil {
		w.Items = w.List
	}
	p := &HistoryPage{Query: w.Query, From: w.From, Total: w.Total, Partial: w.Partial, Raw: clone(l)}
	if w.Cursor != nil {
		p.Cursor, p.HasMore = *w.Cursor, true
	}
	p.Items = parseAll(w.Items, func(r json.RawMessage) HistoryItem {
		var h HistoryItem
		decode(r, &h)
		h.Raw = clone(r)
		return h
	})
	return p, nil
}

// Projects is `_p2pact/projects`: folders to start a chat in; cwd is an extra folder to describe
// (optional, "" — none).
func (c *ChatClient) Projects(ctx context.Context, cwd string) (*Projects, error) {
	params := map[string]any{}
	if cwd != "" {
		params["cwd"] = cwd
	}
	res, lines, err := c.extension(ctx, "projects", params)
	if err != nil {
		return nil, err
	}
	l := pickResult(res, lines, "dirs", "projects")
	p := &Projects{Raw: clone(l)}
	decode(l, &struct {
		Dirs        *[]string            `json:"dirs"`
		ProjectDirs *map[string][]string `json:"project_dirs"`
		DirRepos    *map[string]string   `json:"dir_repos"`
	}{&p.Dirs, &p.ProjectDirs, &p.DirRepos})
	return p, nil
}

// Agents is `_p2pact/agents`: agents with the models they offer for [NewSessionOptions.Model],
// and the ready-made presets (agent + model), the first is the main one.
func (c *ChatClient) Agents(ctx context.Context) (*AgentList, error) {
	res, lines, err := c.extension(ctx, "agents", nil)
	if err != nil {
		return nil, err
	}
	var w struct{ Agents, Presets json.RawMessage }
	decode(res, &w)
	if w.Agents == nil {
		// an older engine: the lines `agents` and `presets`, each with a `list`
		var a, p struct{ List json.RawMessage }
		decode(commandLine(lines, "agents"), &a)
		decode(commandLine(lines, "presets"), &p)
		w.Agents, w.Presets = a.List, p.List
	}
	out := &AgentList{Raw: clone(res)}
	out.Agents = parseAll(w.Agents, func(r json.RawMessage) AgentModels {
		var a AgentModels
		decode(r, &a)
		a.Raw = clone(r)
		return a
	})
	out.Presets = parseAll(w.Presets, func(r json.RawMessage) AgentPreset {
		var p AgentPreset
		decode(r, &p)
		p.Raw = clone(r)
		return p
	})
	return out, nil
}

// Diff is `_p2pact/diff`: the changes in the chat's folder (git).
func (c *ChatClient) Diff(ctx context.Context, sessionID string) (*DiffResult, error) {
	res, lines, err := c.extension(ctx, "diff", map[string]any{"sessionId": sessionID})
	if err != nil {
		return nil, err
	}
	l := res
	if !hasKey(res, "files") && !hasKey(res, "error") {
		l = commandLine(lines, "diff")
	}
	var w struct {
		Files []struct {
			Path           string
			Added, Removed int
			Status         string
		}
		Patch     string
		Truncated bool
		Error     string
	}
	decode(l, &w)
	d := &DiffResult{Patch: w.Patch, Truncated: w.Truncated, Error: w.Error, Raw: clone(l)}
	for _, f := range w.Files {
		d.Files = append(d.Files, DiffFile{f.Path, f.Added, f.Removed, f.Status})
	}
	return d, nil
}

// Image is `_p2pact/image`: the bytes (base64) of an image a message points to.
func (c *ChatClient) Image(ctx context.Context, sessionID, path string) (*ImageResult, error) {
	res, lines, err := c.extension(ctx, "image", map[string]any{"sessionId": sessionID, "path": path})
	if err != nil {
		return nil, err
	}
	l := res
	if !hasKey(res, "data") && !hasKey(res, "error") {
		l = commandLine(lines, "image")
	}
	var w struct{ Path, Mime, Data, Error string }
	decode(l, &w)
	return &ImageResult{w.Data, w.Error, clone(l), w.Path, w.Mime}, nil
}

func hasKey(raw json.RawMessage, key string) bool {
	var m map[string]json.RawMessage
	decode(raw, &m)
	_, ok := m[key]
	return ok
}
