package client

import (
	"reflect"
	"testing"
)

// legacy is a fixture answer as an engine without typed results sends it: only `lines`.
func legacy(m map[string]any) map[string]any {
	res := asMap(m["result"])
	return map[string]any{"jsonrpc": "2.0", "result": map[string]any{"lines": res["lines"]}}
}

// TestTypedExtensions runs every typed call against its fixture twice: the fixture as is (typed
// result) and with the typed fields stripped (only `lines`, an older engine).
func TestTypedExtensions(t *testing.T) {
	for _, form := range []string{"typed", "legacy"} {
		t.Run(form, func(t *testing.T) {
			v := connect(t, nil, nil)
			v.engine.override("1:_p2pact/image", func(map[string]any) map[string]any {
				return fixture(t, "p2pact.chat", "_p2pact.image.data.response")
			})
			if form == "legacy" {
				for _, m := range []string{"older", "commands", "files", "history", "history_open", "projects", "agents", "diff", "close", "restart", "hide"} {
					name := "_p2pact." + m
					v.engine.override("1:_p2pact/"+m, func(map[string]any) map[string]any {
						return legacy(fixture(t, "p2pact.chat", name+".response"))
					})
				}
				v.engine.override("1:_p2pact/image", func(map[string]any) map[string]any {
					return legacy(fixture(t, "p2pact.chat", "_p2pact.image.data.response"))
				})
			}
			chat, ctx := v.computer.Chat(), ctx5(t)
			sent := func(m, fx string) { t.Helper(); v.assertSent(1, "_p2pact/"+m, "p2pact.chat", "_p2pact."+fx+".request") }

			if info, _ := chat.Initialize(ctx); info == nil || info.V != 2 {
				t.Fatalf("initialize %+v", info)
			}
			v.assertSent(1, "initialize", "p2pact.chat", "initialize.request")

			page, err := chat.Older(ctx, "s1", 3)
			if err != nil || len(page.Messages) != 1 || page.Messages[0].Text != "привет" || page.More {
				t.Fatalf("%v %+v", err, page)
			}
			if form == "typed" && page.Run != "r1" {
				t.Fatalf("run %q", page.Run)
			}
			sent("older", "older")

			cmds, err := chat.Commands(ctx, "s1")
			want := []SlashCommand{{Name: "review", Desc: "Review the changes", Hint: "<pr>", Args: []SlashArg{{"main", "base branch"}}}}
			if err != nil || len(cmds) != 1 {
				t.Fatalf("%v %+v", err, cmds)
			}
			cmds[0].Raw = nil
			if !reflect.DeepEqual(cmds, want) {
				t.Fatalf("%+v", cmds)
			}
			sent("commands", "commands")

			files, err := chat.Files(ctx, "s1", "fac")
			if err != nil || !reflect.DeepEqual(files, []string{"agent/pkg/acpchat/facade.go"}) {
				t.Fatalf("%v %v", err, files)
			}
			sent("files", "files")

			h, err := chat.History(ctx, "", 0)
			if err != nil || len(h.Items) != 1 || h.Total != 2 || h.From != 0 {
				t.Fatalf("%v %+v", err, h)
			}
			if it := h.Items[0]; it.ID != "h1" || it.Agent != "claude" || it.Dir != "/w/proj" || it.Title != "Fix the build" || it.Updated != 1793700000000 || it.Count != 12 || it.Open {
				t.Fatalf("%+v", it)
			}
			if form == "typed" && (!h.HasMore || h.Cursor != 1) {
				t.Fatalf("cursor %+v", h)
			}
			sent("history", "history")

			if r, err := chat.HistoryOpen(ctx, "h1"); err != nil || !r.OK {
				t.Fatalf("%v %+v", err, r)
			}
			sent("history_open", "history_open")

			p, err := chat.Projects(ctx, "/w/proj")
			if err != nil || !reflect.DeepEqual(p.Dirs, []string{"/w/proj"}) ||
				!reflect.DeepEqual(p.ProjectDirs, map[string][]string{"proj": {"/w/proj", "/w/proj-api"}}) ||
				p.DirRepos["/w/proj"] != "git@example.com:team/proj.git" {
				t.Fatalf("%v %+v", err, p)
			}
			sent("projects", "projects")

			ag, err := chat.Agents(ctx)
			if err != nil || len(ag.Agents) != 1 || len(ag.Presets) != 1 {
				t.Fatalf("%v %+v", err, ag)
			}
			if a := ag.Agents[0]; a.ID != "claude" || a.Name != "Claude Code" || a.Type != "claude" || !a.Enabled || !reflect.DeepEqual(a.Models, []string{"opus", "sonnet"}) || a.Default != "sonnet" {
				t.Fatalf("%+v", a)
			}
			if ag.Presets[0].ID != "p1" || ag.Presets[0].Name != "Claude Sonnet" {
				t.Fatalf("%+v", ag.Presets)
			}
			sent("agents", "agents")

			img, err := chat.Image(ctx, "s1", "/w/proj/ok.png")
			if err != nil || img.Error != "" || img.Data == "" {
				t.Fatalf("%v %+v", err, img)
			}
			if form == "typed" && (img.Path != "/w/proj/ok.png" || img.Mime != "image/png") {
				t.Fatalf("%+v", img)
			}
			sent("image", "image.data")

			d, err := chat.Diff(ctx, "s1")
			if err != nil || len(d.Files) != 1 || d.Files[0].Status != "M" || d.Patch == "" {
				t.Fatalf("%v %+v", err, d)
			}
			sent("diff", "diff")

			for name, call := range map[string]func() (*OKResult, error){
				"close":   func() (*OKResult, error) { return chat.CloseChat(ctx, "s1") },
				"restart": func() (*OKResult, error) { return chat.RestartChat(ctx, "s1") },
				"hide":    func() (*OKResult, error) { return chat.HideChat(ctx, "s1", true) },
			} {
				if r, err := call(); err != nil || !r.OK || r.Error != "" {
					t.Fatalf("%s: %v %+v", name, err, r)
				}
				sent(name, name)
			}
		})
	}
}

func TestTypedWriteFailure(t *testing.T) {
	v := connect(t, nil, nil)
	v.engine.override("1:_p2pact/restart", func(map[string]any) map[string]any {
		return map[string]any{"jsonrpc": "2.0", "result": map[string]any{"ok": false, "error": "not run here", "lines": []any{}}}
	})
	r, err := v.computer.Chat().RestartChat(ctx5(t), "s1")
	if err != nil || r.OK || r.Error != "not run here" {
		t.Fatalf("%v %+v", err, r)
	}
}

func TestTypedErrorsOfImage(t *testing.T) {
	v := connect(t, nil, nil)
	img, err := v.computer.Chat().Image(ctx5(t), "s1", "/w/proj/shot.png")
	if err != nil || img.Error != "not_found" || img.Path != "/w/proj/shot.png" || img.Data != "" {
		t.Fatalf("%v %+v", err, img)
	}
}
