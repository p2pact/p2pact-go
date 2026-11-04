package client

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/p2pact/p2pact-go"
)

// The client against the real Nomad Code engine (Go, agent/cmd/nomadcode, TestAppE2E): the
// engine runs as a `go test` process on 127.0.0.1 with a random port, nothing of the user's
// engine is touched. Only with P2PACT_ENGINE_E2E=<path to nomad-code/agent>.

type e2eEngine struct {
	t    *testing.T
	dir  string
	log  string
	cmd  *exec.Cmd
	done chan error
}

func startEngine(t *testing.T, decide string) *e2eEngine {
	t.Helper()
	agent := os.Getenv("P2PACT_ENGINE_E2E")
	if agent == "" {
		t.Skip("P2PACT_ENGINE_E2E is not set")
	}
	e := &e2eEngine{t: t, dir: t.TempDir(), done: make(chan error, 1)}
	e.log = filepath.Join(e.dir, "engine.log")
	logf, err := os.Create(e.log)
	if err != nil {
		t.Fatal(err)
	}
	e.cmd = exec.Command("go", "test", "-count=1", "-v", "-run", "^TestAppE2E$", "./engine")
	e.cmd.Dir = agent
	e.cmd.Stdout, e.cmd.Stderr = logf, logf
	e.cmd.Env = append(os.Environ(), "NOMAD_APP_E2E="+e.dir, "NOMAD_APP_E2E_DECIDE="+decide)
	if err := e.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { e.done <- e.cmd.Wait(); logf.Close() }()
	t.Cleanup(func() {
		_ = e.cmd.Process.Kill()
	})
	return e
}

func (e *e2eEngine) tail() string {
	b, _ := os.ReadFile(e.log)
	if len(b) > 3000 {
		b = b[len(b)-3000:]
	}
	return string(b)
}

func (e *e2eEngine) waitFile(name string) string {
	e.t.Helper()
	end := time.Now().Add(2 * time.Minute)
	for time.Now().Before(end) {
		if b, err := os.ReadFile(filepath.Join(e.dir, name)); err == nil && len(b) > 0 {
			return string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Fatalf("no file %s from the engine: %s", name, e.tail())
	return ""
}

func (e *e2eEngine) finish() {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.dir, "done"), []byte("ok"), 0o600); err != nil {
		e.t.Fatal(err)
	}
	select {
	case err := <-e.done:
		if err != nil {
			e.t.Fatalf("the engine failed: %v: %s", err, e.tail())
		}
	case <-time.After(90 * time.Second):
		e.t.Fatalf("the engine did not finish: %s", e.tail())
	}
}

var e2eWants = []p2pact.Grant{{Tool: ToolChat, Level: p2pact.LevelWrite}, {Tool: ToolFleet, Level: p2pact.LevelRead}}

func e2eApp(t *testing.T) *Client {
	t.Helper()
	c, err := New(t.TempDir(), "E2E app", &Config{UDP: "127.0.0.1:0", NoTCP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// waitGrants waits for the computer to tell the grants after the person's decision.
func waitGrants(t *testing.T, c *Computer, tool string, level int) {
	t.Helper()
	eventually(t, "grants of "+tool, func() bool { return c.Level(tool) == level })
}

func TestAppE2E(t *testing.T) {
	t.Run("approved", func(t *testing.T) {
		e := startEngine(t, "yes")
		app := e2eApp(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		comp, err := app.Pair(ctx, e.waitFile("invite"), e2eWants)
		if err != nil {
			t.Fatalf("%v: %s", err, e.tail())
		}
		if err := comp.WhenOnline(ctx); err != nil {
			t.Fatal(err)
		}
		if got := e.waitFile("decision"); got != "approved" {
			t.Fatalf("decision %q", got)
		}
		waitGrants(t, comp, ToolChat, p2pact.LevelWrite)
		waitGrants(t, comp, ToolFleet, p2pact.LevelRead)

		chat := comp.Chat()
		info, err := chat.Initialize(ctx)
		if err != nil || !info.LoadSession {
			t.Fatalf("%v %+v", err, info)
		}
		list, err := chat.ListAllSessions(ctx, "")
		if err != nil || len(list) != 1 || list[0].ID != "s1" {
			t.Fatalf("%v %v", list, err)
		}
		if info.V < 2 {
			t.Fatalf("the engine does not speak v 2: %d", info.V)
		}

		// typed extension results (chat spec §9.3)
		if ag, err := chat.Agents(ctx); err != nil || ag == nil {
			t.Fatalf("agents: %v", err)
		}
		if p, err := chat.Projects(ctx, ""); err != nil || p == nil {
			t.Fatalf("projects: %v", err)
		}
		if h, err := chat.History(ctx, "", 0); err != nil || h == nil || h.Total < len(h.Items) {
			t.Fatalf("history: %v %+v", err, h)
		}

		// history
		loaded, err := chat.LoadSession(ctx, "s1", "")
		if err != nil {
			t.Fatal(err)
		}
		var texts []string
		for _, u := range loaded.Updates {
			switch u.Type {
			case UpdateUserMessage:
				texts = append(texts, "u:"+u.Text())
			case UpdateAgentMessage:
				texts = append(texts, "a:"+u.Text())
			}
		}
		if s := strings.Join(texts, "|"); !strings.Contains(s, "u:привет") || !strings.Contains(s, "a:Готово") {
			t.Fatalf("history: %v", texts)
		}

		// fleet: read
		fleet := comp.Fleet()
		fs, err := fleet.Sessions(ctx)
		if err != nil || len(fs) != 1 || fs[0].ID != "s1" {
			t.Fatalf("%v %v", fs, err)
		}
		events, stop := fleet.Events.Chan()
		defer stop()
		if _, err := fleet.Watch(ctx, false); err != nil {
			t.Fatal(err)
		}

		// the permission handler answers the engine's question
		asked := make(chan *PermissionRequest, 1)
		chat.SetPermissionHandler(func(_ context.Context, r *PermissionRequest) (PermissionOutcome, error) {
			asked <- r
			return r.Allow(), nil
		})

		// the prompt answers the Stop hook
		e.waitFile("ready")
		type result struct {
			r   *PromptResult
			err error
		}
		prompt := make(chan result, 1)
		go func() {
			r, err := chat.Prompt(ctx, "s1", "из приложения")
			prompt <- result{r, err}
		}()
		if s := e.waitFile("stop"); !strings.Contains(s, "из приложения") {
			t.Fatalf("stop: %s", s)
		}
		if r := next(t, asked); r.SessionID != "s1" {
			t.Fatalf("%+v", r)
		}
		if s := e.waitFile("perm"); !strings.Contains(s, `"behavior":"allow"`) {
			t.Fatalf("perm: %s", s)
		}
		// the turn ends once the permission is answered and the agent is idle again
		select {
		case r := <-prompt:
			if r.err != nil || r.r.StopReason != "end_turn" {
				t.Fatalf("%v %+v: %s", r.err, r.r, e.tail())
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("the prompt did not end: %s", e.tail())
		}

		// the fleet watch event about the finished turn
		deadline := time.After(20 * time.Second)
	watch:
		for {
			select {
			case ev := <-events:
				if ev.Type != FleetSessionMessages || ev.ID != "s1" {
					continue
				}
				for _, m := range ev.Messages {
					if m.Text == "Сделано" {
						break watch
					}
				}
			case <-deadline:
				t.Fatal("no fleet event with the agent's reply")
			}
		}

		// fleet is read-only for us
		if err := fleet.Send(ctx, "s1", "нельзя"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("session/send must be forbidden: %v", err)
		}
		e.finish()
	})

	t.Run("read only", func(t *testing.T) {
		e := startEngine(t, "read")
		app := e2eApp(t)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		comp, err := app.Pair(ctx, e.waitFile("invite"), e2eWants)
		if err != nil {
			t.Fatalf("%v: %s", err, e.tail())
		}
		if err := comp.WhenOnline(ctx); err != nil {
			t.Fatal(err)
		}
		if got := e.waitFile("decision"); got != "read" {
			t.Fatalf("decision %q", got)
		}
		waitGrants(t, comp, ToolChat, p2pact.LevelRead)
		list, err := comp.Chat().ListAllSessions(ctx, "")
		if err != nil || len(list) != 1 || list[0].ID != "s1" {
			t.Fatalf("%v %v", list, err)
		}
		if _, err := comp.Chat().Prompt(ctx, "s1", "нельзя"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("prompt must be forbidden: %v", err)
		}
		e.finish()
	})
}
