package client

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go"
)

// Tool 4 `p2pact.plugins` (plugins spec): the plugins a computer hosts. JSON-RPC over `4.1
// rpc`. Install and remove stay on the computer.

// PluginStatus of a plugin. Values the SDK does not know are kept as they came.
type PluginStatus string

const (
	PluginRunning    PluginStatus = "running"
	PluginStarting   PluginStatus = "starting"
	PluginRestarting PluginStatus = "restarting"
	// PluginStopped: switched off.
	PluginStopped PluginStatus = "stopped"
	// PluginFailed: disabled after repeated exits.
	PluginFailed PluginStatus = "failed"
	// PluginUnsupported: not for this system.
	PluginUnsupported PluginStatus = "unsupported"
	// PluginBroken: unreadable manifest.
	PluginBroken PluginStatus = "broken"
)

// PluginInfo is an entry of `plugins/list`.
type PluginInfo struct {
	Name    string
	Version string
	Title   string
	Enabled bool
	Status  PluginStatus
	Error   string
	// Restarts is how many times the plugin was restarted; PID is 0 when it does not run.
	Restarts int
	PID      int
	// Tools the manifest allows.
	Tools []string
	// Announced: the tools the plugin has announced now, a subset of Tools.
	Announced []string
	// Needs: `tool[:read|:write]` the plugin asked for.
	Needs []string
	Raw   json.RawMessage
}

func parsePlugin(raw json.RawMessage) PluginInfo {
	var w struct {
		Name, Version, Title string
		Enabled              bool
		Status               string
		Error                string
		Restarts, PID        int
		Tools, Announced     []string
		Needs                []string
	}
	decode(raw, &w)
	return PluginInfo{w.Name, w.Version, w.Title, w.Enabled, PluginStatus(w.Status), w.Error, w.Restarts, w.PID,
		w.Tools, w.Announced, w.Needs, clone(raw)}
}

// PluginGrants is what a plugin may use of the computer, and which methods of its own tools
// need only read.
type PluginGrants struct {
	Name   string
	Grants []p2pact.Grant
	Read   map[string][]int
	Raw    json.RawMessage
}

// PluginsClient is tool 4 `p2pact.plugins` of one computer.
type PluginsClient struct {
	computer *Computer

	// Events of the watch ([PluginsClient.Watch]) of this computer.
	Events Events[PluginEvent]

	mu       sync.Mutex
	watching bool
}

func (p *PluginsClient) call(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	return p.computer.rpc(ctx, numPlugins, method, params, 0, false)
}

// List is `plugins/list`.
func (p *PluginsClient) List(ctx context.Context) ([]PluginInfo, error) {
	r, err := p.call(ctx, "plugins/list", nil)
	if err != nil {
		return nil, err
	}
	var w struct{ Plugins json.RawMessage }
	decode(r, &w)
	return parseAll(w.Plugins, parsePlugin), nil
}

// Log is `plugins/log`: the last lines of the plugin's log (0 — the computer's choice).
func (p *PluginsClient) Log(ctx context.Context, name string, lines int) (string, error) {
	params := map[string]any{"name": name}
	if lines > 0 {
		params["lines"] = lines
	}
	r, err := p.call(ctx, "plugins/log", params)
	if err != nil {
		return "", err
	}
	var w struct{ Log string }
	decode(r, &w)
	return w.Log, nil
}

// Grants is `plugins/grants`.
func (p *PluginsClient) Grants(ctx context.Context, name string) (*PluginGrants, error) {
	r, err := p.call(ctx, "plugins/grants", map[string]any{"name": name})
	if err != nil {
		return nil, err
	}
	var w struct {
		Name   string
		Grants []struct {
			Tool  string
			Level json.RawMessage
		}
		Read map[string][]int
	}
	decode(r, &w)
	if w.Name == "" {
		w.Name = name
	}
	var grants []p2pact.Grant
	for _, g := range w.Grants {
		grants = append(grants, p2pact.Grant{Tool: g.Tool, Level: parseLevel(g.Level)})
	}
	return &PluginGrants{w.Name, grants, w.Read, r}, nil
}

// parseLevel reads a level as the engine sends it ("read"/"write"), or as a number (1/2).
func parseLevel(raw json.RawMessage) int {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch s {
		case "read":
			return p2pact.LevelRead
		case "write":
			return p2pact.LevelWrite
		}
		return 0
	}
	var n int
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	return 0
}

// PluginEvent is a `plugins/changed` event: the plugin's entry now.
type PluginEvent struct {
	Plugin PluginInfo
	// Removed: the plugin is gone; Plugin is its last entry.
	Removed bool
}

// PluginsWatch is an active watch: Close it to unsubscribe.
type PluginsWatch struct {
	// Plugins at the start.
	Plugins []PluginInfo
	c       *PluginsClient
}

// Close unsubscribes.
func (w *PluginsWatch) Close(ctx context.Context) error { return w.c.Unwatch(ctx) }

// Watch is `plugins/watch`: subscribes to Events (changes of plugins) and returns the list.
// The subscription is repeated after the computer's next hello.
func (p *PluginsClient) Watch(ctx context.Context) (*PluginsWatch, error) {
	p.mu.Lock()
	p.watching = true
	p.mu.Unlock()
	r, err := p.call(ctx, "plugins/watch", nil)
	if err != nil {
		p.mu.Lock()
		p.watching = false
		p.mu.Unlock()
		return nil, err
	}
	var w struct{ Plugins json.RawMessage }
	decode(r, &w)
	return &PluginsWatch{Plugins: parseAll(w.Plugins, parsePlugin), c: p}, nil
}

// Unwatch is `plugins/unwatch`.
func (p *PluginsClient) Unwatch(ctx context.Context) error {
	p.mu.Lock()
	p.watching = false
	p.mu.Unlock()
	_, err := p.call(ctx, "plugins/unwatch", nil)
	return err
}

func (p *PluginsClient) reconnected() {
	p.mu.Lock()
	w := p.watching
	p.mu.Unlock()
	if !w {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = p.call(ctx, "plugins/watch", nil)
	}()
}

func (p *PluginsClient) notified(args []cbor.RawMessage) {
	if len(args) == 0 {
		return
	}
	var msg struct {
		Method string
		Params json.RawMessage
	}
	decode(toJSON(args[0]), &msg)
	if msg.Method != "plugins/changed" {
		return
	}
	var rm struct{ Removed bool }
	decode(msg.Params, &rm)
	p.Events.emit(PluginEvent{Plugin: parsePlugin(msg.Params), Removed: rm.Removed})
}

// Enable starts a plugin (and keeps it on across the computer's restarts). Needs write.
func (p *PluginsClient) Enable(ctx context.Context, name string) error {
	_, err := p.call(ctx, "plugins/enable", map[string]any{"name": name})
	return err
}

// Disable switches a plugin off. Needs write.
func (p *PluginsClient) Disable(ctx context.Context, name string) error {
	_, err := p.call(ctx, "plugins/disable", map[string]any{"name": name})
	return err
}

// CallTool calls a method of a tool a plugin of the computer serves (core spec §8.2) by the
// tool's name; the number is the computer's own. See [Computer.CallTool].
func (p *PluginsClient) CallTool(ctx context.Context, name string, method int, args ...any) ([]cbor.RawMessage, error) {
	return p.computer.CallTool(ctx, name, method, args...)
}
