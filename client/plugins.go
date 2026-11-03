package client

import (
	"context"
	"encoding/json"

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
		Grants []p2pact.Grant
		Read   map[string][]int
	}
	decode(r, &w)
	if w.Name == "" {
		w.Name = name
	}
	return &PluginGrants{w.Name, w.Grants, w.Read, r}, nil
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
