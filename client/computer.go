package client

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go"
)

// Computer is a paired computer: the device that runs agents. The typed clients of its tools
// hang off it: [Computer.Chat], [Computer.Fleet], [Computer.Plugins].
type Computer struct {
	owner *Client
	id    string

	chat    *ChatClient
	fleet   *FleetClient
	plugins *PluginsClient

	ready     chan struct{}
	readyOnce sync.Once
	mu        sync.Mutex
	hello     bool
}

func newComputer(c *Client, id string) *Computer {
	comp := &Computer{owner: c, id: id, ready: make(chan struct{})}
	comp.chat = &ChatClient{computer: comp, known: map[string]ChatSession{}, pending: map[string]context.CancelFunc{}}
	comp.fleet = &FleetClient{computer: comp}
	comp.plugins = &PluginsClient{computer: comp}
	return comp
}

// ID is the computer's address, the key of its pairing.
func (c *Computer) ID() string { return c.id }

// Name of the computer, as it told.
func (c *Computer) Name() string {
	if p := c.owner.node.Trust.Get(c.id); p != nil {
		return p.Name
	}
	return ""
}

// OS of the computer ("" — not told).
func (c *Computer) OS() string {
	if p := c.owner.node.Trust.Get(c.id); p != nil {
		return p.OS
	}
	return ""
}

// State: online when a session with the computer runs and it has told its tools.
func (c *Computer) State() ConnectionState {
	c.mu.Lock()
	hello := c.hello
	c.mu.Unlock()
	if hello && len(c.owner.node.Paths(c.id)) > 0 {
		return Online
	}
	return Offline
}

// Paths are the roads in use: "udp", "tcp", "relay:<address>"…
func (c *Computer) Paths() []string { return c.owner.node.Paths(c.id) }

// Grants is what the computer lets us use of its tools, as it told (event 0.6). Everything until
// it says — unless we asked for something when pairing: then nothing until it says.
func (c *Computer) Grants() []p2pact.Grant {
	if g := c.owner.node.GrantedBy(c.id); g != nil {
		return g
	}
	return p2pact.DefaultGrants()
}

// Level is the level we have on a tool of the computer: 0 none, 1 [p2pact.LevelRead], 2
// [p2pact.LevelWrite].
func (c *Computer) Level(tool string) int { return p2pact.GrantLevel(c.Grants(), tool) }

func (c *Computer) CanRead(tool string) bool  { return c.Level(tool) >= p2pact.LevelRead }
func (c *Computer) CanWrite(tool string) bool { return c.Level(tool) >= p2pact.LevelWrite }

// Chat is tool 1, p2pact.chat.
func (c *Computer) Chat() *ChatClient { return c.chat }

// Fleet is tool 2, p2pact.fleet.
func (c *Computer) Fleet() *FleetClient { return c.fleet }

// Plugins is tool 4, p2pact.plugins.
func (c *Computer) Plugins() *PluginsClient { return c.plugins }

// WhenOnline waits for the computer's hello (at once, if it has come).
func (c *Computer) WhenOnline(ctx context.Context) error {
	select {
	case <-c.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Computer) helloArrived() {
	c.mu.Lock()
	c.hello = true
	c.mu.Unlock()
	c.chat.reconnected()
	c.fleet.reconnected()
	c.plugins.reconnected()
	c.readyOnce.Do(func() { close(c.ready) })
	c.owner.ComputerEvents.emit(ComputerEvent{Type: EventOnline, Computer: c})
}

// rpc is a JSON-RPC call over the tool's `rpc` method (chat spec §2): the result object, or the
// tool's error. noTimeout leaves the wait to ctx alone.
func (c *Computer) rpc(ctx context.Context, tool int, method string, params map[string]any, stream uint64, noTimeout bool) (json.RawMessage, error) {
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		req["params"] = params
	}
	if !noTimeout {
		var cancel context.CancelFunc
		ctx, cancel = c.owner.callCtx(ctx)
		defer cancel()
	}
	res, err := c.owner.node.CallOn(ctx, c.id, stream, tool, 1, wire(req))
	if err != nil {
		return nil, typed(err)
	}
	if len(res) == 0 {
		return nil, &Error{Code: p2pact.ErrFailed, Text: "empty response"}
	}
	return rpcResult(toJSON(res[0]))
}

// notify sends a JSON-RPC notification as the tool's `notify` event.
func (c *Computer) notify(tool int, method string, params map[string]any, stream uint64) error {
	msg := map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
	return c.owner.node.EventOn(c.id, stream, tool, 1, wire(msg))
}

// ToolNumber is the number the computer gave a tool of its own (a plugin's) in its hello;
// false until it is known.
func (c *Computer) ToolNumber(name string) (int, bool) { return c.owner.node.ToolNumber(c.id, name) }

// CallTool calls a method of a tool by name; the number is the computer's own (hosted tools,
// core spec §8.2). It waits for the computer's hello if it has not come. The result elements
// are CBOR as the tool sent them.
func (c *Computer) CallTool(ctx context.Context, name string, method int, args ...any) ([]cbor.RawMessage, error) {
	if _, ok := c.ToolNumber(name); !ok {
		c.mu.Lock()
		hello := c.hello
		c.mu.Unlock()
		if !hello {
			// the hello may still be on its way after pairing
			wait := c.owner.cfg.CallTimeout
			if wait <= 0 {
				wait = 10 * time.Second
			}
			t := time.NewTimer(wait)
			defer t.Stop()
			select {
			case <-c.ready:
			case <-t.C:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	cctx, cancel := c.owner.callCtx(ctx)
	defer cancel()
	wired := make([]any, len(args))
	for i, a := range args {
		wired[i] = wire(a)
	}
	res, err := c.owner.node.CallTool(cctx, c.id, name, method, wired...)
	return res, typed(err)
}
