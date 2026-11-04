// Package client is a typed client for the public tools of P2PACT: chat (tool 1), fleet
// (tool 2) and plugins (tool 4). An application pairs with a computer (a device running a
// P2PACT engine) by its invite, and gets the typed clients of the computer's tools.
//
//	c, _ := client.New(dir, "My app", nil)          // keys and paired computers live in dir
//	defer c.Close()
//	computer, _ := c.Pair(ctx, "p2pact1.…", nil)     // asks DefaultWants
//	sessions, _ := computer.Chat().ListAllSessions(ctx, "")
//
// Calls take a context and fail with *Error (the P2PACT error codes: errors.Is(err,
// client.ErrForbidden)) or *RPCError (the tool's own errors). Typed values keep the JSON they
// were read from in Raw. Events are delivered by [Events]: a callback or a channel.
package client

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go"
)

// The names of the public tools (core spec §8) and their fixed numbers.
const (
	ToolChat    = "p2pact.chat"
	ToolFleet   = "p2pact.fleet"
	ToolPlugins = "p2pact.plugins"
	// ToolTerm is the terminal (tool 5, spec term.md); the SDK has no typed client for it: call it
	// with [Computer.CallTool]. A computer that knows it by a former name still answers once
	// the alias is declared: Node().AliasTool(former, ToolTerm).
	ToolTerm = "p2pact.term"

	numChat    = 1
	numFleet   = 2
	numPlugins = 4
)

// DefaultWants is what the SDK asks for when pairing: chat and fleet in full, the plugins'
// view. The person of the computer may narrow it ([Computer.Grants] tells what was granted).
var DefaultWants = []p2pact.Grant{
	{Tool: ToolChat, Level: p2pact.LevelWrite},
	{Tool: ToolFleet, Level: p2pact.LevelWrite},
	{Tool: ToolPlugins, Level: p2pact.LevelRead},
}

// Config is how a client reaches computers. The zero value (or nil) is fine.
type Config struct {
	// UDP is the address to listen on; "" is "0.0.0.0:0". NoUDP turns the road off.
	UDP   string
	NoUDP bool
	// TCP is the address to listen on; "" — the client only dials. NoTCP turns the road off.
	TCP   string
	NoTCP bool
	// Relay is used when a computer's invite names none.
	Relay *p2pact.RelayHint
	// CallTimeout is how long a call waits for its answer; 0 is a minute, negative — for ever.
	// Prompts never time out (the context decides). PairTimeout bounds pairing, 0 is 30 s.
	CallTimeout time.Duration
	PairTimeout time.Duration
}

// ConnectionState of a computer.
type ConnectionState int

const (
	// Offline: no live road to the computer.
	Offline ConnectionState = iota
	// Online: a session with the computer runs and it has told its tools.
	Online
)

func (s ConnectionState) String() string {
	if s == Online {
		return "online"
	}
	return "offline"
}

// ComputerEventType tells which change a [ComputerEvent] is.
type ComputerEventType int

const (
	// EventPaired: pairing finished (on our side).
	EventPaired ComputerEventType = iota + 1
	// EventOnline: the computer's hello came, a session runs, its tools are known. After a
	// restart it comes again.
	EventOnline
	// EventGrantsChanged: the computer told what we may use of its tools (event 0.6).
	EventGrantsChanged
	// EventForgotten: the computer was unpaired.
	EventForgotten
)

// ComputerEvent is a change of a computer the application may show. Grants is set for
// EventGrantsChanged.
type ComputerEvent struct {
	Type     ComputerEventType
	Computer *Computer
	Grants   []p2pact.Grant
}

// ToolEvent is an event of a tool the SDK has no typed layer for (a plugin's tool). The numbers
// are the computer's own; Tool is its name ("" — unnamed).
type ToolEvent struct {
	Computer   *Computer
	Tool       string
	ToolNumber int
	Event      int
	Args       []cbor.RawMessage
}

// Client is an application's side of P2PACT: it pairs with computers, keeps them, and gives the
// typed clients of their public tools. The state (keys, paired computers) lives in the
// directory given to [New]; keeping that safe is the application's job.
type Client struct {
	node  *p2pact.Node
	cfg   Config
	owned bool

	mu        sync.Mutex
	computers map[string]*Computer

	// ComputerEvents: pairing, hellos and grants of computers.
	ComputerEvents Events[ComputerEvent]
	// ToolEvents: events of tools without a typed layer (a plugin's tool).
	ToolEvents Events[ToolEvent]
}

// New makes a client with its own node, started and listening as the config says.
func New(dir, name string, cfg *Config) (*Client, error) {
	n, err := p2pact.NewNode(dir, name)
	if err != nil {
		return nil, err
	}
	c := newClient(n, cfg, true)
	n.Kind = p2pact.KindClient
	if !c.cfg.NoUDP {
		addr := c.cfg.UDP
		if addr == "" {
			addr = "0.0.0.0:0"
		}
		if err := n.ListenUDP(addr); err != nil {
			return nil, err
		}
	}
	if !c.cfg.NoTCP {
		if err := n.ListenTCP(c.cfg.TCP); err != nil {
			n.Close()
			return nil, err
		}
	}
	if c.cfg.Relay != nil {
		n.SetRelay(*c.cfg.Relay)
	}
	n.OnPaired = c.Paired
	n.OnHello = c.Hello
	n.OnGranted = c.Granted
	n.OnEvent = c.Event
	n.Start()
	return c, nil
}

// Wrap gives the typed clients over a node the application already runs: it owns the keys, the
// roads, the pairing and the node's callbacks. The SDK only serves the chat tool's calls from
// the computers (wrap before [p2pact.Node.Start]); cfg's roads are not used. The application
// keeps OnHello, OnEvent, OnGranted and OnPaired of the node and passes them on: [Client.Hello],
// [Client.Event], [Client.Granted], [Client.Paired]. Close leaves the node open.
func Wrap(node *p2pact.Node, cfg *Config) *Client { return newClient(node, cfg, false) }

func newClient(n *p2pact.Node, cfg *Config, owned bool) *Client {
	c := &Client{node: n, owned: owned, computers: map[string]*Computer{}}
	if cfg != nil {
		c.cfg = *cfg
	}
	// the computer's calls into the chat tool: permissions and questions of agents (chat spec §6, §9.1)
	n.Handle(numChat, 1, func(peer string, args []cbor.RawMessage) ([]any, error) {
		comp := c.computerOrNil(peer)
		if comp == nil {
			return nil, &p2pact.Error{Code: p2pact.ErrForbidden, Text: "unknown computer"}
		}
		reply := comp.chat.incoming(args)
		return nil, p2pact.Later(func() ([]any, error) { return reply(), nil })
	})
	return c
}

// Node is the protocol node, for what this SDK does not wrap. Do not set its callbacks (unless
// you wrapped it).
func (c *Client) Node() *p2pact.Node { return c.node }

// Hello is the node's OnHello: for a wrapped node, pass it on first thing.
func (c *Client) Hello(peer string) {
	if comp := c.computerOrNil(peer); comp != nil {
		comp.helloArrived()
	}
}

// Event is the node's OnEvent: for a wrapped node, in the order the node gave it.
func (c *Client) Event(peer string, tool, ev int, args []cbor.RawMessage) {
	comp := c.computerOrNil(peer)
	if comp == nil {
		return
	}
	switch {
	case tool == numChat && ev == 1:
		comp.chat.notified(args)
	case tool == numFleet && ev == 1:
		comp.fleet.notified(args)
	case tool == numPlugins && ev == 1:
		comp.plugins.notified(args)
	case tool == numPlugins:
	default:
		c.ToolEvents.emit(ToolEvent{Computer: comp, Tool: c.node.PeerToolName(peer, tool), ToolNumber: tool, Event: ev, Args: args})
	}
}

// Granted is the node's OnGranted: the computer told what we may use.
func (c *Client) Granted(peer string, grants []p2pact.Grant) {
	if comp := c.computerOrNil(peer); comp != nil {
		c.ComputerEvents.emit(ComputerEvent{Type: EventGrantsChanged, Computer: comp, Grants: grants})
	}
}

// Paired is the node's OnPaired: pairing finished.
func (c *Client) Paired(p p2pact.Peer) {
	if usable(p) {
		c.ComputerEvents.emit(ComputerEvent{Type: EventPaired, Computer: c.computerOf(p.Addr)})
	}
}

func usable(p p2pact.Peer) bool { return p.Kind != p2pact.KindPlugin && p.Kind != p2pact.KindClient }

// Pair pairs with a computer by its invite ("p2pact1.…", from `nomad invite` or the like) as a
// client application, asking for wants (nil — [DefaultWants]). It returns when the pairing is
// done; the person at the computer may narrow the grants later still: [EventGrantsChanged].
// Until the computer has told, [Computer.Grants] is empty when anything was asked.
func (c *Client) Pair(ctx context.Context, invite string, wants []p2pact.Grant) (*Computer, error) {
	inv, err := p2pact.ParseInvite(invite)
	if err != nil {
		return nil, err
	}
	if wants == nil {
		wants = DefaultWants
	}
	d := c.cfg.PairTimeout
	if d == 0 {
		d = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	peer, err := c.node.JoinWants(ctx, inv, wants)
	if err != nil {
		return nil, err
	}
	return c.computerOf(peer.Addr), nil
}

// Computers lists the paired computers.
func (c *Client) Computers() []*Computer {
	var out []*Computer
	for _, p := range c.node.Trust.List() {
		if usable(p) {
			out = append(out, c.computerOf(p.Addr))
		}
	}
	return out
}

// Computer finds a paired computer by its address ([Computer.ID]), or nil.
func (c *Client) Computer(id string) *Computer { return c.computerOrNil(id) }

// Forget unpairs a computer: its keys and conversation state go.
func (c *Client) Forget(comp *Computer) {
	c.node.Forget(comp.id)
	c.mu.Lock()
	delete(c.computers, comp.id)
	c.mu.Unlock()
	c.ComputerEvents.emit(ComputerEvent{Type: EventForgotten, Computer: comp})
}

// NetworkChanged tells the client the device's network changed (Wi-Fi to mobile): it listens
// anew and the sessions stay.
func (c *Client) NetworkChanged() {
	if c.owned && !c.cfg.NoUDP {
		addr := c.cfg.UDP
		if addr == "" {
			addr = "0.0.0.0:0"
		}
		_ = c.node.RebindUDP(addr)
	}
}

// Close stops the node, if the client made it.
func (c *Client) Close() {
	if c.owned {
		c.node.Close()
	}
}

func (c *Client) computerOrNil(addr string) *Computer {
	c.mu.Lock()
	comp := c.computers[addr]
	c.mu.Unlock()
	if comp != nil {
		return comp
	}
	if p := c.node.Trust.Get(addr); p != nil && usable(*p) {
		return c.computerOf(addr)
	}
	return nil
}

func (c *Client) computerOf(addr string) *Computer {
	c.mu.Lock()
	defer c.mu.Unlock()
	comp := c.computers[addr]
	if comp == nil {
		comp = newComputer(c, addr)
		c.computers[addr] = comp
	}
	return comp
}

// callCtx bounds a call by the configured timeout.
func (c *Client) callCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	d := c.cfg.CallTimeout
	if d == 0 {
		d = time.Minute
	}
	if d < 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

// rpcResult reads a JSON-RPC response: the result, or the tool's error.
func rpcResult(msg json.RawMessage) (json.RawMessage, error) {
	var m struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(msg, &m); err != nil {
		return nil, &Error{Code: p2pact.ErrFailed, Text: "empty response"}
	}
	if m.Error != nil {
		code := m.Error.Code
		if code == 0 {
			code = RPCFailed
		}
		return nil, &RPCError{Code: code, Message: m.Error.Message, Data: m.Error.Data}
	}
	if len(m.Result) == 0 || string(m.Result) == "null" {
		return json.RawMessage("{}"), nil
	}
	return m.Result, nil
}
