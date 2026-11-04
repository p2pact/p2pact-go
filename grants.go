package p2pact

import (
	"errors"
	"slices"

	"github.com/fxamacker/cbor/v2"
)

// Levels of a grant (spec §8.1).
const (
	LevelRead  = 1 // the methods a tool marks as read, and the tool's events
	LevelWrite = 2 // everything
)

// AllTools is the tool name that stands for every tool, present and future.
const AllTools = "*"

// Grant lets a device use a tool at a level: one element of [[tool name, level]…] (spec §8.1).
type Grant struct {
	Tool  string `json:"tool"`
	Level int    `json:"level"`
}

// DefaultGrants is what a person's own device gets: everything, ["*", 2]. A trusted device
// whose grants were never set has it too.
func DefaultGrants() []Grant { return []Grant{{AllTools, LevelWrite}} }

// GrantLevel is the level a list of grants gives for a tool name: the highest of the entries
// that name it or "*"; 0 — none. A nil list is the default (everything).
func GrantLevel(grants []Grant, tool string) int {
	if grants == nil {
		return LevelWrite
	}
	level := 0
	for _, g := range grants {
		if (g.Tool == tool || g.Tool == AllTools) && g.Level > level {
			level = g.Level
		}
	}
	return level
}

// Allowed is what we let the device use of ours (spec §8.1); the default if never set.
func (p Peer) Allowed() []Grant {
	if p.Grants == nil {
		return DefaultGrants()
	}
	return slices.Clone(p.Grants)
}

// Offered is what the device lets us use of its tools, as it told us; the default if it never did.
func (p Peer) Offered() []Grant {
	if p.Granted == nil {
		return DefaultGrants()
	}
	return slices.Clone(p.Granted)
}

// grantsWire is the grants as they go on the wire: [[tool name, level]…].
func grantsWire(g []Grant) [][]any {
	out := make([][]any, 0, len(g))
	for _, x := range g {
		out = append(out, []any{x.Tool, x.Level})
	}
	return out
}

// parseGrants reads [[tool name, level]…]; a malformed entry is skipped.
func parseGrants(raw cbor.RawMessage) ([]Grant, bool) {
	var list []cbor.RawMessage
	if cbor.Unmarshal(raw, &list) != nil {
		return nil, false
	}
	out := make([]Grant, 0, len(list))
	for _, e := range list {
		var pair []cbor.RawMessage
		var g Grant
		if cbor.Unmarshal(e, &pair) != nil || len(pair) < 2 || cbor.Unmarshal(pair[0], &g.Tool) != nil ||
			cbor.Unmarshal(pair[1], &g.Level) != nil || g.Level < 1 {
			continue
		}
		if g.Level > LevelWrite {
			g.Level = LevelWrite
		}
		out = append(out, g)
	}
	return out, true
}

// cleanGrants drops entries without a level and merges repeats, keeping the highest.
func cleanGrants(in []Grant) []Grant {
	out := []Grant{}
	for _, g := range in {
		if g.Tool == "" || g.Level < 1 {
			continue
		}
		if g.Level > LevelWrite {
			g.Level = LevelWrite
		}
		if i := slices.IndexFunc(out, func(x Grant) bool { return x.Tool == g.Tool }); i >= 0 {
			out[i].Level = max(out[i].Level, g.Level)
			continue
		}
		out = append(out, g)
	}
	return out
}

// LevelHandler is a tool method that checks the caller's level itself: the node only requires
// read, and passes the level (1 or 2) on. For a tool whose single method carries many (chat
// 1.1: one P2PACT method for all of ACP), where what a call needs depends on its arguments.
type LevelHandler func(peer string, level int, args []cbor.RawMessage) ([]any, error)

// HandleLevel registers method tool.method like [Node.Handle], for a handler that checks the
// level itself (see [LevelHandler]).
func (n *Node) HandleLevel(tool, method int, h LevelHandler) {
	n.mu.Lock()
	n.levelHandlers[[2]int{tool, method}] = h
	n.mu.Unlock()
}

// MarkRead declares methods of a tool as read (spec §8.1): a device with read on the tool may
// call them. The others are write.
func (n *Node) MarkRead(tool int, methods ...int) {
	n.mu.Lock()
	for _, m := range methods {
		n.readMethods[[2]int{tool, m}] = true
	}
	n.mu.Unlock()
}

// Grants is what we let a device use of ours (spec §8.1).
func (n *Node) Grants(peer string) []Grant {
	if p := n.Trust.Get(peer); p != nil {
		return p.Allowed()
	}
	return nil
}

// GrantedBy is what a device lets us use of its tools, as it told us (event 0.6 or method 0.6);
// the default if it never did.
func (n *Node) GrantedBy(peer string) []Grant {
	if p := n.Trust.Get(peer); p != nil {
		return p.Offered()
	}
	return nil
}

// Level is the level a device has on one of our tools, by name (counting its aliases, [Node.AliasTool]).
func (n *Node) Level(peer, tool string) int {
	if p := n.Trust.Get(peer); p != nil {
		return n.LevelIn(p.Grants, tool)
	}
	return 0
}

// SetGrants replaces what a trusted device may use (an empty list revokes everything), keeps
// it with the trust and tells the device with event 0.6.
func (n *Node) SetGrants(peer string, grants []Grant) error {
	grants = cleanGrants(grants)
	if !n.Trust.SetGrants(peer, grants) {
		return errors.New("unknown device")
	}
	return n.Event(peer, 0, 6, grantsWire(grants))
}

// Grant changes one entry: the device gets level on the tool (LevelRead, LevelWrite); level 0
// removes the entry.
func (n *Node) Grant(peer, tool string, level int) error {
	p := n.Trust.Get(peer)
	if p == nil {
		return errors.New("unknown device")
	}
	var list []Grant
	for _, g := range p.Allowed() {
		if g.Tool != tool {
			list = append(list, g)
		}
	}
	if level > 0 {
		list = append(list, Grant{tool, level})
	}
	return n.SetGrants(peer, list)
}

// RevokeGrants takes everything away from a device but tool 0: it stays trusted and in session.
func (n *Node) RevokeGrants(peer string) error { return n.SetGrants(peer, []Grant{}) }

// grantsHandler is method 0.6: what the caller may use on this device.
func (n *Node) grantsHandler(peer string, _ []cbor.RawMessage) ([]any, error) {
	return []any{grantsWire(n.Grants(peer))}, nil
}

// grantsEventLocked tells the device what it may use, unless we never set it (the default it
// assumes). A newcomer that asked has been granted something explicit, even ["*", 2]: it waits
// for this event (spec §2).
func (n *Node) grantsEventLocked(peer string) {
	p := n.Trust.Get(peer)
	if p == nil || p.Grants == nil {
		return
	}
	msg, _ := cbor.Marshal([]any{3, 0, 6, grantsWire(p.Grants)})
	n.pushLocked(n.peerLocked(peer), msg, 0, false, false)
}

// requiredLevelLocked is the level a call needs.
func (n *Node) requiredLevelLocked(tool, method int) int {
	if n.levelHandlers[[2]int{tool, method}] != nil || n.readMethods[[2]int{tool, method}] ||
		(n.toolHandlers[tool] != nil && n.handlers[[2]int{tool, method}] == nil) {
		return LevelRead
	}
	return LevelWrite
}
