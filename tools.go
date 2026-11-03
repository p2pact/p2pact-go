package p2pact

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// Tools given by the spec (§8): the same number on every device. Their names are what grants
// (§8.1) are written in.
var fixedTools = map[string]int{
	"p2pact.service": 0,
	"p2pact.chat":    1,
	"p2pact.fleet":   2,
	"p2pact.family":  3,
	"p2pact.plugins": 4,
}

// FirstNamedTool is the first number a device may choose for a named tool (spec §8).
const FirstNamedTool = 64

// ValidToolName reports a tool name of spec §8: lowercase, dot-separated, the reverse of a
// domain ("com.example.jira"). Names under "p2pact." are given by the spec.
func ValidToolName(name string) bool {
	parts := strings.Split(name, ".")
	if len(parts) < 2 || parts[0] == "p2pact" {
		return false
	}
	for _, p := range parts {
		if p == "" || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// toolRef is a named tool on a device: its number there and its version.
type toolRef struct{ Number, Version int }

// RegisterTool gives a tool of ours a name and picks its number: the first one from 64 up that
// no other tool of ours uses. The same name gets the same number for the rest of the run. The
// number is announced in the hello's named map (spec §8), and the devices in session get the
// new hello at once. Other devices may number the same name differently: callers use
// [Node.ToolNumber].
func (n *Node) RegisterTool(name string, version int) (int, error) {
	if !ValidToolName(name) {
		return 0, errors.New("bad tool name: " + name)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if num, ok := n.names[name]; ok {
		if n.versions[num] != version {
			n.versions[num] = version
			n.reannounceToolsLocked()
		}
		return num, nil
	}
	num := FirstNamedTool
	for n.toolUsedLocked(num) {
		num++
	}
	n.names[name] = num
	n.numbers[num] = name
	n.versions[num] = version
	n.reannounceToolsLocked()
	return num, nil
}

func (n *Node) toolUsedLocked(num int) bool {
	if _, ok := n.numbers[num]; ok {
		return true
	}
	for k := range n.handlers {
		if k[0] == num {
			return true
		}
	}
	return false
}

func (n *Node) reannounceToolsLocked() {
	for peer := range n.current {
		n.sendInfoLocked(peer)
	}
}

// HandleTool registers method of the named tool (the tool is registered at version 1 if it is
// not yet) and returns nothing else to do: [Node.Handle] by name.
func (n *Node) HandleTool(name string, method int, h Handler) error {
	num, ok := fixedTools[name]
	if !ok {
		var err error
		if num, err = n.RegisterTool(name, 1); err != nil {
			return err
		}
	}
	n.Handle(num, method, h)
	return nil
}

// ToolName is the name of a tool of ours by its number ("" — it has none: a number of the
// implementation's own).
func (n *Node) ToolName(tool int) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.toolNameLocked(tool)
}

func (n *Node) toolNameLocked(tool int) string {
	for name, num := range fixedTools {
		if num == tool {
			return name
		}
	}
	return n.numbers[tool]
}

// ToolNumber resolves a tool name to the number the device announced for it in its hello (spec
// §8); the tools of the spec have their fixed numbers. false — the device has not announced it
// (or we have not heard its hello yet).
func (n *Node) ToolNumber(peer, name string) (int, bool) {
	if num, ok := fixedTools[name]; ok {
		return num, true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if ps := n.peers[peer]; ps != nil {
		if ref, ok := ps.named[name]; ok {
			return ref.Number, true
		}
	}
	return 0, false
}

// PeerToolName is the name of a tool of a device by the number it announced: what an OnEvent
// handler needs ("" — unnamed).
func (n *Node) PeerToolName(peer string, tool int) string {
	for name, num := range fixedTools {
		if num == tool {
			return name
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if ps := n.peers[peer]; ps != nil {
		for name, ref := range ps.named {
			if ref.Number == tool {
				return name
			}
		}
	}
	return ""
}

// CallTool is [Node.Call] by tool name: the number is the device's own.
func (n *Node) CallTool(ctx context.Context, peer, name string, method int, args ...any) ([]cbor.RawMessage, error) {
	return n.CallToolOn(ctx, peer, 0, name, method, args...)
}

// CallToolOn is [Node.CallOn] by tool name.
func (n *Node) CallToolOn(ctx context.Context, peer string, stream uint64, name string, method int, args ...any) ([]cbor.RawMessage, error) {
	num, ok := n.ToolNumber(peer, name)
	if !ok {
		return nil, &Error{Code: ErrNoMethod, Text: "the device has no tool " + name}
	}
	return n.CallOn(ctx, peer, stream, num, method, args...)
}

// namedLocked is the hello's named map: {name: [tool, version]}.
func (n *Node) namedLocked() map[string][2]int {
	out := make(map[string][2]int, len(n.names))
	for name, num := range n.names {
		out[name] = [2]int{num, n.versions[num]}
	}
	return out
}

// ToolHandler is one handler for every method of a tool (see [Node.HandleToolAll]): it gets the
// method number and the caller's level (1 or 2), and checks the level itself.
type ToolHandler func(peer string, level, method int, args []cbor.RawMessage) ([]any, error)

// HandleToolAll serves every method of the named tool with h (the tool is registered at version
// 1 if it is not yet). The node only requires read on the tool; what each method needs is for h
// to check. Methods registered one by one with [Node.Handle] keep their own handlers. For a
// device that hosts another program's tool (spec §8.2).
func (n *Node) HandleToolAll(name string, h ToolHandler) error {
	num, err := n.RegisterTool(name, 1)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.toolHandlers[num] = h
	n.mu.Unlock()
	return nil
}

// UnregisterTool takes a named tool back: it leaves the hello (sent again to the devices in
// session) and its handlers are dropped. Registering the name again may give another number.
func (n *Node) UnregisterTool(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	num, ok := n.names[name]
	if !ok {
		return
	}
	delete(n.names, name)
	delete(n.numbers, num)
	delete(n.versions, num)
	delete(n.toolHandlers, num)
	for k := range n.handlers {
		if k[0] == num {
			delete(n.handlers, k)
		}
	}
	for k := range n.levelHandlers {
		if k[0] == num {
			delete(n.levelHandlers, k)
		}
	}
	for k := range n.readMethods {
		if k[0] == num {
			delete(n.readMethods, k)
		}
	}
	n.reannounceToolsLocked()
}

// PeerTools lists the named tools a device announced in its hello, sorted by name.
func (n *Node) PeerTools(peer string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []string
	if ps := n.peers[peer]; ps != nil {
		for name := range ps.named {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
