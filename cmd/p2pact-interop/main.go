// Command p2pact-interop is the reference interop peer for p2pact-tests: a P2PACT node driven
// by JSON lines on stdin, answering on stdout. Every implementation ships one with the same
// commands, so any two can be tested against each other.
//
//	{"cmd":"listen","udp":"127.0.0.1:0","tcp":"127.0.0.1:0"}  → {"addr":"…","udp":"…","tcp":"…"}
//	{"cmd":"invite"}                                          → {"invite":"p2pact1.…"}
//	{"cmd":"join","invite":"…"}                               → {"peer":"…"}
//	{"cmd":"known","peer":"…"}                                → {"known":true|false}
//	{"cmd":"call","peer":"…","data":"<base64>","stream":N}    → {"data":"<base64>"}  (echo, tool 64 method 1; stream optional)
//	{"cmd":"later","peer":"…","data":"<base64>","stream":N}   → {"data":"<base64>"}
//	  a call answered later (spec §6): calls tool 64 method 2 on the stream, which the other
//	  side holds until a 64.1 call reaches it, then a 64.1 call on the same stream; answers with
//	  the 64.2 result, or an error if the 64.1 call waited behind the held one
//	{"cmd":"dict","raw":"<base64>"}                           → {"ok":true}
//	{"cmd":"road","listen":"127.0.0.1:0","mtu":20,"rate":N}   → {"road":"127.0.0.1:…"}
//	{"cmd":"road","dial":"127.0.0.1:…","mtu":20,"rate":N,"peer":"…"} → {"ok":true}
//	  an application road (stream) over a local TCP connection that stands in for a Bluetooth
//	  LE link: writes of at most mtu bytes, paced to rate bytes a second (0 — not paced); the
//	  listening side attaches the first connection it accepts; peer optional (bound road)
//	{"cmd":"relay","addr":"host:port","fp":"hex","ws":["wss://…"]} → {"ok":true}
//	  uses a relay (TLS address and certificate fingerprint) and tells its WebSocket URLs in
//	  the hints, so a browser can pair by our invite; say it before "invite"
//	{"cmd":"advertise","hints":{"udp":["…"],"tcp":["…"]}}    → {"ok":true}
//	  announces these addresses instead of our own (invites, hellos); the address our relay
//	  sees us at still joins the UDP ones; "hints" absent or null — our own addresses again
//	{"cmd":"close"}
//
// Kinds, named tools, grants, wants, the local socket and hosted tools (spec §1, §2, §8):
//
//	{"cmd":"kind","kind":N}                                   → {"ok":true}   (say it before pairing; 0 — not said)
//	{"cmd":"peer-info","peer":"…","tool":"name"}              → {"kind":N,"tools":["…"],"number":N|null}
//	  what we know of a device: the kind it told (pairing, hello), the named tools it announced,
//	  and the number it gave the named tool (null — not announced)
//	{"cmd":"tool","name":"…"}                                 → {"number":N}
//	  registers a named tool of ours: method 1 echoes (read), 2 echoes (write), 3 answers the tool's
//	  name (read)
//	{"cmd":"call-tool","peer":"…","name":"…","method":N,"data":"<base64>","stream":N} → {"data":"<base64>"}
//	  calls a tool by name; an error answer carries "code" (the call's error code, 4 — forbidden)
//	{"cmd":"grant","peer":"…","tool":"…","level":N}           → {"ok":true}   (level 0 removes the entry)
//	{"cmd":"set-grants","peer":"…","grants":[["tool",N]…]}      → {"ok":true}   (replaces the list; [] takes everything away)
//	{"cmd":"grants","peer":"…"}                               → {"allowed":[["tool",N]…],"granted":[["tool",N]…]}
//	  what we let the device use, and what it lets us use (as it told us: event 0.6)
//	{"cmd":"emit","peer":"…","name":"…","event":N,"data":"<base64>"} → {"ok":true}
//	  sends an event of our named tool (it goes only to a device with read on the tool)
//	{"cmd":"events"}                                          → {"events":[{"peer":"…","tool":"name","event":N,"data":"<base64>"}]}
//	  the events received so far (tool 0 left out)
//	{"cmd":"on-wants","level":N}                              → {"ok":true}
//	  from now on a newcomer is granted what it wanted, narrowed to level N at most
//	join takes "wants":[["tool",N]…] (permissions asked for)
//	{"cmd":"local","listen":"path"} | {"cmd":"local","use":"path"} → {"ok":true}
//	  opens the local socket (a device) or reaches a device over its socket (a program)
//	{"cmd":"plugin-env","grants":[["tool",N]…]}               → {"socket":"path","invite":"p2pact1.…"}
//	  the environment for a program the device starts (P2PACT_SOCKET, P2PACT_INVITE)
//	{"cmd":"proxy","name":"…","plugin":"…"}                   → {"ok":true}
//	  hosts the named tool for a program paired as a plugin: one handler for all its methods
//	  (method 2 needs write), every call is forwarded to the program's tool of that name
//
// Via a third device (spec §3):
//
//	{"cmd":"hide"}                                            → {"ok":true}
//	  announces no addresses from now on (in invites and hellos): known devices reach us only
//	  over roads they already have, or through a forwarder
//	{"cmd":"forward","a":"…","b":"…","on":true|false}         → {"ok":true}
//	  opts in (or out) as a forwarder between two devices we trust
//	{"cmd":"paths","peer":"…"}                                → {"paths":["udp","via:<forwarder>",…]}
//	  the live roads to a known device (also "tcp", "relay:<address>", "local", "app:<name>")
//	{"cmd":"forward-stats"}                                   → {"forwarded":N,"dropped":N}
//
// Errors: {"error":"…"}. Usage: p2pact-interop [data dir] [name]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	p2pact "github.com/p2pact/p2pact-go"
)

// grantsIn reads [["tool",N]…]; grantsOut writes them back.
func grantsIn(l [][]any) []p2pact.Grant {
	var out []p2pact.Grant
	for _, e := range l {
		if len(e) == 2 {
			t, _ := e[0].(string)
			lv, _ := e[1].(float64)
			out = append(out, p2pact.Grant{Tool: t, Level: int(lv)})
		}
	}
	return out
}

func grantsOut(g []p2pact.Grant) [][]any {
	out := [][]any{}
	for _, x := range g {
		out = append(out, []any{x.Tool, x.Level})
	}
	return out
}

func rawArgs(args []cbor.RawMessage) []any {
	out := make([]any, len(args))
	for i, a := range args {
		out[i] = a
	}
	return out
}

func main() {
	dir, name := "", "go"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if len(os.Args) > 2 {
		name = os.Args[2]
	}
	if dir == "" {
		var err error
		if dir, err = os.MkdirTemp("", "p2pact-interop-"); err != nil {
			panic(err)
		}
	}
	n, err := p2pact.NewNode(dir, name)
	if err != nil {
		panic(err)
	}
	// 64.2 echoes too, but answers later: once a 64.1 call has run after it (on its stream, that
	// call is behind it; it passes only if the held call does not hold up the stream)
	var mu sync.Mutex
	var held []chan struct{}
	n.Handle(64, 1, func(_ string, args []cbor.RawMessage) ([]any, error) {
		var b []byte
		if len(args) == 0 || cbor.Unmarshal(args[0], &b) != nil {
			return nil, &p2pact.Error{Code: p2pact.ErrBadArgs, Text: "no data"}
		}
		mu.Lock()
		for _, c := range held {
			close(c)
		}
		held = nil
		mu.Unlock()
		return []any{b}, nil
	})
	n.Handle(64, 2, func(_ string, args []cbor.RawMessage) ([]any, error) {
		var b []byte
		if len(args) == 0 || cbor.Unmarshal(args[0], &b) != nil {
			return nil, &p2pact.Error{Code: p2pact.ErrBadArgs, Text: "no data"}
		}
		c := make(chan struct{})
		mu.Lock()
		held = append(held, c)
		mu.Unlock()
		return nil, p2pact.Later(func() ([]any, error) {
			select {
			case <-c:
				return []any{b}, nil
			case <-time.After(30 * time.Second):
				return nil, &p2pact.Error{Code: p2pact.ErrFailed, Text: "no call came behind"}
			}
		})
	})
	var evMu sync.Mutex
	events := []map[string]any{}
	ownTools := map[string]int{}
	n.OnEvent = func(peer string, tool, ev int, args []cbor.RawMessage) {
		var b []byte
		if len(args) > 0 {
			_ = cbor.Unmarshal(args[0], &b)
		}
		evMu.Lock()
		events = append(events, map[string]any{"peer": peer, "tool": n.PeerToolName(peer, tool), "event": ev, "data": b})
		evMu.Unlock()
	}
	n.Start()
	out := json.NewEncoder(os.Stdout)
	say := func(v any) { _ = out.Encode(v) }
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	for in.Scan() {
		var req struct {
			Cmd, UDP, Invite, Peer  string
			TCP                     *string
			Data, Raw               []byte
			Stream                  uint64
			Listen, Dial            string
			MTU, Rate               int
			Kind, Level, Method     int
			Event                   int
			Name, Tool, Use, Plugin string
			Addr, FP                string
			WS                      []string
			Wants, Grants           [][]any
			A, B                    string
			On                      bool
			Hints                   *struct{ UDP, TCP []string }
		}
		if json.Unmarshal(in.Bytes(), &req) != nil {
			say(map[string]string{"error": "bad json"})
			continue
		}
		fail := func(err error) { say(map[string]string{"error": err.Error()}) }
		switch req.Cmd {
		case "listen":
			if req.UDP != "" {
				if err := n.ListenUDP(req.UDP); err != nil {
					fail(err)
					continue
				}
			}
			if req.TCP != nil {
				if err := n.ListenTCP(*req.TCP); err != nil {
					fail(err)
					continue
				}
			}
			r := map[string]string{"addr": n.ID.Addr(), "udp": "", "tcp": ""}
			if n.UDP() != nil {
				r["udp"] = n.UDP().LocalAddr()
			}
			if n.TCP() != nil {
				r["tcp"] = n.TCP().LocalAddr()
			}
			say(r)
		case "invite":
			say(map[string]string{"invite": n.Invite(10 * time.Minute).String()})
		case "join":
			inv, err := p2pact.ParseInvite(req.Invite)
			if err != nil {
				fail(err)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			var p p2pact.Peer
			if req.Wants != nil {
				p, err = n.JoinWants(ctx, inv, grantsIn(req.Wants))
			} else {
				p, err = n.Join(ctx, inv)
			}
			cancel()
			if err != nil {
				fail(err)
				continue
			}
			say(map[string]string{"peer": p.Addr})
		case "known":
			say(map[string]bool{"known": n.Trust.Get(req.Peer) != nil})
		case "call":
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			res, err := n.CallOn(ctx, req.Peer, req.Stream, 64, 1, req.Data)
			cancel()
			var b []byte
			if err == nil && (len(res) == 0 || cbor.Unmarshal(res[0], &b) != nil) {
				err = os.ErrInvalid
			}
			if err != nil {
				fail(err)
				continue
			}
			say(map[string][]byte{"data": b})
		case "later":
			type answer struct {
				res []cbor.RawMessage
				err error
			}
			first := make(chan answer, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				res, err := n.CallOn(ctx, req.Peer, req.Stream, 64, 2, req.Data)
				first <- answer{res, err}
			}()
			time.Sleep(100 * time.Millisecond) // the held call goes first
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := n.CallOn(ctx, req.Peer, req.Stream, 64, 1, []byte("behind"))
			cancel()
			if err != nil {
				fail(fmt.Errorf("the call behind the held one: %w", err))
				continue
			}
			a := <-first
			var b []byte
			if a.err == nil && (len(a.res) == 0 || cbor.Unmarshal(a.res[0], &b) != nil) {
				a.err = os.ErrInvalid
			}
			if a.err != nil {
				fail(fmt.Errorf("the held call: %w", a.err))
				continue
			}
			say(map[string][]byte{"data": b})
		case "dict":
			if err := n.AddDict(req.Raw); err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "relay":
			n.SetRelay(p2pact.RelayHint{Addr: req.Addr, FP: req.FP})
			n.SetRelayWS(req.WS...)
			say(map[string]bool{"ok": true})
		case "advertise":
			if req.Hints == nil {
				n.SetAdvertise(nil)
			} else {
				n.SetAdvertise(&p2pact.Hints{UDP: req.Hints.UDP, TCP: req.Hints.TCP})
			}
			say(map[string]bool{"ok": true})
		case "road":
			cfg := p2pact.AppRoadConfig{Name: "ble", Stream: true, MTU: req.MTU, Rate: req.Rate}
			if req.Listen != "" {
				ln, err := net.Listen("tcp", req.Listen)
				if err != nil {
					fail(err)
					continue
				}
				go func() {
					c, err := ln.Accept()
					ln.Close()
					if err == nil {
						linkRoad(n, c, "", cfg)
					}
				}()
				say(map[string]string{"road": ln.Addr().String()})
				continue
			}
			c, err := net.Dial("tcp", req.Dial)
			if err != nil {
				fail(err)
				continue
			}
			if err := linkRoad(n, c, req.Peer, cfg); err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "kind":
			n.Kind = req.Kind
			say(map[string]bool{"ok": true})
		case "peer-info":
			r := map[string]any{"kind": 0, "tools": n.PeerTools(req.Peer), "number": nil}
			if p := n.Trust.Get(req.Peer); p != nil {
				r["kind"] = p.Kind
			}
			if req.Tool != "" {
				if num, ok := n.ToolNumber(req.Peer, req.Tool); ok {
					r["number"] = num
				}
			}
			say(r)
		case "tool":
			name := req.Name
			num, err := n.RegisterTool(name, 1)
			if err != nil {
				fail(err)
				continue
			}
			ownTools[name] = num
			echo := func(_ string, args []cbor.RawMessage) ([]any, error) {
				var b []byte
				if len(args) == 0 || cbor.Unmarshal(args[0], &b) != nil {
					return nil, &p2pact.Error{Code: p2pact.ErrBadArgs, Text: "no data"}
				}
				return []any{b}, nil
			}
			_ = n.HandleTool(name, 1, echo)
			_ = n.HandleTool(name, 2, echo)
			_ = n.HandleTool(name, 3, func(string, []cbor.RawMessage) ([]any, error) { return []any{[]byte(name)}, nil })
			n.MarkRead(num, 1, 3)
			say(map[string]int{"number": num})
		case "call-tool":
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			res, err := n.CallToolOn(ctx, req.Peer, req.Stream, req.Name, req.Method, req.Data)
			cancel()
			var b []byte
			if err == nil && (len(res) == 0 || cbor.Unmarshal(res[0], &b) != nil) {
				err = os.ErrInvalid
			}
			if err != nil {
				e := map[string]any{"error": err.Error()}
				var pe *p2pact.Error
				if errors.As(err, &pe) {
					e["code"] = pe.Code
				}
				say(e)
				continue
			}
			say(map[string][]byte{"data": b})
		case "grant":
			if err := n.Grant(req.Peer, req.Tool, req.Level); err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "set-grants":
			if err := n.SetGrants(req.Peer, grantsIn(req.Grants)); err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "grants":
			say(map[string]any{"allowed": grantsOut(n.Grants(req.Peer)), "granted": grantsOut(n.GrantedBy(req.Peer))})
		case "emit":
			if err := n.Event(req.Peer, ownTools[req.Name], req.Event, req.Data); err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "events":
			evMu.Lock()
			say(map[string]any{"events": events})
			evMu.Unlock()
		case "on-wants":
			max := req.Level
			n.OnWants = func(_ p2pact.Peer, wants []p2pact.Grant) ([]p2pact.Grant, bool) {
				var out []p2pact.Grant
				for _, g := range wants {
					out = append(out, p2pact.Grant{Tool: g.Tool, Level: min(g.Level, max)})
				}
				return out, true
			}
			say(map[string]bool{"ok": true})
		case "local":
			var err error
			if req.Listen != "" {
				err = n.ListenLocal(req.Listen)
			} else {
				err = n.UseLocal(req.Use)
			}
			if err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "plugin-env":
			env, err := n.PluginEnv(10*time.Minute, grantsIn(req.Grants))
			if err != nil {
				fail(err)
				continue
			}
			r := map[string]string{}
			for _, kv := range env {
				k, v, _ := strings.Cut(kv, "=")
				r[map[string]string{p2pact.EnvSocket: "socket", p2pact.EnvInvite: "invite"}[k]] = v
			}
			say(r)
		case "proxy":
			name, plugin := req.Name, req.Plugin
			err := n.HandleToolAll(name, func(_ string, level, method int, args []cbor.RawMessage) ([]any, error) {
				if method == 2 && level < p2pact.LevelWrite {
					return nil, &p2pact.Error{Code: p2pact.ErrForbidden, Text: "forbidden"}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				res, err := n.CallTool(ctx, plugin, name, method, rawArgs(args)...)
				if err != nil {
					return nil, err
				}
				return rawArgs(res), nil
			})
			if err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "hide":
			n.SetAdvertise(&p2pact.Hints{})
			say(map[string]bool{"ok": true})
		case "forward":
			if err := n.AllowForward(req.A, req.B, req.On); err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "paths":
			p := n.Paths(req.Peer)
			if p == nil {
				p = []string{}
			}
			say(map[string][]string{"paths": p})
		case "forward-stats":
			fw, dr := n.ForwardStats()
			say(map[string]int64{"forwarded": fw, "dropped": dr})
		case "close":
			n.Close()
			return
		default:
			say(map[string]string{"error": "unknown command " + req.Cmd})
		}
	}
	n.Close()
}

// pipeLink is a Bluetooth LE link stood in for by a TCP connection: Send writes at most MTU
// bytes at a time, at the link's rate.
type pipeLink struct {
	c    net.Conn
	rate int
	free time.Time
}

func (l *pipeLink) Send(b []byte) error {
	if l.rate > 0 {
		now := time.Now()
		if l.free.Before(now.Add(-10 * time.Millisecond)) { // idle: the link starts now (an oversleep does not slow it)
			l.free = now
		}
		l.free = l.free.Add(time.Duration(len(b)) * time.Second / time.Duration(l.rate))
		if d := time.Until(l.free); d > 2*time.Millisecond {
			time.Sleep(d)
		}
	}
	_, err := l.c.Write(b)
	return err
}

// linkRoad attaches a connection as an application road and feeds it what arrives, in pieces of
// at most MTU bytes, as GATT delivers them.
func linkRoad(n *p2pact.Node, c net.Conn, peer string, cfg p2pact.AppRoadConfig) error {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	r, err := n.AttachRoad(peer, &pipeLink{c: c, rate: cfg.Rate}, cfg)
	if err != nil {
		c.Close()
		return err
	}
	go func() {
		defer r.Detach()
		defer c.Close()
		buf := make([]byte, cfg.MTU)
		for {
			k, err := c.Read(buf)
			if err != nil {
				return
			}
			r.Receive(buf[:k])
		}
	}()
	return nil
}
