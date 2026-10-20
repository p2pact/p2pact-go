// Command p2pact-interop is the reference interop peer for p2pact-tests: a P2PACT node driven
// by JSON lines on stdin, answering on stdout. Every implementation ships one with the same
// commands, so any two can be tested against each other.
//
//	{"cmd":"listen","udp":"127.0.0.1:0","tcp":"127.0.0.1:0"}  → {"addr":"…","udp":"…","tcp":"…"}
//	{"cmd":"invite"}                                          → {"invite":"p2pact1.…"}
//	{"cmd":"join","invite":"…"}                               → {"peer":"…"}
//	{"cmd":"known","peer":"…"}                                → {"known":true|false}
//	{"cmd":"call","peer":"…","data":"<base64>"}               → {"data":"<base64>"}  (echo, tool 64 method 1)
//	{"cmd":"dict","raw":"<base64>"}                           → {"ok":true}
//	{"cmd":"close"}
//
// Errors: {"error":"…"}. Usage: p2pact-interop [data dir] [name]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	p2pact "github.com/p2pact/p2pact-go"
)

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
	n.Handle(64, 1, func(_ string, args []cbor.RawMessage) ([]any, error) {
		var b []byte
		if len(args) == 0 || cbor.Unmarshal(args[0], &b) != nil {
			return nil, &p2pact.Error{Code: p2pact.ErrBadArgs, Text: "no data"}
		}
		return []any{b}, nil
	})
	n.Start()
	out := json.NewEncoder(os.Stdout)
	say := func(v any) { _ = out.Encode(v) }
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	for in.Scan() {
		var req struct {
			Cmd, UDP, Invite, Peer string
			TCP                    *string
			Data, Raw              []byte
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
			p, err := n.Join(ctx, inv)
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
			res, err := n.Call(ctx, req.Peer, 64, 1, req.Data)
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
		case "dict":
			if err := n.AddDict(req.Raw); err != nil {
				fail(err)
				continue
			}
			say(map[string]bool{"ok": true})
		case "close":
			n.Close()
			return
		default:
			say(map[string]string{"error": "unknown command " + req.Cmd})
		}
	}
	n.Close()
}
