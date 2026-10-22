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
//	{"cmd":"close"}
//
// Errors: {"error":"…"}. Usage: p2pact-interop [data dir] [name]
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
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
			Stream                 uint64
			Listen, Dial           string
			MTU, Rate              int
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
