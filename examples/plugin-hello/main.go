// Command plugin-hello is an example P2PACT plugin: the engine starts it, it pairs over the
// local socket, announces the tool dev.p2pact.example.hello and sends an event every few seconds.
//
//	hello tool (dev.p2pact.example.hello)
//	  method 1  hello.greet {name}  -> "Hello, <name>"   (read: listed in plugin.json "read")
//	  method 2  hello.bump          -> counter            (write)
//	  event  1  tick [counter]      every HELLO_INTERVAL (default 5s)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/p2pact/p2pact-go"
)

const (
	tool        = "dev.p2pact.example.hello"
	methodGreet = 1
	methodBump  = 2
	eventTick   = 1
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// keys live in the folder the engine gives the plugin; the invite and socket come from the
	// environment (P2PACT_INVITE, P2PACT_SOCKET)
	dir := os.Getenv("P2PACT_PLUGIN_DATA")
	if dir == "" {
		dir = "data"
	}
	joinCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	n, host, err := p2pact.NewPlugin(joinCtx, dir, "Hello plugin")
	cancel()
	if err != nil {
		log.Fatalf("not started by a P2PACT device: %v", err)
	}
	defer n.Close()
	log.Printf("paired with %s", host.Name)

	var counter int
	greet := func(_ string, args []cbor.RawMessage) ([]any, error) {
		var name string
		if len(args) > 0 {
			_ = cbor.Unmarshal(args[0], &name)
		}
		if name == "" {
			name = "world"
		}
		return []any{"Hello, " + name}, nil
	}
	bump := func(string, []cbor.RawMessage) ([]any, error) {
		counter++
		return []any{counter}, nil
	}
	if err := n.HandleTool(tool, methodGreet, greet); err != nil {
		log.Fatal(err)
	}
	if err := n.HandleTool(tool, methodBump, bump); err != nil {
		log.Fatal(err)
	}
	num, _ := n.RegisterTool(tool, 1)

	every := 5 * time.Second
	if d, err := time.ParseDuration(os.Getenv("HELLO_INTERVAL")); err == nil && d > 0 {
		every = d
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			counter++
			if err := n.Event(host.Addr, num, eventTick, counter); err != nil {
				fmt.Fprintln(os.Stderr, "tick:", err)
			}
		}
	}
}
