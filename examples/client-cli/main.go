// Command client-cli is a small P2PACT client application on the client package: it pairs with a
// computer by its invite, lists its chats, sends a message and watches the fleet.
//
//	client-cli pair p2pact1.…       pair with a computer (an invite from `nomad invite`)
//	client-cli chats                list the computer's chats
//	client-cli send <chat> <text>   send a message and print the agent's reply as it comes
//	client-cli watch                print what happens on the computer until Ctrl-C
//
// State (keys, paired computers) lives in $P2PACT_CLIENT_DIR, default ~/.p2pact-client-cli.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/p2pact/p2pact-go/client"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: client-cli pair <invite> | chats | send <chat> <text> | watch")
	os.Exit(2)
}

func run(ctx context.Context, cmd string, args []string) error {
	dir := os.Getenv("P2PACT_CLIENT_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".p2pact-client-cli")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	c, err := client.New(dir, "client-cli", nil)
	if err != nil {
		return err
	}
	defer c.Close()

	if cmd == "pair" {
		if len(args) != 1 {
			usage()
		}
		comp, err := c.Pair(ctx, args[0], nil) // asks chat and fleet in full, plugins to read
		if err != nil {
			return err
		}
		fmt.Printf("paired with %s (%s)\n", comp.Name(), comp.ID())
		fmt.Println("the person at the computer may still narrow what we may use; waiting for the answer")
		return waitGrants(ctx, comp)
	}

	comps := c.Computers()
	if len(comps) == 0 {
		return fmt.Errorf("no paired computer: client-cli pair <invite>")
	}
	comp := comps[0]
	wctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := comp.WhenOnline(wctx); err != nil {
		return fmt.Errorf("%s is not reachable: %w", comp.Name(), err)
	}

	switch cmd {
	case "chats":
		list, err := comp.Chat().ListAllSessions(ctx, "")
		if err != nil {
			return err
		}
		for _, s := range list {
			fmt.Printf("%s  %-8s %-7s %s  %s\n", s.ID, s.State, s.Agent, s.CWD, s.Title)
		}
	case "send":
		if len(args) < 2 {
			usage()
		}
		return send(ctx, comp, args[0], strings.Join(args[1:], " "))
	case "watch":
		return watch(ctx, comp)
	default:
		usage()
	}
	return nil
}

// waitGrants prints what the computer allows once it has told.
func waitGrants(ctx context.Context, comp *client.Computer) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for len(comp.Grants()) == 0 {
		select {
		case <-ctx.Done():
			return fmt.Errorf("the computer did not say what we may use")
		case <-time.After(100 * time.Millisecond):
		}
	}
	for _, g := range comp.Grants() {
		fmt.Printf("  %s level %d\n", g.Tool, g.Level)
	}
	return nil
}

func send(ctx context.Context, comp *client.Computer, session, text string) error {
	chat := comp.Chat()
	// answer the agent's permission requests on the terminal
	chat.SetPermissionHandler(func(ctx context.Context, r *client.PermissionRequest) (client.PermissionOutcome, error) {
		fmt.Printf("\n[permission] %s\n", r.ToolCall.Title)
		for i, o := range r.Options {
			fmt.Printf("  %d) %s\n", i+1, o.Name)
		}
		fmt.Print("choose: ")
		var n int
		if _, err := fmt.Scan(&n); err != nil || n < 1 || n > len(r.Options) {
			return client.Cancelled, nil
		}
		return r.Select(r.Options[n-1]), nil
	})
	updates, cancel := chat.Updates.Chan()
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for u := range updates {
			if u.SessionID == session && u.Type == client.UpdateAgentMessage {
				fmt.Print(u.Text())
			}
		}
	}()
	res, err := chat.Prompt(ctx, session, text)
	if err != nil {
		return err
	}
	cancel()
	<-done
	fmt.Printf("\n[%s]\n", res.StopReason)
	return nil
}

func watch(ctx context.Context, comp *client.Computer) error {
	fleet := comp.Fleet()
	events, cancel := fleet.Events.Chan()
	defer cancel()
	w, err := fleet.Watch(ctx, false)
	if err != nil {
		return err
	}
	defer func() {
		cctx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = w.Close(cctx)
	}()
	for _, s := range w.Sessions {
		fmt.Printf("session %s %s %s\n", s.ID, s.Phase, s.Title)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-events:
			switch e.Type {
			case client.FleetSessionsChanged:
				for _, s := range e.Sessions {
					fmt.Printf("session %s %s %s\n", s.ID, s.Phase, s.Title)
				}
			case client.FleetSessionMessages:
				for _, m := range e.Messages {
					fmt.Printf("%s [%s] %s\n", e.ID, m.Role, m.Text)
				}
			case client.FleetNotify:
				fmt.Println("notify:", e.Text)
			}
		}
	}
}
