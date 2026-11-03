package p2pact

import (
	"context"
	"errors"
	"os"
	"time"
)

// Environment variables a device gives a program it starts (spec §2, local programs).
const (
	EnvSocket = "P2PACT_SOCKET" // the path of the device's local socket
	EnvInvite = "P2PACT_INVITE" // a single-use invite with no hints
)

// PluginInvite makes the invite for a program the device starts (spec §2): single use, no hints
// (the program reaches the device over the local socket), valid for ttl, and the program is
// granted exactly grants — the install gave them, nobody is asked. The program must pair with
// kind [KindPlugin] over the local socket; it is never added to the family and never reached
// over another road.
func (n *Node) PluginInvite(ttl time.Duration, grants []Grant) *Invite {
	n.mu.Lock()
	defer n.mu.Unlock()
	inv := &Invite{Key: n.ID.Key.Public, Name: n.Name, Secret: randBytes(32), Exp: time.Now().Add(ttl)}
	id := hexs(inv.ID())
	n.invites[id] = inv
	n.inviteGrants[id] = cleanGrants(grants)
	return inv
}

// PluginEnv is PluginInvite and the environment to start the program with, "NAME=value" for
// [os/exec.Cmd.Env]: P2PACT_SOCKET and P2PACT_INVITE. The node must listen on its local socket.
func (n *Node) PluginEnv(ttl time.Duration, grants []Grant) ([]string, error) {
	path := n.LocalPath()
	if path == "" {
		return nil, errors.New("the node does not listen on a local socket")
	}
	return []string{EnvSocket + "=" + path, EnvInvite + "=" + n.PluginInvite(ttl, grants).String()}, nil
}

// NewPlugin is the plugin side (spec §2): it reads P2PACT_SOCKET and P2PACT_INVITE, dials the
// socket and pairs with kind [KindPlugin] and no wants. dir keeps the plugin's keys; the node
// is started. It returns the device the plugin runs on. A plugin started again gets a new
// invite and pairs again.
func NewPlugin(ctx context.Context, dir, name string) (*Node, Peer, error) {
	sock, inv := os.Getenv(EnvSocket), os.Getenv(EnvInvite)
	if sock == "" || inv == "" {
		return nil, Peer{}, errors.New(EnvSocket + " and " + EnvInvite + " are not set: not started by a P2PACT device")
	}
	invite, err := ParseInvite(inv)
	if err != nil {
		return nil, Peer{}, err
	}
	n, err := NewNode(dir, name)
	if err != nil {
		return nil, Peer{}, err
	}
	n.Kind = KindPlugin
	if err := n.UseLocal(sock); err != nil {
		n.Close()
		return nil, Peer{}, err
	}
	n.Start()
	host, err := n.Join(ctx, invite)
	if err != nil {
		n.Close()
		return nil, Peer{}, err
	}
	return n, host, nil
}
