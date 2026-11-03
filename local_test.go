package p2pact

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// shortDir is a directory with a short path: a unix socket path is limited to about 100 bytes.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "p2p")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestLocalSocketPairingAndCalls(t *testing.T) {
	sock := filepath.Join(shortDir(t), "node.sock")
	a, b := node(t, "Mac", false, nil), node(t, "Tool", false, nil)
	defer a.Close()
	defer b.Close()
	if err := a.ListenLocal(sock); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
			t.Fatalf("socket file: %v %v", fi, err)
		}
	}
	if err := a.ListenLocal(sock); err == nil {
		t.Fatal("a second listener on the same node")
	}
	if err := b.UseLocal(sock); err != nil {
		t.Fatal(err)
	}
	pair(t, a, b)
	echo(t, b, a, []byte("over the socket"), 5*time.Second)
	echo(t, a, b, bytes10k(), 5*time.Second)
	if paths := b.Paths(a.ID.Addr()); len(paths) != 1 || paths[0] != "local" {
		t.Fatalf("roads %v", paths)
	}
	if !b.Trust.Get(a.ID.Addr()).Local {
		t.Fatal("the dialing side does not remember the road")
	}
}

func bytes10k() []byte { return []byte(strings.Repeat("local ", 2000)) }

// A socket file nobody listens on is replaced; one in use is not; something else is not touched.
func TestLocalSocketStale(t *testing.T) {
	dir := shortDir(t)
	sock := filepath.Join(dir, "n.sock")
	a := node(t, "A", false, nil)
	if err := a.ListenLocal(sock); err != nil {
		t.Fatal(err)
	}
	b := node(t, "B", false, nil)
	defer b.Close()
	if err := b.ListenLocal(sock); err == nil {
		t.Fatal("took a socket in use")
	}
	a.Close() // closing the listener removes the file; leave a stale one as a crash would
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.ListenLocal(filepath.Join(dir, "file")); err == nil {
		t.Fatal("replaced a regular file")
	}
	if err := b.ListenLocal(sock); err != nil {
		t.Fatalf("after the first closed: %v", err)
	}
}

// A plugin: the device starts it with the two variables; it pairs with kind 3, gets the
// install's grants, is reachable over the socket only.
func TestPluginPairsByEnv(t *testing.T) {
	sock := filepath.Join(shortDir(t), "host.sock")
	host := node(t, "Mac", true, nil) // it has UDP: a plugin must still never use it
	defer host.Close()
	if err := host.ListenLocal(sock); err != nil {
		t.Fatal(err)
	}
	if _, err := host.RegisterTool("com.acme.host", 1); err != nil {
		t.Fatal(err)
	}
	if err := host.HandleTool("com.acme.host", 1, func(string, []cbor.RawMessage) ([]any, error) { return []any{"host"}, nil }); err != nil {
		t.Fatal(err)
	}
	grants := []Grant{{"com.acme.host", LevelWrite}}
	env, err := host.PluginEnv(time.Hour, grants)
	if err != nil || len(env) != 2 || !strings.HasPrefix(env[0], "P2PACT_SOCKET=") || !strings.HasPrefix(env[1], "P2PACT_INVITE=") {
		t.Fatalf("env %v %v", env, err)
	}
	inv, _ := ParseInvite(strings.TrimPrefix(env[1], "P2PACT_INVITE="))
	if inv.Hints.UDP != nil || inv.Hints.TCP != nil || inv.Hints.Relay != nil {
		t.Fatalf("the invite has hints: %+v", inv.Hints)
	}
	asked := false
	host.mu.Lock()
	host.OnWants = func(Peer, []Grant) ([]Grant, bool) { asked = true; return nil, false }
	host.mu.Unlock()
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		t.Setenv(k, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	plug, h, err := NewPlugin(ctx, t.TempDir(), "Plugin")
	if err != nil {
		t.Fatal(err)
	}
	defer plug.Close()
	if h.Addr != host.ID.Addr() || h.Kind != KindUnknown && h.Kind != KindComputer {
		t.Fatalf("host: %+v", h)
	}
	eventually(t, "host trusts the plugin", func() bool { return host.Trust.Get(plug.ID.Addr()) != nil })
	p := host.Trust.Get(plug.ID.Addr())
	if p.Kind != KindPlugin || !reflect.DeepEqual(p.Allowed(), grants) || p.Hints.UDP != nil || p.Hints.TCP != nil {
		t.Fatalf("plugin as the host sees it: %+v", p)
	}
	if asked {
		t.Fatal("the person was asked about a plugin")
	}
	// the plugin calls the host within its grants, not outside them
	eventually(t, "hello", func() bool { _, ok := plug.ToolNumber(host.ID.Addr(), "com.acme.host"); return ok })
	if _, err := plug.CallTool(ctx5(t), host.ID.Addr(), "com.acme.host", 1); err != nil {
		t.Fatalf("within grants: %v", err)
	}
	if _, err := plug.Call(ctx5(t), host.ID.Addr(), 64, 1, []byte("x")); callCode(err) != ErrForbidden {
		t.Fatalf("outside grants: %v", err)
	}
	// the host calls the plugin's tool (its grants for the host are the default)
	if err := plug.HandleTool("com.acme.plug", 1, func(string, []cbor.RawMessage) ([]any, error) { return []any{"plugin"}, nil }); err != nil {
		t.Fatal(err)
	}
	eventually(t, "plugin hello", func() bool { _, ok := host.ToolNumber(plug.ID.Addr(), "com.acme.plug"); return ok })
	if _, err := host.CallTool(ctx5(t), plug.ID.Addr(), "com.acme.plug", 1); err != nil {
		t.Fatalf("host to plugin: %v", err)
	}
	if paths := host.Paths(plug.ID.Addr()); len(paths) != 1 || paths[0] != "local" {
		t.Fatalf("roads to the plugin: %v", paths)
	}
	// single use
	short, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if _, _, err := NewPlugin(short, t.TempDir(), "Again"); err == nil {
		t.Fatal("an invite was used twice")
	}
	// not a family member
	if err := host.Befriend(*p); err == nil {
		t.Fatal("a plugin was befriended")
	}
}

// A plugin pairing over any other road is refused, and so is a program using a plugin invite as
// something else.
func TestPluginOnlyOverLocal(t *testing.T) {
	sock := filepath.Join(shortDir(t), "host.sock")
	host, other := node(t, "Mac", true, nil), node(t, "Other", true, nil)
	defer host.Close()
	defer other.Close()
	if err := host.ListenLocal(sock); err != nil {
		t.Fatal(err)
	}
	setKind(other, KindPlugin)
	short := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 1500*time.Millisecond)
	}
	ctx, cancel := short()
	defer cancel()
	_, _ = other.Join(ctx, host.Invite(time.Minute)) // the joiner cannot tell: the host just stays silent
	time.Sleep(200 * time.Millisecond)
	if host.Trust.Get(other.ID.Addr()) != nil {
		t.Fatal("a plugin over UDP is trusted")
	}
	setKind(other, KindClient) // not a plugin: the invite made for programs is not for it
	if err := other.UseLocal(sock); err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := short()
	defer cancel2()
	_, _ = other.Join(ctx2, host.PluginInvite(time.Minute, nil))
	time.Sleep(200 * time.Millisecond)
	if host.Trust.Get(other.ID.Addr()) != nil {
		t.Fatal("a program invite was used by a client")
	}
}

func TestPluginEnvNeedsSocket(t *testing.T) {
	n := node(t, "Mac", false, nil)
	defer n.Close()
	if _, err := n.PluginEnv(time.Minute, nil); err == nil {
		t.Fatal("env without a socket")
	}
	t.Setenv(EnvSocket, "")
	if _, _, err := NewPlugin(context.Background(), t.TempDir(), "x"); err == nil {
		t.Fatal("a plugin started by nobody")
	}
}
