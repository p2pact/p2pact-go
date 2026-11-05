package p2pact

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// goneLog records OnGone calls.
type goneLog struct {
	mu    sync.Mutex
	peers []string
}

func (g *goneLog) on(peer string) {
	g.mu.Lock()
	g.peers = append(g.peers, peer)
	g.mu.Unlock()
}

func (g *goneLog) count(peer string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := 0
	for _, p := range g.peers {
		if p == peer {
			k++
		}
	}
	return k
}

// stopper closes n once, now or at the end of the test.
func stopper(t *testing.T, n *Node) func() {
	var once sync.Once
	f := func() { once.Do(n.Close) }
	t.Cleanup(f)
	return f
}

// localPair: host listens on a local socket, prog dials it; both paired and talking.
func localPair(t *testing.T) (host, prog *Node, hostGone, progGone *goneLog, stopHost, stopProg func()) {
	t.Helper()
	sock := filepath.Join(shortDir(t), "node.sock")
	host, prog = node(t, "Mac", false, nil), node(t, "Window", false, nil)
	stopHost, stopProg = stopper(t, host), stopper(t, prog)
	hostGone, progGone = &goneLog{}, &goneLog{}
	host.mu.Lock()
	host.OnGone = hostGone.on
	host.mu.Unlock()
	prog.mu.Lock()
	prog.OnGone = progGone.on
	prog.mu.Unlock()
	if err := host.ListenLocal(sock); err != nil {
		t.Fatal(err)
	}
	if err := prog.UseLocal(sock); err != nil {
		t.Fatal(err)
	}
	pair(t, host, prog)
	echo(t, prog, host, []byte("hi"), 5*time.Second)
	return host, prog, hostGone, progGone, stopHost, stopProg
}

// A program on the local socket that exits is gone for the node at once; the node's own
// connection ending is gone for the program, once, not on every redial that fails.
func TestGoneLocalProgramExits(t *testing.T) {
	host, prog, hostGone, _, _, stopProg := localPair(t)
	addr := prog.ID.Addr()
	stopProg()
	eventually(t, "the host sees the program gone", func() bool { return hostGone.count(addr) == 1 })
	if p := host.Paths(addr); len(p) != 0 {
		t.Fatalf("roads to a program that exited: %v", p)
	}

	// the other way: the host exits, the program is told once though it keeps redialing
	host2, prog2, _, progGone2, stopHost2, _ := localPair(t)
	hostAddr := host2.ID.Addr()
	stopHost2()
	eventually(t, "the program sees the host gone", func() bool { return progGone2.count(hostAddr) == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	_, _ = prog2.Call(ctx, hostAddr, 64, 1, []byte("into the void")) // it dials (and fails) again and again
	if k := progGone2.count(hostAddr); k != 1 {
		t.Fatalf("gone %d times", k)
	}
}

// The connection drops while the program lives: gone; the program dials again and the session
// goes on over the new connection (no OnGone for that).
func TestGoneLocalReconnect(t *testing.T) {
	host, prog, hostGone, _, _, _ := localPair(t)
	addr := prog.ID.Addr()
	prog.loc.closeConns()
	eventually(t, "gone", func() bool { return hostGone.count(addr) == 1 })
	echo(t, prog, host, []byte("back"), 5*time.Second)
	echo(t, host, prog, []byte("and back"), 5*time.Second)
	if k := hostGone.count(addr); k != 1 {
		t.Fatalf("gone %d times", k)
	}
}

// A device that stops answering (a half-open road) is gone once data to it goes unacknowledged
// for 10 s.
func TestGoneSessionDead(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the 10 s of a dead session")
	}
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	g := &goneLog{}
	a.mu.Lock()
	a.OnGone = g.on
	a.mu.Unlock()
	pair(t, a, b)
	echo(t, a, b, []byte("hello"), 5*time.Second)
	b.UDP().SetDrop(func() bool { return true })
	if err := a.Event(b.ID.Addr(), 64, 1, []byte("lost")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for g.count(b.ID.Addr()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no OnGone for a device that stopped answering")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
