package p2pact

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"
)

func storeNode(t *testing.T, dir, udp string) *Node {
	t.Helper()
	n, err := NewNode(dir, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.ListenUDP(udp); err != nil {
		t.Fatal(err)
	}
	n.Start()
	return n
}

// Invites not yet opened survive a restart (with their ask flag); a used one, an expired one
// and one made for a program do not; an invite works once even across restarts.
func TestInviteStoreSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	a := storeNode(t, dir, "127.0.0.1:0")
	if ids, err := a.EnableInviteStore(); err != nil || len(ids) != 0 {
		t.Fatalf("%v %v", ids, err)
	}
	if _, err := a.EnableInviteStore(); err == nil {
		t.Fatal("the store turned on twice")
	}
	addr := a.UDP().LocalAddr()
	plain, ask := a.Invite(time.Hour), a.InviteAsk(time.Hour)
	short := a.Invite(time.Second)
	a.PluginInvite(time.Hour, nil)
	used := a.Invite(time.Hour)
	b := node(t, "Phone", true, nil)
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := b.Join(ctx, used); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond) // short expires
	a.Close()

	a = storeNode(t, dir, addr)
	got, err := a.EnableInviteStore()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{hexs(plain.ID()), hexs(ask.ID())}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("came back %v, want %v (not %s, %s)", got, want, hexs(short.ID()), hexs(used.ID()))
	}
	if !a.HasInvite(hexs(plain.ID())) || a.HasInvite(hexs(used.ID())) {
		t.Fatal("HasInvite")
	}
	asked := make(chan string, 2)
	a.mu.Lock()
	a.OnAsk = func(p Peer, _ []Grant) ([]Grant, bool) {
		asked <- p.Name
		return []Grant{{"p2pact.chat", LevelRead}}, true
	}
	a.mu.Unlock()
	c, d := node(t, "Client", true, nil), node(t, "Other", true, nil)
	defer c.Close()
	defer d.Close()
	setKind(c, KindClient)
	if _, err := c.JoinWants(ctx, ask, []Grant{{AllTools, LevelWrite}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("an invite that asks did not ask after the restart")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	if _, err := d.Join(ctx2, ask); err == nil {
		t.Fatal("a single-use invite worked twice")
	}
	if _, err := d.Join(ctx, plain); err != nil {
		t.Fatal(err)
	}
	eventually(t, "plain invite used", func() bool { return !a.HasInvite(hexs(plain.ID())) })
	a.Close()

	a = storeNode(t, dir, addr)
	defer a.Close()
	if got, _ := a.EnableInviteStore(); len(got) != 0 {
		t.Fatalf("used invites came back: %v", got)
	}
}

func TestInviteStoreDropAndDamagedFile(t *testing.T) {
	dir := t.TempDir()
	a := storeNode(t, dir, "127.0.0.1:0")
	a.EnableInviteStore()
	inv := a.Invite(time.Hour)
	a.DropInvite(hexs(inv.ID()))
	a.Close()
	b := storeNode(t, dir, "127.0.0.1:0")
	if got, _ := b.EnableInviteStore(); len(got) != 0 {
		t.Fatalf("dropped invite came back: %v", got)
	}
	b.Close()
	if err := os.WriteFile(dir+"/net-invites.json", []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := storeNode(t, dir, "127.0.0.1:0")
	defer c.Close()
	if got, err := c.EnableInviteStore(); err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}
