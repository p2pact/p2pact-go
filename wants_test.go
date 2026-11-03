package p2pact

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func joinWants(t *testing.T, inviter, joiner *Node, wants []Grant) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv, err := ParseInvite(inviter.Invite(10 * time.Minute).String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := joiner.JoinWants(ctx, inv, wants); err != nil {
		t.Fatalf("pairing: %v", err)
	}
}

func TestWantsAskedAreGranted(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "App", true, nil)
	defer a.Close()
	defer b.Close()
	setKind(b, KindClient)
	want := []Grant{{"com.acme.x", LevelRead}, {"p2pact.chat", LevelWrite}}
	joinWants(t, a, b, want)
	eventually(t, "the inviter remembers the joiner", func() bool { return a.Trust.Get(b.ID.Addr()) != nil })
	p := a.Trust.Get(b.ID.Addr())
	if !reflect.DeepEqual(p.Allowed(), want) || p.Kind != KindClient {
		t.Fatalf("granted %v kind %d", p.Allowed(), p.Kind)
	}
	eventually(t, "the newcomer is told", func() bool { return reflect.DeepEqual(b.GrantedBy(a.ID.Addr()), want) })
}

// Pairing without wants asks for everything: behaviour as before, and no event 0.6 is needed.
func TestWantsNoneIsEverything(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	if p := a.Trust.Get(b.ID.Addr()); p.Grants != nil || !reflect.DeepEqual(p.Allowed(), DefaultGrants()) {
		t.Fatalf("%+v", p.Grants)
	}
	echo(t, b, a, []byte("x"), 5*time.Second)
}

// The inviting application sees the wants and decides what is granted before it accepts.
func TestWantsDecidedByApplication(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "App", true, nil)
	defer a.Close()
	defer b.Close()
	type seen struct {
		peer  Peer
		wants []Grant
	}
	asked := make(chan seen, 4)
	paired := make(chan Peer, 4)
	release := make(chan struct{})
	a.mu.Lock()
	a.OnWants = func(p Peer, wants []Grant) ([]Grant, bool) {
		asked <- seen{p, wants}
		<-release
		return []Grant{{"com.acme.x", LevelRead}}, true
	}
	a.OnPaired = func(p Peer) { paired <- p }
	a.mu.Unlock()
	setKind(b, KindClient)
	joinWants(t, a, b, []Grant{{AllTools, LevelWrite}})
	s := <-asked
	if s.peer.Name != "App" || s.peer.Kind != KindClient || !reflect.DeepEqual(s.wants, []Grant{{AllTools, LevelWrite}}) {
		t.Fatalf("the application saw %+v", s)
	}
	// undecided: the newcomer may use nothing
	if got := a.Grants(b.ID.Addr()); len(got) != 0 {
		t.Fatalf("before the decision: %v", got)
	}
	if _, err := b.Call(ctx5(t), a.ID.Addr(), 64, 1, []byte("x")); callCode(err) != ErrForbidden {
		t.Fatalf("a call before the decision: %v", err)
	}
	close(release)
	select {
	case p := <-paired:
		if !reflect.DeepEqual(p.Allowed(), []Grant{{"com.acme.x", LevelRead}}) {
			t.Fatalf("OnPaired: %v", p.Allowed())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnPaired did not come")
	}
	eventually(t, "narrowed grants told", func() bool {
		return reflect.DeepEqual(b.GrantedBy(a.ID.Addr()), []Grant{{"com.acme.x", LevelRead}})
	})
}

// No wants in the payload (an older device): the application is shown ["*", 2]; it may refuse.
func TestWantsRefused(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Old", true, nil)
	defer a.Close()
	defer b.Close()
	got := make(chan []Grant, 1)
	a.mu.Lock()
	a.OnWants = func(p Peer, wants []Grant) ([]Grant, bool) { got <- wants; return nil, false }
	a.mu.Unlock()
	joinWants(t, a, b, nil)
	if w := <-got; !reflect.DeepEqual(w, DefaultGrants()) {
		t.Fatalf("wants of a device that did not ask: %v", w)
	}
	eventually(t, "forgotten", func() bool { return a.Trust.Get(b.ID.Addr()) == nil })
}

// OnAsk is asked only about newcomers that came by an InviteAsk invite; others keep what they
// asked for (OnWants unset).
func TestWantsAskOnlyForInviteAsk(t *testing.T) {
	a, b, c := node(t, "Mac", true, nil), node(t, "App", true, nil), node(t, "Phone", true, nil)
	defer a.Close()
	defer b.Close()
	defer c.Close()
	setKind(b, KindClient)
	asked := make(chan string, 4)
	a.mu.Lock()
	a.OnAsk = func(p Peer, wants []Grant) ([]Grant, bool) {
		asked <- p.Name
		return []Grant{{"p2pact.chat", LevelRead}}, true
	}
	a.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv, _ := ParseInvite(a.InviteAsk(10 * time.Minute).String())
	if _, err := b.JoinWants(ctx, inv, []Grant{{AllTools, LevelWrite}}); err != nil {
		t.Fatal(err)
	}
	if n := <-asked; n != "App" {
		t.Fatalf("asked about %q", n)
	}
	eventually(t, "narrowed", func() bool {
		return reflect.DeepEqual(a.Grants(b.ID.Addr()), []Grant{{"p2pact.chat", LevelRead}})
	})
	// a plain invite: not asked, gets what it wants
	joinWants(t, a, c, []Grant{{"com.acme.x", LevelWrite}})
	eventually(t, "plain invite grants as asked", func() bool {
		return reflect.DeepEqual(a.Grants(c.ID.Addr()), []Grant{{"com.acme.x", LevelWrite}})
	})
	select {
	case n := <-asked:
		t.Fatalf("asked about %q on a plain invite", n)
	default:
	}
}
