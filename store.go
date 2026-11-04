package p2pact

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// An invite lives in the node's memory (spec §2) and is lost when the program restarts: an
// invite handed out and not yet opened would stop working. [Node.EnableInviteStore] makes the
// node keep its issued invites in dir/net-invites.json — each with its expiry and whether it
// asks (InviteAsk) — and read them back on the next start. A single-use invite leaves the file
// when somebody pairs by it, an expired one when the node prunes it. Invites made for
// programs (PluginInvite) live as long as the program and are never stored.

type storedInvite struct {
	Invite string `json:"invite"`
	Ask    bool   `json:"ask,omitempty"`
}

func (n *Node) invitePath() string { return filepath.Join(n.dir, "net-invites.json") }

// EnableInviteStore turns the invite store on: the invites left by an earlier run come back
// (the unexpired ones; they join the relay like any invite of ours) and every invite made or
// used from now on is written down. Call it once, after NewNode and before the invites are
// made. It returns the ids (hex) of the invites that came back.
func (n *Node) EnableInviteStore() ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.inviteStore {
		return nil, errors.New("the invite store is already on")
	}
	var list []storedInvite
	if b, err := os.ReadFile(n.invitePath()); err == nil {
		if json.Unmarshal(b, &list) != nil {
			list = nil // a damaged file: the invites are lost, the node goes on
		}
	}
	var ids []string
	for _, s := range list {
		inv, err := ParseInvite(s.Invite) // an expired invite is an error: pruned
		if err != nil || string(inv.Key) != string(n.ID.Key.Public) {
			continue
		}
		id := hexs(inv.ID())
		if _, dup := n.invites[id]; dup {
			continue
		}
		n.invites[id] = inv
		if s.Ask {
			n.inviteAsk[id] = true
		}
		ids = append(ids, id)
		if n.own != nil && !n.paused {
			n.relayLocked(*n.own).join(id, "a")
		}
	}
	sort.Strings(ids)
	n.inviteStore = true
	n.saveInvitesLocked()
	return ids, nil
}

// HasInvite reports whether the invite with this id (hex) is one of ours and still open.
func (n *Node) HasInvite(id string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	inv := n.invites[id]
	return inv != nil && time.Now().Before(inv.Exp)
}

// DropInvite takes our invite back: nobody can pair by it any more. It does nothing for an
// unknown id.
func (n *Node) DropInvite(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.invites[id] == nil {
		return
	}
	delete(n.invites, id)
	delete(n.inviteAsk, id)
	delete(n.inviteGrants, id)
	if n.own != nil {
		n.relayLocked(*n.own).leave(id)
	}
	n.saveInvitesLocked()
}

// InviteIDs are the ids (hex) of our open invites that the store keeps (not those for programs).
func (n *Node) InviteIDs() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var ids []string
	now := time.Now()
	for id, inv := range n.invites {
		if _, plugin := n.inviteGrants[id]; !plugin && now.Before(inv.Exp) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// saveInvitesLocked writes the invites down when the store is on.
func (n *Node) saveInvitesLocked() {
	if !n.inviteStore {
		return
	}
	now := time.Now()
	list := []storedInvite{}
	for id, inv := range n.invites {
		if _, plugin := n.inviteGrants[id]; plugin || !now.Before(inv.Exp) {
			continue
		}
		list = append(list, storedInvite{Invite: inv.String(), Ask: n.inviteAsk[id]})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Invite < list[j].Invite })
	b, _ := json.MarshalIndent(list, "", "  ")
	writeAtomic(n.invitePath(), b)
}
