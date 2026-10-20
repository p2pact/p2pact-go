package p2pact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Hints tell where to find a device (spec §7).
type Hints struct {
	UDP   []string   `json:"udp,omitempty"`   // ip:port addresses
	TCP   []string   `json:"tcp,omitempty"`   // ip:port addresses (fallback road)
	Relay *RelayHint `json:"relay,omitempty"` // its relay
}

// RelayHint is a relay: its address and the SHA-256 of its certificate (hex).
type RelayHint struct {
	Addr string `json:"addr"`
	FP   string `json:"fp"`
}

// Peer is a known device (spec §2).
type Peer struct {
	Addr       string `json:"addr"`
	Key        []byte `json:"key"`
	Name       string `json:"name"`
	PairSecret []byte `json:"pair_secret"`
	Hints      Hints  `json:"hints"`
	Added      int64  `json:"added"`
	SignKey    []byte `json:"sign_key,omitempty"` // Ed25519
	OS         string `json:"os,omitempty"`       // runtime.GOOS; android and ios are phones
	Via        string `json:"via,omitempty"`      // joined through our invite with this id (hex)
}

// Phone reports a phone OS: a phone is never the family parent (spec/family.md §1).
func Phone(os string) bool { return os == "android" || os == "ios" }

// relayChannel is the pair's relay channel: only these two devices know it.
func (p *Peer) relayChannel() string { return hexs(mac(p.PairSecret, "relay")[:16]) }

// Trust is the set of known devices in dir/net-peers.json.
type Trust struct {
	path  string
	mu    sync.Mutex
	peers map[string]*Peer
}

func LoadTrust(dir string) *Trust {
	t := &Trust{path: filepath.Join(dir, "net-peers.json"), peers: map[string]*Peer{}}
	var list []*Peer
	if b, err := os.ReadFile(t.path); err == nil && json.Unmarshal(b, &list) == nil {
		for _, p := range list {
			if len(p.Key) == 32 && Address(p.Key) == p.Addr {
				t.peers[p.Addr] = p
			}
		}
	}
	return t
}

func (t *Trust) Get(addr string) *Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	if p := t.peers[addr]; p != nil {
		cp := *p
		return &cp
	}
	return nil
}

func (t *Trust) List() []Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Peer, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// Put adds or updates a known device.
func (t *Trust) Put(p Peer) {
	t.mu.Lock()
	if p.Added == 0 {
		p.Added = time.Now().UnixMilli()
	}
	t.peers[p.Addr] = &p
	t.saveLocked()
	t.mu.Unlock()
}

// SetHints stores fresh hints of a known device (from its hello).
func (t *Trust) SetHints(addr, name, os string, h Hints) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.peers[addr]
	if p == nil {
		return
	}
	if name != "" {
		p.Name = name
	}
	if os != "" {
		p.OS = os
	}
	if len(h.UDP) > 0 {
		p.Hints.UDP = h.UDP
	}
	if len(h.TCP) > 0 {
		p.Hints.TCP = h.TCP
	}
	if h.Relay != nil {
		p.Hints.Relay = h.Relay
	}
	t.saveLocked()
}

func (t *Trust) Remove(addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.peers[addr] == nil {
		return false
	}
	delete(t.peers, addr)
	t.saveLocked()
	return true
}

func (t *Trust) saveLocked() {
	list := make([]*Peer, 0, len(t.peers))
	for _, p := range t.peers {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Addr < list[j].Addr })
	b, _ := json.MarshalIndent(list, "", "  ")
	_ = os.WriteFile(t.path, b, 0o600)
}
