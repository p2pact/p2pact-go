package relay

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"sync"
	"time"
)

// Code slots (spec §2 short code, §3): a device that shows a short code puts a sealed invite
// under a slot derived from the code; the device that typed the code gets it. One request per
// connection: the first line has "op" instead of "channel", the relay answers once and closes.
//
//	→ {"relay":1,"op":"put","slot":"<32 hex>","box":"<base64url>","ttl":300,"tok":"<32 hex>"}
//	→ {"relay":1,"op":"get","slot":"<32 hex>"}
//	→ {"relay":1,"op":"del","slot":"<32 hex>","tok":"<32 hex>"}
//	← {"ok":true[,"box":"…"]} or {"error":"not found" | "taken" | "slow down" | "bad request"}
//
// The code is low-entropy, so the relay limits guessing: gets per client address (an IPv6
// client counts by its /64), reads per slot, and a short life. The box is sealed with a key
// derived from the code by PBKDF2, so the relay cannot read it cheaply; the invite inside asks
// the inviting device's person before granting anything, which is what actually guards pairing.
const (
	maxSlots     = 10000
	maxBox       = 2048 // base64url characters
	maxSlotTTL   = 10 * time.Minute
	maxSlotReads = 3
	getsPerMin   = 10 // per client address
	putsPerMin   = 30 // put and del, per client address
)

type slot struct {
	box   string
	tok   string
	exp   time.Time
	reads int
}

// bucket counts requests of one client address in the current minute.
type bucket struct {
	start      time.Time
	gets, puts int
}

type slots struct {
	mu    sync.Mutex
	m     map[string]*slot
	rate  map[string]*bucket
	now   func() time.Time
	sweep time.Time
}

func newSlots(now func() time.Time) *slots {
	return &slots{m: map[string]*slot{}, rate: map[string]*bucket{}, now: now}
}

type slotReq struct {
	Op   string `json:"op"`
	Slot string `json:"slot"`
	Box  string `json:"box"`
	TTL  int    `json:"ttl"`
	Tok  string `json:"tok"`
}

type slotResp struct {
	OK    bool   `json:"ok,omitempty"`
	Box   string `json:"box,omitempty"`
	Error string `json:"error,omitempty"`
}

// rateKey is the client address as rate limits see it: an IPv6 address by its /64.
func rateKey(host string) string {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil {
		return host
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// allow counts a request of host; false — over the limit for this minute.
func (t *slots) allow(host string, get bool) bool {
	now := t.now()
	k := rateKey(host)
	b := t.rate[k]
	if b == nil || now.Sub(b.start) >= time.Minute {
		b = &bucket{start: now}
		t.rate[k] = b
	}
	if get {
		b.gets++
		return b.gets <= getsPerMin
	}
	b.puts++
	return b.puts <= putsPerMin
}

// gc drops expired slots and old buckets, at most once every 10 s.
func (t *slots) gc() {
	now := t.now()
	if now.Sub(t.sweep) < 10*time.Second {
		return
	}
	t.sweep = now
	for k, s := range t.m {
		if !now.Before(s.exp) {
			delete(t.m, k)
		}
	}
	for k, b := range t.rate {
		if now.Sub(b.start) >= time.Minute {
			delete(t.rate, k)
		}
	}
}

func validBox(b string) bool {
	if b == "" || len(b) > maxBox {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(b)
	return err == nil
}

// handle answers one request from host.
func (t *slots) handle(host string, r slotReq) slotResp {
	if !validChannel(r.Slot) {
		return slotResp{Error: "bad request"}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gc()
	now := t.now()
	switch r.Op {
	case "get":
		if !t.allow(host, true) {
			return slotResp{Error: "slow down"}
		}
		s := t.m[r.Slot]
		if s == nil || !now.Before(s.exp) {
			delete(t.m, r.Slot)
			return slotResp{Error: "not found"}
		}
		if s.reads++; s.reads >= maxSlotReads {
			delete(t.m, r.Slot)
		}
		return slotResp{OK: true, Box: s.box}
	case "put":
		if !validChannel(r.Tok) || !validBox(r.Box) {
			return slotResp{Error: "bad request"}
		}
		if !t.allow(host, false) {
			return slotResp{Error: "slow down"}
		}
		ttl := time.Duration(r.TTL) * time.Second
		if ttl <= 0 || ttl > maxSlotTTL {
			ttl = maxSlotTTL
		}
		if s := t.m[r.Slot]; s != nil && now.Before(s.exp) && s.tok != r.Tok {
			return slotResp{Error: "taken"}
		} else if s == nil && len(t.m) >= maxSlots {
			return slotResp{Error: "slow down"}
		}
		t.m[r.Slot] = &slot{box: r.Box, tok: r.Tok, exp: now.Add(ttl)}
		return slotResp{OK: true}
	case "del":
		if !t.allow(host, false) {
			return slotResp{Error: "slow down"}
		}
		if s := t.m[r.Slot]; s != nil && s.tok == r.Tok {
			delete(t.m, r.Slot)
		}
		return slotResp{OK: true}
	}
	return slotResp{Error: "bad request"}
}

// serveSlot answers a first line that names an op; the caller closes the connection.
func (s *Server) serveSlot(c net.Conn, ip string, line []byte) {
	var r slotReq
	resp := slotResp{Error: "bad request"}
	if json.Unmarshal(line, &r) == nil {
		resp = s.slots.handle(ip, r)
	}
	b, _ := json.Marshal(resp)
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write(append(b, '\n'))
}
