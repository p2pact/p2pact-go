package p2pact

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Invite is an invitation to pair (spec §2): `p2pact1.<base64url(CBOR)>`.
type Invite struct {
	Key    []byte
	Name   string
	Secret []byte
	Exp    time.Time
	Hints  Hints
}

// ID is the invite id in pairing packets and its relay channel.
func (i *Invite) ID() []byte { return mac(i.Secret, "invite")[:16] }

const invitePrefix = "p2pact1."

type inviteWire struct {
	_      struct{} `cbor:",toarray"`
	V      int
	Key    []byte
	Name   string
	Secret []byte
	Exp    int64
	Hints  hintsWire
}

// hintsWire is [UDP addresses, [relay address, fingerprint], TCP addresses].
type hintsWire struct {
	_     struct{} `cbor:",toarray"`
	UDP   []string
	Relay []string
	TCP   []string
}

func toWire(h Hints) hintsWire {
	w := hintsWire{UDP: h.UDP, TCP: h.TCP}
	if h.Relay != nil {
		w.Relay = []string{h.Relay.Addr, h.Relay.FP}
	}
	return w
}

func fromWire(w hintsWire) Hints {
	h := Hints{UDP: w.UDP, TCP: w.TCP}
	if len(w.Relay) == 2 && w.Relay[0] != "" {
		h.Relay = &RelayHint{Addr: w.Relay[0], FP: w.Relay[1]}
	}
	return h
}

func (i *Invite) String() string {
	b, _ := cbor.Marshal(inviteWire{V: 1, Key: i.Key, Name: i.Name, Secret: i.Secret, Exp: i.Exp.Unix(), Hints: toWire(i.Hints)})
	return invitePrefix + base64.RawURLEncoding.EncodeToString(b)
}

// ParseInvite parses an invite string; an expired invite is an error.
func ParseInvite(s string) (*Invite, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, invitePrefix) {
		return nil, errors.New("not an invite")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, invitePrefix))
	if err != nil {
		return nil, errors.New("invite is corrupt")
	}
	var w inviteWire
	if cbor.Unmarshal(b, &w) != nil || w.V != 1 || len(w.Key) != 32 || len(w.Secret) != 32 {
		return nil, errors.New("invite is corrupt")
	}
	inv := &Invite{Key: w.Key, Name: w.Name, Secret: w.Secret, Exp: time.Unix(w.Exp, 0), Hints: fromWire(w.Hints)}
	if time.Now().After(inv.Exp) {
		return nil, errors.New("invite expired")
	}
	return inv, nil
}

func hexs(b []byte) string { return hex.EncodeToString(b) }
