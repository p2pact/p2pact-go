// Package p2pact is the reference implementation of the P2P Agent Chat Protocol (https://github.com/p2pact/p2pact):
// device keys, pairing by invite, Noise sessions over any road, delivery with
// acknowledgements, CBOR messages and dictionary compression.
//
// Roads today: UDP and relay. TCP, Bluetooth and "via a third device" come next.
package p2pact

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/curve25519"
)

// Prologue is the protocol version bound into every handshake (spec §10).
const Prologue = "p2pact/1"

var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// Identity holds a device's permanent keys (spec §1): X25519 for sessions and Ed25519 for
// signatures (the family book, spec/family.md §2).
type Identity struct {
	Key  noise.DHKey
	Sign ed25519.PrivateKey
}

// SignPublic is the public signing key.
func (i *Identity) SignPublic() ed25519.PublicKey { return i.Sign.Public().(ed25519.PublicKey) }

// Shared derives a secret shared with device pub without pairing: X25519 of the two
// permanent keys, equal on both sides. Used by devices that know each other from the family
// book.
func (i *Identity) Shared(pub []byte, label string) ([]byte, error) {
	s, err := curve25519.X25519(i.Key.Private, pub)
	if err != nil {
		return nil, err
	}
	return mac(s, label), nil
}

// Addr is this device's address.
func (i *Identity) Addr() string { return Address(i.Key.Public) }

// Address is a device address from its public key: the first 16 bytes of BLAKE2s, lowercase
// base32.
func Address(pub []byte) string {
	h := blake2s.Sum256(pub)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h[:16]))
}

// LoadIdentity reads keys from dir/net-key.json, creating them (owner-only) if missing.
func LoadIdentity(dir string) (*Identity, error) {
	path := filepath.Join(dir, "net-key.json")
	var f struct {
		Private []byte `json:"private"`
		Public  []byte `json:"public"`
		Sign    []byte `json:"sign,omitempty"` // Ed25519 seed
	}
	if b, err := os.ReadFile(path); err == nil {
		if json.Unmarshal(b, &f) != nil || len(f.Private) != 32 || len(f.Public) != 32 {
			return nil, errors.New("net-key.json is corrupt")
		}
		id := &Identity{Key: noise.DHKey{Private: f.Private, Public: f.Public}}
		if len(f.Sign) == ed25519.SeedSize {
			id.Sign = ed25519.NewKeyFromSeed(f.Sign)
			return id, nil
		}
		// keys from a version without signatures: add a signing key
		f.Sign = randBytes(ed25519.SeedSize)
		id.Sign = ed25519.NewKeyFromSeed(f.Sign)
		b, _ := json.Marshal(f)
		return id, os.WriteFile(path, b, 0o600)
	}
	k, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	f.Private, f.Public, f.Sign = k.Private, k.Public, randBytes(ed25519.SeedSize)
	b, _ := json.Marshal(f)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return &Identity{Key: k, Sign: ed25519.NewKeyFromSeed(f.Sign)}, nil
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// mac is HMAC-BLAKE2s(key, label): relay channels and invite ids are derived from secrets.
func mac(key []byte, label string) []byte {
	h, _ := blake2s.New256(key)
	h.Write([]byte(label))
	return h.Sum(nil)
}
