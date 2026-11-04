package p2pact

import (
	"bufio"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Short code (spec §2): an invite a person can type. The inviting device seals a fresh invite
// with a key derived from an 8-symbol code and puts it on its relay (PublishCode) and in its
// local discovery record (CodeTXT); the other device, given the code, gets it back (FetchCode,
// InviteFromTXT) and joins as with any invite. The code is low-entropy: it only finds the
// invite. Issue it with InviteAsk and grant nothing until the person has compared a check both
// sides compute from the invite secret and both keys.

// CodeAlphabet is Crockford base32 without I, L, O, U.
const CodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CodeLen is the number of symbols in a code (40 bits).
const CodeLen = 8

// CodeService is the DNS-SD service type of local discovery (spec §7).
const CodeService = "_p2pact._udp"

const (
	codeSalt   = "p2pact-code"
	codeRounds = 100000
	codePiece  = 200 // characters of the box per TXT entry
)

var (
	// ErrCodeNotFound — nobody shows this code now (wrong, expired or already used).
	ErrCodeNotFound = errors.New("code not found")
	// ErrCodeUnsupported — the relay has no code slots (an older relay).
	ErrCodeUnsupported = errors.New("relay has no code slots")
	// ErrCodeTaken — the slot is held by another device: pick another code.
	ErrCodeTaken = errors.New("code taken")
	// ErrCodeSlowDown — the relay limits requests from this address.
	ErrCodeSlowDown = errors.New("relay: too many code requests")
)

// NewCode returns a random code of CodeLen symbols.
func NewCode() string {
	b := make([]byte, CodeLen)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = CodeAlphabet[int(b[i])%len(CodeAlphabet)]
	}
	return string(b)
}

// NormalizeCode returns the code as typed by a person in canonical form: upper case, spaces and
// dashes dropped, O→0, I/L→1, U→V. "" — not a code.
func NormalizeCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case ' ', '-', '\t', '\n', '·':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		case 'U':
			r = 'V'
		}
		if !strings.ContainsRune(CodeAlphabet, r) {
			return ""
		}
		b.WriteRune(r)
	}
	if b.Len() != CodeLen {
		return ""
	}
	return b.String()
}

// FormatCode shows a code to a person: "K7Q2-M9PX".
func FormatCode(code string) string {
	if len(code) != CodeLen {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// CodeSlot returns the slot of a code (32 hex: the relay key and the TXT tag) and its sealing key.
func CodeSlot(code string) (slot string, key []byte, err error) {
	c := NormalizeCode(code)
	if c == "" {
		return "", nil, errors.New("not a code")
	}
	k, err := pbkdf2.Key(sha256.New, c, []byte(codeSalt), codeRounds, 48)
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(k[:16]), k[16:], nil
}

// SealCode seals an invite under a code: its slot and the box.
func SealCode(code, invite string) (slot, box string, err error) {
	slot, key, err := CodeSlot(code)
	if err != nil {
		return "", "", err
	}
	box, err = sealBox(slot, key, invite)
	return slot, box, err
}

func sealBox(slot string, key []byte, invite string) (string, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	ad, _ := hex.DecodeString(slot)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(invite), ad)), nil
}

// OpenCode opens a box with the code; the invite inside must parse and not be expired.
func OpenCode(code, box string) (string, error) {
	slot, key, err := CodeSlot(code)
	if err != nil {
		return "", err
	}
	return openBox(slot, key, box)
}

func openBox(slot string, key []byte, box string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(box)
	if err != nil {
		return "", errors.New("code box is corrupt")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("code box is corrupt")
	}
	ad, _ := hex.DecodeString(slot)
	pt, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], ad)
	if err != nil {
		return "", errors.New("code box does not open with this code")
	}
	if _, err := ParseInvite(string(pt)); err != nil {
		return "", err
	}
	return string(pt), nil
}

// CodeTXT returns the TXT entries of the local discovery record (spec §7) for a device with
// address addr ("" — left out) showing a code for invite.
func CodeTXT(addr, code, invite string) ([]string, error) {
	slot, box, err := SealCode(code, invite)
	if err != nil {
		return nil, err
	}
	txt := []string{"v=1"}
	if addr != "" {
		txt = append(txt, "a="+addr)
	}
	txt = append(txt, "t="+slot)
	for i := 0; len(box) > 0; i++ {
		n := min(codePiece, len(box))
		txt = append(txt, "b"+strconv.Itoa(i)+"="+box[:n])
		box = box[n:]
	}
	return txt, nil
}

// InviteFromTXT returns the invite of a discovery record (its TXT as key → value) if it shows
// code; "" — it does not.
func InviteFromTXT(code string, txt map[string]string) string {
	slot, key, err := CodeSlot(code)
	if err != nil || txt["t"] != slot {
		return ""
	}
	var keys []int
	for k := range txt {
		if n, err := strconv.Atoi(strings.TrimPrefix(k, "b")); err == nil && strings.HasPrefix(k, "b") && n >= 0 {
			keys = append(keys, n)
		}
	}
	sort.Ints(keys)
	var box strings.Builder
	for i, n := range keys {
		if n != i {
			return "" // a piece is missing
		}
		box.WriteString(txt["b"+strconv.Itoa(n)])
	}
	inv, err := openBox(slot, key, box.String())
	if err != nil {
		return ""
	}
	return inv
}

// slotCall makes one code slot request to a relay (spec §3).
func slotCall(ctx context.Context, relay RelayHint, req map[string]any) (map[string]any, error) {
	r := &RelayRoad{hint: relay}
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := r.dial(); ch <- res{c, err} }()
	var conn net.Conn
	select {
	case <-ctx.Done():
		go func() {
			if x := <-ch; x.c != nil {
				x.c.Close()
			}
		}()
		return nil, ctx.Err()
	case x := <-ch:
		if x.err != nil {
			return nil, x.err
		}
		conn = x.c
	}
	defer conn.Close()
	dl := time.Now().Add(15 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(dl) {
		dl = d
	}
	_ = conn.SetDeadline(dl)
	req["relay"] = 1
	b, _ := json.Marshal(req)
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReaderSize(conn, 8<<10).ReadString('\n')
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if json.Unmarshal([]byte(line), &out) != nil {
		return nil, errors.New("relay: bad answer")
	}
	switch e, _ := out["error"].(string); e {
	case "":
		return out, nil
	case "not found":
		return nil, ErrCodeNotFound
	case "taken":
		return nil, ErrCodeTaken
	case "slow down":
		return nil, ErrCodeSlowDown
	case "bad hello":
		return nil, ErrCodeUnsupported
	default:
		return nil, fmt.Errorf("relay: %s", e)
	}
}

// CodeOffer is a code published on a relay; Withdraw takes it down.
type CodeOffer struct {
	Relay RelayHint
	Slot  string
	tok   string
}

// PublishCode puts invite under code on relay for ttl (at most 10 minutes). ErrCodeTaken —
// another device holds this code: make a new one.
func PublishCode(ctx context.Context, relay RelayHint, code, invite string, ttl time.Duration) (*CodeOffer, error) {
	slot, box, err := SealCode(code, invite)
	if err != nil {
		return nil, err
	}
	tok := make([]byte, 16)
	_, _ = rand.Read(tok)
	o := &CodeOffer{Relay: relay, Slot: slot, tok: hex.EncodeToString(tok)}
	secs := int((ttl + time.Second - 1) / time.Second)
	if _, err := slotCall(ctx, relay, map[string]any{"op": "put", "slot": slot, "box": box, "ttl": secs, "tok": o.tok}); err != nil {
		return nil, err
	}
	return o, nil
}

// Withdraw removes the code from the relay (it expires by itself otherwise).
func (o *CodeOffer) Withdraw(ctx context.Context) error {
	_, err := slotCall(ctx, o.Relay, map[string]any{"op": "del", "slot": o.Slot, "tok": o.tok})
	return err
}

// FetchCode gets the invite shown under code from relay. ErrCodeNotFound — nobody shows it;
// ErrCodeUnsupported — an older relay.
func FetchCode(ctx context.Context, relay RelayHint, code string) (string, error) {
	slot, key, err := CodeSlot(code)
	if err != nil {
		return "", err
	}
	out, err := slotCall(ctx, relay, map[string]any{"op": "get", "slot": slot})
	if err != nil {
		return "", err
	}
	box, _ := out["box"].(string)
	return openBox(slot, key, box)
}
