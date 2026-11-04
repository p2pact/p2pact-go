package p2pact

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestNormalizeCode(t *testing.T) {
	for in, want := range map[string]string{
		"K7Q2-M9PX":  "K7Q2M9PX",
		"k7q2 m9px":  "K7Q2M9PX",
		"oilu-0000":  "011V0000",
		"K7Q2M9P":    "",
		"K7Q2-M9PX1": "",
		"K7Q2-M9P!":  "",
	} {
		if got := NormalizeCode(in); got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
	c := NewCode()
	if NormalizeCode(c) != c || FormatCode(c)[4] != '-' {
		t.Fatalf("NewCode %q", c)
	}
}

// The vector other implementations check against (p2pact-kotlin CodeTest).
func TestCodeSlotVector(t *testing.T) {
	slot, key, err := CodeSlot("k7q2-m9px")
	if err != nil {
		t.Fatal(err)
	}
	if slot != "ae1aa553fe39be90efcf1eded8ddf3e6" || hexs(key) != "01c23c62071cac48fe6a5cdc7fbf99940219a11f632e3e6565addfbe895c60ca" {
		t.Fatalf("slot %s key %s", slot, hexs(key))
	}
	// box of "p2pact1.vector" with nonce 00 01 … 0b
	const box = "AAECAwQFBgcICQoLKQMqysat2QOxFoZEfLdtACgMmw_hEYgh-uCshFLh"
	raw, _ := base64.RawURLEncoding.DecodeString(box)
	aead, _ := chacha20poly1305.New(key)
	ad, _ := hex.DecodeString(slot)
	if pt, err := aead.Open(nil, raw[:12], raw[12:], ad); err != nil || string(pt) != "p2pact1.vector" {
		t.Fatalf("box vector: %q %v", pt, err)
	}
}

func codeInvite(t *testing.T) string {
	t.Helper()
	n := node(t, "laptop", false, nil)
	return n.InviteAsk(5 * time.Minute).String()
}

func TestSealOpenCode(t *testing.T) {
	inv := codeInvite(t)
	slot, box, err := SealCode("K7Q2-M9PX", inv)
	if err != nil {
		t.Fatal(err)
	}
	if s2, _, _ := CodeSlot("k7q2m9px"); s2 != slot {
		t.Fatal("slot depends on the typing")
	}
	if got, err := OpenCode("k7q2 m9px", box); err != nil || got != inv {
		t.Fatalf("open: %v", err)
	}
	if _, err := OpenCode("K7Q2-M9PY", box); err == nil {
		t.Fatal("another code opened the box")
	}
	if _, box2, _ := SealCode("K7Q2-M9PX", inv); box2 == box {
		t.Fatal("the nonce repeats")
	}
}

func TestCodeTXT(t *testing.T) {
	inv := codeInvite(t)
	txt, err := CodeTXT("abc", "K7Q2-M9PX", inv)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range txt {
		if len(e) > 255 {
			t.Fatalf("TXT entry of %d bytes", len(e))
		}
		k, v, _ := strings.Cut(e, "=")
		m[k] = v
	}
	if m["v"] != "1" || m["a"] != "abc" || m["b1"] == "" {
		t.Fatalf("record %v", m)
	}
	if got := InviteFromTXT("K7Q2M9PX", m); got != inv {
		t.Fatal("invite not found in the record")
	}
	if InviteFromTXT("K7Q2M9PY", m) != "" {
		t.Fatal("another code matched")
	}
	delete(m, "b1")
	if InviteFromTXT("K7Q2M9PX", m) != "" {
		t.Fatal("a record with a missing piece opened")
	}
}

func TestPublishFetchCode(t *testing.T) {
	rh := relayServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	inv := codeInvite(t)
	code := NewCode()
	if _, err := FetchCode(ctx, rh, code); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("fetch before publish: %v", err)
	}
	o, err := PublishCode(ctx, rh, code, inv, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublishCode(ctx, rh, code, inv, 5*time.Minute); !errors.Is(err, ErrCodeTaken) {
		t.Fatalf("second device with the same code: %v", err)
	}
	got, err := FetchCode(ctx, rh, FormatCode(strings.ToLower(code)))
	if err != nil || got != inv {
		t.Fatalf("fetch: %q %v", got, err)
	}
	if err := o.Withdraw(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchCode(ctx, rh, code); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("fetch after withdraw: %v", err)
	}
}

// An older relay answers a slot request as a bad channel hello.
func TestFetchCodeOldRelay(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = bufio.NewReader(c).ReadString('\n')
				_, _ = c.Write([]byte(`{"error":"bad hello"}` + "\n"))
			}()
		}
	}()
	sum := sha256.Sum256(der)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := FetchCode(ctx, RelayHint{Addr: ln.Addr().String(), FP: hexs(sum[:])}, NewCode()); !errors.Is(err, ErrCodeUnsupported) {
		t.Fatalf("old relay: %v", err)
	}
}
