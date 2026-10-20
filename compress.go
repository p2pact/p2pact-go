package p2pact

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2s"
)

// Compression (spec §5): zstd with a dictionary. A compressed message is [dictionary slot 1]
// [zstd frame without its magic and dictionary id]: the receiver knows both from the slot in
// the sender's dictionary list. Slot 0 means no dictionary.

// zipMin: shorter messages are not compressed; the gain is below the overhead.
const zipMin = 64

// dictKeep is how many dictionaries to keep: new ones and those still in flight.
const dictKeep = 4

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// Dict is a compression dictionary; its id is the first 16 bytes of BLAKE2s of its bytes.
type Dict struct {
	ID  []byte
	Raw []byte
	zid uint32 // dictionary id inside zstd (from its header; 0 for a raw one)

	once sync.Once
	enc  *zstd.Encoder
	dec  *zstd.Decoder
	err  error
}

// DictID is a dictionary's id from its bytes.
func DictID(raw []byte) []byte {
	h := blake2s.Sum256(raw)
	return h[:16]
}

// NewDict loads a dictionary (`zstd --train` or dict.BuildZstdDict output).
func NewDict(raw []byte) (*Dict, error) {
	info, err := zstd.InspectDictionary(raw)
	if err != nil {
		return nil, err
	}
	return &Dict{ID: DictID(raw), Raw: raw, zid: info.ID()}, nil
}

func (d *Dict) init() error {
	d.once.Do(func() {
		d.enc, d.err = zstd.NewWriter(nil, zstd.WithEncoderDict(d.Raw), zstd.WithEncoderCRC(false),
			zstd.WithEncoderLevel(zstd.SpeedBestCompression), zstd.WithEncoderConcurrency(1))
		if d.err == nil {
			d.dec, d.err = zstd.NewReader(nil, zstd.WithDecoderDicts(d.Raw), zstd.WithDecoderConcurrency(1),
				zstd.WithDecoderMaxMemory(msgMax))
		}
	})
	return d.err
}

var plainZ struct {
	once sync.Once
	enc  *zstd.Encoder
	dec  *zstd.Decoder
}

func plainCodec() (*zstd.Encoder, *zstd.Decoder) {
	plainZ.once.Do(func() {
		plainZ.enc, _ = zstd.NewWriter(nil, zstd.WithEncoderCRC(false), zstd.WithEncoderLevel(zstd.SpeedBestCompression),
			zstd.WithEncoderConcurrency(1))
		plainZ.dec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(msgMax))
	})
	return plainZ.enc, plainZ.dec
}

// compress compresses msg for a receiver that has dictionary d (nil — none); slot is d's
// position in our list (from 1; 0 — no dictionary). It returns nil when not worth it.
func compress(msg []byte, d *Dict, slot int) []byte {
	if len(msg) < zipMin {
		return nil
	}
	enc, _ := plainCodec()
	if d != nil {
		if d.init() != nil {
			return nil
		}
		enc = d.enc
	}
	frame := stripFrame(enc.EncodeAll(msg, nil))
	if frame == nil || 1+len(frame) >= len(msg) {
		return nil
	}
	return append([]byte{byte(slot)}, frame...)
}

// decompress reverses compress; d is the dictionary for the slot in the first byte (nil for 0).
func decompress(b []byte, d *Dict) ([]byte, error) {
	if len(b) < 2 {
		return nil, errShort
	}
	_, dec := plainCodec()
	zid := uint32(0)
	if d != nil {
		if err := d.init(); err != nil {
			return nil, err
		}
		dec, zid = d.dec, d.zid
	}
	frame := restoreFrame(b[1:], zid)
	if frame == nil {
		return nil, errShort
	}
	return dec.DecodeAll(frame, nil)
}

// stripFrame drops the zstd magic (4 bytes) and dictionary id (up to 4) from a frame: the
// receiver knows both.
func stripFrame(f []byte) []byte {
	if len(f) < 6 || !bytes.Equal(f[:4], zstdMagic) {
		return nil
	}
	f = f[4:]
	fhd := f[0]
	didLen := [4]int{0, 1, 2, 4}[fhd&3]
	at := 1
	if fhd&0x20 == 0 { // not single-segment: a window descriptor follows
		at++
	}
	if len(f) < at+didLen {
		return nil
	}
	out := append([]byte{fhd &^ 3}, f[1:at]...)
	return append(out, f[at+didLen:]...)
}

// restoreFrame puts back the magic and dictionary id zid (0 — no dictionary).
func restoreFrame(f []byte, zid uint32) []byte {
	if len(f) < 2 || f[0]&3 != 0 {
		return nil
	}
	fhd := f[0]
	at := 1
	if fhd&0x20 == 0 {
		at++
	}
	if len(f) < at {
		return nil
	}
	out := append([]byte{}, zstdMagic...)
	if zid == 0 {
		return append(out, f...)
	}
	out = append(out, fhd|3)
	out = append(out, f[1:at]...)
	out = binary.LittleEndian.AppendUint32(out, zid)
	return append(out, f[at:]...)
}

// --- storage: dir/net-dicts/<id hex>; the order (newest first) is in the file "order" ---

type dictStore struct {
	dir   string
	dicts []*Dict // newest first
}

func loadDicts(dir string) *dictStore {
	s := &dictStore{dir: filepath.Join(dir, "net-dicts")}
	b, _ := os.ReadFile(filepath.Join(s.dir, "order"))
	for _, h := range strings.Fields(string(b)) {
		raw, err := os.ReadFile(filepath.Join(s.dir, h))
		if err != nil {
			continue
		}
		d, err := NewDict(raw)
		if err != nil || hexs(d.ID) != h {
			continue
		}
		s.dicts = append(s.dicts, d)
	}
	return s
}

func (s *dictStore) get(id []byte) *Dict {
	for _, d := range s.dicts {
		if bytes.Equal(d.ID, id) {
			return d
		}
	}
	return nil
}

// add puts a dictionary first (moving it up if known) and deletes the oldest extra ones.
func (s *dictStore) add(d *Dict) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	h := hexs(d.ID)
	if err := os.WriteFile(filepath.Join(s.dir, h), d.Raw, 0o600); err != nil {
		return err
	}
	out := []*Dict{d}
	for _, x := range s.dicts {
		if !bytes.Equal(x.ID, d.ID) {
			out = append(out, x)
		}
	}
	for _, x := range out[min(len(out), dictKeep):] {
		_ = os.Remove(filepath.Join(s.dir, hexs(x.ID)))
	}
	s.dicts = out[:min(len(out), dictKeep)]
	var ids []string
	for _, x := range s.dicts {
		ids = append(ids, hexs(x.ID))
	}
	return os.WriteFile(filepath.Join(s.dir, "order"), []byte(strings.Join(ids, "\n")+"\n"), 0o600)
}

func (s *dictStore) ids() [][]byte {
	out := make([][]byte, 0, len(s.dicts))
	for _, d := range s.dicts {
		out = append(out, d.ID)
	}
	return out
}

// pick returns our newest dictionary that the receiver also has (its list is theirs, minus
// lacks) and its slot in our list (from 1). Nothing in common: no dictionary, slot 0.
func (s *dictStore) pick(theirs, lacks [][]byte) (*Dict, int) {
	for i, d := range s.dicts {
		if has(theirs, d.ID) && !has(lacks, d.ID) {
			return d, i + 1
		}
	}
	return nil, 0
}

func has(list [][]byte, id []byte) bool {
	for _, x := range list {
		if bytes.Equal(x, id) {
			return true
		}
	}
	return false
}

var errNoDict = errors.New("dictionary missing")
