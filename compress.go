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

// zipFastFrom: from this size on, a faster zstd level — the best one costs more time than
// the few percent of bytes it saves.
const zipFastFrom = 32 << 10

// dictKeep is how many dictionaries of one kind to keep (common ones, ours for a device,
// a device's own): new ones and those still in flight.
const dictKeep = 4

var zstdMagic = []byte{0x28, 0xb5, 0x2f, 0xfd}

// Dict is a compression dictionary; its id is the first 16 bytes of BLAKE2s of its bytes.
type Dict struct {
	ID  []byte
	Raw []byte
	zid uint32 // dictionary id inside zstd (from its header; 0 for a raw one)
	// peer: "" — a common dictionary, anyone may have it; otherwise it belongs to the pair
	// with this device and is never shown or given to another. own: we trained it (for peer).
	peer string
	own  bool

	once sync.Once
	enc  *zstd.Encoder
	fast *zstd.Encoder
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
		// not the best level: with a dictionary it costs ~30× the time (0.6 ms a message, under
		// the node's lock) for ~3 % fewer bytes
		d.enc, d.err = zstd.NewWriter(nil, zstd.WithEncoderDict(d.Raw), zstd.WithEncoderCRC(false),
			zstd.WithEncoderLevel(zstd.SpeedBetterCompression), zstd.WithEncoderConcurrency(1))
		if d.err == nil {
			d.fast, d.err = zstd.NewWriter(nil, zstd.WithEncoderDict(d.Raw), zstd.WithEncoderCRC(false),
				zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
		}
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
	fast *zstd.Encoder
	dec  *zstd.Decoder
}

func plainCodec() (*zstd.Encoder, *zstd.Decoder) {
	plainZ.once.Do(func() {
		plainZ.enc, _ = zstd.NewWriter(nil, zstd.WithEncoderCRC(false), zstd.WithEncoderLevel(zstd.SpeedBestCompression),
			zstd.WithEncoderConcurrency(1))
		plainZ.fast, _ = zstd.NewWriter(nil, zstd.WithEncoderCRC(false), zstd.WithEncoderLevel(zstd.SpeedDefault),
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
	if len(msg) >= zipFastFrom {
		enc = plainZ.fast
	}
	if d != nil {
		if d.init() != nil {
			return nil
		}
		enc = d.enc
		if len(msg) >= zipFastFrom {
			enc = d.fast
		}
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

// --- storage: dir/net-dicts/<id hex>; the order (newest first) is in the file "order",
// a line per dictionary: "<id hex>" for a common one, "<id hex> <device> own|their" for a pair's.

type dictStore struct {
	dir   string
	dicts []*Dict // newest first
	// slots: what we list to each device, by slot. A dictionary keeps its slot while listed
	// (a message compressed with it may still be on its way on another stream, behind the new
	// list); a dropped one leaves an empty id, and a new one goes to the end.
	slots map[string][][]byte
}

// slotsMax: past this many slots, a new dictionary takes the oldest empty one.
const slotsMax = 32

func loadDicts(dir string) *dictStore {
	s := &dictStore{dir: filepath.Join(dir, "net-dicts"), slots: map[string][][]byte{}}
	b, _ := os.ReadFile(filepath.Join(s.dir, "order"))
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 1 && len(f) != 3 { // a damaged line: never take a pair's dictionary for a common one
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, f[0]))
		if err != nil {
			continue
		}
		d, err := NewDict(raw)
		if err != nil || hexs(d.ID) != f[0] {
			continue
		}
		if len(f) == 3 {
			d.peer, d.own = f[1], f[2] == "own"
		}
		s.dicts = append(s.dicts, d)
	}
	return s
}

// visible reports whether d may be used with, listed to or given to peer.
func (d *Dict) visible(peer string) bool { return d.peer == "" || d.peer == peer }

// get returns dictionary id if peer may see it.
func (s *dictStore) get(id []byte, peer string) *Dict {
	for _, d := range s.dicts {
		if bytes.Equal(d.ID, id) && d.visible(peer) {
			return d
		}
	}
	return nil
}

// add puts a dictionary first (moving it up if known) and deletes the oldest extra ones of
// its kind.
func (s *dictStore) add(d *Dict) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.dir, hexs(d.ID)), d.Raw, 0o600); err != nil {
		return err
	}
	out, dropped := []*Dict{d}, []*Dict{}
	kinds := map[[2]any]int{{d.peer, d.own}: 1}
	for _, x := range s.dicts {
		if bytes.Equal(x.ID, d.ID) && x.peer == d.peer {
			continue
		}
		k := [2]any{x.peer, x.own}
		if kinds[k]++; kinds[k] > dictKeep {
			dropped = append(dropped, x)
			continue
		}
		out = append(out, x)
	}
	for _, x := range dropped {
		if !s.listed(out, x.ID) { // one file serves the same bytes kept as another kind
			_ = os.Remove(filepath.Join(s.dir, hexs(x.ID)))
		}
	}
	s.dicts = out
	return s.saveOrder()
}

// saveOrder writes the file "order" (through a temporary file: a torn one could turn a pair's
// dictionary into a common one, though loading skips damaged lines too).
func (s *dictStore) saveOrder() error {
	var lines []string
	for _, x := range s.dicts {
		line := hexs(x.ID)
		if x.peer != "" {
			line += " " + x.peer + map[bool]string{true: " own", false: " their"}[x.own]
		}
		lines = append(lines, line)
	}
	return writeFileAtomic(filepath.Join(s.dir, "order"), []byte(strings.Join(lines, "\n")+"\n"))
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// list is what peer sees of our dictionaries, newest first: the common ones and the pair's.
func (s *dictStore) list(peer string) []*Dict {
	var out []*Dict
	for _, d := range s.dicts {
		if d.visible(peer) && !s.listed(out, d.ID) {
			out = append(out, d)
		}
	}
	return out
}

func (s *dictStore) listed(list []*Dict, id []byte) bool {
	for _, d := range list {
		if bytes.Equal(d.ID, id) {
			return true
		}
	}
	return false
}

// ids is our list for peer, by slot (an empty id — a free slot).
func (s *dictStore) ids(peer string) [][]byte {
	list := s.list(peer)
	slots := s.slots[peer]
	for i, id := range slots {
		if len(id) > 0 && !s.listed(list, id) {
			slots[i] = []byte{}
		}
	}
	for j := len(list) - 1; j >= 0; j-- { // the oldest first, so the newest gets the last slot
		d := list[j]
		if has(slots, d.ID) {
			continue
		}
		free := -1
		if len(slots) >= slotsMax {
			for i, id := range slots {
				if len(id) == 0 {
					free = i
					break
				}
			}
		}
		if free < 0 {
			slots = append(slots, d.ID)
		} else {
			slots[free] = d.ID
		}
	}
	s.slots[peer] = slots
	return append([][]byte(nil), slots...)
}

// slotOf is d's slot in our list for peer (from 1).
func (s *dictStore) slotOf(peer string, d *Dict) int {
	for i, id := range s.ids(peer) {
		if bytes.Equal(id, d.ID) {
			return i + 1
		}
	}
	return 0
}

// own returns our newest dictionary trained for peer, nil if none.
func (s *dictStore) own(peer string) *Dict {
	for _, d := range s.dicts {
		if d.own && d.peer == peer {
			return d
		}
	}
	return nil
}

// pick returns the dictionary to compress for peer and its slot in our list for peer (from
// 1): ours trained for it if it has it, else the newest it also has (its list is theirs,
// minus lacks). Nothing in common: no dictionary, slot 0.
func (s *dictStore) pick(peer string, theirs, lacks [][]byte) (*Dict, int) {
	list := s.list(peer)
	ok := func(d *Dict) bool { return has(theirs, d.ID) && !has(lacks, d.ID) }
	for _, d := range list {
		if d.own && ok(d) {
			return d, s.slotOf(peer, d)
		}
	}
	for _, d := range list {
		if ok(d) {
			return d, s.slotOf(peer, d)
		}
	}
	return nil, 0
}

// forget drops what belongs to the pair with peer: our dictionaries for it and its own.
func (s *dictStore) forget(peer string) {
	var keep, drop []*Dict
	for _, d := range s.dicts {
		if d.peer == peer {
			drop = append(drop, d)
		} else {
			keep = append(keep, d)
		}
	}
	if len(drop) == 0 {
		return
	}
	s.dicts = keep
	for _, d := range drop {
		if !s.listed(keep, d.ID) {
			_ = os.Remove(filepath.Join(s.dir, hexs(d.ID)))
		}
	}
	delete(s.slots, peer)
	_ = s.saveOrder()
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
