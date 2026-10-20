package p2pact

import (
	"encoding/binary"
	"errors"
)

// Packet types (spec §4.1).
const (
	pInit  = 1 // known-peer handshake start: [1][sender index 4][Noise]
	pResp  = 2 // reply: [2][receiver index 4][sender index 4][Noise]
	pPair1 = 3 // pairing: [3][invite id 16][sender index 4][Noise]
	pPair2 = 4 // [4][receiver index 4][sender index 4][Noise]
	pPair3 = 5 // [5][receiver index 4][Noise]
	pData  = 6 // [6][receiver index 4][packet number 4][ciphertext + tag 16]
	pReset = 7 // [7][index we do not know 4]
)

// dataHeader is the cleartext part of a data packet before the ciphertext; it is also the
// associated data the tag covers.
const dataHeader = 9

// MaxPacket is the largest packet: it crosses any network without fragmentation.
const MaxPacket = 1200

var errShort = errors.New("packet too short")

func u32(b []byte) uint32 { return binary.BigEndian.Uint32(b) }

func put32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

// window remembers the last 2048 packet numbers: replays and too-old packets are dropped
// (spec §4.1).
type window struct {
	top  uint64 // highest accepted number + 1 (0 — nothing yet)
	bits [32]uint64
}

const windowSize = 2048

// accept reports whether n is new and remembers it; a replay or a number older than the
// window is refused.
func (w *window) accept(n uint64) bool {
	switch {
	case n+1 > w.top:
		shift := n + 1 - w.top
		if shift >= windowSize {
			w.bits = [32]uint64{}
		} else {
			for i := uint64(0); i < shift; i++ {
				w.clear((w.top + i) % windowSize)
			}
		}
		w.top = n + 1
	case w.top-n > windowSize:
		return false
	case w.has(n % windowSize):
		return false
	}
	w.set(n % windowSize)
	return true
}

func (w *window) has(i uint64) bool { return w.bits[i/64]&(1<<(i%64)) != 0 }
func (w *window) set(i uint64)      { w.bits[i/64] |= 1 << (i % 64) }
func (w *window) clear(i uint64)    { w.bits[i/64] &^= 1 << (i % 64) }
