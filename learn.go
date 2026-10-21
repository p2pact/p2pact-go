package p2pact

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/blake2s"
)

// Our own dictionaries (spec §5): a device trains a dictionary for each device it talks to, on
// that conversation, so the dictionary shows the other side nothing it has not already seen.
// It learns what it sent; while that is little, what it got fills the history up to 256 KB
// (it helps then, and stops helping once there is enough of our own). The first dictionary
// comes at 32 KB of history; then a new one when the history has doubled (up to 1 MB), monthly,
// or when compression got 15 % worse than right after training.

const (
	learnFirst   = 32 << 10  // history to train the first dictionary on
	learnMax     = 1 << 20   // our messages kept: the newest
	learnHeard   = 256 << 10 // the received ones fill the history up to this
	learnSample  = 4 << 10   // a message is cut to this: a dictionary helps its start most
	learnWindow  = 32 << 10  // bytes sent to measure compression over
	learnWorse   = 1.15      // retrain when compression is this much worse than the first window
	learnMonth   = 30 * 24 * time.Hour
	learnDictMax = 64 << 10
)

// history is one conversation, kept in dir/net-history/<hash of the device's address>.
type history struct {
	path        string
	fileSize    int64
	buf         []byte // records not yet written: the disk is written outside the node's lock
	rewrite     bool   // the file has outgrown the history: write it anew
	flushing    bool
	gone        bool // the device was forgotten: write nothing more
	own, heard  [][]byte
	ownSize     int
	heardSize   int
	trained     int       // history size when the current dictionary was trained
	at          time.Time // when it was trained
	plain, zips int       // compression with the current dictionary over the current window
	base        float64   // and over the first window after training
	training    bool
}

// size is how much the next dictionary would be trained on.
func (h *history) size() int { return h.ownSize + min(h.heardSize, max(0, learnHeard-h.ownSize)) }

func (h *history) add(m []byte, heard bool) {
	if len(m) > learnSample {
		m = m[:learnSample]
	}
	list, size, limit := &h.own, &h.ownSize, learnMax
	if heard {
		list, size, limit = &h.heard, &h.heardSize, learnHeard
	}
	*list = append(*list, m)
	*size += len(m)
	for *size > limit {
		*size -= len((*list)[0])
		*list = (*list)[1:]
	}
}

func historyPath(dir, peer string) string {
	sum := blake2s.Sum256([]byte(peer))
	return filepath.Join(dir, "net-history", hexs(sum[:8]))
}

func (n *Node) historyLocked(ps *peerState) *history {
	if ps.hist != nil {
		return ps.hist
	}
	h := &history{path: historyPath(n.dir, ps.addr)}
	ps.hist = h
	b, _ := os.ReadFile(h.path)
	h.fileSize = int64(len(b))
	for len(b) >= 5 {
		l := int(binary.BigEndian.Uint32(b))
		if l > learnSample || len(b) < 5+l || b[4] > 1 { // a torn record: the rest is lost
			break
		}
		h.add(b[5:5+l], b[4] == 1)
		b = b[5+l:]
	}
	if d := n.dicts.own(ps.addr); d != nil {
		h.trained = h.size()
		if fi, err := os.Stat(filepath.Join(n.dicts.dir, hexs(d.ID))); err == nil {
			h.at = fi.ModTime()
		}
	}
	return h
}

// record is a message in the file: [length 4][1 — received, 0 — sent][bytes].
func record(b, m []byte, heard bool) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(m)))
	return append(append(b, map[bool]byte{false: 0, true: 1}[heard]), m...)
}

// saveLocked queues a message for the file; when the file has outgrown the history twice, it
// is written anew from the history.
func (n *Node) saveLocked(h *history, m []byte, heard bool) {
	h.buf = record(h.buf, m, heard)
	if h.fileSize+int64(len(h.buf)) > 2*(learnMax+learnHeard) {
		h.rewrite = true
	}
	if !h.flushing {
		h.flushing = true
		go n.flushHistory(h)
	}
}

func (n *Node) flushHistory(h *history) {
	for {
		n.mu.Lock()
		data, whole := h.buf, h.rewrite
		if whole {
			data = nil
			for _, x := range h.own {
				data = record(data, x, false)
			}
			for _, x := range h.heard {
				data = record(data, x, true)
			}
		}
		h.buf, h.rewrite = nil, false
		if len(data) == 0 || h.gone {
			h.flushing = false
			n.mu.Unlock()
			return
		}
		n.mu.Unlock()
		_ = os.MkdirAll(filepath.Dir(h.path), 0o700)
		if whole {
			_ = writeFileAtomic(h.path, data)
		} else if f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			_, _ = f.Write(data)
			_ = f.Close()
		}
		n.mu.Lock()
		if whole {
			h.fileSize = int64(len(data))
		} else {
			h.fileSize += int64(len(data))
		}
		n.mu.Unlock()
	}
}

// hearLocked records a conversation message we got from the device.
func (n *Node) hearLocked(ps *peerState, msg []byte) {
	if n.NoLearning || n.NoCompression || len(msg) < zipMin {
		return
	}
	h := n.historyLocked(ps)
	m := bytes.Clone(msg[:min(len(msg), learnSample)])
	h.add(m, true)
	n.saveLocked(h, m, true)
}

// learnLocked records a conversation message we send and trains a new dictionary when it is
// time. d and z are the dictionary it was compressed with and the result (nil — sent as is).
func (n *Node) learnLocked(ps *peerState, msg []byte, d *Dict, z []byte) {
	if n.NoLearning || len(msg) < zipMin {
		return
	}
	h := n.historyLocked(ps)
	m := bytes.Clone(msg[:min(len(msg), learnSample)])
	h.add(m, false)
	n.saveLocked(h, m, false)
	own := n.dicts.own(ps.addr)
	if own != nil && d == own {
		h.plain += len(msg)
		h.zips += len(msg)
		if z != nil {
			h.zips += len(z) - len(msg)
		}
	}
	if h.training {
		return
	}
	size := h.size()
	switch {
	case own == nil:
		if size < max(learnFirst, 2*h.trained) { // trained: a try that failed
			return
		}
	case size < learnFirst: // too little to replace what we have (the history was lost, say)
		return
	case h.trained < learnMax && size >= 2*h.trained: // the history doubled
	case time.Since(h.at) > learnMonth:
	case h.plain >= learnWindow:
		ratio := float64(h.zips) / float64(h.plain)
		h.plain, h.zips = 0, 0
		if h.base == 0 {
			h.base = ratio
			return
		}
		if ratio < h.base*learnWorse {
			return
		}
	default:
		return
	}
	h.training = true
	ownMsgs := append([][]byte(nil), h.own...)
	heard := append([][]byte(nil), h.heard[len(h.heard)-countFrom(h.heard, max(0, learnHeard-h.ownSize)):]...)
	go func() {
		n.train <- struct{}{}
		defer func() { <-n.train }()
		// tested on our newest messages: the dictionary is for what we send
		var train, test [][]byte
		if len(ownMsgs) >= 8 {
			split := len(ownMsgs) * 3 / 4
			train, test = append(heard, ownMsgs[:split]...), ownMsgs[split:]
		} else {
			all := append(heard, ownMsgs...)
			split := len(all) * 3 / 4
			train, test = all[:split], all[split:]
		}
		var d *Dict
		err := errors.New("node closed")
		select {
		case <-n.stop:
		default:
			d, err = safeTrain(train, test, min(learnDictMax, max(size/4, 4<<10)))
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		// a failure waits like a success: until the history doubles or a month passes
		h.training, h.trained, h.at = false, size, time.Now()
		select {
		case <-n.stop:
			return
		default:
		}
		if err != nil {
			return
		}
		d.peer, d.own = ps.addr, true
		if n.addDictLocked(d) == nil {
			h.plain, h.zips, h.base = 0, 0, 0
		}
	}()
}

// countFrom is how many of the newest messages fit in n bytes.
func countFrom(msgs [][]byte, n int) int {
	c := 0
	for i := len(msgs) - 1; i >= 0 && n >= len(msgs[i]); i-- {
		n -= len(msgs[i])
		c++
	}
	return c
}

// DictState tells what compresses messages to peer: own — our newest dictionary trained for it
// (nil — none yet), using — the one used now (nil — none, plain zstd), training — a new one is
// being trained.
func (n *Node) DictState(peer string) (own, using []byte, training bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if d := n.dicts.own(peer); d != nil {
		own = d.ID
	}
	if ps := n.peers[peer]; ps != nil {
		if d, _ := n.dicts.pick(peer, ps.dicts, ps.lacks); d != nil {
			using = d.ID
		}
		training = ps.hist != nil && ps.hist.training
	}
	return own, using, training
}

// safeTrain trains a dictionary; a panic in the trainer is an error, not a crash.
func safeTrain(train, test [][]byte, size int) (d *Dict, err error) {
	defer func() {
		if r := recover(); r != nil {
			d, err = nil, fmt.Errorf("training: %v", r)
		}
	}()
	raw, err := trainDict(train, test, size)
	if err != nil {
		return nil, err
	}
	return NewDict(raw)
}
