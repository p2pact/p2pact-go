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
	worse       bool      // a window came out 15 % worse than the first
	checked     time.Time // the last monthly and 15 % check
	due         string    // a new dictionary is due ("" — not), waiting for a lull since dueAt
	dueAt       time.Time
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
	if !h.flushing && n.goLocked(func() { n.flushHistory(h) }) {
		h.flushing = true
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

// Learning is deferred: sending and receiving only queue the message (queueLocked). Once a
// second the queue goes into the history in one go, off the sending path, and training waits
// for a lull in the conversation: the first dictionaries by the history's size, the monthly
// and the 15 % checks once a day.
var (
	learnTick  = time.Second
	learnLull  = time.Second    // no messages with the device for this long: time to train
	learnWait  = time.Minute    // or train anyway after waiting this long for a lull
	learnCheck = 24 * time.Hour // how often the monthly and the 15 % checks run
)

// learnQueueMax: bytes waiting for the history; past it messages are skipped — a dictionary
// needs what the conversation is like, not every message of it.
const learnQueueMax = 1 << 20

// learnOwnMin: a device that sends (almost) nothing worth compressing has no use for a
// dictionary of its own, however much it receives.
const learnOwnMin = 8

type pending struct {
	msg         []byte // not copied: a message is not changed once sent or received
	heard       bool
	plain, zips int // compressed with our dictionary for the device: its size before and after
}

// hearLocked queues a conversation message we got from the device.
func (n *Node) hearLocked(ps *peerState, msg []byte) {
	if !n.NoCompression {
		n.queueLocked(ps, pending{msg: msg, heard: true})
	}
}

// learnLocked queues a conversation message we send; d and z are the dictionary it was
// compressed with and the result (nil — sent as is).
func (n *Node) learnLocked(ps *peerState, msg []byte, d *Dict, z []byte) {
	p := pending{msg: msg}
	if d != nil && d.own {
		p.plain, p.zips = len(msg), len(msg)
		if z != nil {
			p.zips = len(z)
		}
	}
	n.queueLocked(ps, p)
}

func (n *Node) queueLocked(ps *peerState, p pending) {
	if n.NoLearning || len(p.msg) < zipMin || ps.queued >= learnQueueMax {
		return
	}
	ps.queue = append(ps.queue, p)
	ps.queued += min(len(p.msg), learnSample)
	ps.lastTalk = time.Now()
}

// learnLoop takes the queues into the histories and trains when it is time.
func (n *Node) learnLoop() {
	defer n.wg.Done()
	t := time.NewTicker(learnTick)
	defer t.Stop()
	for {
		select {
		case <-n.stop:
			return
		case now := <-t.C:
			n.learnTick(now)
		}
	}
}

func (n *Node) learnTick(now time.Time) {
	type batch struct {
		ps *peerState
		q  []pending
	}
	var work []batch
	n.mu.Lock()
	for _, ps := range n.peers {
		if len(ps.queue) > 0 || (ps.hist != nil && ps.hist.due != "") {
			work = append(work, batch{ps, ps.queue})
			ps.queue, ps.queued = nil, 0
		}
	}
	n.mu.Unlock()
	for _, w := range work {
		cut := make([][]byte, len(w.q)) // copied outside the lock
		for i, p := range w.q {
			cut[i] = bytes.Clone(p.msg[:min(len(p.msg), learnSample)])
		}
		n.mu.Lock()
		if n.peers[w.ps.addr] == w.ps { // not forgotten meanwhile
			h := n.historyLocked(w.ps)
			for i, p := range w.q {
				h.add(cut[i], p.heard)
				n.saveLocked(h, cut[i], p.heard)
				h.plain += p.plain
				h.zips += p.zips
			}
			n.considerLocked(w.ps, h, now)
		}
		n.mu.Unlock()
	}
}

// considerLocked decides whether a new dictionary is due and trains it in a lull.
func (n *Node) considerLocked(ps *peerState, h *history, now time.Time) {
	if h.training {
		return
	}
	own := n.dicts.own(ps.addr)
	size := h.size()
	if h.plain >= learnWindow { // compression over the last window of what we sent with it
		ratio := float64(h.zips) / float64(h.plain)
		h.plain, h.zips = 0, 0
		if h.base == 0 {
			h.base = ratio
		} else if ratio >= h.base*learnWorse {
			h.worse = true
		}
	}
	if h.due == "" && len(h.own) >= learnOwnMin {
		switch {
		case own == nil:
			if size >= max(learnFirst, 2*h.trained) { // trained: a try that failed
				h.due = "first"
			}
		case size < learnFirst: // too little to replace what we have (the history was lost, say)
		case h.trained < learnMax && size >= 2*h.trained:
			h.due = "doubled"
		case now.Sub(h.checked) >= learnCheck:
			h.checked = now
			if now.Sub(h.at) > learnMonth || h.worse {
				h.due = "check"
			}
		}
		if h.due != "" {
			h.dueAt = now
		}
	}
	if h.due == "" || (now.Sub(ps.lastTalk) < learnLull && now.Sub(h.dueAt) < learnWait) {
		return
	}
	h.due, h.worse, h.training = "", false, true
	ownMsgs := append([][]byte(nil), h.own...)
	heard := append([][]byte(nil), h.heard[len(h.heard)-countFrom(h.heard, max(0, learnHeard-h.ownSize)):]...)
	if !n.goLocked(func() {
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
		// a failure waits like a success: until the history doubles or the next check
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
	}) {
		h.training = false
	}
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
// due or being trained, or messages wait to be learnt.
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
		training = len(ps.queue) > 0 || ps.hist != nil && (ps.hist.training || ps.hist.due != "")
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
