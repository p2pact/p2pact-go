package client

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2s"
)

// StreamOf is the stream of a session or resource: the first 8 bytes of BLAKE2s(id) as a
// number, 0 replaced by 1 (chat spec §2); no id — 0.
func StreamOf(id string) uint64 {
	if id == "" {
		return 0
	}
	sum := blake2s.Sum256([]byte(id))
	var n uint64
	for _, b := range sum[:8] {
		n = n<<8 | uint64(b)
	}
	if n == 0 {
		return 1
	}
	return n
}

var jsonDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{DefaultMapType: reflect.TypeOf(map[string]any(nil))}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// toJSON makes a CBOR value into JSON: byte strings become base64 text. An undecodable value
// is null.
func toJSON(raw cbor.RawMessage) json.RawMessage {
	var v any
	if err := jsonDec.Unmarshal(raw, &v); err != nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// wire makes a JSON tree ready for CBOR: whole floats become integers (a JSON number read as
// float64 is still a whole number on the wire).
func wire(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = wire(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = wire(e)
		}
		return out
	case float64:
		if x == math.Floor(x) && math.Abs(x) < 1e15 {
			return int64(x)
		}
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
	case json.RawMessage:
		var t any
		d := json.NewDecoder(bytes.NewReader(x))
		d.UseNumber()
		if d.Decode(&t) == nil {
			return wire(t)
		}
	}
	return v
}

// decode reads JSON into v leniently: a field of the wrong type is skipped, the rest is read.
func decode(raw json.RawMessage, v any) {
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, v)
	}
}

func rawList(raw json.RawMessage) []json.RawMessage {
	var l []json.RawMessage
	decode(raw, &l)
	return l
}

func parseAll[T any](raw json.RawMessage, parse func(json.RawMessage) T) []T {
	l := rawList(raw)
	out := make([]T, 0, len(l))
	for _, r := range l {
		out = append(out, parse(r))
	}
	return out
}

func clone(b []byte) json.RawMessage { return append(json.RawMessage(nil), b...) }

// p2pactMeta is the object at `_meta.p2pact` of an ACP object (chat spec §8).
type p2pactMeta struct {
	Meta struct {
		P2pact json.RawMessage `json:"p2pact"`
	} `json:"_meta"`
}

func metaOf(raw json.RawMessage) json.RawMessage {
	var m p2pactMeta
	decode(raw, &m)
	return m.Meta.P2pact
}
