package client

import (
	"errors"
	"fmt"

	"github.com/p2pact/p2pact-go"
)

// Error is a P2PACT error (core spec §6): the call never reached the tool. Code is one of the
// p2pact.Err* constants. Match one with errors.Is against the sentinels below, or read Code
// with errors.As.
type Error struct {
	Code int
	Text string
}

func (e *Error) Error() string { return fmt.Sprintf("p2pact error %d: %s", e.Code, e.Text) }

// Is reports an error with the same code, so errors.Is(err, client.ErrForbidden) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Sentinels for errors.Is, one per code of the spec.
var (
	ErrNoMethod     = &Error{Code: p2pact.ErrNoMethod, Text: "no such tool or method"}
	ErrBadArgs      = &Error{Code: p2pact.ErrBadArgs, Text: "bad arguments"}
	ErrNotFound     = &Error{Code: p2pact.ErrNotFound, Text: "not found"}
	ErrForbidden    = &Error{Code: p2pact.ErrForbidden, Text: "forbidden"} // the grants do not allow the call (spec §8.1)
	ErrFailed       = &Error{Code: p2pact.ErrFailed, Text: "failed"}
	ErrNotDelivered = &Error{Code: p2pact.ErrNotDeliver, Text: "not delivered"}
)

// JSON-RPC error codes of the tools themselves.
const (
	RPCMethodNotFound = -32601
	RPCInvalidParams  = -32602
	RPCNoSuchResource = -32004
	RPCFailed         = -32000
)

// RPCError is a JSON-RPC error of the tool itself (the call was delivered). Data is the
// optional extra, as JSON.
type RPCError struct {
	Code    int
	Message string
	Data    []byte
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

func (e *RPCError) IsMethodNotFound() bool { return e.Code == RPCMethodNotFound }
func (e *RPCError) IsNoSuchResource() bool { return e.Code == RPCNoSuchResource }

// typed turns the library's error into ours; anything else stays as it is.
func typed(err error) error {
	var pe *p2pact.Error
	if errors.As(err, &pe) {
		return &Error{Code: pe.Code, Text: pe.Text}
	}
	return err
}
