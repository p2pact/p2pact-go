package p2pact

import (
	"context"
	"errors"
)

// AfterEvents waits until the events already queued for a device on a stream have been handed
// to OnEvent. A call's result is not queued behind the events the device sent before it (it
// goes straight to the caller), so a client that must see "everything up to the result" — a
// loaded chat's history — waits with this after the call returns. Do not call it from OnEvent
// of the same stream: it would wait for itself.
func (n *Node) AfterEvents(ctx context.Context, peer string, stream uint64) error {
	done := make(chan struct{})
	n.mu.Lock()
	ps := n.peerLocked(peer)
	if ps == nil {
		n.mu.Unlock()
		return errors.New("unknown device")
	}
	n.inboxLocked(ps, stream, func() { close(done) })
	n.mu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
