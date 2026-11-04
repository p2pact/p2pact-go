package p2pact

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Close waits for the application's callbacks in flight: after it returns, nothing of the
// node runs and nothing writes the application's files (a test's TempDir, an engine's data).
func TestCloseWaitsForCallbacks(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer b.Close()
	var started, finished atomic.Bool
	a.OnHello = func(string) {
		started.Store(true)
		time.Sleep(300 * time.Millisecond)
		finished.Store(true)
	}
	pair(t, a, b)
	deadline := time.Now().Add(10 * time.Second)
	for !started.Load() {
		if time.Now().After(deadline) {
			t.Fatal("OnHello was not called")
		}
		time.Sleep(5 * time.Millisecond)
	}
	a.Close()
	if !finished.Load() {
		t.Fatal("Close returned while OnHello was still running")
	}
}

// Close waits for a call handler in flight: what it writes is written when Close returns; a
// call and an event queued behind it on its stream do not run.
func TestCloseWaitsForHandlers(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer b.Close()
	pair(t, a, b)
	file := filepath.Join(t.TempDir(), "out")
	var started, after atomic.Bool
	a.Handle(64, 2, func(string, []cbor.RawMessage) ([]any, error) {
		started.Store(true)
		time.Sleep(300 * time.Millisecond)
		return nil, os.WriteFile(file, []byte("done"), 0o600)
	})
	a.Handle(64, 3, func(string, []cbor.RawMessage) ([]any, error) { after.Store(true); return nil, nil })
	a.mu.Lock()
	a.OnEvent = func(string, int, int, []cbor.RawMessage) { after.Store(true) }
	a.mu.Unlock()
	call := func(method int) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = b.CallOn(ctx, a.ID.Addr(), 7, 64, method)
	}
	go call(2)
	eventually(t, "the handler did not start", started.Load)
	_ = b.EventOn(a.ID.Addr(), 7, 64, 1)
	go call(3)
	time.Sleep(100 * time.Millisecond) // both reach a, behind the slow call
	a.Close()
	if got, err := os.ReadFile(file); err != nil || string(got) != "done" {
		t.Fatalf("Close returned before the handler finished: %q %v", got, err)
	}
	time.Sleep(200 * time.Millisecond)
	if after.Load() {
		t.Fatal("work queued behind the handler ran after Close")
	}
}

// A handler that waits selects on Context: Close ends the wait; an answer given Later is
// waited for the same way.
func TestCloseCancelsHandlers(t *testing.T) {
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer b.Close()
	pair(t, a, b)
	var started, cancelled, laterDone atomic.Bool
	a.Handle(64, 2, func(string, []cbor.RawMessage) ([]any, error) {
		started.Store(true)
		select {
		case <-a.Context().Done():
			cancelled.Store(true)
		case <-time.After(time.Minute):
		}
		return nil, nil
	})
	a.Handle(64, 3, func(string, []cbor.RawMessage) ([]any, error) {
		return nil, Later(func() ([]any, error) {
			<-a.Context().Done()
			time.Sleep(50 * time.Millisecond)
			laterDone.Store(true)
			return nil, nil
		})
	})
	go func() { _, _ = b.CallOn(context.Background(), a.ID.Addr(), 1, 64, 2) }()
	go func() { _, _ = b.CallOn(context.Background(), a.ID.Addr(), 2, 64, 3) }()
	eventually(t, "the handler did not start", started.Load)
	time.Sleep(100 * time.Millisecond)
	t0 := time.Now()
	a.Close()
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("Close took %v", d)
	}
	if !cancelled.Load() || !laterDone.Load() {
		t.Fatalf("Close returned before the handlers ended: cancelled %v, later %v", cancelled.Load(), laterDone.Load())
	}
}

// A handler that ignores Context holds up Close for closeWait at most.
func TestCloseBoundedWait(t *testing.T) {
	defer func(d time.Duration) { closeWait = d }(closeWait)
	closeWait = 200 * time.Millisecond
	a, b := node(t, "Mac", true, nil), node(t, "Phone", true, nil)
	defer b.Close()
	pair(t, a, b)
	release := make(chan struct{})
	defer close(release)
	var started atomic.Bool
	a.Handle(64, 2, func(string, []cbor.RawMessage) ([]any, error) {
		started.Store(true)
		<-release
		return nil, nil
	})
	go func() { _, _ = b.CallOn(context.Background(), a.ID.Addr(), 1, 64, 2) }()
	eventually(t, "the handler did not start", started.Load)
	t0 := time.Now()
	a.Close()
	if d := time.Since(t0); d < closeWait || d > 2*time.Second {
		t.Fatalf("Close took %v, want about %v", d, closeWait)
	}
}
