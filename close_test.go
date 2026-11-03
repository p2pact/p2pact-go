package p2pact

import (
	"sync/atomic"
	"testing"
	"time"
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
