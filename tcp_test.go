package p2pact

import (
	"bytes"
	"testing"
	"time"
)

func tcpNode(t *testing.T, name, addr string, udp bool) *Node {
	t.Helper()
	n := nodeIn(t, t.TempDir(), name, udp, nil)
	if err := n.ListenTCP(addr); err != nil {
		t.Fatal(err)
	}
	return n
}

// TCP only: pairing and talking without any UDP.
func TestPairAndCallTCPOnly(t *testing.T) {
	a, b := tcpNode(t, "Laptop", "127.0.0.1:0", false), tcpNode(t, "Phone", "", false)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, b, a, []byte("hello over tcp"), 5*time.Second)
	echo(t, a, b, bytes.Repeat([]byte("long "), 2000), 5*time.Second)
	if paths := b.Paths(a.ID.Addr()); len(paths) != 1 || paths[0] != "tcp" {
		t.Fatalf("roads %v", paths)
	}
}

// UDP stops working: the same session continues over TCP.
func TestFallbackToTCP(t *testing.T) {
	a, b := tcpNode(t, "Laptop", "127.0.0.1:0", true), tcpNode(t, "Phone", "127.0.0.1:0", true)
	defer a.Close()
	defer b.Close()
	pair(t, a, b)
	echo(t, a, b, []byte("over udp"), 5*time.Second)
	before := a.handshakes.Load() + b.handshakes.Load()
	off := func() bool { return true }
	a.UDP().Drop, b.UDP().Drop = off, off
	echo(t, a, b, []byte("over tcp"), 10*time.Second)
	if after := a.handshakes.Load() + b.handshakes.Load(); after != before {
		t.Errorf("switching to tcp needed %d new handshakes", after-before)
	}
}
