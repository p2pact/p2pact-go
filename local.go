package p2pact

import (
	"errors"
	"net"
	"os"
	"time"
)

// The local socket road (spec §3): programs on the same computer (a plugin, a CLI, an MCP
// server) talk to the node with the same packets over a stream socket, framed as on TCP. The
// node listens (ListenLocal); a program dials (UseLocal, then Join or a session as usual).
// Only the device's own OS user may open the socket: that is who may even try to pair; trust
// still comes from pairing.

// ListenLocal opens the local socket at path: a Unix domain socket (SOCK_STREAM) readable and
// writable by our OS user only (mode 0600). An old socket file nobody listens on is replaced.
func (n *Node) ListenLocal(path string) error {
	if path == "" {
		return errors.New("no socket path")
	}
	n.mu.Lock()
	taken := n.loc != nil
	n.mu.Unlock()
	if taken {
		return errors.New("the local socket is already in use")
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return errors.New(path + " is not a socket")
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return errors.New(path + " is in use")
		}
		_ = os.Remove(path)
	}
	l, err := listenStream("unix", "local", path, n.receive)
	if err != nil {
		return err
	}
	if err := restrictSocket(path); err != nil {
		l.close()
		return err
	}
	n.mu.Lock()
	n.loc, n.localPath = l, path
	n.mu.Unlock()
	return nil
}

// UseLocal makes the node reach a device on this computer over its local socket at path: Join
// and the session use it. The node does not listen.
func (n *Node) UseLocal(path string) error {
	if path == "" {
		return errors.New("no socket path")
	}
	l, _ := listenStream("unix", "local", "", n.receive)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.loc != nil {
		return errors.New("the local socket is already in use")
	}
	n.loc, n.localPath = l, path
	return nil
}

// LocalPath is the path of the local socket: the one we listen on, or the one we dial ("" — none).
func (n *Node) LocalPath() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.localPath
}

// isLocalLocked reports a packet that came over our local socket.
func (n *Node) isLocalLocked(from Endpoint) bool { return n.loc != nil && from.Road == Road(n.loc) }
