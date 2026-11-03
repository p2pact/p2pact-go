//go:build !windows

package p2pact

import "os"

// restrictSocket leaves the socket to our OS user only.
func restrictSocket(path string) error { return os.Chmod(path, 0o600) }
