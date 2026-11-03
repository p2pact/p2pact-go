//go:build windows

package p2pact

// TODO(windows): the spec (§3) names a named pipe for Windows. Go's "unix" network works on
// Windows 10 and later (AF_UNIX), so the local socket road runs as a socket file there, with
// the same framing; a named pipe with an ACL for the current user (go-winio) can replace it
// without touching the protocol. File modes mean nothing on Windows: until then the socket
// belongs in a directory only the user can read (their profile), which the caller chooses.
func restrictSocket(path string) error { return nil }
