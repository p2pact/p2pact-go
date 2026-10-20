// Command p2pact-relay runs a P2PACT relay: it forwards encrypted packets between two devices
// that cannot reach each other directly. It cannot read them.
//
//	p2pact-relay -addr :8443 -data /var/lib/p2pact-relay
//
// The certificate is self-signed and created on first run; its fingerprint is printed at
// start. Give devices the address and the fingerprint (RelayHint).
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/p2pact/p2pact-go/relay"
)

func main() {
	addr := flag.String("addr", ":8443", "listen address")
	data := flag.String("data", "/var/lib/p2pact-relay", "where to keep the certificate")
	printFP := flag.Bool("fingerprint", false, "print the certificate fingerprint and exit")
	flag.Parse()

	cert, err := relay.LoadOrMakeCert(filepath.Join(*data, "cert.pem"), filepath.Join(*data, "key.pem"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "certificate:", err)
		os.Exit(1)
	}
	fp := relay.Fingerprint(cert)
	if *printFP {
		fmt.Println(fp)
		return
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	slog.Info("relay started", "addr", *addr, "fingerprint", fp)
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err := relay.NewServer().Serve(tl); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
