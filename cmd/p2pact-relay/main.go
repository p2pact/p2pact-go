// Command p2pact-relay runs a P2PACT relay: it forwards encrypted packets between two devices
// that cannot reach each other directly. It cannot read them.
//
//	p2pact-relay -addr :8443 -data /var/lib/p2pact-relay
//	p2pact-relay -addr :8443 -ws-host relay.example.org            # wss://relay.example.org/ on :443
//	p2pact-relay -ws-addr :8444 -ws-cert fullchain.pem -ws-key key.pem
//	p2pact-relay -addr 127.0.0.1:0 -ws-addr 127.0.0.1:8080          # plain ws, loopback only (tests)
//
// The TLS certificate is self-signed and created on first run; its fingerprint is printed at
// start. Give devices the address and the fingerprint (RelayHint).
//
// A WebSocket listener (-ws-addr, -ws-host) serves browsers, which cannot pin a certificate: it
// needs one from a certificate authority — Let's Encrypt for -ws-host (kept in <data>/autocert,
// port 443 must be reachable), or files (-ws-cert, -ws-key). It feeds the same channels as the
// TLS listener. Without a certificate it is plain ws and refuses anything but a loopback address.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme/autocert"

	"github.com/p2pact/p2pact-go/relay"
)

func fail(err any) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	addr := flag.String("addr", ":8443", "TLS listen address")
	data := flag.String("data", "/var/lib/p2pact-relay", "where to keep the certificate")
	printFP := flag.Bool("fingerprint", false, "print the certificate fingerprint and exit")
	wsAddr := flag.String("ws-addr", "", "WebSocket listen address (default :443 with -ws-host)")
	wsHost := flag.String("ws-host", "", "public host name of the WebSocket relay: a Let's Encrypt certificate is obtained for it")
	wsCert := flag.String("ws-cert", "", "certificate chain (PEM) for wss")
	wsKey := flag.String("ws-key", "", "private key (PEM) for wss")
	flag.Parse()

	cert, err := relay.LoadOrMakeCert(filepath.Join(*data, "cert.pem"), filepath.Join(*data, "key.pem"))
	if err != nil {
		fail("certificate: " + err.Error())
	}
	fp := relay.Fingerprint(cert)
	if *printFP {
		fmt.Println(fp)
		return
	}
	srv := relay.NewServer()

	if *wsHost != "" && *wsAddr == "" {
		*wsAddr = ":443"
	}
	if *wsAddr != "" {
		var tc *tls.Config
		switch {
		case *wsCert != "" || *wsKey != "":
			c, err := tls.LoadX509KeyPair(*wsCert, *wsKey)
			if err != nil {
				fail("ws certificate: " + err.Error())
			}
			tc = &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
		case *wsHost != "":
			m := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(*wsHost),
				Cache:      autocert.DirCache(filepath.Join(*data, "autocert")),
			}
			tc = m.TLSConfig()
			tc.MinVersion = tls.VersionTLS12
			tc.NextProtos = []string{"http/1.1", "acme-tls/1"} // no h2: WebSocket upgrades are HTTP/1.1
		case !relay.IsLoopbackAddr(*wsAddr):
			fail("plain ws is for loopback only: give -ws-host or -ws-cert and -ws-key for " + *wsAddr)
		}
		wl, err := net.Listen("tcp", *wsAddr)
		if err != nil {
			fail(err)
		}
		scheme := "ws"
		if tc != nil {
			wl = tls.NewListener(wl, tc)
			scheme = "wss"
		}
		slog.Info("websocket relay started", "url", scheme+"://"+wl.Addr().String()+"/", "host", *wsHost)
		go func() {
			if err := srv.ServeWS(wl); err != nil {
				fail(err)
			}
		}()
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fail(err)
	}
	slog.Info("relay started", "addr", ln.Addr().String(), "fingerprint", fp)
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err := srv.Serve(tl); err != nil {
		fail(err)
	}
}
