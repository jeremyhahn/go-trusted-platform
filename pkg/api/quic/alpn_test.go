// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build codec_msgpack

package quic

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	quicgo "github.com/quic-go/quic-go"
)

// startSelfSignedServer runs a server on the TLS configuration the daemon
// builds for itself, so the ALPN it advertises is the production one.
func startSelfSignedServer(t *testing.T) (addr string, clientTLS func(alpn string) *tls.Config) {
	t.Helper()
	serverTLS, err := GenerateSelfSignedTLSConfig()
	if err != nil {
		t.Fatalf("build the server TLS configuration: %v", err)
	}
	server, err := NewServer(&ServerConfig{ListenAddr: "127.0.0.1:0", TLSConfig: serverTLS})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return server.ListenAddr(), func(alpn string) *tls.Config {
		config := generateTestClientTLSConfig(serverTLS)
		config.NextProtos = []string{alpn}
		return config
	}
}

// TestServerTLSAdvertisesOnlyThePlatformALPN pins the server's ALPN to the
// constant every platform client offers; disjoint sets fail the handshake
// with no_application_protocol before a stream is opened.
func TestServerTLSAdvertisesOnlyThePlatformALPN(t *testing.T) {
	addr, clientTLS := startSelfSignedServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quicgo.DialAddr(ctx, addr, clientTLS(quicwire.ALPNProtocol), &quicgo.Config{})
	if err != nil {
		t.Fatalf("a client offering %q must complete the handshake: %v", quicwire.ALPNProtocol, err)
	}
	defer func() {
		if err := conn.CloseWithError(0, "done"); err != nil {
			t.Errorf("close: %v", err)
		}
	}()
	if got := conn.ConnectionState().TLS.NegotiatedProtocol; got != quicwire.ALPNProtocol {
		t.Errorf("negotiated ALPN %q, want %q", got, quicwire.ALPNProtocol)
	}
}

// TestServerRefusesAWrongALPNAtTheHandshake proves a protocol no listener
// advertises fails the handshake, rather than opening a stream nothing reads.
func TestServerRefusesAWrongALPNAtTheHandshake(t *testing.T) {
	addr, clientTLS := startSelfSignedServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := quicgo.DialAddr(ctx, addr, clientTLS("device-quic"), &quicgo.Config{})
	if err == nil {
		closeErr := conn.CloseWithError(0, "unexpected success")
		t.Fatalf("the server accepted ALPN \"device-quic\", which it does not advertise (close: %v)", closeErr)
	}
}
