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

package testutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestGenerateTestTLSBundle(t *testing.T) {

	t.Run("generates valid CA certificate", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)

		if bundle.CACert == nil {
			t.Fatal("CACert is nil")
		}
		if !bundle.CACert.IsCA {
			t.Error("CACert.IsCA should be true")
		}
		if bundle.CACert.Subject.CommonName != "Test Platform CA" {
			t.Errorf("CACert CommonName = %q, want %q", bundle.CACert.Subject.CommonName, "Test Platform CA")
		}
		if bundle.CACert.NotAfter.Before(time.Now()) {
			t.Error("CACert should not be expired")
		}

		// Verify CA key is ECDSA P-256
		pub, ok := bundle.CACert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("CACert public key is not ECDSA")
		}
		if pub.Curve != elliptic.P256() {
			t.Error("CACert key curve should be P-256")
		}
	})

	t.Run("generates valid CA PEM and pool", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)

		if len(bundle.CACertPEM) == 0 {
			t.Fatal("CACertPEM is empty")
		}
		if bundle.CAPool == nil {
			t.Fatal("CAPool is nil")
		}

		// Verify the PEM can be parsed back
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(bundle.CACertPEM) {
			t.Error("CACertPEM is not valid PEM")
		}
	})

	t.Run("generates valid server certificate", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)

		if len(bundle.ServerCert.Certificate) == 0 {
			t.Fatal("ServerCert has no certificate data")
		}

		leaf, err := x509.ParseCertificate(bundle.ServerCert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse server certificate: %v", err)
		}

		if leaf.Subject.CommonName != "localhost" {
			t.Errorf("server cert CommonName = %q, want %q", leaf.Subject.CommonName, "localhost")
		}

		// Verify SANs
		hasLocalhost := false
		for _, dns := range leaf.DNSNames {
			if dns == "localhost" {
				hasLocalhost = true
			}
		}
		if !hasLocalhost {
			t.Error("server cert should have localhost DNS SAN")
		}

		hasLoopback := false
		for _, ip := range leaf.IPAddresses {
			if ip.Equal(net.IPv4(127, 0, 0, 1)) {
				hasLoopback = true
			}
		}
		if !hasLoopback {
			t.Error("server cert should have 127.0.0.1 IP SAN")
		}

		// Verify ExtKeyUsage
		hasServerAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth {
				hasServerAuth = true
			}
		}
		if !hasServerAuth {
			t.Error("server cert should have ServerAuth ExtKeyUsage")
		}

		// Verify signed by CA
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:     bundle.CAPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			t.Errorf("server cert verification against CA failed: %v", err)
		}
	})

	t.Run("generates valid client certificate", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)

		if len(bundle.ClientCert.Certificate) == 0 {
			t.Fatal("ClientCert has no certificate data")
		}

		leaf, err := x509.ParseCertificate(bundle.ClientCert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse client certificate: %v", err)
		}

		if leaf.Subject.CommonName != "test-client" {
			t.Errorf("client cert CommonName = %q, want %q", leaf.Subject.CommonName, "test-client")
		}

		// Verify ExtKeyUsage
		hasClientAuth := false
		for _, usage := range leaf.ExtKeyUsage {
			if usage == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
			}
		}
		if !hasClientAuth {
			t.Error("client cert should have ClientAuth ExtKeyUsage")
		}

		// Verify signed by CA
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:     bundle.CAPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}); err != nil {
			t.Errorf("client cert verification against CA failed: %v", err)
		}
	})

	t.Run("certificates expire within expected window", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)

		leaf, err := x509.ParseCertificate(bundle.ServerCert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse server certificate: %v", err)
		}

		remaining := time.Until(leaf.NotAfter)
		if remaining < 50*time.Minute || remaining > 65*time.Minute {
			t.Errorf("server cert remaining lifetime = %v, expected ~1 hour", remaining)
		}

		// CA should outlive leaf certs
		caRemaining := time.Until(bundle.CACert.NotAfter)
		if caRemaining <= remaining {
			t.Error("CA cert should outlive server cert")
		}
	})

	t.Run("each invocation produces unique certificates", func(t *testing.T) {
		bundle1 := GenerateTestTLSBundle(t)
		bundle2 := GenerateTestTLSBundle(t)

		leaf1, err := x509.ParseCertificate(bundle1.ServerCert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse first server certificate: %v", err)
		}
		leaf2, err := x509.ParseCertificate(bundle2.ServerCert.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse second server certificate: %v", err)
		}

		pub1, ok := leaf1.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("first server cert public key is not ECDSA")
		}
		pub2, ok := leaf2.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatal("second server cert public key is not ECDSA")
		}

		b1, err := pub1.ECDH()
		if err != nil {
			t.Fatalf("failed to convert first key to ECDH: %v", err)
		}
		b2, err := pub2.ECDH()
		if err != nil {
			t.Fatalf("failed to convert second key to ECDH: %v", err)
		}
		if bytes.Equal(b1.Bytes(), b2.Bytes()) {
			t.Error("two bundles should have different server keys")
		}
	})
}

func TestServerTLSConfig(t *testing.T) {

	t.Run("enforces TLS 1.3 minimum", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ServerTLSConfig()

		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %d, want %d (TLS 1.3)", cfg.MinVersion, tls.VersionTLS13)
		}
	})

	t.Run("requires and verifies client certificates", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ServerTLSConfig()

		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
		}
	})

	t.Run("includes server certificate", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ServerTLSConfig()

		if len(cfg.Certificates) != 1 {
			t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
		}
		if len(cfg.Certificates[0].Certificate) == 0 {
			t.Error("server certificate data is empty")
		}
	})

	t.Run("includes client CA pool", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ServerTLSConfig()

		if cfg.ClientCAs == nil {
			t.Error("ClientCAs should not be nil")
		}
	})

	t.Run("does not set InsecureSkipVerify", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ServerTLSConfig()

		if cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify must be false")
		}
	})
}

func TestClientTLSConfig(t *testing.T) {

	t.Run("enforces TLS 1.3 minimum", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ClientTLSConfig()

		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %d, want %d (TLS 1.3)", cfg.MinVersion, tls.VersionTLS13)
		}
	})

	t.Run("includes root CA pool", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ClientTLSConfig()

		if cfg.RootCAs == nil {
			t.Error("RootCAs should not be nil")
		}
	})

	t.Run("includes client certificate", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ClientTLSConfig()

		if len(cfg.Certificates) != 1 {
			t.Fatalf("len(Certificates) = %d, want 1", len(cfg.Certificates))
		}
		if len(cfg.Certificates[0].Certificate) == 0 {
			t.Error("client certificate data is empty")
		}
	})

	t.Run("does not set InsecureSkipVerify", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)
		cfg := bundle.ClientTLSConfig()

		if cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify must be false")
		}
	})

	t.Run("completes mTLS handshake with server config", func(t *testing.T) {
		bundle := GenerateTestTLSBundle(t)

		serverCfg := bundle.ServerTLSConfig()
		clientCfg := bundle.ClientTLSConfig()

		listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
		if err != nil {
			t.Fatalf("failed to create TLS listener: %v", err)
		}
		defer listener.Close()

		handshakeDone := make(chan error, 1)
		go func() {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				handshakeDone <- acceptErr
				return
			}
			defer conn.Close()

			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				handshakeDone <- ErrNotTLSConnection
				return
			}
			handshakeDone <- tlsConn.Handshake()
		}()

		clientCfg.ServerName = "localhost"
		conn, err := tls.Dial("tcp", listener.Addr().String(), clientCfg)
		if err != nil {
			t.Fatalf("client TLS dial failed: %v", err)
		}
		defer conn.Close()

		if serverErr := <-handshakeDone; serverErr != nil {
			t.Fatalf("server handshake failed: %v", serverErr)
		}

		state := conn.ConnectionState()
		if state.Version != tls.VersionTLS13 {
			t.Errorf("negotiated TLS version = %d, want %d (TLS 1.3)", state.Version, tls.VersionTLS13)
		}
	})
}

func TestServerConnectionState(t *testing.T) {
	t.Run("is a completed TLS 1.3 handshake", func(t *testing.T) {
		state := ServerConnectionState(t)

		if !state.HandshakeComplete {
			t.Error("HandshakeComplete = false, want true")
		}
		if state.Version != tls.VersionTLS13 {
			t.Errorf("Version = %d, want %d (TLS 1.3)", state.Version, tls.VersionTLS13)
		}
	})

	t.Run("each call is a separate connection", func(t *testing.T) {
		first, err := ServerConnectionState(t).ExportKeyingMaterial("testutil", nil, 32)
		if err != nil {
			t.Fatalf("first exporter failed: %v", err)
		}
		second, err := ServerConnectionState(t).ExportKeyingMaterial("testutil", nil, 32)
		if err != nil {
			t.Fatalf("second exporter failed: %v", err)
		}
		if bytes.Equal(first, second) {
			t.Error("two connections exported the same keying material")
		}
	})
}
