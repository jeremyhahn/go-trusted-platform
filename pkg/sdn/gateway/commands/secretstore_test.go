// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/controlplane"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/proxysvc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/secrets"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
)

// secretStoreFixture returns a configuration with a `secret-store:`
// section, the platform CA as `platform-ca-file:` and the node identity as
// the `control-plane:` pair, all from one bundle. The control-plane section
// is left disabled: the node identity is the node's whether or not the
// telemetry reporter runs.
func secretStoreFixture(t *testing.T) (*ServeConfig, *testutil.TestTLSBundle) {
	t.Helper()
	bundle := testutil.GenerateTestTLSBundle(t)
	certFile, keyFile, caFile := writeKeypairFixtures(t, bundle, bundle.ClientCert, "client")
	return &ServeConfig{
		Secrets:        &secrets.Config{QuicBaaSAddr: "127.0.0.1:9443"},
		PlatformCAFile: caFile,
		ControlPlane:   &controlplane.Config{CertFile: certFile, KeyFile: keyFile},
	}, bundle
}

func TestSecretStoreTLSPresentsTheNodeIdentity(t *testing.T) {
	cfg, bundle := secretStoreFixture(t)
	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		t.Fatalf("buildPlatformAnchor: %v", err)
	}
	tlsFn, err := secretStoreTLS(cfg, anchor)
	if err != nil {
		t.Fatalf("secretStoreTLS: %v", err)
	}
	tlsCfg, err := tlsFn(context.Background(), cfg.Secrets.QuicBaaSAddr)
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 || !bytes.Equal(tlsCfg.Certificates[0].Certificate[0], bundle.ClientCert.Certificate[0]) {
		t.Fatal("the store session must present the control-plane node certificate")
	}
	if tlsCfg.RootCAs == nil {
		t.Fatal("the store session must still verify the store against the platform anchor")
	}
}

func TestBuildHostRuntimeSecretStoreNeedsTheNodeIdentity(t *testing.T) {
	cfg, _ := secretStoreFixture(t)
	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		t.Fatalf("buildPlatformAnchor: %v", err)
	}
	pair := *cfg.ControlPlane
	for name, cp := range map[string]*controlplane.Config{
		"no control-plane section": nil,
		"no cert-file":             {KeyFile: pair.KeyFile},
		"no key-file":              {CertFile: pair.CertFile},
	} {
		t.Run(name, func(t *testing.T) {
			cfg.ControlPlane = cp
			_, err := buildHostRuntime(cfg, anchor, testLogger())
			var sectionErr *ErrConfigSection
			if !errors.As(err, &sectionErr) || sectionErr.Section != "secret-store" {
				t.Fatalf("err = %v, want *ErrConfigSection for secret-store", err)
			}
			var idErr *secrets.ErrClientIdentityRequired
			if !errors.As(err, &idErr) {
				t.Fatalf("err = %v, want secrets.ErrClientIdentityRequired", err)
			}
		})
	}
}

func TestBuildHostRuntimeSecretStoreIdentityMustLoad(t *testing.T) {
	cfg, _ := secretStoreFixture(t)
	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		t.Fatalf("buildPlatformAnchor: %v", err)
	}
	cfg.ControlPlane.KeyFile = filepath.Join(t.TempDir(), "missing-key.pem")
	_, err = buildHostRuntime(cfg, anchor, testLogger())
	var sectionErr *ErrConfigSection
	if !errors.As(err, &sectionErr) || sectionErr.Section != "secret-store" {
		t.Fatalf("err = %v, want *ErrConfigSection for secret-store", err)
	}
	var loadErr *proxysvc.ErrCertificateLoadFailed
	if !errors.As(err, &loadErr) || loadErr.CertFile != cfg.ControlPlane.CertFile {
		t.Fatalf("err = %v, want *proxysvc.ErrCertificateLoadFailed naming the cert-file", err)
	}
}

// handshakeResult is what the client-auth store saw of one session.
type handshakeResult struct {
	peerCN string
	err    error
}

// startClientAuthStore listens on loopback as a store that requires and
// verifies a client certificate issued by the bundle CA, and reports each
// session's server-side handshake outcome.
func startClientAuthStore(t *testing.T, bundle *testutil.TestTLSBundle) (string, <-chan handshakeResult) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{bundle.ServerCert},
		ClientCAs:    bundle.CAPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if cerr := ln.Close(); cerr != nil && !errors.Is(cerr, net.ErrClosed) {
			t.Errorf("close listener: %v", cerr)
		}
	})
	results := make(chan handshakeResult, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			results <- serveHandshake(conn.(*tls.Conn))
		}
	}()
	return ln.Addr().String(), results
}

func serveHandshake(conn *tls.Conn) handshakeResult {
	res := handshake(conn)
	if cerr := conn.Close(); cerr != nil && res.err == nil {
		res.err = cerr
	}
	return res
}

func handshake(conn *tls.Conn) handshakeResult {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return handshakeResult{err: err}
	}
	if err := conn.Handshake(); err != nil {
		return handshakeResult{err: err}
	}
	return handshakeResult{peerCN: conn.ConnectionState().PeerCertificates[0].Subject.CommonName}
}

// dialStore dials addr with tlsFn's config and returns what the store saw.
// The store's verdict is the one that counts: under TLS 1.3 the client's
// handshake completes before the server has checked its certificate.
func dialStore(t *testing.T, tlsFn secrets.TLSFunc, addr string, results <-chan handshakeResult) handshakeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsCfg, err := tlsFn(ctx, addr)
	if err != nil {
		t.Fatalf("tls: %v", err)
	}
	dialer := &tls.Dialer{Config: tlsCfg}
	if conn, err := dialer.DialContext(ctx, "tcp", addr); err == nil {
		if cerr := conn.Close(); cerr != nil {
			t.Fatalf("close: %v", cerr)
		}
	}
	select {
	case res := <-results:
		return res
	case <-ctx.Done():
		t.Fatalf("the store saw no session: %v", ctx.Err())
		return handshakeResult{}
	}
}

func TestSecretStoreSessionAgainstAClientAuthStore(t *testing.T) {
	cfg, bundle := secretStoreFixture(t)
	anchor, err := buildPlatformAnchor(cfg)
	if err != nil {
		t.Fatalf("buildPlatformAnchor: %v", err)
	}
	addr, results := startClientAuthStore(t, bundle)

	gatewayTLS, err := secretStoreTLS(cfg, anchor)
	if err != nil {
		t.Fatalf("secretStoreTLS: %v", err)
	}
	accepted := dialStore(t, gatewayTLS, addr, results)
	if accepted.err != nil {
		t.Fatalf("a store requiring client certificates refused the gateway: %v", accepted.err)
	}
	leaf, err := x509.ParseCertificate(bundle.ClientCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse node certificate: %v", err)
	}
	if accepted.peerCN != leaf.Subject.CommonName {
		t.Fatalf("store saw caller %q, want the node identity %q", accepted.peerCN, leaf.Subject.CommonName)
	}

	// The anchor's config alone is the one-way session #658 removed.
	unidentified := func(ctx context.Context, _ string) (*tls.Config, error) { return anchor.TLSConfig(ctx) }
	if refused := dialStore(t, unidentified, addr, results); refused.err == nil {
		t.Fatal("a store requiring client certificates must refuse a caller that presents none")
	}
}
