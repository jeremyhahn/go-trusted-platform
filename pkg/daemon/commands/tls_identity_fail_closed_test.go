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

// tls_identity_fail_closed_test.go asserts the fail-closed contract of
// applyDaemonTLSIdentity (#32): when a TLS-terminating transport is enabled
// and the daemon identity cannot be provisioned, the function returns a typed
// error and serve aborts startup instead of warning and serving plaintext.

package commands

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	daemon "github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

// tlsTransportConfig returns a daemon config with one TLS-terminating
// transport enabled, which obliges applyDaemonTLSIdentity to produce an
// identity or fail.
func tlsTransportConfig() *daemon.Config {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableQUIC = false
	cfg.EnableGRPCTCP = true
	return cfg
}

func TestApplyDaemonTLSIdentity_NilAppFailsClosed(t *testing.T) {
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), nil, tlsTransportConfig(), false)
	if err == nil {
		t.Fatal("expected typed error for nil app, got nil")
	}
	var typed ErrTLSIdentityRequiresApp
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityRequiresApp, got %T (%v)", err, err)
	}
}

// TestApplyDaemonTLSIdentity_NoPlatformDirFailsClosed asserts the bundles
// are never written to a fallback location: without a platform directory
// there is nowhere sanctioned to keep them.
func TestApplyDaemonTLSIdentity_NoPlatformDirFailsClosed(t *testing.T) {
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, tlsTransportConfig(), false)
	if err == nil {
		t.Fatal("expected typed error for an empty platform directory, got nil")
	}
	var typed ErrTLSIdentityRequiresPlatformDir
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityRequiresPlatformDir, got %T (%v)", err, err)
	}
}

func TestApplyDaemonTLSIdentity_NilCAFailsClosed(t *testing.T) {
	a := &app.App{PlatformDir: t.TempDir()}
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), a, tlsTransportConfig(), false)
	if err == nil {
		t.Fatal("expected typed error for nil CA, got nil")
	}
	var typed ErrProvisionMissingCA
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingCA, got %T (%v)", err, err)
	}
}

func TestApplyDaemonTLSIdentity_NilConfigFailsClosed(t *testing.T) {
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, nil, false)
	if err == nil {
		t.Fatal("expected typed error for nil config, got nil")
	}
	var typed ErrTLSIdentityRequiresConfig
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityRequiresConfig, got %T (%v)", err, err)
	}
}

// TestApplyDaemonTLSIdentity_MCPHTTPOnlyRequiresIdentity asserts the MCP
// HTTP transport counts as TLS-terminating (#844): with every other network
// transport off it still needs the daemon identity, so a missing CA fails
// closed instead of being skipped as UDS-only mode.
func TestApplyDaemonTLSIdentity_MCPHTTPOnlyRequiresIdentity(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableGRPCTCP = false
	cfg.EnableQUIC = false
	cfg.EnableMCP = true
	cfg.MCPConfig = daemon.DefaultMCPConfig()
	cfg.MCPConfig.Transport = "http"

	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{PlatformDir: t.TempDir()}, cfg, false)
	var typed ErrProvisionMissingCA
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingCA for MCP-HTTP-only mode, got %T (%v)", err, err)
	}
}

// A webservice-only daemon hands its REST routes to the webservice
// listener (RESTRoutesOnly). That listener terminates TLS for them and the
// routes verify clients against the daemon's roots, so the identity must be
// provisioned even with every daemon transport off.
func TestApplyDaemonTLSIdentity_RESTRoutesOnlyRequiresIdentity(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableGRPCTCP = false
	cfg.EnableQUIC = false
	cfg.EnableMCP = false
	cfg.RESTRoutesOnly = true

	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{PlatformDir: t.TempDir()}, cfg, false)
	var typed ErrProvisionMissingCA
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrProvisionMissingCA for REST-routes-only mode, got %T (%v)", err, err)
	}
}

// TestApplyDaemonTLSIdentity_MCPStdioOnlySkips asserts stdio MCP binds no
// network listener and so, like UDS, needs no TLS identity.
func TestApplyDaemonTLSIdentity_MCPStdioOnlySkips(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableGRPCTCP = false
	cfg.EnableQUIC = false
	cfg.EnableMCP = true
	cfg.MCPConfig = daemon.DefaultMCPConfig()
	cfg.MCPConfig.Transport = "stdio"

	if err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, cfg, false); err != nil {
		t.Fatalf("stdio MCP must not require a TLS identity, got %v", err)
	}
}

// TestApplyDaemonTLSIdentity_UDSOnlySkips asserts the sanctioned carve-out:
// with no TLS-terminating transport enabled (Unix-domain-socket-only mode)
// the daemon needs no TLS identity and startup proceeds.
func TestApplyDaemonTLSIdentity_UDSOnlySkips(t *testing.T) {
	cfg := daemon.DefaultConfig()
	cfg.EnableREST = false
	cfg.EnableGRPCTCP = false
	cfg.EnableQUIC = false
	cfg.EnableGRPCUDS = true

	// Even with a nil CA the UDS-only daemon must start: the carve-out is
	// decided before any provisioning dependency is touched.
	if err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{}, cfg, false); err != nil {
		t.Fatalf("UDS-only mode must not require a TLS identity, got %v", err)
	}
	if cfg.TLSIdentity != nil {
		t.Error("UDS-only mode must not install TLS material")
	}
}

// handshakeServerLeaf runs a TLS handshake over an in-memory pipe against a
// server presenting serverCert and returns the leaf the client verified.
func handshakeServerLeaf(t *testing.T, serverCert tls.Certificate, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12})
	client := tls.Client(clientConn, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12})

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	peers := client.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		t.Fatal("server presented no certificate")
	}
	return peers[0]
}

// TestApplyDaemonTLSIdentity_ServesKeystoreHeldIdentity asserts the boot
// path (#33): the listener certificate's key is the CA keystore's signer,
// no server key file is written under the platform directory, and a TLS
// client is presented the keystore-held certificate.
func TestApplyDaemonTLSIdentity_ServesKeystoreHeldIdentity(t *testing.T) {
	ca := newFakeKeystoreCA(t)
	platformDir := t.TempDir()
	cfg := tlsTransportConfig()

	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{CA: ca, PlatformDir: platformDir}, cfg, true)
	if err != nil {
		t.Fatalf("applyDaemonTLSIdentity: %v", err)
	}
	served := cfg.TLSIdentity.Current()
	if served == nil || served.Leaf == nil {
		t.Fatal("the daemon serves no identity")
	}
	signer := ca.signerOf(served.Leaf)
	if signer == nil {
		t.Fatal("the keystore holds no daemon server key")
	}
	if served == nil || served.PrivateKey != crypto.PrivateKey(signer) {
		t.Fatal("the listener certificate is not backed by the keystore signer")
	}
	assertNoServerKeyOnDisk(t, platformDir, signer.Public())
	if want := filepath.Join(platformDir, "tls", "ca-bundle.crt"); cfg.MTLSClientCAFile != want {
		t.Errorf("MTLSClientCAFile = %q, want %q", cfg.MTLSClientCAFile, want)
	}
	if !cfg.EnableMTLS {
		t.Error("requireClientCert must enable mTLS")
	}

	leaf := handshakeServerLeaf(t, *served, ca.root.pool())
	if !leaf.Equal(ca.certs[served.Leaf.Subject.CommonName]) {
		t.Error("the listener presented a certificate other than the keystore-held one")
	}
}

// TestApplyDaemonTLSIdentity_KeystoreUnavailableFailsClosed asserts an
// unavailable keystore is a typed error that installs no TLS material, so
// serve starts no TLS listener, and writes no TLS file.
func TestApplyDaemonTLSIdentity_KeystoreUnavailableFailsClosed(t *testing.T) {
	ca := newFakeKeystoreCA(t)
	ca.unavailable = true
	platformDir := t.TempDir()
	cfg := tlsTransportConfig()

	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{CA: ca, PlatformDir: platformDir}, cfg, false)
	var typed ErrTLSIdentityKeystore
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityKeystore, got %T (%v)", err, err)
	}
	if cfg.TLSIdentity != nil || cfg.MTLSClientCAPool != nil {
		t.Error("a keystore failure must install no TLS material")
	}
	entries, readErr := os.ReadDir(filepath.Join(platformDir, "tls"))
	if readErr != nil {
		t.Fatalf("read tls dir: %v", readErr)
	}
	if len(entries) != 0 {
		t.Errorf("a keystore failure must write no TLS file, found %d", len(entries))
	}
}

func TestApplyDaemonTLSIdentity_RequiresPlatformDir(t *testing.T) {
	cfg := tlsTransportConfig()
	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{CA: newFakeKeystoreCA(t)}, cfg, false)
	var typed ErrTLSIdentityRequiresPlatformDir
	if !errors.As(err, &typed) {
		t.Fatalf("expected ErrTLSIdentityRequiresPlatformDir, got %T (%v)", err, err)
	}
	if cfg.TLSIdentity != nil {
		t.Error("no TLS material may be installed without a platform directory")
	}
}
