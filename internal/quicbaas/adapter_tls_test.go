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

package quicbaas

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// writeSvcClientCert generates an ephemeral ECDSA leaf carrying a SPIFFE "svc"
// SAN and writes the cert + key + a self-signed CA to disk. It models the
// cluster service identity the platform presents to the broker: a verified
// mTLS chain whose leaf SPIFFE URI has Kind == "svc", which the broker's
// default-deny gate short-circuits without requiring a platform token.
func writeSvcClientCert(t *testing.T) (caPath, certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "platform-svc"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:         true,
	}
	uri, err := url.Parse("spiffe://platform.local/tenant/system/svc/trusted-platform")
	if err != nil {
		t.Fatalf("parse spiffe uri: %v", err)
	}
	tmpl.URIs = append(tmpl.URIs, uri)

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	caPath = filepath.Join(dir, "ca.pem")
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client-key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return caPath, certPath, keyPath
}

// captureFactory records the options passed to the SDK client factory so a test
// can assert that the mTLS option was wired for a given transport.
func captureFactory(captured *[]quicbaas.Option) ClientFactory {
	return func(address string, opts ...quicbaas.Option) (quicbaas.Client, error) {
		*captured = append([]quicbaas.Option(nil), opts...)
		return NewMockClient(), nil
	}
}

// TestRemoteAdapterWiresClientCert proves that every remote transport presents
// the configured mTLS client certificate (the cluster service identity). The
// adapter's create*Client methods are exercised directly with and without TLS
// material so the appended option count is observable: a TLS-configured adapter
// must append exactly one more option (WithTLS) than one with no TLS material.
// This is the regression guard for default-deny — without the WithTLS option
// the broker would 401/403 these service-to-service calls.
func TestRemoteAdapterWiresClientCert(t *testing.T) {
	caPath, certPath, keyPath := writeSvcClientCert(t)
	logger := logging.NewLogger(slog.LevelDebug, nil)

	withCert := &TLSConfig{CACert: caPath, ClientCert: certPath, ClientKey: keyPath}

	creators := []struct {
		name   string
		base   *Config
		create func(a *Adapter) (quicbaas.Client, error)
	}{
		{
			name:   "rest",
			base:   &Config{Transport: TransportREST, Address: "https://broker:8443", RequestTimeout: time.Second},
			create: func(a *Adapter) (quicbaas.Client, error) { return a.createRESTClient() },
		},
		{
			name:   "quic",
			base:   &Config{Transport: TransportQUIC, Address: "broker:8443", RequestTimeout: time.Second},
			create: func(a *Adapter) (quicbaas.Client, error) { return a.createQUICClient() },
		},
		{
			name:   "grpc",
			base:   &Config{Transport: TransportGRPC, Address: "broker:8443", RequestTimeout: time.Second},
			create: func(a *Adapter) (quicbaas.Client, error) { return a.createGRPCClient() },
		},
		{
			name:   "unix",
			base:   &Config{Transport: TransportUnix, UnixSocket: "/tmp/quicbaas.sock", RequestTimeout: time.Second},
			create: func(a *Adapter) (quicbaas.Client, error) { return a.createUnixClient() },
		},
	}

	for _, tc := range creators {
		t.Run(tc.name, func(t *testing.T) {
			// No TLS material: the create method appends no mTLS option. The
			// config is built directly (bypassing Validate, which mandates a CA
			// for remote transports) to capture the true no-TLS baseline.
			noTLSCfg := *tc.base
			var noTLSOpts []quicbaas.Option
			noTLS := &Adapter{config: &noTLSCfg, logger: logger, clientFactory: captureFactory(&noTLSOpts)}
			if _, err := tc.create(noTLS); err != nil {
				t.Fatalf("%s: create (no tls): %v", tc.name, err)
			}

			// With client cert: exactly one additional option (WithTLS) carries
			// the cluster service identity.
			certCfg := *tc.base
			certCfg.TLS = withCert
			var certOpts []quicbaas.Option
			withAdapter := &Adapter{config: &certCfg, logger: logger, clientFactory: captureFactory(&certOpts)}
			if _, err := tc.create(withAdapter); err != nil {
				t.Fatalf("%s: create (cert): %v", tc.name, err)
			}

			if len(certOpts) != len(noTLSOpts)+1 {
				t.Fatalf("%s: expected mTLS option to be appended (no-tls=%d, with-cert=%d)",
					tc.name, len(noTLSOpts), len(certOpts))
			}
		})
	}
}

// TestRemoteAdapterRealCertLoads drives the real SDK client factory so that the
// mTLS option is actually applied (loadTLSConfig reads the files). A valid
// client cert constructs cleanly; a bogus path fails closed. This proves the
// configured certificate is genuinely loaded and presented, not silently
// dropped.
func TestRemoteAdapterRealCertLoads(t *testing.T) {
	caPath, certPath, keyPath := writeSvcClientCert(t)
	logger := logging.NewLogger(slog.LevelDebug, nil)
	ctx := context.Background()

	t.Run("valid_cert_constructs", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportREST,
			Address:        "https://broker:8443",
			RequestTimeout: time.Second,
			TLS:            &TLSConfig{CACert: caPath, ClientCert: certPath, ClientKey: keyPath},
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("new adapter: %v", err)
		}
		// Uses defaultClientFactory (real SDK NewClient) which applies options.
		if err := adapter.Start(ctx, nil); err != nil {
			t.Fatalf("expected valid cert to construct, got: %v", err)
		}
		if adapter.Client() == nil {
			t.Fatal("expected non-nil client")
		}
		_ = adapter.Stop(ctx)
	})

	t.Run("bogus_cert_fails_closed", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportREST,
			Address:        "https://broker:8443",
			RequestTimeout: time.Second,
			TLS:            &TLSConfig{CACert: caPath, ClientCert: "/nonexistent/client.pem", ClientKey: "/nonexistent/key.pem"},
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("new adapter: %v", err)
		}
		if err := adapter.Start(ctx, nil); err == nil {
			t.Fatal("expected start to fail with bogus client cert, got nil")
		}
	})
}
