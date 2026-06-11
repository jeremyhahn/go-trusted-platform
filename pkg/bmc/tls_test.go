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

package bmc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// fakeTLSProvider is a TLSProvider that returns a distinctive tls.Config
// so tests can verify the provider path was taken.
type fakeTLSProvider struct {
	cfg *tls.Config
	err error
}

func (f *fakeTLSProvider) TLSConfig(_ context.Context, _ string) (*tls.Config, error) {
	return f.cfg, f.err
}

// recordingTLSProvider records the endpoint it receives.
type recordingTLSProvider struct {
	endpoint string
}

func (r *recordingTLSProvider) TLSConfig(_ context.Context, endpoint string) (*tls.Config, error) {
	r.endpoint = endpoint
	return &tls.Config{MinVersion: tls.VersionTLS13}, nil
}

// --- BuildTLSConfig ---

func TestBuildTLSConfig_ProviderPath(t *testing.T) {
	want := &tls.Config{
		ServerName: "distinctive-marker.example.com",
		MinVersion: tls.VersionTLS13,
	}
	cfg := &Config{
		Address: "192.168.1.1",
		Port:    443,
		TLS:     &fakeTLSProvider{cfg: want},
	}
	got, err := BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if got.ServerName != want.ServerName {
		t.Errorf("got ServerName %q, want %q", got.ServerName, want.ServerName)
	}
}

func TestBuildTLSConfig_ProviderPrecedenceOverLegacy(t *testing.T) {
	// SkipTLSVerify is set but provider is also set; provider must win and
	// InsecureSkipVerify must NOT appear in the returned config.
	providerCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	cfg := &Config{
		Address:       "192.168.1.1",
		Port:          443,
		TLS:           &fakeTLSProvider{cfg: providerCfg},
		SkipTLSVerify: true, // must be ignored
	}
	got, err := BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if got.InsecureSkipVerify {
		t.Error("provider is set but InsecureSkipVerify was set (legacy field leaked through)")
	}
}

func TestBuildTLSConfig_ProviderErrorPropagates(t *testing.T) {
	cause := errors.New("resolver unavailable")
	cfg := &Config{
		Address: "192.168.1.1",
		Port:    443,
		TLS:     &fakeTLSProvider{err: cause},
	}
	_, err := BuildTLSConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error from provider")
	}
	var tlsErr ErrTLSProvider
	if !errors.As(err, &tlsErr) {
		t.Errorf("err type = %T, want ErrTLSProvider", err)
	}
	if !errors.Is(err, cause) {
		t.Errorf("cause not wrapped: got %v", err)
	}
	if tlsErr.Endpoint == "" {
		t.Error("ErrTLSProvider.Endpoint is empty")
	}
}

func TestBuildTLSConfig_LegacySkipVerify(t *testing.T) {
	cfg := &Config{SkipTLSVerify: true}
	got, err := BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if !got.InsecureSkipVerify {
		t.Error("SkipTLSVerify=true not reflected")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS12", got.MinVersion)
	}
}

func TestBuildTLSConfig_LegacyCACertPath(t *testing.T) {
	// Build a PEM bundle using an httptest TLS server certificate.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	tmp := t.TempDir()
	pemPath := filepath.Join(tmp, "ca.pem")
	pemBytes := encodeCertPEM(t, srv.Certificate())
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA PEM: %v", err)
	}

	cfg := &Config{CACertPath: pemPath}
	got, err := BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if got.RootCAs == nil {
		t.Error("RootCAs not populated")
	}
}

func TestBuildTLSConfig_LegacyCACertPath_ReadFailure(t *testing.T) {
	cfg := &Config{CACertPath: "/nonexistent/path/ca.pem"}
	_, err := BuildTLSConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for bad CA path")
	}
	var want ErrInvalidConfig
	if !errors.As(err, &want) {
		t.Errorf("err type = %T, want ErrInvalidConfig", err)
	}
}

func TestBuildTLSConfig_NilProviderNoLegacy_DefaultVerified(t *testing.T) {
	// No provider, no skip-verify, no CA path: should produce a standard
	// verified config with no InsecureSkipVerify.
	cfg := &Config{}
	got, err := BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if got.InsecureSkipVerify {
		t.Error("default config must not have InsecureSkipVerify set")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS12", got.MinVersion)
	}
}

// --- httpsEndpoint ---

func TestHTTPSEndpoint_IPMIPort(t *testing.T) {
	cfg := &Config{Address: "192.168.1.1", Port: ipmiBMCPort}
	if got := httpsEndpoint(cfg); got != "192.168.1.1:443" {
		t.Errorf("httpsEndpoint(ipmi port) = %q, want 192.168.1.1:443", got)
	}
}

func TestHTTPSEndpoint_ZeroPort(t *testing.T) {
	cfg := &Config{Address: "192.168.1.1", Port: 0}
	if got := httpsEndpoint(cfg); got != "192.168.1.1:443" {
		t.Errorf("httpsEndpoint(port 0) = %q, want 192.168.1.1:443", got)
	}
}

func TestHTTPSEndpoint_ExplicitPort(t *testing.T) {
	cfg := &Config{Address: "192.168.1.1", Port: 8443}
	if got := httpsEndpoint(cfg); got != "192.168.1.1:8443" {
		t.Errorf("httpsEndpoint(8443) = %q, want 192.168.1.1:8443", got)
	}
}

func TestHTTPSEndpoint_Port443(t *testing.T) {
	cfg := &Config{Address: "bmc.example.com", Port: 443}
	if got := httpsEndpoint(cfg); got != "bmc.example.com:443" {
		t.Errorf("httpsEndpoint(443) = %q, want bmc.example.com:443", got)
	}
}

// --- ErrTLSProvider ---

func TestErrTLSProvider_Error(t *testing.T) {
	cause := errors.New("dial timeout")
	e := ErrTLSProvider{Endpoint: "192.168.1.1:443", Err: cause}
	msg := e.Error()
	if msg == "" {
		t.Error("empty error string")
	}
	if !errors.Is(e, cause) {
		t.Error("Unwrap did not return cause")
	}
}

func TestErrTLSProvider_NoEndpoint(t *testing.T) {
	e := ErrTLSProvider{Err: errors.New("boom")}
	if e.Error() == "" {
		t.Error("empty error string with no endpoint")
	}
}

// --- helpers ---

// encodeCertPEM encodes a DER certificate to PEM.
func encodeCertPEM(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
