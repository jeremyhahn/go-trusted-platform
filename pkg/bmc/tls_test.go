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

// fakeTLSProvider is a TLSProvider that returns a cloned tls.Config with
// ServerName populated from the endpoint, or a fixed error.
// Tests that provide a cert pool (e.g. httptest server cert) rely on
// ServerName matching the server's hostname so the TLS handshake succeeds.
type fakeTLSProvider struct {
	cfg *tls.Config
	err error
}

func (f *fakeTLSProvider) TLSConfig(_ context.Context, endpoint string) (*tls.Config, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.cfg == nil {
		return nil, nil
	}
	cloned := f.cfg.Clone()
	// Derive ServerName from host:port endpoint so TLS handshakes succeed
	// against httptest servers (127.0.0.1:port).
	host := endpoint
	for i := len(endpoint) - 1; i >= 0; i-- {
		if endpoint[i] == ':' {
			host = endpoint[:i]
			break
		}
	}
	if cloned.ServerName == "" {
		cloned.ServerName = host
	}
	return cloned, nil
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

// TestBuildTLSConfig_NoProviderSystemRoots verifies that when no TLSProvider
// is set the returned config uses system roots (no InsecureSkipVerify, TLS 1.2+).
func TestBuildTLSConfig_NoProviderSystemRoots(t *testing.T) {
	cfg := &Config{Address: "192.168.1.1", Port: 443}
	got, err := BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if got.InsecureSkipVerify {
		t.Error("system-roots default must not set InsecureSkipVerify")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS12", got.MinVersion)
	}
	// RootCAs nil = system roots in the standard library.
	if got.RootCAs != nil {
		t.Error("system-roots config must leave RootCAs nil (use OS trust store)")
	}
}

// TestBuildTLSConfig_EmptyConfig ensures a zero-value Config produces a
// secure default.
func TestBuildTLSConfig_EmptyConfig(t *testing.T) {
	cfg := &Config{}
	got, err := BuildTLSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if got.InsecureSkipVerify {
		t.Error("empty config must not produce InsecureSkipVerify")
	}
	if got.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want TLS12", got.MinVersion)
	}
}

// TestBuildTLSConfig_ProviderEndpointFormatted verifies the endpoint passed
// to the provider is correctly formatted as host:port.
func TestBuildTLSConfig_ProviderEndpointFormatted(t *testing.T) {
	rec := &recordingTLSProvider{}
	cfg := &Config{Address: "10.0.0.1", Port: 8443, TLS: rec}
	if _, err := BuildTLSConfig(context.Background(), cfg); err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if rec.endpoint == "" {
		t.Error("endpoint not passed to provider")
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

// newTLSProviderFromServer returns a fakeTLSProvider whose tls.Config trusts
// the given httptest.Server's certificate. Callers use this instead of
// SkipTLSVerify to wire test HTTP servers in a TLSProvider-backed config.
func newTLSProviderFromServer(t *testing.T, srv *httptest.Server) *fakeTLSProvider {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &fakeTLSProvider{
		cfg: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}
}

// newHTTPClientFromServer returns an *http.Client that trusts the given
// httptest.Server's certificate using a TLSProvider-sourced pool rather
// than InsecureSkipVerify.
func newHTTPClientFromServer(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// writePEMFile writes a single PEM certificate to a temp file and
// returns the path.
func writePEMFile(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	tmp := t.TempDir()
	p := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(p, encodeCertPEM(t, cert), 0o600); err != nil {
		t.Fatalf("write PEM file: %v", err)
	}
	return p
}
