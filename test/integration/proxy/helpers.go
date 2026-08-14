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

//go:build integration

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Environment variable names for service endpoints. Kept in sync with
// build/docker/devcontainer/run-integration-tests.sh.
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
	EnvClientCert           = "PLATFORM_CLIENT_CERT"
	EnvClientKey            = "PLATFORM_CLIENT_KEY"
	EnvCACert               = "PLATFORM_CA_CERT"
)

// ServiceEndpoints carries the resolved endpoints for one integration run.
type ServiceEndpoints struct {
	PlatformGRPC string
	PlatformREST string
	PlatformQUIC string
	PlatformMCP  string
	PlatformUnix string
	PlatformCTL  string
}

// GetServiceEndpoints resolves the endpoints from the environment with the
// devcontainer defaults.
func GetServiceEndpoints() *ServiceEndpoints {
	return &ServiceEndpoints{
		PlatformGRPC: envOr(EnvPlatformGRPCEndpoint, "localhost:10443"),
		PlatformREST: envOr(EnvPlatformRESTEndpoint, "https://localhost:8443"),
		PlatformQUIC: envOr(EnvPlatformQUICEndpoint, "localhost:9444"),
		PlatformMCP:  envOr(EnvPlatformMCPEndpoint, "http://localhost:9445"),
		PlatformUnix: envOr(EnvPlatformUnixSocket, "/run/platformd.sock"),
		PlatformCTL:  envOr(EnvPlatformCTL, "platformctl"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// =============================================================================
// Echo fixture — the "legacy app" the proxy protects
// =============================================================================

// EchoResponse is the JSON body the echo backend returns: the request as
// the backend saw it, so tests can assert exactly which headers survived
// the proxy hop.
type EchoResponse struct {
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Host    string      `json:"host"`
	Headers http.Header `json:"headers"`
}

// StartEchoBackend starts a plain-HTTP echo server standing in for a
// legacy application without TLS or platform awareness.
func StartEchoBackend(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := EchoResponse{
			Method:  r.Method,
			Path:    r.URL.Path,
			Host:    r.Host,
			Headers: r.Header.Clone(),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// DecodeEcho parses an echo backend response body.
func DecodeEcho(t *testing.T, resp *http.Response) *EchoResponse {
	t.Helper()
	defer resp.Body.Close()
	var echo EchoResponse
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		t.Fatalf("decode echo response: %v", err)
	}
	return &echo
}

// =============================================================================
// Bounded condition polling (ticker-driven, no sleep loops)
// =============================================================================

// WaitFor polls cond on a ticker until it returns true or the timeout
// elapses, failing the test with the description on expiry.
func WaitFor(t *testing.T, timeout, interval time.Duration, description string, cond func() bool) {
	t.Helper()
	if cond() {
		return
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatalf("timed out after %v waiting for %s", timeout, description)
		case <-ticker.C:
			if cond() {
				return
			}
		}
	}
}

// =============================================================================
// Client TLS material
// =============================================================================

// PlatformClientTLS loads the harness mTLS client credentials plus the
// platform CA bundle from the environment.
func PlatformClientTLS(t *testing.T) *tls.Config {
	t.Helper()
	certFile := os.Getenv(EnvClientCert)
	keyFile := os.Getenv(EnvClientKey)
	caFile := os.Getenv(EnvCACert)
	if certFile == "" || keyFile == "" || caFile == "" {
		t.Fatalf("mTLS environment not configured; need %s, %s, %s", EnvClientCert, EnvClientKey, EnvCACert)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read CA bundle: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("CA bundle %s contains no certificates", caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}
}

// GatewayTLSFixture is an ephemeral CA plus server keypair for the gatewayd
// front door under test.
type GatewayTLSFixture struct {
	// CertFile and KeyFile are the PEM server keypair paths for the
	// proxysvc TLS section.
	CertFile string
	KeyFile  string
	// CAPool anchors client-side verification of the gatewayd listener.
	CAPool *x509.CertPool
}

// GenerateGatewayTLS creates an ephemeral CA and a 127.0.0.1/localhost
// server certificate for the in-process gatewayd listener, written as PEM
// files under a test temp dir.
func GenerateGatewayTLS(t *testing.T) *GatewayTLSFixture {
	t.Helper()
	now := time.Now()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "proxy-integration-ca"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "gatewayd-proxy-test"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "gatewayd.pem")
	keyFile := filepath.Join(dir, "gatewayd-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write server cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &GatewayTLSFixture{CertFile: certFile, KeyFile: keyFile, CAPool: pool}
}

// UniqueID builds a collision-free resource identifier for one test run.
func UniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

// ShortContext derives a bounded per-call context.
func ShortContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}
