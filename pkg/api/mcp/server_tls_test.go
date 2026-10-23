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

package mcp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// newTestServerCertificate returns a self-signed ECDSA server certificate
// for 127.0.0.1 and a pool that trusts it.
func newTestServerCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "mcp-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// newTestTLSConfig returns a server TLS config carrying a fresh test
// certificate, for tests that start the HTTP transport.
func newTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	cert, _ := newTestServerCertificate(t)
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// startTLSTestServer starts an HTTP-transport MCP server on an ephemeral
// loopback port with the given auth manager and returns its bound address
// and the pool that trusts its certificate.
func startTLSTestServer(t *testing.T, authMgr AuthManager) (string, *x509.CertPool) {
	t.Helper()

	cert, pool := newTestServerCertificate(t)
	config := DefaultConfig()
	config.HTTPAddr = "127.0.0.1:0"
	config.AuthManager = authMgr
	config.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

	server := NewServer(newMockServiceProvider(), config, newTestLogger())
	if err := server.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Stop(); err != nil {
			t.Errorf("stop: %v", err)
		}
	})

	return server.httpListener.Addr().String(), pool
}

// toolsCallBody is a JSON-RPC tools/call request for vtpm_list, a tool that
// requires the vtpm:read permission and therefore a validated bearer token.
func toolsCallBody(t *testing.T) []byte {
	t.Helper()

	body, err := json.Marshal(mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "vtpm_list",
			"arguments": map[string]interface{}{},
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return body
}

func postMCP(client *http.Client, url, token string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req)
}

func TestServer_HTTPTLS_StartWithoutTLSConfigRefused(t *testing.T) {
	config := DefaultConfig()
	config.HTTPAddr = "127.0.0.1:0"

	server := NewServer(newMockServiceProvider(), config, newTestLogger())
	err := server.Start()

	var tlsErr *HTTPTLSRequiredError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("Start() error = %v, want *HTTPTLSRequiredError", err)
	}
	if server.httpListener != nil {
		t.Error("a listener was bound although Start refused")
	}
	if server.running.Load() {
		t.Error("server reports running after a refused Start")
	}
}

func TestServer_HTTPTLS_StartWithoutCertificateRefused(t *testing.T) {
	config := DefaultConfig()
	config.HTTPAddr = "127.0.0.1:0"
	config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13}

	server := NewServer(newMockServiceProvider(), config, newTestLogger())
	err := server.Start()

	var tlsErr *HTTPTLSRequiredError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("Start() error = %v, want *HTTPTLSRequiredError", err)
	}
	if server.httpListener != nil {
		t.Error("a listener was bound although Start refused")
	}
}

func TestServer_HTTPTLS_ListenFailureReturnsTypedError(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer occupied.Close()

	config := DefaultConfig()
	config.HTTPAddr = occupied.Addr().String()
	config.TLSConfig = newTestTLSConfig(t)

	server := NewServer(newMockServiceProvider(), config, newTestLogger())
	err = server.Start()

	var listenErr *HTTPListenError
	if !errors.As(err, &listenErr) {
		t.Fatalf("Start() error = %v, want *HTTPListenError", err)
	}
	if server.running.Load() {
		t.Error("server reports running after a failed bind")
	}
}

func TestServer_HTTPTLS_PlaintextRefused(t *testing.T) {
	tokens := make(chan string, 1)
	addr, _ := startTLSTestServer(t, &mockAuthManager{
		validateFunc: func(ctx context.Context, token string) (bool, error) {
			tokens <- token
			return true, nil
		},
	})

	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := postMCP(plain, "http://"+addr+"/mcp", "plaintext-token", toolsCallBody(t))
	if err == nil {
		defer resp.Body.Close()
		raw, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}
		var rpc mcpwire.JSONRPCResponse
		if json.Unmarshal(raw, &rpc) == nil && rpc.Result != nil {
			t.Fatalf("plaintext request was served: %s", raw)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("plaintext status = %d, want 400 from the TLS listener", resp.StatusCode)
		}
	}

	select {
	case token := <-tokens:
		t.Fatalf("token %q sent over plaintext reached the auth manager", token)
	default:
	}
}

func TestServer_HTTPTLS_TLS12ClientRefused(t *testing.T) {
	addr, pool := startTLSTestServer(t, &mockAuthManager{})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
		}},
	}

	resp, err := postMCP(client, "https://"+addr+"/mcp", "tls12-token", toolsCallBody(t))
	if err == nil {
		resp.Body.Close()
		t.Fatal("a TLS 1.2 client completed a handshake with the MCP server")
	}
}

func TestServerTLSConfig_PinsPerClientConfig(t *testing.T) {
	cert, _ := newTestServerCertificate(t)
	permissive := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	permissive.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}

	pinned := serverTLSConfig(permissive)
	if pinned == nil {
		t.Fatal("serverTLSConfig refused a config with a certificate")
	}
	if pinned.MinVersion != tls.VersionTLS13 || pinned.MaxVersion != tls.VersionTLS13 {
		t.Errorf("pinned versions = %x..%x, want TLS 1.3 only", pinned.MinVersion, pinned.MaxVersion)
	}
	if permissive.MinVersion != tls.VersionTLS12 {
		t.Error("serverTLSConfig modified the caller's config")
	}

	perClient, err := pinned.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if perClient.MinVersion != tls.VersionTLS13 || perClient.MaxVersion != tls.VersionTLS13 {
		t.Errorf("per-client versions = %x..%x, want TLS 1.3 only", perClient.MinVersion, perClient.MaxVersion)
	}
}

func TestServerTLSConfig_GetConfigForClientAloneRefused(t *testing.T) {
	cfg := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return nil, nil
		},
	}
	if serverTLSConfig(cfg) != nil {
		t.Error("a config with no certificate source was accepted")
	}
}

func TestServer_HTTPTLS_TLS13WithBearerTokenSucceeds(t *testing.T) {
	tokens := make(chan string, 1)
	addr, pool := startTLSTestServer(t, &mockAuthManager{
		validateFunc: func(ctx context.Context, token string) (bool, error) {
			tokens <- token
			return token == "tls13-token", nil
		},
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		}},
	}

	resp, err := postMCP(client, "https://"+addr+"/mcp", "tls13-token", toolsCallBody(t))
	if err != nil {
		t.Fatalf("TLS 1.3 request: %v", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("connection state = %+v, want TLS 1.3", resp.TLS)
	}

	var rpc mcpwire.JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rpc.Error != nil {
		t.Fatalf("tools/call error = %+v, want success", rpc.Error)
	}
	if rpc.Result == nil {
		t.Fatal("tools/call returned no result")
	}

	select {
	case token := <-tokens:
		if token != "tls13-token" {
			t.Errorf("auth manager saw token %q, want tls13-token", token)
		}
	default:
		t.Fatal("bearer token never reached the auth manager")
	}
}
