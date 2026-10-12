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

// mcp_tls_test.go asserts the MCP HTTP transport joins the fail-closed
// contract (#844): it serves TLS 1.3 only, from the daemon's TLS identity,
// and a daemon configured for it refuses to start without that identity.

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mcpOnlyConfig returns a daemon config whose only network transport is
// MCP over HTTP on addr.
func mcpOnlyConfig(addr string) *Config {
	config := DefaultConfig()
	config.SkipIAMValidation = true
	config.EnableREST = false
	config.EnableGRPCTCP = false
	config.EnableGRPCUDS = false
	config.EnableQUIC = false
	config.EnableMCP = true
	config.MCPConfig = DefaultMCPConfig()
	config.MCPConfig.Transport = "http"
	config.MCPConfig.HTTPAddr = addr
	return config
}

// testServerCertPool returns a pool trusting the shared test certificate.
func testServerCertPool(t *testing.T) *x509.CertPool {
	t.Helper()
	cert := testServerTLSCertificate(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return pool
}

func TestDaemon_MCPHTTPFailsClosedWithoutTLS(t *testing.T) {
	config := mcpOnlyConfig(reservePort(t))
	// No TLSCertificate: TLS material is absent.

	d, err := New(config)
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	var tlsFailed ErrTLSConfigFailed
	require.ErrorAs(t, err, &tlsFailed)
	assert.Contains(t, tlsFailed.Reason, "MCP")
	assertNothingListening(t, config.MCPConfig.HTTPAddr)
}

func TestDaemon_MCPHTTPServesTLS13Only(t *testing.T) {
	cert := testServerTLSCertificate(t)
	config := mcpOnlyConfig(reservePort(t))
	config.TLSCertificate = &cert

	d, err := New(config)
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, d.Stop(ctx))
	}()

	addr := config.MCPConfig.HTTPAddr
	pool := testServerCertPool(t)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,
	})
	require.NoError(t, err, "TLS 1.3 handshake with the daemon's MCP listener")
	assert.Equal(t, uint16(tls.VersionTLS13), conn.ConnectionState().Version)
	require.NoError(t, conn.Close())

	conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		RootCAs:    pool,
		MaxVersion: tls.VersionTLS12,
	})
	if err == nil {
		require.NoError(t, conn.Close())
		t.Fatal("a TLS 1.2 client completed a handshake with the daemon's MCP listener")
	}

	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Post("http://"+addr+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err == nil {
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"plaintext HTTP must be rejected by the TLS listener")
	}
}

func TestDaemon_MCPStartFailureIsFatal(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer occupied.Close()

	cert := testServerTLSCertificate(t)
	config := mcpOnlyConfig(occupied.Addr().String())
	config.TLSCertificate = &cert

	d, err := New(config)
	require.NoError(t, err)

	err = d.Start(context.Background())
	require.Error(t, err)
	var startErr *MCPServerStartError
	assert.ErrorAs(t, err, &startErr)
}

func TestMCPServerStartError_Unwraps(t *testing.T) {
	cause := ErrTLSConfigFailed{Reason: "bind"}
	err := &MCPServerStartError{Err: cause}

	assert.Equal(t, "daemon: MCP server failed to start: tls config failed: bind", err.Error())
	var unwrapped ErrTLSConfigFailed
	assert.ErrorAs(t, err, &unwrapped)
}

func TestConfig_MCPServesHTTP(t *testing.T) {
	stdio := DefaultMCPConfig()
	stdio.Transport = "stdio"
	httpCfg := DefaultMCPConfig()
	httpCfg.Transport = "http"

	tests := []struct {
		name    string
		enabled bool
		mcpCfg  *MCPConfig
		want    bool
	}{
		{name: "disabled", enabled: false, mcpCfg: httpCfg, want: false},
		{name: "nil config defaults to http", enabled: true, mcpCfg: nil, want: DefaultMCPConfig().Transport == "http"},
		{name: "stdio", enabled: true, mcpCfg: stdio, want: false},
		{name: "http", enabled: true, mcpCfg: httpCfg, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			config.EnableMCP = tt.enabled
			config.MCPConfig = tt.mcpCfg
			assert.Equal(t, tt.want, config.MCPServesHTTP())
		})
	}
}

func TestNewServerTLSConfig_MTLSRequiresClientCert(t *testing.T) {
	config := DefaultConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = testServerCertPool(t)

	tlsConfig, err := newServerTLSConfig(config, transportMCP, testServerTLSCertificate(t))
	require.NoError(t, err)
	assert.Equal(t, tls.RequireAndVerifyClientCert, tlsConfig.ClientAuth)
	assert.Same(t, config.MTLSClientCAPool, tlsConfig.ClientCAs)
	assert.Len(t, tlsConfig.Certificates, 1)
}

func TestNewServerTLSConfig_MTLSWithoutClientCAFailsClosed(t *testing.T) {
	config := DefaultConfig()
	config.EnableMTLS = true
	config.MTLSClientCAPool = nil
	config.MTLSClientCAFile = ""

	tlsConfig, err := newServerTLSConfig(config, transportMCP, testServerTLSCertificate(t))
	assert.Nil(t, tlsConfig)
	var authRequired ErrTransportAuthRequired
	require.ErrorAs(t, err, &authRequired)
	assert.Equal(t, transportMCP, authRequired.Transport)
}

func TestDaemon_MCPHTTPEnforcesDaemonMTLS(t *testing.T) {
	cert := testServerTLSCertificate(t)
	config := mcpOnlyConfig(reservePort(t))
	config.TLSCertificate = &cert
	config.EnableMTLS = true
	config.MTLSClientCAPool = testServerCertPool(t)

	d, err := New(config)
	require.NoError(t, err)
	require.NoError(t, d.Start(context.Background()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assert.NoError(t, d.Stop(ctx))
	}()

	// No client certificate: the mTLS policy REST and gRPC enforce must
	// refuse the request on MCP as well.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    testServerCertPool(t),
			MinVersion: tls.VersionTLS13,
		}},
	}
	resp, err := client.Post("https://"+config.MCPConfig.HTTPAddr+"/mcp", "application/json",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err == nil {
		resp.Body.Close()
		t.Fatal("MCP served a client that presented no certificate under mTLS")
	}
}

func TestDaemon_CreateMCPServerWithoutCertificateRefused(t *testing.T) {
	config := mcpOnlyConfig(reservePort(t))

	d, err := New(config)
	require.NoError(t, err)
	assert.Nil(t, d.concreteMcpServer, "no MCP server may be built without TLS material")

	server, err := d.createMCPServer()
	assert.Nil(t, server)
	var tlsFailed ErrTLSConfigFailed
	assert.ErrorAs(t, err, &tlsFailed)
}
