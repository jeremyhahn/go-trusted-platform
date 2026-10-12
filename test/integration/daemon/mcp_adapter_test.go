//go:build integration

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

package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// mcpTransportProbeToken is the bearer credential the transport case sends.
// initialize does not validate it; the case proves where the header travels,
// not who it authenticates.
const mcpTransportProbeToken = "mcp-transport-probe"

// TestDaemonMCPTransportSecurity proves the daemon serves MCP over TLS 1.3
// only (#844): a bearer-carrying request over mTLS is answered at TLS 1.3, a
// TLS 1.2 handshake is rejected, and a plain http:// dial is not served.
func TestDaemonMCPTransportSecurity(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := DefaultTestContext()
	defer cancel()

	endpointURL := helpers.MCPEndpointURL(NewMCPAdapter().endpoint)

	t.Run("TLS13WithBearer", func(t *testing.T) {
		req := newMCPInitializeRequest(t, ctx, endpointURL, true)
		resp, err := helpers.NewHTTPClient(DefaultMCPTimeout).Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", endpointURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s: status %d, want 200", endpointURL, resp.StatusCode)
		}
		if resp.TLS == nil {
			t.Fatalf("MCP answered %s without TLS", endpointURL)
		}
		if resp.TLS.Version != tls.VersionTLS13 {
			t.Fatalf("MCP negotiated TLS version %#04x, want TLS 1.3", resp.TLS.Version)
		}

		var rpcResp jsonRPCResponse
		if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
			t.Fatalf("decode initialize response: %v", err)
		}
		if rpcResp.Error != nil {
			t.Fatalf("initialize returned JSON-RPC error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
		}
		if len(rpcResp.Result) == 0 {
			t.Fatal("initialize returned no result")
		}
	})

	t.Run("TLS12Refused", func(t *testing.T) {
		tlsConfig := helpers.TLSConfigOrInsecure().Clone()
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
		client := &http.Client{
			Timeout:   DefaultMCPTimeout,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		}

		req := newMCPInitializeRequest(t, ctx, endpointURL, false)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("MCP completed a TLS 1.2 handshake on %s (status %d)", endpointURL, resp.StatusCode)
		}
	})

	t.Run("PlaintextRefused", func(t *testing.T) {
		parsed, err := url.Parse(endpointURL)
		if err != nil {
			t.Fatalf("parse %s: %v", endpointURL, err)
		}
		parsed.Scheme = "http"
		plainURL := parsed.String()

		req := newMCPInitializeRequest(t, ctx, plainURL, false)
		resp, err := (&http.Client{Timeout: DefaultMCPTimeout}).Do(req)
		if err != nil {
			// Refused at the transport: nothing was served.
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Fatalf("plain %s was served with status 200", plainURL)
		}
	})
}

// newMCPInitializeRequest builds a JSON-RPC initialize POST to target,
// optionally carrying the probe bearer token.
func newMCPInitializeRequest(t *testing.T, ctx context.Context, target string, withBearer bool) *http.Request {
	t.Helper()

	body, err := json.Marshal(jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		Params: mcpInitializeRequest{
			ProtocolVersion: MCPProtocolVersion,
			ClientInfo:      mcpClientInfo{Name: MCPClientName, Version: MCPClientVersion},
		},
		ID: 1,
	})
	if err != nil {
		t.Fatalf("marshal initialize request: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request for %s: %v", target, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if withBearer {
		req.Header.Set("Authorization", "Bearer "+mcpTransportProbeToken)
	}
	return req
}
