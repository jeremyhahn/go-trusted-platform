// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// initializeBody is the JSON-RPC initialize request an MCP client opens
// its session with.
func initializeBody(t *testing.T) []byte {
	t.Helper()

	body, err := json.Marshal(mcpwire.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": mcpwire.MCPVersion,
			"clientInfo":      map[string]interface{}{"name": "issue-533", "version": "1"},
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return body
}

// startInitializeServer starts the HTTPS transport and returns its base
// URL and a TLS 1.3 client that trusts it.
func startInitializeServer(t *testing.T) (string, *http.Client) {
	t.Helper()

	addr, pool := startTLSTestServer(t, &mockAuthManager{
		validateFunc: func(ctx context.Context, token string) (bool, error) {
			return token == "initialize-token", nil
		},
	})
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		}},
	}
	return "https://" + addr, client
}

// TestServer_HTTPTLS_InitializeAnsweredOnMCPPath is the #533 proof that a
// client posting initialize to the /mcp path of the HTTPS transport gets a
// JSON-RPC result naming the protocol version.
func TestServer_HTTPTLS_InitializeAnsweredOnMCPPath(t *testing.T) {
	base, client := startInitializeServer(t)

	resp, err := postMCP(client, base+"/mcp", "initialize-token", initializeBody(t))
	if err != nil {
		t.Fatalf("initialize request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var rpc mcpwire.JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
		t.Fatalf("initialize answer is not JSON-RPC: %v", err)
	}
	if rpc.Error != nil {
		t.Fatalf("initialize error = %+v, want a result", rpc.Error)
	}
	result, ok := rpc.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("initialize result is %T, want an object", rpc.Result)
	}
	if result["protocolVersion"] != mcpwire.MCPVersion {
		t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], mcpwire.MCPVersion)
	}
}

// TestServer_HTTPTLS_InitializeOffMCPPathIsNotFound pins the #533 failure
// signature: the transport serves JSON-RPC only on /mcp, so a client that
// posts to the bare endpoint gets the mux's plain-text 404, which a JSON
// decoder reports as "invalid character 'p' after top-level value".
func TestServer_HTTPTLS_InitializeOffMCPPathIsNotFound(t *testing.T) {
	base, client := startInitializeServer(t)

	resp, err := postMCP(client, base+"/", "initialize-token", initializeBody(t))
	if err != nil {
		t.Fatalf("initialize request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(raw), "page not found") {
		t.Errorf("body = %q, want the mux 404 text", raw)
	}
	var rpc mcpwire.JSONRPCResponse
	if err := json.Unmarshal(raw, &rpc); err == nil {
		t.Errorf("the bare path answered JSON-RPC %+v; #533 assumed it never does", rpc)
	}
}
