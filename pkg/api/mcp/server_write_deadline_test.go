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
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// serveMCPWithExpiredWriteDeadline serves the MCP handler from a server whose
// write timeout has passed by the time any call returns, as a graceful VM stop
// that outlasts the 30 s request timeout leaves it.
func serveMCPWithExpiredWriteDeadline(t *testing.T, requestTimeout time.Duration) *httptest.Server {
	t.Helper()
	config := DefaultConfig()
	config.RequestTimeout = requestTimeout
	config.AuthManager = &mockAuthManager{
		validateFunc: func(ctx context.Context, token string) (bool, error) {
			return token == "deadline-token", nil
		},
	}
	server := httptest.NewUnstartedServer(NewServer(newMockServiceProvider(), config, newTestLogger()).Handler())
	server.Config.WriteTimeout = time.Nanosecond
	server.Start()
	t.Cleanup(server.Close)
	return server
}

// A call that returns after the server's write timeout still answers: the
// write deadline restarts when the reply is ready.
func TestServer_HTTP_ReplyOutlivesTheWriteTimeout(t *testing.T) {
	server := serveMCPWithExpiredWriteDeadline(t, time.Minute)

	resp, err := postMCP(server.Client(), server.URL+"/mcp", "deadline-token", initializeBody(t))
	if err != nil {
		t.Fatalf("the reply must reach the client after the write timeout: %v", err)
	}
	defer resp.Body.Close()

	var rpc mcpwire.JSONRPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
		t.Fatalf("the reply is not JSON-RPC: %v", err)
	}
	if rpc.Error != nil {
		t.Fatalf("initialize error = %+v, want a result", rpc.Error)
	}
}

// With no request timeout the server has no write timeout to restart, and
// the handler leaves the expired deadline alone: the reply is dropped, which
// shows the restart above is what delivers it.
func TestServer_HTTP_NoRequestTimeoutLeavesTheDeadline(t *testing.T) {
	server := serveMCPWithExpiredWriteDeadline(t, 0)

	resp, err := postMCP(server.Client(), server.URL+"/mcp", "deadline-token", initializeBody(t))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("a reply written after the write deadline must not reach the client (status %d)", resp.StatusCode)
	}
}
