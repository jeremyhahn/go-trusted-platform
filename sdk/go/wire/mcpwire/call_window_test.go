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

package mcpwire

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// slowToolServer answers a tools/call only after delay, or gives up when the
// client does.
func slowToolServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: okToolResult(t)}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func newWindowTestClient(t *testing.T, addr string, timeout time.Duration) *Client {
	t.Helper()
	config := DefaultClientConfig(addr)
	config.Timeout = timeout
	config.MaxRetries = 0
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// A reply slower than the client's Timeout arrives when the call's window
// covers it: a graceful VM stop answers only after the guest powers down.
func TestCallToolWithinOutlastsClientTimeout(t *testing.T) {
	const timeout = 50 * time.Millisecond
	client := newWindowTestClient(t, slowToolServer(t, 4*timeout).URL, timeout)

	if _, err := client.CallToolWithin(context.Background(), "vm_stop", nil, time.Minute); err != nil {
		t.Fatalf("CallToolWithin: %v", err)
	}
}

// Without a window the same slow reply is cut off at the client's Timeout.
func TestCallToolTimesOutAtClientTimeout(t *testing.T) {
	const timeout = 50 * time.Millisecond
	client := newWindowTestClient(t, slowToolServer(t, time.Minute).URL, timeout)

	_, err := client.CallTool(context.Background(), "vm_stop", nil)
	if !isTimeout(err) {
		t.Fatalf("CallTool error = %v, want a timeout", err)
	}
}

func TestHTTPClientWithin(t *testing.T) {
	client := newWindowTestClient(t, "http://127.0.0.1:1", 5*time.Second)

	t.Run("a shorter window keeps the client's timeout", func(t *testing.T) {
		if got := client.httpClientWithin(time.Second); got != client.httpClient {
			t.Fatalf("httpClientWithin(1s) = %p, want the client's own %p", got, client.httpClient)
		}
		if got := client.httpClientWithin(0); got != client.httpClient {
			t.Fatalf("httpClientWithin(0) = %p, want the client's own %p", got, client.httpClient)
		}
	})

	t.Run("a longer window lengthens a copy", func(t *testing.T) {
		got := client.httpClientWithin(time.Minute)
		if got == client.httpClient {
			t.Fatal("httpClientWithin(1m) returned the shared client")
		}
		if got.Timeout != time.Minute {
			t.Errorf("Timeout = %v, want 1m", got.Timeout)
		}
		if got.Transport != client.httpClient.Transport {
			t.Error("the copy does not share the client's transport")
		}
		if client.httpClient.Timeout != 5*time.Second {
			t.Errorf("client Timeout changed to %v", client.httpClient.Timeout)
		}
	})
}
