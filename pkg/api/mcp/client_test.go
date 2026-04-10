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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultClientConfig(t *testing.T) {
	t.Run("creates config with server address", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")

		if config.ServerAddr != "http://localhost:9445" {
			t.Errorf("ServerAddr = %s, want http://localhost:9445", config.ServerAddr)
		}
		if config.Timeout != 30*time.Second {
			t.Errorf("Timeout = %v, want 30s", config.Timeout)
		}
		if config.MaxRetries != 3 {
			t.Errorf("MaxRetries = %d, want 3", config.MaxRetries)
		}
		if config.RetryDelay != 1*time.Second {
			t.Errorf("RetryDelay = %v, want 1s", config.RetryDelay)
		}
	})
}

func TestNewClient(t *testing.T) {
	t.Run("creates client with config", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")

		client, err := NewClient(config)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client == nil {
			t.Fatal("NewClient returned nil")
		}
		if client.config != config {
			t.Error("config not set correctly")
		}
	})

	t.Run("returns error for nil config", func(t *testing.T) {
		_, err := NewClient(nil)
		if err == nil {
			t.Error("expected error for nil config")
		}
	})

	t.Run("returns error for empty server address", func(t *testing.T) {
		config := &ClientConfig{
			ServerAddr: "",
		}

		_, err := NewClient(config)
		if err == nil {
			t.Error("expected error for empty server address")
		}
	})

	t.Run("applies options", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		log := newTestLogger()

		client, err := NewClient(config,
			WithMCPClientLogger(log),
			WithMCPToken("test-token"),
		)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client.logger != log {
			t.Error("logger not set correctly")
		}
		if client.token != "test-token" {
			t.Errorf("token = %s, want test-token", client.token)
		}
	})

	t.Run("uses default logger when not provided", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")

		client, err := NewClient(config)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client.logger == nil {
			t.Error("logger should not be nil")
		}
	})
}

func TestClient_Close(t *testing.T) {
	t.Run("closes client", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !client.closed {
			t.Error("client should be closed")
		}
	})

	t.Run("close is idempotent", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("first close error: %v", err)
		}

		err = client.Close()
		if err != nil {
			t.Errorf("second close error: %v", err)
		}
	})
}

func TestClient_SetToken(t *testing.T) {
	t.Run("sets token", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		client.SetToken("new-token")
		if client.token != "new-token" {
			t.Errorf("token = %s, want new-token", client.token)
		}
	})
}

func TestClient_IsConnected(t *testing.T) {
	t.Run("returns true for open client", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !client.IsConnected() {
			t.Error("IsConnected() = false, want true")
		}
	})

	t.Run("returns false for closed client", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		client.Close()
		if client.IsConnected() {
			t.Error("IsConnected() = true, want false")
		}
	})
}

func TestClient_ServerAddr(t *testing.T) {
	t.Run("returns server address", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if client.ServerAddr() != "http://localhost:9445" {
			t.Errorf("ServerAddr() = %s, want http://localhost:9445", client.ServerAddr())
		}
	})
}

func TestClient_Initialize(t *testing.T) {
	t.Run("sends initialize request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/mcp" {
				t.Errorf("path = %s, want /mcp", r.URL.Path)
			}

			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}

			if req.Method != "initialize" {
				t.Errorf("method = %s, want initialize", req.Method)
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"protocolVersion": MCPVersion,
					"serverInfo": map[string]interface{}{
						"name":    "Test Server",
						"version": "1.0.0",
					},
					"capabilities": map[string]interface{}{},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		result, err := client.Initialize(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if result.ProtocolVersion != MCPVersion {
			t.Errorf("ProtocolVersion = %s, want %s", result.ProtocolVersion, MCPVersion)
		}
		if result.ServerInfo.Name != "Test Server" {
			t.Errorf("ServerInfo.Name = %s, want Test Server", result.ServerInfo.Name)
		}
	})
}

func TestClient_ListTools(t *testing.T) {
	t.Run("sends tools/list request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}

			if req.Method != "tools/list" {
				t.Errorf("method = %s, want tools/list", req.Method)
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"tools": []interface{}{
						map[string]interface{}{
							"name":        "test_tool",
							"description": "A test tool",
							"inputSchema": map[string]interface{}{},
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		tools, err := client.ListTools(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(tools) != 1 {
			t.Errorf("len(tools) = %d, want 1", len(tools))
		}
		if tools[0].Name != "test_tool" {
			t.Errorf("tools[0].Name = %s, want test_tool", tools[0].Name)
		}
	})

	t.Run("handles missing tools in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]interface{}{},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		_, err = client.ListTools(context.Background())
		if err == nil {
			t.Error("expected error for missing tools")
		}
	})

	t.Run("handles unexpected response format", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  "not a map",
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		_, err = client.ListTools(context.Background())
		if err == nil {
			t.Error("expected error for unexpected format")
		}
	})
}

func TestClient_CallTool(t *testing.T) {
	t.Run("sends tools/call request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}

			if req.Method != "tools/call" {
				t.Errorf("method = %s, want tools/call", req.Method)
			}

			params, ok := req.Params.(map[string]interface{})
			if !ok {
				t.Fatal("params is not a map")
			}

			if params["name"] != "test_tool" {
				t.Errorf("name = %v, want test_tool", params["name"])
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"success": true,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		result, err := client.CallTool(context.Background(), "test_tool", map[string]interface{}{"arg": "value"})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})
}

func TestClient_ListResources(t *testing.T) {
	t.Run("sends resources/list request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}

			if req.Method != "resources/list" {
				t.Errorf("method = %s, want resources/list", req.Method)
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"resources": []interface{}{
						map[string]interface{}{
							"uri":         "platform://test",
							"name":        "Test",
							"description": "Test resource",
						},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		resources, err := client.ListResources(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(resources) != 1 {
			t.Errorf("len(resources) = %d, want 1", len(resources))
		}
	})

	t.Run("handles missing resources in response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]interface{}{},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		_, err = client.ListResources(context.Background())
		if err == nil {
			t.Error("expected error for missing resources")
		}
	})
}

func TestClient_ReadResource(t *testing.T) {
	t.Run("sends resources/read request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}

			if req.Method != "resources/read" {
				t.Errorf("method = %s, want resources/read", req.Method)
			}

			params, ok := req.Params.(map[string]interface{})
			if !ok {
				t.Fatal("params is not a map")
			}

			if params["uri"] != "platform://test" {
				t.Errorf("uri = %v, want platform://test", params["uri"])
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"contents": []map[string]interface{}{
						{"text": "resource content"},
					},
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		result, err := client.ReadResource(context.Background(), "platform://test")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})
}

func TestClient_Ping(t *testing.T) {
	t.Run("sends ping request", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("failed to decode request: %v", err)
			}

			if req.Method != "ping" {
				t.Errorf("method = %s, want ping", req.Method)
			}

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"pong": true,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		err = client.Ping(context.Background())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestClient_ErrorHandling(t *testing.T) {
	t.Run("handles JSON-RPC error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &JSONRPCError{
					Code:    InvalidParams,
					Message: "Invalid parameters",
					Data:    "missing field",
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		_, err = client.CallTool(context.Background(), "test", nil)
		if err == nil {
			t.Error("expected error")
		}

		mcpErr, ok := err.(*MCPError)
		if !ok {
			t.Fatalf("expected MCPError, got %T", err)
		}
		if mcpErr.Code != InvalidParams {
			t.Errorf("Code = %d, want %d", mcpErr.Code, InvalidParams)
		}
	})

	t.Run("handles closed client", func(t *testing.T) {
		config := DefaultClientConfig("http://localhost:9445")
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		client.Close()

		_, err = client.CallTool(context.Background(), "test", nil)
		if err == nil {
			t.Error("expected error for closed client")
		}
	})

	t.Run("handles invalid JSON response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not valid json"))
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		_, err = client.CallTool(context.Background(), "test", nil)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("includes Authorization header when token set", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader != "Bearer test-token" {
				t.Errorf("Authorization = %s, want Bearer test-token", authHeader)
			}

			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]interface{}{"success": true},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := DefaultClientConfig(server.URL)
		client, err := NewClient(config, WithMCPToken("test-token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		_, err = client.CallTool(context.Background(), "test", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestClient_Retry(t *testing.T) {
	t.Run("retries on transient failure", func(t *testing.T) {
		attempts := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			if attempts < 2 {
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}

			var req JSONRPCRequest
			json.NewDecoder(r.Body).Decode(&req)

			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result:  map[string]interface{}{"success": true},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		config := &ClientConfig{
			ServerAddr: server.URL,
			Timeout:    5 * time.Second,
			MaxRetries: 3,
			RetryDelay: 10 * time.Millisecond,
		}
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		_, err = client.CallTool(context.Background(), "test", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if attempts < 2 {
			t.Errorf("attempts = %d, want >= 2", attempts)
		}
	})

	t.Run("respects context cancellation during retry", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		}))
		defer server.Close()

		config := &ClientConfig{
			ServerAddr: server.URL,
			Timeout:    5 * time.Second,
			MaxRetries: 10,
			RetryDelay: 100 * time.Millisecond,
		}
		client, err := NewClient(config)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer client.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err = client.CallTool(ctx, "test", nil)
		if err == nil {
			t.Error("expected error for cancelled context")
		}
	})
}

func TestMCPError(t *testing.T) {
	t.Run("Error returns formatted message", func(t *testing.T) {
		err := &MCPError{
			Code:    InvalidParams,
			Message: "Invalid parameters",
			Data:    "details",
		}

		expected := "MCP error -32602: Invalid parameters"
		if err.Error() != expected {
			t.Errorf("Error() = %s, want %s", err.Error(), expected)
		}
	})
}

func TestMapToStruct(t *testing.T) {
	t.Run("converts map to struct", func(t *testing.T) {
		src := map[string]interface{}{
			"name":    "test",
			"version": "1.0.0",
		}

		var dst ServerInfo
		err := mapToStruct(src, &dst)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if dst.Name != "test" {
			t.Errorf("Name = %s, want test", dst.Name)
		}
		if dst.Version != "1.0.0" {
			t.Errorf("Version = %s, want 1.0.0", dst.Version)
		}
	})

	t.Run("handles nil source", func(t *testing.T) {
		var dst ServerInfo
		err := mapToStruct(nil, &dst)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestMapToStruct_MarshalError(t *testing.T) {
	// Channels cannot be marshaled
	type unmarshalable struct {
		Ch chan int
	}
	src := unmarshalable{Ch: make(chan int)}
	var dst ServerInfo
	err := mapToStruct(src, &dst)
	if err == nil {
		t.Error("expected error when marshaling channel")
	}
}

func TestMapToStruct_UnmarshalError(t *testing.T) {
	// Provide data that cannot be unmarshaled into an int
	src := map[string]interface{}{"name": "test"}
	var dst int
	err := mapToStruct(src, &dst)
	if err == nil {
		t.Error("expected error when unmarshaling map into int")
	}
}

func TestClient_Initialize_MapError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Return invalid result that cannot be unmarshaled to InitializeResult
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  "not a map",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}
	client, _ := NewClient(config)
	defer client.Close()

	_, err := client.Initialize(context.Background())
	if err == nil {
		t.Error("expected error for invalid initialize result format")
	}
}

func TestClient_ListTools_MapError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Return valid map with tools that cannot be unmarshaled
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"tools": "not an array",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}
	client, _ := NewClient(config)
	defer client.Close()

	_, err := client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for invalid tools format")
	}
}

func TestClient_ListResources_MapError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		json.NewDecoder(r.Body).Decode(&req)

		// Return valid map with resources that cannot be unmarshaled
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]interface{}{
				"resources": "not an array",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}
	client, _ := NewClient(config)
	defer client.Close()

	_, err := client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for invalid resources format")
	}
}

func TestClient_doRequest_CreateRequestError(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "http://localhost:8080",
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}
	client, _ := NewClient(config)
	defer client.Close()

	// Use a context that's already canceled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := client.Ping(ctx)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}
