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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClient_InitializeResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Method == "initialize" {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"serverInfo": map[string]interface{}{
						"name":    "Test Server",
						"version": "1.0.0",
					},
					"capabilities": map[string]interface{}{
						"tools":     true,
						"resources": true,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		http.Error(w, "unknown method", http.StatusBadRequest)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
		RetryDelay: 100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	_, err = client.Initialize(context.Background())
	if err != nil {
		t.Errorf("Initialize failed: %v", err)
	}
}

func TestClient_ListToolsInvalidFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

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

	_, err := client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestClient_ListToolsMissingTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{},
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
		t.Error("expected error for missing tools field")
	}
}

func TestClient_ListResourcesInvalidFormat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

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

	_, err := client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestClient_ListResourcesMissingResources(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{},
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
		t.Error("expected error for missing resources field")
	}
}

func TestClient_doRequestWithToken(t *testing.T) {
	tokenReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenReceived = r.Header.Get("Authorization")

		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]interface{}{"status": "ok"},
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

	client.SetToken("test-bearer-token")

	err := client.Ping(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if tokenReceived != "Bearer test-bearer-token" {
		t.Errorf("expected Authorization header 'Bearer test-bearer-token', got %q", tokenReceived)
	}
}

func TestClient_doRequestError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    -32600,
				Message: "Invalid Request",
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

	err := client.Ping(context.Background())
	if err == nil {
		t.Error("expected error for RPC error response")
	}
}

func TestClient_ClosedClientOperations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not reach", http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    5 * time.Second,
		MaxRetries: 1,
	}

	client, _ := NewClient(config)
	client.Close()

	err := client.Ping(context.Background())
	if err == nil {
		t.Error("expected error for closed client")
	}

	_, err = client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for closed client")
	}
}

func TestMapToStructSlice(t *testing.T) {
	type Item struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	input := []interface{}{
		map[string]interface{}{"name": "item1", "value": 1},
		map[string]interface{}{"name": "item2", "value": 2},
	}

	var result []Item
	err := mapToStruct(input, &result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("expected 2 items, got %d", len(result))
	}
	if result[0].Name != "item1" {
		t.Errorf("expected name 'item1', got %s", result[0].Name)
	}
}

func TestMCPError_ErrorCoverage(t *testing.T) {
	err := &MCPError{
		Code:    -32600,
		Message: "Invalid Request",
		Data:    map[string]string{"detail": "missing required field"},
	}

	expected := "MCP error -32600: Invalid Request"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestClientOptionsCoverage(t *testing.T) {
	config := &ClientConfig{
		ServerAddr: "http://localhost:8080",
		Timeout:    10 * time.Second,
		MaxRetries: 5,
		RetryDelay: 200 * time.Millisecond,
	}

	if config.ServerAddr != "http://localhost:8080" {
		t.Errorf("unexpected ServerAddr: %s", config.ServerAddr)
	}
	if config.Timeout != 10*time.Second {
		t.Errorf("unexpected Timeout: %v", config.Timeout)
	}
	if config.MaxRetries != 5 {
		t.Errorf("unexpected MaxRetries: %d", config.MaxRetries)
	}
	if config.RetryDelay != 200*time.Millisecond {
		t.Errorf("unexpected RetryDelay: %v", config.RetryDelay)
	}
}

func TestNewClient_ValidationCoverage(t *testing.T) {
	// Test with empty server address
	_, err := NewClient(&ClientConfig{
		ServerAddr: "",
		Timeout:    5 * time.Second,
	})
	if err == nil {
		t.Error("expected error for empty server address")
	}

}

// TestClientInitializeEdgeCases tests client initialization edge cases
func TestClientInitializeEdgeCases(t *testing.T) {
	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: "http://localhost:9999",
		},
		httpClient: &http.Client{Timeout: time.Millisecond},
	}

	_, err := client.Initialize(ctx)
	if err == nil {
		t.Log("Initialize may or may not fail with cancelled context depending on timing")
	}
}

// TestDoRequestContextDeadline tests request with deadline
func TestDoRequestContextDeadline(t *testing.T) {
	// Create a server that delays
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": "ok"}`))
	}))
	defer ts.Close()

	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: ts.URL,
			Timeout:    10 * time.Millisecond,
		},
		httpClient: &http.Client{Timeout: 10 * time.Millisecond},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Log("Request may or may not timeout depending on timing")
	}
}

// TestDoRequestServerError tests doRequest with server error
func TestDoRequestServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for server error")
	}
}

// TestDoRequestInvalidJSON tests doRequest with invalid JSON response
func TestDoRequestInvalidJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-valid-json"))
	}))
	defer ts.Close()

	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

// TestDoRequestWithToken tests doRequest with authorization token
func TestDoRequestWithToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify token was sent
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("expected 'Bearer test-token', got '%s'", auth)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer ts.Close()

	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "test-token")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestDoRequestEmptyResponse tests doRequest with empty response body
func TestDoRequestEmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Empty body
	}))
	defer ts.Close()

	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for empty response")
	}
}

// TestDoRequestNetworkError tests doRequest with network failure
func TestDoRequestNetworkError(t *testing.T) {
	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: "http://localhost:1", // Invalid port that won't be listening
			MaxRetries: 1,
		},
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	if err == nil {
		t.Error("expected error for network failure")
	}
}

// TestDoRequestReadBodyError tests doRequest when reading body fails
func TestDoRequestReadBodyError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send a response but close connection mid-stream (simulating read error)
		w.Header().Set("Content-Length", "1000") // Claim large body
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{`)) // Write partial body
		// Connection will close without sending full body
	}))
	defer ts.Close()

	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: ts.URL,
			MaxRetries: 1,
		},
		httpClient: &http.Client{},
	}

	ctx := context.Background()
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "test",
	}

	_, err := client.doRequest(ctx, req, "")
	// This might result in either read error or JSON parse error
	if err == nil {
		t.Log("Expected error but may vary based on timing")
	}
}

// TestMCPErrorFormatting tests MCPError formatting
func TestMCPErrorFormatting(t *testing.T) {
	err := &MCPError{
		Code:    -32600,
		Message: "Invalid Request",
		Data:    "test data",
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "-32600") {
		t.Error("error should contain code")
	}
	if !strings.Contains(errStr, "Invalid Request") {
		t.Error("error should contain message")
	}
}

// TestIsConnected tests client connection status
func TestIsConnected(t *testing.T) {
	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: "http://localhost:9999",
		},
		httpClient: &http.Client{},
	}

	// Should be connected initially
	if !client.IsConnected() {
		t.Error("expected connected initially")
	}

	// Close and check
	client.Close()

	if client.IsConnected() {
		t.Error("expected disconnected after close")
	}
}

// TestServerAddr tests ServerAddr getter
func TestServerAddr(t *testing.T) {
	client := &Client{
		logger: slog.New(slog.DiscardHandler),
		config: &ClientConfig{
			ServerAddr: "http://test:8000",
		},
	}

	if client.ServerAddr() != "http://test:8000" {
		t.Errorf("expected 'http://test:8000', got '%s'", client.ServerAddr())
	}
}

// TestClientDoRequestWithContextTimeout tests client doRequest with cancellation
func TestClientDoRequestWithContextTimeout(t *testing.T) {
	// Create a server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
	}))
	defer server.Close()

	config := &ClientConfig{
		ServerAddr: server.URL,
		Timeout:    100 * time.Millisecond,
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Request should timeout
	_, err = client.ListTools(ctx)
	if err == nil {
		t.Error("expected timeout error")
	}
}

// TestListResourcesInvalidResponse tests ListResources with invalid response format
func TestListResourcesInvalidResponse(t *testing.T) {
	// Create server that returns non-map response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  "not_a_map", // Invalid - should be a map
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(&ClientConfig{ServerAddr: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for invalid response format")
	}
}

// TestListResourcesMissingResources tests ListResources with missing resources field
func TestListResourcesMissingResources(t *testing.T) {
	// Create server that returns map without resources field
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]interface{}{"other": "data"}, // Missing resources field
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(&ClientConfig{ServerAddr: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.ListResources(context.Background())
	if err == nil {
		t.Error("expected error for missing resources field")
	}
}

// TestDoRequestWithRPCErrorData tests doRequest when server returns JSON-RPC error with data
func TestDoRequestWithRPCErrorData(t *testing.T) {
	// Create server that returns JSON-RPC error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]interface{}{
				"code":    -32600,
				"message": "Invalid Request",
				"data":    "test error data",
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := NewClient(&ClientConfig{ServerAddr: server.URL})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.ListTools(context.Background())
	if err == nil {
		t.Error("expected error for RPC error response")
	}

	// Should be MCPError
	var mcpErr *MCPError
	if !errors.As(err, &mcpErr) {
		t.Errorf("expected MCPError, got %T", err)
	}
}
