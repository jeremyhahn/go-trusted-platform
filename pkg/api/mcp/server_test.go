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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

func TestDefaultConfig(t *testing.T) {
	t.Run("returns default configuration", func(t *testing.T) {
		config := DefaultConfig()

		if config.ServerName != "Trusted Platform MCP Server" {
			t.Errorf("ServerName = %s, unexpected", config.ServerName)
		}
		if config.ServerVersion != "1.0.0" {
			t.Errorf("ServerVersion = %s, want 1.0.0", config.ServerVersion)
		}
		if config.Transport != "http" {
			t.Errorf("Transport = %s, want http", config.Transport)
		}
		if config.HTTPAddr != "127.0.0.1:9445" {
			t.Errorf("HTTPAddr = %s, want 127.0.0.1:9445", config.HTTPAddr)
		}
		if config.RequestTimeout != 30*time.Second {
			t.Errorf("RequestTimeout = %v, want 30s", config.RequestTimeout)
		}
		if config.MaxConcurrentRequests != 100 {
			t.Errorf("MaxConcurrentRequests = %d, want 100", config.MaxConcurrentRequests)
		}
	})
}

func TestNewServer(t *testing.T) {
	t.Run("creates server with default config", func(t *testing.T) {
		svc := newMockServiceProvider()

		server := NewServer(svc, nil, nil)

		if server == nil {
			t.Fatal("NewServer returned nil")
		}
		if server.service == nil {
			t.Error("service should not be nil")
		}
		if server.config == nil {
			t.Error("config should not be nil")
		}
		if server.logger == nil {
			t.Error("logger should not be nil")
		}
	})

	t.Run("creates server with custom config", func(t *testing.T) {
		svc := newMockServiceProvider()
		config := &Config{
			ServerName:    "Custom Server",
			ServerVersion: "2.0.0",
			Transport:     "http",
			HTTPAddr:      "0.0.0.0:8080",
		}
		log := newTestLogger()

		server := NewServer(svc, config, log)

		if server.config.ServerName != "Custom Server" {
			t.Errorf("ServerName = %s, want Custom Server", server.config.ServerName)
		}
		if server.logger != log {
			t.Error("logger not set correctly")
		}
	})

	t.Run("initializes tools and resources registries", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		if server.tools == nil {
			t.Error("tools registry should not be nil")
		}
		if server.resources == nil {
			t.Error("resources registry should not be nil")
		}
	})

	t.Run("initializes authorization checker", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		if server.authChecker == nil {
			t.Error("authChecker should not be nil")
		}
	})

	t.Run("initializes with authorization services", func(t *testing.T) {
		svc := newMockServiceProvider()
		authSvc := &mockAuthorizationService{}
		authMgr := &mockAuthManager{}

		config := &Config{
			AuthorizationService: authSvc,
			AuthManager:          authMgr,
		}

		server := NewServer(svc, config, newTestLogger())

		if !server.authChecker.IsEnabled() {
			t.Error("authChecker should be enabled")
		}
	})
}

func TestServer_SetAuthorizationService(t *testing.T) {
	t.Run("sets authorization services", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		authSvc := &mockAuthorizationService{}
		authMgr := &mockAuthManager{}

		server.SetAuthorizationService(authSvc, authMgr)

		if !server.authChecker.IsEnabled() {
			t.Error("authChecker should be enabled")
		}
	})
}

func TestServer_IsRunning(t *testing.T) {
	t.Run("returns false before start", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		if server.IsRunning() {
			t.Error("IsRunning() = true, want false")
		}
	})
}

func TestServer_Start(t *testing.T) {
	t.Run("returns error for already running server", func(t *testing.T) {
		svc := newMockServiceProvider()
		config := DefaultConfig()
		config.HTTPAddr = "127.0.0.1:0" // Use random port
		config.TLSConfig = newTestTLSConfig(t)
		server := NewServer(svc, config, newTestLogger())

		err := server.Start()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		err = server.Start()
		if err == nil {
			t.Error("expected error for already running server")
		}

		server.Stop()
	})

	t.Run("returns error for unsupported transport", func(t *testing.T) {
		svc := newMockServiceProvider()
		config := &Config{
			Transport: "unsupported",
		}
		server := NewServer(svc, config, newTestLogger())

		err := server.Start()
		if err == nil {
			t.Error("expected error for unsupported transport")
		}

		if server.IsRunning() {
			t.Error("server should not be running after error")
		}
	})
}

func TestServer_Stop(t *testing.T) {
	t.Run("stops running server", func(t *testing.T) {
		svc := newMockServiceProvider()
		config := DefaultConfig()
		config.HTTPAddr = "127.0.0.1:0"
		config.TLSConfig = newTestTLSConfig(t)
		server := NewServer(svc, config, newTestLogger())

		err := server.Start()
		if err != nil {
			t.Fatalf("unexpected error starting: %v", err)
		}

		err = server.Stop()
		if err != nil {
			t.Errorf("unexpected error stopping: %v", err)
		}

		if server.IsRunning() {
			t.Error("server should not be running after stop")
		}
	})

	t.Run("returns error for non-running server", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		err := server.Stop()
		if err == nil {
			t.Error("expected error for non-running server")
		}
	})
}

func TestServer_handleHTTPRequest(t *testing.T) {
	svc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(svc, config, newTestLogger())

	t.Run("rejects non-POST requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		w := httptest.NewRecorder()

		server.handleHTTPRequest(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("handles parse error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString("not json"))
		w := httptest.NewRecorder()

		server.handleHTTPRequest(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}

		var resp mcpwire.JSONRPCResponse
		json.NewDecoder(w.Body).Decode(&resp)

		if resp.Error == nil {
			t.Error("expected error in response")
		}
		if resp.Error.Code != mcpwire.ParseError {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.ParseError)
		}
	})

	t.Run("extracts token from Authorization header", func(t *testing.T) {
		rpcReq := mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "ping",
		}
		body, _ := json.Marshal(rpcReq)

		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()

		server.handleHTTPRequest(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestServer_handleHealthCheck(t *testing.T) {
	svc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(svc, config, newTestLogger())

	t.Run("returns health status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		server.handleHealthCheck(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}

		var result map[string]interface{}
		json.NewDecoder(w.Body).Decode(&result)

		if result["status"] != "healthy" {
			t.Errorf("status = %v, want healthy", result["status"])
		}
		if result["mcp"] != mcpwire.MCPVersion {
			t.Errorf("mcp = %v, want %s", result["mcp"], mcpwire.MCPVersion)
		}
	})
}

// TestServer_Handler proves the exported routes are the ones the HTTP
// transport serves, so a caller mounting Handler gets the same surface.
func TestServer_Handler(t *testing.T) {
	server := NewServer(newMockServiceProvider(), DefaultConfig(), newTestLogger())
	h := server.Handler()

	tests := []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"health is served", http.MethodGet, "/health", http.StatusOK},
		{"mcp refuses GET", http.MethodGet, "/mcp", http.StatusMethodNotAllowed},
		{"unknown path is not routed", http.MethodGet, "/nope", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
			if w.Code != tt.want {
				t.Errorf("%s %s = %d, want %d", tt.method, tt.path, w.Code, tt.want)
			}
		})
	}
}

func TestServer_handleRequest(t *testing.T) {
	svc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(svc, config, newTestLogger())
	ctx := context.Background()

	t.Run("rejects invalid JSON-RPC version", func(t *testing.T) {
		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "1.0",
			ID:      1,
			Method:  "ping",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		if resp.Error.Code != mcpwire.InvalidRequest {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.InvalidRequest)
		}
	})

	t.Run("returns error for unknown method", func(t *testing.T) {
		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "unknown_method",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		if resp.Error.Code != mcpwire.MethodNotFound {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.MethodNotFound)
		}
	})
}

func TestServer_handleInitialize(t *testing.T) {
	svc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(svc, config, newTestLogger())
	ctx := context.Background()

	t.Run("returns server info", func(t *testing.T) {
		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "initialize",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}

		if result["protocolVersion"] != mcpwire.MCPVersion {
			t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], mcpwire.MCPVersion)
		}

		serverInfo, ok := result["serverInfo"].(map[string]interface{})
		if !ok {
			t.Fatal("serverInfo is not a map")
		}

		if serverInfo["name"] != config.ServerName {
			t.Errorf("name = %v, want %s", serverInfo["name"], config.ServerName)
		}
	})
}

func TestServer_handleToolsList(t *testing.T) {
	svc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(svc, config, newTestLogger())
	ctx := context.Background()

	t.Run("returns list of tools", func(t *testing.T) {
		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/list",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}

		tools, ok := result["tools"].([]mcpwire.ToolDefinition)
		if !ok {
			t.Fatal("tools is not a slice")
		}

		if len(tools) == 0 {
			t.Error("tools should not be empty")
		}
	})
}

func TestServer_handleToolsCall(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("returns error for missing params", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params:  "not a map",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		if resp.Error.Code != mcpwire.InvalidParams {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.InvalidParams)
		}
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"arguments": map[string]interface{}{},
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		if resp.Error.Code != mcpwire.InvalidParams {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.InvalidParams)
		}
	})

	t.Run("executes tool successfully", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name":      "platform_health",
				"arguments": map[string]interface{}{},
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}
	})

	t.Run("returns error for tool execution failure", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.healthFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name":      "platform_health",
				"arguments": map[string]interface{}{},
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		if resp.Error.Code != mcpwire.InternalError {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.InternalError)
		}
	})

	t.Run("checks authorization for protected tool", func(t *testing.T) {
		svc := newMockServiceProvider()
		authMgr := &mockAuthManager{
			validateFunc: func(ctx context.Context, token string) (bool, error) {
				return token == "valid-token", nil
			},
		}
		config := &Config{
			AuthManager: authMgr,
		}
		server := NewServer(svc, config, log)

		// Without token
		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name":      "vtpm_create",
				"arguments": map[string]interface{}{"name": "test"},
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error for missing token")
		}
		if resp.Error.Code != mcpwire.AuthenticationRequired {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.AuthenticationRequired)
		}
	})

	t.Run("extracts token from params", func(t *testing.T) {
		svc := newMockServiceProvider()
		authMgr := &mockAuthManager{
			validateFunc: func(ctx context.Context, token string) (bool, error) {
				return token == "valid-token", nil
			},
		}
		config := &Config{
			AuthManager: authMgr,
		}
		server := NewServer(svc, config, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "vtpm_create",
				"arguments": map[string]interface{}{
					"name":   "test",
					"_token": "valid-token",
				},
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}
	})

	t.Run("extracts token from context", func(t *testing.T) {
		svc := newMockServiceProvider()
		authMgr := &mockAuthManager{
			validateFunc: func(ctx context.Context, token string) (bool, error) {
				return token == "context-token", nil
			},
		}
		config := &Config{
			AuthManager: authMgr,
		}
		server := NewServer(svc, config, log)

		ctx := ContextWithToken(context.Background(), "context-token")

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name":      "vtpm_create",
				"arguments": map[string]interface{}{"name": "test"},
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}
	})
}

func TestServer_handleResourcesList(t *testing.T) {
	svc := newMockServiceProvider()
	server := NewServer(svc, nil, newTestLogger())
	ctx := context.Background()

	t.Run("returns list of resources", func(t *testing.T) {
		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "resources/list",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}

		resources, ok := result["resources"].([]mcpwire.ResourceDefinition)
		if !ok {
			t.Fatal("resources is not a slice")
		}

		if len(resources) == 0 {
			t.Error("resources should not be empty")
		}
	})
}

func TestServer_handleResourcesRead(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("returns error for missing params", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "resources/read",
			Params:  "not a map",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		if resp.Error.Code != mcpwire.InvalidParams {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.InvalidParams)
		}
	})

	t.Run("returns error for missing uri", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "resources/read",
			Params:  map[string]interface{}{},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		if resp.Error.Code != mcpwire.InvalidParams {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.InvalidParams)
		}
	})

	t.Run("reads resource successfully", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "resources/read",
			Params: map[string]interface{}{
				"uri": "platform://health",
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}
	})

	t.Run("returns error for read failure", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, log)

		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "resources/read",
			Params: map[string]interface{}{
				"uri": "invalid://uri",
			},
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error == nil {
			t.Error("expected error")
		}
		// A malformed URI is the caller's error, not the server's.
		if resp.Error.Code != mcpwire.InvalidParams {
			t.Errorf("error code = %d, want %d", resp.Error.Code, mcpwire.InvalidParams)
		}
	})
}

func TestServer_handlePing(t *testing.T) {
	svc := newMockServiceProvider()
	server := NewServer(svc, nil, newTestLogger())
	ctx := context.Background()

	t.Run("returns pong", func(t *testing.T) {
		req := &mcpwire.JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "ping",
		}

		resp := server.handleRequest(ctx, req)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}

		result, ok := resp.Result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}

		if result["pong"] != true {
			t.Errorf("pong = %v, want true", result["pong"])
		}
	})
}

func TestServer_handleAuthError(t *testing.T) {
	svc := newMockServiceProvider()
	server := NewServer(svc, nil, newTestLogger())

	tests := []struct {
		name         string
		authErr      *AuthorizationError
		expectedCode int
	}{
		{
			name: "missing token",
			authErr: &AuthorizationError{
				Type:    AuthErrorMissingToken,
				Message: "Token required",
			},
			expectedCode: mcpwire.AuthenticationRequired,
		},
		{
			name: "invalid token",
			authErr: &AuthorizationError{
				Type:    AuthErrorInvalidToken,
				Message: "Invalid token",
			},
			expectedCode: mcpwire.InvalidToken,
		},
		{
			name: "permission denied",
			authErr: &AuthorizationError{
				Type:    AuthErrorPermissionDenied,
				Message: "Access denied",
			},
			expectedCode: mcpwire.PermissionDenied,
		},
		{
			name: "authorization service unavailable",
			authErr: &AuthorizationError{
				Type:    AuthErrorServiceUnavailable,
				Message: "IAM unavailable",
			},
			expectedCode: mcpwire.ServiceUnavailable,
		},
		{
			name: "unknown error type",
			authErr: &AuthorizationError{
				Type:    AuthErrorType(99),
				Message: "Unknown error",
			},
			expectedCode: mcpwire.InternalError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := server.handleAuthError(1, tt.authErr)

			if resp.Error == nil {
				t.Error("expected error")
			}
			if resp.Error.Code != tt.expectedCode {
				t.Errorf("error code = %d, want %d", resp.Error.Code, tt.expectedCode)
			}
		})
	}
}

func TestServer_makeErrorResponse(t *testing.T) {
	svc := newMockServiceProvider()
	server := NewServer(svc, nil, newTestLogger())

	t.Run("creates error response with data", func(t *testing.T) {
		resp := server.makeErrorResponse(1, mcpwire.InvalidParams, "Invalid params", "details here")

		if resp.JSONRPC != "2.0" {
			t.Errorf("JSONRPC = %s, want 2.0", resp.JSONRPC)
		}
		if resp.ID != 1 {
			t.Errorf("ID = %v, want 1", resp.ID)
		}
		if resp.Error == nil {
			t.Fatal("Error should not be nil")
		}
		if resp.Error.Code != mcpwire.InvalidParams {
			t.Errorf("Error.Code = %d, want %d", resp.Error.Code, mcpwire.InvalidParams)
		}
		if resp.Error.Message != "Invalid params" {
			t.Errorf("Error.Message = %s, want Invalid params", resp.Error.Message)
		}
		if resp.Error.Data != "details here" {
			t.Errorf("Error.Data = %v, want details here", resp.Error.Data)
		}
	})

	t.Run("creates error response without data", func(t *testing.T) {
		resp := server.makeErrorResponse(1, mcpwire.ParseError, "Parse error", "")

		if resp.Error.Data != nil {
			t.Errorf("Error.Data = %v, want nil", resp.Error.Data)
		}
	})
}

func TestExtractTokenFromHTTPRequest(t *testing.T) {
	t.Run("extracts Bearer token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer my-token")

		token := extractTokenFromHTTPRequest(req)
		if token != "my-token" {
			t.Errorf("token = %s, want my-token", token)
		}
	})

	t.Run("extracts non-Bearer authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Basic abc123")

		token := extractTokenFromHTTPRequest(req)
		if token != "Basic abc123" {
			t.Errorf("token = %s, want Basic abc123", token)
		}
	})

	t.Run("extracts X-Auth-Token header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("X-Auth-Token", "header-token")

		token := extractTokenFromHTTPRequest(req)
		if token != "header-token" {
			t.Errorf("token = %s, want header-token", token)
		}
	})

	t.Run("prefers Authorization over X-Auth-Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer auth-token")
		req.Header.Set("X-Auth-Token", "x-auth-token")

		token := extractTokenFromHTTPRequest(req)
		if token != "auth-token" {
			t.Errorf("token = %s, want auth-token", token)
		}
	})

	t.Run("returns empty for no token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)

		token := extractTokenFromHTTPRequest(req)
		if token != "" {
			t.Errorf("token = %s, want empty", token)
		}
	})
}

func TestExtractTokenFromParams(t *testing.T) {
	t.Run("extracts _token from arguments", func(t *testing.T) {
		params := map[string]interface{}{
			"arguments": map[string]interface{}{
				"_token": "arg-token",
			},
		}

		token := extractTokenFromParams(params)
		if token != "arg-token" {
			t.Errorf("token = %s, want arg-token", token)
		}
	})

	t.Run("extracts accessToken from arguments", func(t *testing.T) {
		params := map[string]interface{}{
			"arguments": map[string]interface{}{
				"accessToken": "access-token",
			},
		}

		token := extractTokenFromParams(params)
		if token != "access-token" {
			t.Errorf("token = %s, want access-token", token)
		}
	})

	t.Run("extracts _token from top level", func(t *testing.T) {
		params := map[string]interface{}{
			"_token": "top-level-token",
		}

		token := extractTokenFromParams(params)
		if token != "top-level-token" {
			t.Errorf("token = %s, want top-level-token", token)
		}
	})

	t.Run("prefers arguments _token over accessToken", func(t *testing.T) {
		params := map[string]interface{}{
			"arguments": map[string]interface{}{
				"_token":      "underscore-token",
				"accessToken": "access-token",
			},
		}

		token := extractTokenFromParams(params)
		if token != "underscore-token" {
			t.Errorf("token = %s, want underscore-token", token)
		}
	})

	t.Run("returns empty for no token", func(t *testing.T) {
		params := map[string]interface{}{
			"name": "test",
		}

		token := extractTokenFromParams(params)
		if token != "" {
			t.Errorf("token = %s, want empty", token)
		}
	})
}

func TestNewServer_InitializesOAuthMetadataHandler(t *testing.T) {
	t.Run("initializes OAuth metadata handler", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		if server.oauthMetadata == nil {
			t.Error("oauthMetadata should not be nil")
		}
	})

	t.Run("initializes with custom OAuth config", func(t *testing.T) {
		svc := newMockServiceProvider()
		config := &Config{
			OAuthMetadata: &OAuthMetadataConfig{
				ResourceURL:             "https://mcp.example.com:8000",
				AuthorizationServerURLs: []string{"https://auth.example.com"},
			},
		}

		server := NewServer(svc, config, newTestLogger())

		metadata := server.oauthMetadata.GetMetadata()
		if metadata.Resource != "https://mcp.example.com:8000" {
			t.Errorf("resource = %s, want https://mcp.example.com:8000", metadata.Resource)
		}
		if len(metadata.AuthorizationServers) != 1 {
			t.Fatalf("auth servers count = %d, want 1", len(metadata.AuthorizationServers))
		}
		if metadata.AuthorizationServers[0] != "https://auth.example.com" {
			t.Errorf("auth server = %s, want https://auth.example.com", metadata.AuthorizationServers[0])
		}
	})
}

func TestServer_SetOAuthMetadata(t *testing.T) {
	t.Run("sets resource URL and auth servers", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		server.SetOAuthMetadata(
			"https://new-mcp.example.com:8000",
			[]string{"https://auth1.example.com", "https://auth2.example.com"},
		)

		metadata := server.oauthMetadata.GetMetadata()
		if metadata.Resource != "https://new-mcp.example.com:8000" {
			t.Errorf("resource = %s, want https://new-mcp.example.com:8000", metadata.Resource)
		}
		if len(metadata.AuthorizationServers) != 2 {
			t.Fatalf("auth servers count = %d, want 2", len(metadata.AuthorizationServers))
		}
	})
}

func TestServer_GetOAuthMetadataHandler(t *testing.T) {
	t.Run("returns OAuth metadata handler", func(t *testing.T) {
		svc := newMockServiceProvider()
		server := NewServer(svc, nil, newTestLogger())

		handler := server.GetOAuthMetadataHandler()

		if handler == nil {
			t.Error("GetOAuthMetadataHandler() returned nil")
		}
		if handler != server.oauthMetadata {
			t.Error("GetOAuthMetadataHandler() returned different handler")
		}
	})
}

func TestServer_OAuthMetadataEndpoint(t *testing.T) {
	t.Run("serves OAuth metadata at well-known endpoint", func(t *testing.T) {
		svc := newMockServiceProvider()
		config := &Config{
			ServerName:    "Test MCP Server",
			ServerVersion: "1.0.0",
			Transport:     "http",
			HTTPAddr:      "127.0.0.1:0",
			TLSConfig:     newTestTLSConfig(t),
			OAuthMetadata: &OAuthMetadataConfig{
				ResourceURL:             "https://mcp.example.com:8000",
				AuthorizationServerURLs: []string{"https://auth.example.com"},
			},
		}
		server := NewServer(svc, config, newTestLogger())

		// Start server
		if err := server.Start(); err != nil {
			t.Fatalf("failed to start server: %v", err)
		}
		defer server.Stop()

		// Make direct request to the handler
		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()

		server.oauthMetadata.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}

		var metadata OAuthProtectedResourceMetadata
		if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if metadata.Resource != "https://mcp.example.com:8000" {
			t.Errorf("resource = %s, want https://mcp.example.com:8000", metadata.Resource)
		}
	})
}
