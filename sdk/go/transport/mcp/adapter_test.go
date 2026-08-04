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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

func TestConnect_NilOptions(t *testing.T) {
	ctx := context.Background()

	_, err := Connect(ctx, nil)
	if !errors.Is(err, platform.ErrNilOptions) {
		t.Errorf("Connect(nil) error = %v, want %v", err, platform.ErrNilOptions)
	}
}

func TestConnect_EmptyAddress(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions()
	opts.MCPAddr = ""

	_, err := Connect(ctx, opts)
	if !errors.Is(err, platform.ErrEmptyAddress) {
		t.Errorf("Connect() error = %v, want %v", err, platform.ErrEmptyAddress)
	}
}

func TestConnect_WithMCPServer(t *testing.T) {
	// Create a test MCP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcpapi.JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Respond to initialize
		if req.Method == "initialize" {
			resp := mcpapi.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"serverInfo": map[string]string{
						"name":    "test-server",
						"version": "1.0.0",
					},
					"capabilities": map[string]interface{}{},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithMCPAddr(server.URL),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer adapter.Close()

	if !adapter.IsConnected() {
		t.Error("adapter should report connected")
	}

	if adapter.Connection() == nil {
		t.Error("Connection() should not return nil")
	}
}

func TestConnect_AddsHTTPPrefix(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return valid MCP response
		resp := mcpapi.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  map[string]interface{}{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Extract host:port without scheme
	addrWithoutScheme := server.URL[7:] // Remove "http://"

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithMCPAddr(addrWithoutScheme),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer adapter.Close()

	// Target should still be original address
	if adapter.Target() != addrWithoutScheme {
		t.Errorf("Target() = %q, want %q", adapter.Target(), addrWithoutScheme)
	}
}

func TestAdapter_Target(t *testing.T) {
	a := &Adapter{
		address: "localhost:9445",
	}

	if got := a.Target(); got != "localhost:9445" {
		t.Errorf("Target() = %q, want %q", got, "localhost:9445")
	}
}

func TestAdapter_IsConnected(t *testing.T) {
	a := &Adapter{}

	// Initially not connected
	if a.IsConnected() {
		t.Error("IsConnected() should return false initially")
	}

	// After storing true but no client
	a.connected.Store(true)
	if a.IsConnected() {
		t.Error("IsConnected() should return false without client")
	}

	// After storing closed
	a.closed.Store(true)
	if a.IsConnected() {
		t.Error("IsConnected() should return false when closed")
	}
}

func TestAdapter_Close_NotConnected(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(false)

	err := a.Close()
	if err != nil {
		t.Errorf("Close() on disconnected adapter should not return error, got %v", err)
	}
}

func TestAdapter_Close_NilClient(t *testing.T) {
	a := &Adapter{
		client: nil,
	}
	a.connected.Store(true)

	err := a.Close()
	if err != nil {
		t.Errorf("Close() with nil client should not return error, got %v", err)
	}
	if a.IsConnected() {
		t.Error("IsConnected() should return false after Close()")
	}
}

func TestAdapter_Close_Idempotent(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)

	// First close
	err := a.Close()
	if err != nil {
		t.Errorf("first Close() returned error: %v", err)
	}

	// Second close should be safe
	err = a.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

func TestAdapter_Connection(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)

	conn := a.Connection()
	if conn == nil {
		t.Error("Connection() should not return nil")
	}

	// Verify it's the right type
	_, ok := conn.(*mcpClientConn)
	if !ok {
		t.Errorf("Connection() returned %T, want *mcpClientConn", conn)
	}
}

func TestAdapter_Client(t *testing.T) {
	a := &Adapter{
		client: nil,
	}

	// With nil client
	if a.Client() != nil {
		t.Error("Client() should return nil when no client is set")
	}
}

func TestAdapter_SetToken(t *testing.T) {
	// With nil client - should not panic
	a := &Adapter{
		client: nil,
	}
	a.SetToken("test-token")
	// If we get here without panic, the test passes
}

func TestMCPClientConn_Invoke_Closed(t *testing.T) {
	a := &Adapter{}
	a.closed.Store(true)

	conn := &mcpClientConn{adapter: a}

	err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetHealth", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should return error when closed")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestMCPClientConn_Invoke_NilClient(t *testing.T) {
	a := &Adapter{
		client: nil,
	}
	a.connected.Store(true)

	conn := &mcpClientConn{adapter: a}

	err := conn.Invoke(context.Background(), "/platform.v1.PlatformDaemon/GetHealth", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should return error with nil client")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unavailable {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unavailable)
	}
}

func TestMCPClientConn_Invoke_UnmappedMethod(t *testing.T) {
	// Create a minimal MCP client
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := mcpapi.JSONRPCResponse{JSONRPC: "2.0", ID: 1, Result: map[string]interface{}{}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, err := mcpapi.NewClient(mcpapi.DefaultClientConfig(server.URL))
	if err != nil {
		t.Fatalf("failed to create MCP client: %v", err)
	}

	a := &Adapter{
		client: client,
	}
	a.connected.Store(true)

	conn := &mcpClientConn{adapter: a}

	err = conn.Invoke(context.Background(), "/unknown.Service/UnknownMethod", nil, nil)
	if err == nil {
		t.Fatal("Invoke() should return error for unmapped method")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unimplemented {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unimplemented)
	}
}

func TestMCPClientConn_NewStream(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(true)

	conn := &mcpClientConn{adapter: a}

	_, err := conn.NewStream(context.Background(), nil, "/test/method")
	if err == nil {
		t.Fatal("NewStream() should return error")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Unimplemented {
		t.Errorf("status code = %v, want %v", st.Code(), codes.Unimplemented)
	}
}

func TestGRPCMethodToMCPToolMap_Health(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{"/platform.v1.PlatformDaemon/GetHealth", "platform_health"},
		{"/platform.v1.PlatformDaemon/GetStatus", "platform_daemon_status"},
		{"/platform.v1.PlatformDaemon/GetVersion", "platform_daemon_version"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			tool, ok := grpcMethodToMCPToolMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if tool != tt.expected {
				t.Errorf("tool = %q, want %q", tool, tt.expected)
			}
		})
	}
}

func TestGRPCMethodToMCPToolMap_CA(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{"/platform.v1.CAService/GetCAInfo", "ca_info"},
		{"/platform.v1.CAService/IssueCertificate", "ca_issue"},
		{"/platform.v1.CAService/RevokeCertificate", "ca_revoke"},
		{"/platform.v1.CAService/RenewCertificate", "ca_renew"},
		{"/platform.v1.CAService/VerifyCertificate", "ca_verify"},
		{"/platform.v1.CAService/GetCRL", "ca_crl"},
		{"/platform.v1.CAService/GetCABundle", "ca_bundle"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			tool, ok := grpcMethodToMCPToolMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if tool != tt.expected {
				t.Errorf("tool = %q, want %q", tool, tt.expected)
			}
		})
	}
}

func TestGRPCMethodToMCPToolMap_KMS(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{"/platform.v1.KeyManagementService/GenerateKey", "kms_generate_key"},
		{"/platform.v1.KeyManagementService/Encrypt", "kms_encrypt"},
		{"/platform.v1.KeyManagementService/Decrypt", "kms_decrypt"},
		{"/platform.v1.KeyManagementService/Sign", "kms_sign"},
		{"/platform.v1.KeyManagementService/Verify", "kms_verify"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			tool, ok := grpcMethodToMCPToolMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if tool != tt.expected {
				t.Errorf("tool = %q, want %q", tool, tt.expected)
			}
		})
	}
}

func TestGRPCMethodToMCPToolMap_VTPM(t *testing.T) {
	tests := []struct {
		method   string
		expected string
	}{
		{"/platform.v1.VTPMService/QuoteVTPM", "vtpm_quote"},
		{"/platform.v1.VTPMService/SealVTPM", "vtpm_seal"},
		{"/platform.v1.VTPMService/UnsealVTPM", "vtpm_unseal"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			tool, ok := grpcMethodToMCPToolMap[tt.method]
			if !ok {
				t.Fatalf("method %s not found in map", tt.method)
			}
			if tool != tt.expected {
				t.Errorf("tool = %q, want %q", tool, tt.expected)
			}
		})
	}
}

func TestTranslateMCPErrorToGRPC(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode codes.Code
	}{
		{
			name:         "nil error",
			err:          nil,
			expectedCode: codes.OK,
		},
		{
			name:         "parse error",
			err:          &mcpapi.MCPError{Code: mcpapi.ParseError, Message: "parse error"},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "invalid request",
			err:          &mcpapi.MCPError{Code: mcpapi.InvalidRequest, Message: "invalid request"},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "method not found",
			err:          &mcpapi.MCPError{Code: mcpapi.MethodNotFound, Message: "method not found"},
			expectedCode: codes.Unimplemented,
		},
		{
			name:         "invalid params",
			err:          &mcpapi.MCPError{Code: mcpapi.InvalidParams, Message: "invalid params"},
			expectedCode: codes.InvalidArgument,
		},
		{
			name:         "internal error",
			err:          &mcpapi.MCPError{Code: mcpapi.InternalError, Message: "internal error"},
			expectedCode: codes.Internal,
		},
		{
			name:         "authentication required",
			err:          &mcpapi.MCPError{Code: mcpapi.AuthenticationRequired, Message: "authentication required"},
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "invalid token",
			err:          &mcpapi.MCPError{Code: mcpapi.InvalidToken, Message: "invalid token"},
			expectedCode: codes.Unauthenticated,
		},
		{
			name:         "permission denied",
			err:          &mcpapi.MCPError{Code: mcpapi.PermissionDenied, Message: "permission denied"},
			expectedCode: codes.PermissionDenied,
		},
		{
			name:         "service unavailable",
			err:          &mcpapi.MCPError{Code: mcpapi.ServiceUnavailable, Message: "service unavailable"},
			expectedCode: codes.Unavailable,
		},
		{
			name:         "unknown MCP error",
			err:          &mcpapi.MCPError{Code: -99999, Message: "unknown"},
			expectedCode: codes.Unknown,
		},
		{
			name:         "generic error",
			err:          errors.New("generic error"),
			expectedCode: codes.Unavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grpcErr := translateMCPErrorToGRPC(tt.err)
			if tt.err == nil {
				if grpcErr != nil {
					t.Errorf("translateMCPErrorToGRPC(nil) = %v, want nil", grpcErr)
				}
				return
			}

			st, ok := status.FromError(grpcErr)
			if !ok {
				t.Fatalf("expected gRPC status error, got %T: %v", grpcErr, grpcErr)
			}
			if st.Code() != tt.expectedCode {
				t.Errorf("code = %v, want %v", st.Code(), tt.expectedCode)
			}
		})
	}
}

func TestStructToMap(t *testing.T) {
	type testStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	input := &testStruct{Name: "test", Value: 42}
	result, err := structToMap(input)
	if err != nil {
		t.Fatalf("structToMap() returned error: %v", err)
	}

	if result["name"] != "test" {
		t.Errorf("result[name] = %v, want 'test'", result["name"])
	}
	if result["value"].(float64) != 42 {
		t.Errorf("result[value] = %v, want 42", result["value"])
	}
}

func TestStructToMap_Nil(t *testing.T) {
	result, err := structToMap(nil)
	if err != nil {
		t.Errorf("structToMap(nil) returned error: %v", err)
	}
	if result != nil {
		t.Errorf("structToMap(nil) = %v, want nil", result)
	}
}

func TestStructToMap_UnmarshalError(t *testing.T) {
	// Use a type that fails unmarshal (channel cannot be unmarshaled)
	input := map[string]interface{}{
		"chan": make(chan int),
	}
	_, err := structToMap(input)
	if err == nil {
		t.Error("structToMap() should return error for unmarshallable type")
	}

	var marshalErr ErrMarshalFailed
	if !errors.As(err, &marshalErr) {
		t.Errorf("expected ErrMarshalFailed, got %T: %v", err, err)
	}
}

func TestMapToStruct(t *testing.T) {
	type testStruct struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	input := map[string]interface{}{
		"name":  "test",
		"value": float64(42),
	}

	var result testStruct
	err := mapToStruct(input, &result)
	if err != nil {
		t.Fatalf("mapToStruct() returned error: %v", err)
	}

	if result.Name != "test" {
		t.Errorf("result.Name = %q, want 'test'", result.Name)
	}
	if result.Value != 42 {
		t.Errorf("result.Value = %d, want 42", result.Value)
	}
}

func TestMapToStruct_Nil(t *testing.T) {
	var result struct{}
	err := mapToStruct(nil, &result)
	if err != nil {
		t.Errorf("mapToStruct(nil) returned error: %v", err)
	}
}

func TestMapToStruct_NilDst(t *testing.T) {
	input := map[string]interface{}{"key": "value"}
	err := mapToStruct(input, nil)
	if err != nil {
		t.Errorf("mapToStruct(_, nil) returned error: %v", err)
	}
}

func TestErrClientClosed_Error(t *testing.T) {
	err := ErrClientClosed{}
	expected := "MCP client is closed"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrRPCFailed_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrRPCFailed
		expected string
	}{
		{
			name:     "without data",
			err:      ErrRPCFailed{Code: -32600, Message: "Invalid Request"},
			expected: "MCP RPC error -32600: Invalid Request",
		},
		{
			name:     "with data",
			err:      ErrRPCFailed{Code: -32602, Message: "Invalid params", Data: "missing field"},
			expected: "MCP RPC error -32602: Invalid params (data: missing field)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestErrToolNotFound_Error(t *testing.T) {
	err := ErrToolNotFound{Name: "unknown.tool"}
	expected := "MCP tool not found: unknown.tool"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrResourceNotFound_Error(t *testing.T) {
	err := ErrResourceNotFound{URI: "resource://missing"}
	expected := "MCP resource not found: resource://missing"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrMethodNotMapped_Error(t *testing.T) {
	err := ErrMethodNotMapped{Method: "/test.Service/Method"}
	expected := "gRPC method not mapped to MCP tool: /test.Service/Method"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrInvalidResponse_Error(t *testing.T) {
	err := ErrInvalidResponse{Reason: "missing result field"}
	expected := "invalid MCP response: missing result field"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrMarshalFailed_Error(t *testing.T) {
	innerErr := errors.New("invalid type")
	err := ErrMarshalFailed{Err: innerErr}

	expected := "failed to marshal request: invalid type"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrMarshalFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("invalid type")
	err := ErrMarshalFailed{Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestErrUnmarshalFailed_Error(t *testing.T) {
	innerErr := errors.New("invalid json")
	err := ErrUnmarshalFailed{Err: innerErr}

	expected := "failed to unmarshal response: invalid json"
	if got := err.Error(); got != expected {
		t.Errorf("Error() = %q, want %q", got, expected)
	}
}

func TestErrUnmarshalFailed_Unwrap(t *testing.T) {
	innerErr := errors.New("invalid json")
	err := ErrUnmarshalFailed{Err: innerErr}

	if !errors.Is(err, innerErr) {
		t.Error("Unwrap() should return the inner error")
	}
}

func TestMCPErrorCodeToGRPCMap_Coverage(t *testing.T) {
	// Verify all expected MCP error codes are mapped
	expectedCodes := []int{
		mcpapi.ParseError,
		mcpapi.InvalidRequest,
		mcpapi.MethodNotFound,
		mcpapi.InvalidParams,
		mcpapi.InternalError,
		mcpapi.AuthenticationRequired,
		mcpapi.InvalidToken,
		mcpapi.PermissionDenied,
		mcpapi.ServiceUnavailable,
	}

	for _, code := range expectedCodes {
		if _, ok := mcpErrorCodeToGRPCMap[code]; !ok {
			t.Errorf("MCP error code %d not mapped to gRPC code", code)
		}
	}
}
