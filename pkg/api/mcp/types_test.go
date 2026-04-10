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
	"testing"
)

func TestConstants(t *testing.T) {
	t.Run("MCPVersion is set correctly", func(t *testing.T) {
		expected := "2024-11-05"
		if MCPVersion != expected {
			t.Errorf("MCPVersion = %s, want %s", MCPVersion, expected)
		}
	})

	t.Run("JSON-RPC error codes have correct values", func(t *testing.T) {
		tests := []struct {
			name     string
			constant int
			expected int
		}{
			{"ParseError", ParseError, -32700},
			{"InvalidRequest", InvalidRequest, -32600},
			{"MethodNotFound", MethodNotFound, -32601},
			{"InvalidParams", InvalidParams, -32602},
			{"InternalError", InternalError, -32603},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.constant != tt.expected {
					t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
				}
			})
		}
	})

	t.Run("Custom auth error codes have correct values", func(t *testing.T) {
		tests := []struct {
			name     string
			constant int
			expected int
		}{
			{"AuthenticationRequired", AuthenticationRequired, -32001},
			{"InvalidToken", InvalidToken, -32002},
			{"PermissionDenied", PermissionDenied, -32003},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.constant != tt.expected {
					t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.expected)
				}
			})
		}
	})
}

func TestAuthErrorType(t *testing.T) {
	tests := []struct {
		name     string
		errType  AuthErrorType
		expected int
	}{
		{"AuthErrorNone", AuthErrorNone, 0},
		{"AuthErrorMissingToken", AuthErrorMissingToken, 1},
		{"AuthErrorInvalidToken", AuthErrorInvalidToken, 2},
		{"AuthErrorPermissionDenied", AuthErrorPermissionDenied, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if int(tt.errType) != tt.expected {
				t.Errorf("%s = %d, want %d", tt.name, int(tt.errType), tt.expected)
			}
		})
	}
}

func TestAuthorizationError(t *testing.T) {
	t.Run("Error returns message", func(t *testing.T) {
		err := &AuthorizationError{
			Type:    AuthErrorMissingToken,
			Message: "Authentication required",
		}

		if err.Error() != "Authentication required" {
			t.Errorf("Error() = %s, want %s", err.Error(), "Authentication required")
		}
	})

	t.Run("Error with empty message returns empty string", func(t *testing.T) {
		err := &AuthorizationError{
			Type:    AuthErrorNone,
			Message: "",
		}

		if err.Error() != "" {
			t.Errorf("Error() = %s, want empty string", err.Error())
		}
	})

	t.Run("AuthorizationError implements error interface", func(t *testing.T) {
		var _ error = &AuthorizationError{}
	})
}

func TestContextWithToken(t *testing.T) {
	t.Run("adds token to context", func(t *testing.T) {
		ctx := context.Background()
		token := "test-token-12345"

		newCtx := ContextWithToken(ctx, token)

		retrievedToken := TokenFromContext(newCtx)
		if retrievedToken != token {
			t.Errorf("TokenFromContext() = %s, want %s", retrievedToken, token)
		}
	})

	t.Run("empty token is stored correctly", func(t *testing.T) {
		ctx := context.Background()
		token := ""

		newCtx := ContextWithToken(ctx, token)

		retrievedToken := TokenFromContext(newCtx)
		if retrievedToken != token {
			t.Errorf("TokenFromContext() = %s, want empty string", retrievedToken)
		}
	})

	t.Run("overwrites existing token", func(t *testing.T) {
		ctx := context.Background()
		firstToken := "first-token"
		secondToken := "second-token"

		ctx = ContextWithToken(ctx, firstToken)
		ctx = ContextWithToken(ctx, secondToken)

		retrievedToken := TokenFromContext(ctx)
		if retrievedToken != secondToken {
			t.Errorf("TokenFromContext() = %s, want %s", retrievedToken, secondToken)
		}
	})
}

func TestTokenFromContext(t *testing.T) {
	t.Run("returns empty string when no token in context", func(t *testing.T) {
		ctx := context.Background()

		token := TokenFromContext(ctx)
		if token != "" {
			t.Errorf("TokenFromContext() = %s, want empty string", token)
		}
	})

	t.Run("returns token when present", func(t *testing.T) {
		ctx := ContextWithToken(context.Background(), "my-token")

		token := TokenFromContext(ctx)
		if token != "my-token" {
			t.Errorf("TokenFromContext() = %s, want my-token", token)
		}
	})

	t.Run("returns empty string when wrong type in context", func(t *testing.T) {
		// This tests the type assertion failure path
		ctx := context.WithValue(context.Background(), tokenContextKey{}, 12345)

		token := TokenFromContext(ctx)
		if token != "" {
			t.Errorf("TokenFromContext() = %s, want empty string for wrong type", token)
		}
	})
}

func TestJSONRPCRequest(t *testing.T) {
	t.Run("struct has correct fields", func(t *testing.T) {
		req := JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      1,
			Method:  "test_method",
			Params:  map[string]interface{}{"key": "value"},
		}

		if req.JSONRPC != "2.0" {
			t.Errorf("JSONRPC = %s, want 2.0", req.JSONRPC)
		}
		if req.ID != 1 {
			t.Errorf("ID = %v, want 1", req.ID)
		}
		if req.Method != "test_method" {
			t.Errorf("Method = %s, want test_method", req.Method)
		}
		if req.Params == nil {
			t.Error("Params should not be nil")
		}
	})

	t.Run("ID can be string", func(t *testing.T) {
		req := JSONRPCRequest{
			JSONRPC: "2.0",
			ID:      "string-id",
			Method:  "test",
		}

		if req.ID != "string-id" {
			t.Errorf("ID = %v, want string-id", req.ID)
		}
	})

	t.Run("ID can be nil for notifications", func(t *testing.T) {
		req := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "notification",
		}

		if req.ID != nil {
			t.Errorf("ID = %v, want nil", req.ID)
		}
	})
}

func TestJSONRPCResponse(t *testing.T) {
	t.Run("success response", func(t *testing.T) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Result:  map[string]interface{}{"status": "ok"},
		}

		if resp.JSONRPC != "2.0" {
			t.Errorf("JSONRPC = %s, want 2.0", resp.JSONRPC)
		}
		if resp.ID != 1 {
			t.Errorf("ID = %v, want 1", resp.ID)
		}
		if resp.Error != nil {
			t.Error("Error should be nil for success response")
		}
	})

	t.Run("error response", func(t *testing.T) {
		resp := JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      1,
			Error: &JSONRPCError{
				Code:    InvalidParams,
				Message: "Invalid parameters",
				Data:    "missing field",
			},
		}

		if resp.Result != nil {
			t.Error("Result should be nil for error response")
		}
		if resp.Error == nil {
			t.Fatal("Error should not be nil for error response")
		}
		if resp.Error.Code != InvalidParams {
			t.Errorf("Error.Code = %d, want %d", resp.Error.Code, InvalidParams)
		}
	})
}

func TestJSONRPCError(t *testing.T) {
	t.Run("creates error with all fields", func(t *testing.T) {
		err := JSONRPCError{
			Code:    InternalError,
			Message: "Something went wrong",
			Data:    map[string]string{"detail": "stack trace"},
		}

		if err.Code != InternalError {
			t.Errorf("Code = %d, want %d", err.Code, InternalError)
		}
		if err.Message != "Something went wrong" {
			t.Errorf("Message = %s, want Something went wrong", err.Message)
		}
		if err.Data == nil {
			t.Error("Data should not be nil")
		}
	})

	t.Run("Data can be nil", func(t *testing.T) {
		err := JSONRPCError{
			Code:    ParseError,
			Message: "Parse error",
		}

		if err.Data != nil {
			t.Errorf("Data = %v, want nil", err.Data)
		}
	})
}

func TestToolDefinition(t *testing.T) {
	t.Run("creates tool definition with all fields", func(t *testing.T) {
		tool := ToolDefinition{
			Name:        "test_tool",
			Description: "A test tool for testing",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"param1": map[string]interface{}{"type": "string"},
				},
				"required": []string{"param1"},
			},
		}

		if tool.Name != "test_tool" {
			t.Errorf("Name = %s, want test_tool", tool.Name)
		}
		if tool.Description != "A test tool for testing" {
			t.Errorf("Description = %s, want A test tool for testing", tool.Description)
		}
		if tool.InputSchema == nil {
			t.Error("InputSchema should not be nil")
		}
	})

	t.Run("InputSchema can be empty", func(t *testing.T) {
		tool := ToolDefinition{
			Name:        "no_params_tool",
			Description: "Tool with no parameters",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		}

		if tool.InputSchema == nil {
			t.Error("InputSchema should not be nil even when empty")
		}
	})
}

func TestResourceDefinition(t *testing.T) {
	t.Run("creates resource definition with all fields", func(t *testing.T) {
		resource := ResourceDefinition{
			URI:         "platform://test/resource",
			Name:        "Test Resource",
			Description: "A test resource",
			MimeType:    "application/json",
		}

		if resource.URI != "platform://test/resource" {
			t.Errorf("URI = %s, want platform://test/resource", resource.URI)
		}
		if resource.Name != "Test Resource" {
			t.Errorf("Name = %s, want Test Resource", resource.Name)
		}
		if resource.Description != "A test resource" {
			t.Errorf("Description = %s, want A test resource", resource.Description)
		}
		if resource.MimeType != "application/json" {
			t.Errorf("MimeType = %s, want application/json", resource.MimeType)
		}
	})

	t.Run("MimeType can be empty", func(t *testing.T) {
		resource := ResourceDefinition{
			URI:         "platform://test",
			Name:        "Test",
			Description: "Test without mime type",
		}

		if resource.MimeType != "" {
			t.Errorf("MimeType = %s, want empty string", resource.MimeType)
		}
	})
}
