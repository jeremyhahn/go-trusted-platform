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
