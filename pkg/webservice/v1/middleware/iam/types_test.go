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

package iam

import (
	"context"
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// TestContextKey tests that ContextKey type works correctly.
func TestContextKey(t *testing.T) {
	t.Parallel()
	t.Run("SessionContextKey_is_defined", func(t *testing.T) {
		if SessionContextKey == "" {
			t.Error("expected SessionContextKey to be non-empty")
		}
		if SessionContextKey != ContextKey("iam_session") {
			t.Errorf("expected SessionContextKey to be 'iam_session', got %q", SessionContextKey)
		}
	})
}

// TestConstants tests the defined constants.
func TestConstants(t *testing.T) {
	t.Parallel()
	t.Run("header_constants", func(t *testing.T) {
		if TenantIDHeader != "X-Tenant-ID" {
			t.Errorf("expected TenantIDHeader 'X-Tenant-ID', got %q", TenantIDHeader)
		}
		if AuthorizationHeader != "Authorization" {
			t.Errorf("expected AuthorizationHeader 'Authorization', got %q", AuthorizationHeader)
		}
		if BearerPrefix != "Bearer " {
			t.Errorf("expected BearerPrefix 'Bearer ', got %q", BearerPrefix)
		}
		if PolicyContextHeader != "X-Policy-Context" {
			t.Errorf("expected PolicyContextHeader 'X-Policy-Context', got %q", PolicyContextHeader)
		}
	})
}

// TestHTTPMethodToAction tests the HTTP method to action mapping.
func TestHTTPMethodToAction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		method   string
		expected string
	}{
		{"GET", "read"},
		{"HEAD", "read"},
		{"OPTIONS", "read"},
		{"POST", "create"},
		{"PUT", "update"},
		{"PATCH", "update"},
		{"DELETE", "delete"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			action, ok := HTTPMethodToAction[tt.method]
			if !ok {
				t.Errorf("expected %s to be mapped", tt.method)
			}
			if action != tt.expected {
				t.Errorf("expected %s -> %s, got %s", tt.method, tt.expected, action)
			}
		})
	}

	t.Run("TRACE_not_mapped", func(t *testing.T) {
		_, ok := HTTPMethodToAction["TRACE"]
		if ok {
			t.Error("expected TRACE not to be mapped")
		}
	})
}

// TestGetSessionFromContext tests the GetSessionFromContext function.
func TestGetSessionFromContext(t *testing.T) {
	t.Parallel()
	t.Run("returns_session_when_present", func(t *testing.T) {
		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		ctx := context.WithValue(context.Background(), SessionContextKey, session)

		retrieved, ok := GetSessionFromContext(ctx)

		if !ok {
			t.Error("expected session to be found")
		}
		if retrieved != session {
			t.Error("expected retrieved session to match original")
		}
	})

	t.Run("returns_false_when_not_present", func(t *testing.T) {
		ctx := context.Background()

		_, ok := GetSessionFromContext(ctx)

		if ok {
			t.Error("expected session not to be found")
		}
	})

	t.Run("returns_false_for_wrong_type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), SessionContextKey, "not a session")

		_, ok := GetSessionFromContext(ctx)

		if ok {
			t.Error("expected session not to be found for wrong type")
		}
	})

	t.Run("returns_false_for_nil_value", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), SessionContextKey, nil)

		_, ok := GetSessionFromContext(ctx)

		if ok {
			t.Error("expected session not to be found for nil value")
		}
	})
}

// TestSetSessionInContext tests the SetSessionInContext function.
func TestSetSessionInContext(t *testing.T) {
	t.Parallel()
	t.Run("sets_session_in_context", func(t *testing.T) {
		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		ctx := context.Background()
		newCtx := SetSessionInContext(ctx, session)

		// Verify original context is unchanged
		_, ok := GetSessionFromContext(ctx)
		if ok {
			t.Error("expected original context to be unchanged")
		}

		// Verify new context has session
		retrieved, ok := GetSessionFromContext(newCtx)
		if !ok {
			t.Error("expected session to be in new context")
		}
		if retrieved != session {
			t.Error("expected retrieved session to match original")
		}
	})

	t.Run("overwrites_existing_session", func(t *testing.T) {
		session1 := NewIAMSession(&sdkiam.User{
			ID:       "user-1",
			TenantID: "tenant-1",
		})
		session2 := NewIAMSession(&sdkiam.User{
			ID:       "user-2",
			TenantID: "tenant-2",
		})

		ctx := SetSessionInContext(context.Background(), session1)
		ctx = SetSessionInContext(ctx, session2)

		retrieved, ok := GetSessionFromContext(ctx)
		if !ok {
			t.Error("expected session to be found")
		}
		if retrieved.UserID() != "user-2" {
			t.Errorf("expected user-2, got %s", retrieved.UserID())
		}
	})
}

// TestIAMSession_Interface tests that IAMSession interface is properly defined.
func TestIAMSession_Interface(t *testing.T) {
	t.Parallel()
	t.Run("interface_has_all_required_methods", func(t *testing.T) {
		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		// Test that all interface methods are callable
		_ = session.User()
		_ = session.TenantID()
		_ = session.UserID()
		_ = session.Email()
		_ = session.Name()
		_ = session.Roles()
		_ = session.Groups()
		_ = session.HasRole("admin")
		_ = session.HasGroup("developers")
		_ = session.HasAnyRole("admin", "user")
		_ = session.HasAllRoles("admin", "user")
		_ = session.IsMFAVerified()
		_ = session.MFATimestamp()
		_ = session.Attributes()
		_, _ = session.GetAttribute("key")
		_ = session.ToSubject()
	})
}

// TestServiceClientInterfaces tests that service client interfaces are properly defined.
func TestServiceClientInterfaces(t *testing.T) {
	t.Parallel()
	t.Run("IAMServiceClient_interface", func(t *testing.T) {
		var _ IAMServiceClient = &mockIAMServiceClient{}
	})

	t.Run("PEPServiceClient_interface", func(t *testing.T) {
		var _ PEPServiceClient = &mockPEPServiceClient{}
	})
}
