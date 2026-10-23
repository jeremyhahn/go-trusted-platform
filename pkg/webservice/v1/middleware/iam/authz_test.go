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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestNewAuthzMiddleware tests the NewAuthzMiddleware constructor.
func TestNewAuthzMiddleware(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()
	pepService := newMockPEPServiceClient()

	t.Run("creates_middleware_with_valid_config", func(t *testing.T) {
		config := AuthzConfig{
			DefaultDeny: true,
			CacheTTL:    5 * time.Minute,
		}

		middleware, err := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if middleware == nil {
			t.Fatal("expected middleware to be non-nil")
		}
	})

	t.Run("creates_middleware_with_caching_enabled", func(t *testing.T) {
		config := AuthzConfig{
			CacheDecisions: true,
			CacheTTL:       5 * time.Minute,
		}

		middleware, err := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if middleware == nil {
			t.Fatal("expected middleware to be non-nil")
		}
		if middleware.cache == nil {
			t.Fatal("expected cache to be initialized")
		}
	})

	t.Run("returns_error_for_nil_logger", func(t *testing.T) {
		config := AuthzConfig{}
		_, err := NewAuthzMiddleware(nil, httpWriter, config, pepService)

		if err == nil {
			t.Fatal("expected error for nil logger")
		}
		if _, ok := err.(ErrInvalidConfig); !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("returns_error_for_nil_response_writer", func(t *testing.T) {
		config := AuthzConfig{}
		_, err := NewAuthzMiddleware(logger, nil, config, pepService)

		if err == nil {
			t.Fatal("expected error for nil response writer")
		}
	})

	t.Run("returns_error_for_nil_pep_service", func(t *testing.T) {
		config := AuthzConfig{}
		_, err := NewAuthzMiddleware(logger, httpWriter, config, nil)

		if err == nil {
			t.Fatal("expected error for nil PEP service")
		}
	})
}

// TestAuthzMiddleware_Handler tests the Handler method.
func TestAuthzMiddleware_Handler(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()
	pepService := newMockPEPServiceClient()

	t.Run("wraps_handler_correctly", func(t *testing.T) {
		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		handler := middleware.Handler(next)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected next handler to be called")
		}
	})
}

// TestAuthzMiddleware_Authorize tests the Authorize method.
func TestAuthzMiddleware_Authorize(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("allows_authorized_request", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{
				Allowed:       true,
				MatchedPolicy: "allow-all",
				MatchedRule:   "rule-1",
			}, nil
		}

		config := AuthzConfig{DefaultDeny: true}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
			Roles:    []string{"admin"},
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if !called {
			t.Error("expected next handler to be called")
		}
		// The decision must be asked for the session's own principal.
		if len(pepService.checkCalls) != 1 {
			t.Fatalf("expected 1 PDP check, got %d", len(pepService.checkCalls))
		}
		subject := pepService.checkCalls[0].Subject
		if subject.ID != "user-123" || subject.TenantID != "tenant-456" || len(subject.Roles) != 1 || subject.Roles[0] != "admin" {
			t.Errorf("PDP subject = %+v; want user-123 in tenant-456 with role admin", subject)
		}
	})

	t.Run("denies_unauthorized_request", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{
				Allowed:       false,
				MatchedPolicy: "deny-policy",
				MatchedRule:   "deny-rule",
			}, nil
		}

		config := AuthzConfig{DefaultDeny: true}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/123", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if called {
			t.Error("expected next handler not to be called")
		}
		if httpWriter.getError403Count() != 1 {
			t.Error("expected Error403 to be called")
		}
	})

	t.Run("denies_request_without_session", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if called {
			t.Error("expected next handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("requires_mfa_when_configured", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		config := AuthzConfig{RequireMFA: true}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSessionWithMFA(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		}, false, time.Time{})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if called {
			t.Error("expected next handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})

	t.Run("checks_mfa_grace_period", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		config := AuthzConfig{
			RequireMFA:     true,
			MFAGracePeriod: 5 * time.Minute,
		}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		// MFA verified 10 minutes ago (outside grace period)
		session := NewIAMSessionWithMFA(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		}, true, time.Now().Add(-10*time.Minute))

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if called {
			t.Error("expected next handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called for expired MFA")
		}
	})

	t.Run("handles_pep_service_error", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return nil, errors.New("service unavailable")
		}

		config := AuthzConfig{DefaultDeny: true}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if called {
			t.Error("expected next handler not to be called")
		}
		if httpWriter.getError500Count() != 1 {
			t.Error("expected Error500 to be called")
		}
	})
}

// TestAuthzMiddleware_HTTPMethodToAction tests HTTP method to action mapping.
func TestAuthzMiddleware_HTTPMethodToAction(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	tests := []struct {
		method         string
		expectedAction string
	}{
		{http.MethodGet, "read"},
		{http.MethodHead, "read"},
		{http.MethodOptions, "read"},
		{http.MethodPost, "create"},
		{http.MethodPut, "update"},
		{http.MethodPatch, "update"},
		{http.MethodDelete, "delete"},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			pepService := newMockPEPServiceClient()
			var capturedAction string
			pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
				capturedAction = req.Action
				return &sdkiam.CheckResponse{Allowed: true}, nil
			}

			config := AuthzConfig{}
			middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

			session := NewIAMSession(&sdkiam.User{
				ID:       "user-123",
				TenantID: "tenant-456",
			})

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			req := httptest.NewRequest(tt.method, "/api/resource", nil)
			req = req.WithContext(SetSessionInContext(req.Context(), session))
			rec := httptest.NewRecorder()

			middleware.Authorize(rec, req, next)

			if capturedAction != tt.expectedAction {
				t.Errorf("expected action %q for %s, got %q", tt.expectedAction, tt.method, capturedAction)
			}
		})
	}

	t.Run("falls_back_to_lowercase_method_for_unknown", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		var capturedAction string
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			capturedAction = req.Action
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		req := httptest.NewRequest("CUSTOM", "/api/resource", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if capturedAction != "custom" {
			t.Errorf("expected action 'custom' for CUSTOM method, got %q", capturedAction)
		}
	})
}

// TestAuthzMiddleware_ExtractResource tests resource extraction from URL.
func TestAuthzMiddleware_ExtractResource(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	tests := []struct {
		path             string
		expectedResource string
	}{
		{"/api/users", "api/users"},
		{"/api/users/123", "api/users/123"},
		{"/", "/"},
		{"/api/", "api/"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			pepService := newMockPEPServiceClient()
			var capturedResource string
			pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
				capturedResource = req.Resource
				return &sdkiam.CheckResponse{Allowed: true}, nil
			}

			config := AuthzConfig{}
			middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

			session := NewIAMSession(&sdkiam.User{
				ID:       "user-123",
				TenantID: "tenant-456",
			})

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req = req.WithContext(SetSessionInContext(req.Context(), session))
			rec := httptest.NewRecorder()

			middleware.Authorize(rec, req, next)

			if capturedResource != tt.expectedResource {
				t.Errorf("expected resource %q for path %q, got %q", tt.expectedResource, tt.path, capturedResource)
			}
		})
	}
}

// TestAuthzMiddleware_ExtractPolicyContext tests policy context extraction.
func TestAuthzMiddleware_ExtractPolicyContext(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	t.Run("extracts_context_from_header", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		var capturedContext map[string]interface{}
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			capturedContext = req.Context
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		policyContext := map[string]string{"environment": "production", "region": "us-east-1"}
		contextJSON, _ := json.Marshal(policyContext)

		req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req.Header.Set(PolicyContextHeader, string(contextJSON))
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if capturedContext["environment"] != "production" {
			t.Error("expected environment to be 'production'")
		}
		if capturedContext["region"] != "us-east-1" {
			t.Error("expected region to be 'us-east-1'")
		}
	})

	t.Run("includes_request_metadata", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		var capturedContext map[string]interface{}
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			capturedContext = req.Context
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
		req.Host = "api.example.com"
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		middleware.Authorize(rec, req, next)

		if capturedContext["request.method"] != "POST" {
			t.Errorf("expected request.method to be 'POST', got %q", capturedContext["request.method"])
		}
		if capturedContext["request.path"] != "/api/users" {
			t.Errorf("expected request.path to be '/api/users', got %q", capturedContext["request.path"])
		}
		if capturedContext["request.host"] != "api.example.com" {
			t.Errorf("expected request.host to be 'api.example.com', got %q", capturedContext["request.host"])
		}
		if capturedContext["request.time"] == "" {
			t.Error("expected request.time to be set")
		}
	})
}

// TestAuthzMiddleware_Caching tests the authorization decision caching.
func TestAuthzMiddleware_Caching(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	t.Run("caches_authorization_decisions", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		checkCount := 0
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			checkCount++
			return &sdkiam.CheckResponse{
				Allowed:       true,
				MatchedPolicy: "test-policy",
				MatchedRule:   "test-rule",
			}, nil
		}

		config := AuthzConfig{
			CacheDecisions: true,
			CacheTTL:       5 * time.Minute,
		}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		// First request - should call PEP service
		req1 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req1 = req1.WithContext(SetSessionInContext(req1.Context(), session))
		middleware.Authorize(httptest.NewRecorder(), req1, next)

		// Second request - should use cache
		req2 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req2 = req2.WithContext(SetSessionInContext(req2.Context(), session))
		middleware.Authorize(httptest.NewRecorder(), req2, next)

		if checkCount != 1 {
			t.Errorf("expected PEP service to be called once, got %d", checkCount)
		}
	})

	t.Run("clears_cache", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		checkCount := 0
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			checkCount++
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{
			CacheDecisions: true,
			CacheTTL:       5 * time.Minute,
		}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		// First request
		req1 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req1 = req1.WithContext(SetSessionInContext(req1.Context(), session))
		middleware.Authorize(httptest.NewRecorder(), req1, next)

		// Clear cache
		middleware.ClearCache()

		// Second request - should call PEP service again
		req2 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req2 = req2.WithContext(SetSessionInContext(req2.Context(), session))
		middleware.Authorize(httptest.NewRecorder(), req2, next)

		if checkCount != 2 {
			t.Errorf("expected PEP service to be called twice after cache clear, got %d", checkCount)
		}
	})

	t.Run("clears_user_cache", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		checkCount := 0
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			checkCount++
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{
			CacheDecisions: true,
			CacheTTL:       5 * time.Minute,
		}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

		// First request
		req1 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req1 = req1.WithContext(SetSessionInContext(req1.Context(), session))
		middleware.Authorize(httptest.NewRecorder(), req1, next)

		// Clear user cache
		middleware.ClearUserCache("tenant-456", "user-123")

		// Second request - should call PEP service again
		req2 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
		req2 = req2.WithContext(SetSessionInContext(req2.Context(), session))
		middleware.Authorize(httptest.NewRecorder(), req2, next)

		if checkCount != 2 {
			t.Errorf("expected PEP service to be called twice after user cache clear, got %d", checkCount)
		}
	})

	t.Run("clear_cache_noop_when_caching_disabled", func(t *testing.T) {
		pepService := newMockPEPServiceClient()

		config := AuthzConfig{
			CacheDecisions: false,
		}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		// These should not panic
		middleware.ClearCache()
		middleware.ClearUserCache("tenant", "user")
	})
}

// TestAuthzMiddleware_CheckResource tests the CheckResource method.
func TestAuthzMiddleware_CheckResource(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	t.Run("returns_allowed_for_authorized_resource", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		allowed, err := middleware.CheckResource(context.Background(), session, "read", "/api/users")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !allowed {
			t.Error("expected allowed to be true")
		}
	})

	t.Run("returns_not_allowed_for_unauthorized_resource", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{Allowed: false}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		allowed, err := middleware.CheckResource(context.Background(), session, "delete", "/api/users/123")

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Error("expected allowed to be false")
		}
	})
}

// TestAuthzMiddleware_CheckBatch tests the CheckBatch method.
func TestAuthzMiddleware_CheckBatch(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	t.Run("returns_results_for_batch_check", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		pepService.checkBatchFunc = func(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
			return &sdkiam.CheckBatchResponse{
				Results: []sdkiam.CheckResponse{{Allowed: true}, {Allowed: false}, {Allowed: true}},
			}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		resources := []string{"/api/users/1", "/api/users/2", "/api/users/3"}
		results, err := middleware.CheckBatch(context.Background(), session, "read", resources)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(results) != 3 {
			t.Errorf("expected 3 results, got %d", len(results))
		}
		if !results["/api/users/1"] {
			t.Error("expected /api/users/1 to be allowed")
		}
		if results["/api/users/2"] {
			t.Error("expected /api/users/2 to be denied")
		}
		if !results["/api/users/3"] {
			t.Error("expected /api/users/3 to be allowed")
		}
		// Results are mapped back by index, so request i must carry resource i.
		if len(pepService.checkBatchCalls) != 1 {
			t.Fatalf("expected 1 batch call, got %d", len(pepService.checkBatchCalls))
		}
		requests := pepService.checkBatchCalls[0].Requests
		if len(requests) != len(resources) {
			t.Fatalf("expected %d batch requests, got %d", len(resources), len(requests))
		}
		for i, r := range requests {
			if r.Resource != resources[i] || r.Action != "read" || r.Subject.ID != "user-123" || r.Subject.TenantID != "tenant-456" {
				t.Errorf("request %d = %+v; want read %s by user-123 in tenant-456", i, r, resources[i])
			}
		}
	})

	t.Run("handles_pep_service_error", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		pepService.checkBatchFunc = func(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
			return nil, errors.New("service unavailable")
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		resources := []string{"/api/users/1", "/api/users/2"}
		_, err := middleware.CheckBatch(context.Background(), session, "read", resources)

		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("uses_default_decision_when_results_incomplete", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		pepService.checkBatchFunc = func(ctx context.Context, req *sdkiam.CheckBatchRequest) (*sdkiam.CheckBatchResponse, error) {
			// Return fewer results than requested
			return &sdkiam.CheckBatchResponse{
				Results: []sdkiam.CheckResponse{{Allowed: true}},
			}, nil
		}

		config := AuthzConfig{DefaultDeny: true}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{
			ID:       "user-123",
			TenantID: "tenant-456",
		})

		resources := []string{"/api/users/1", "/api/users/2"}
		results, err := middleware.CheckBatch(context.Background(), session, "read", resources)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if results["/api/users/1"] != true {
			t.Error("expected /api/users/1 to use returned result")
		}
		if results["/api/users/2"] != false {
			t.Error("expected /api/users/2 to use default deny")
		}
	})
}

// TestResourceAuthorizer tests the ResourceAuthorizer helper.
func TestResourceAuthorizer(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	t.Run("CanRead_checks_read_action", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		var capturedAction, capturedResource string
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			capturedAction = req.Action
			capturedResource = req.Resource
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		authorizer := middleware.NewResourceAuthorizer("/api/users")
		session := NewIAMSession(&sdkiam.User{ID: "user-123", TenantID: "tenant-456"})

		_, _ = authorizer.CanRead(context.Background(), session, "123")

		if capturedAction != "read" {
			t.Errorf("expected action 'read', got %q", capturedAction)
		}
		if capturedResource != "/api/users/123" {
			t.Errorf("expected resource '/api/users/123', got %q", capturedResource)
		}
	})

	t.Run("CanCreate_checks_create_action", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		var capturedAction, capturedResource string
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			capturedAction = req.Action
			capturedResource = req.Resource
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		authorizer := middleware.NewResourceAuthorizer("/api/users")
		session := NewIAMSession(&sdkiam.User{ID: "user-123", TenantID: "tenant-456"})

		_, _ = authorizer.CanCreate(context.Background(), session)

		if capturedAction != "create" {
			t.Errorf("expected action 'create', got %q", capturedAction)
		}
		if capturedResource != "/api/users" {
			t.Errorf("expected resource '/api/users', got %q", capturedResource)
		}
	})

	t.Run("CanUpdate_checks_update_action", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		var capturedAction, capturedResource string
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			capturedAction = req.Action
			capturedResource = req.Resource
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		authorizer := middleware.NewResourceAuthorizer("/api/users")
		session := NewIAMSession(&sdkiam.User{ID: "user-123", TenantID: "tenant-456"})

		_, _ = authorizer.CanUpdate(context.Background(), session, "456")

		if capturedAction != "update" {
			t.Errorf("expected action 'update', got %q", capturedAction)
		}
		if capturedResource != "/api/users/456" {
			t.Errorf("expected resource '/api/users/456', got %q", capturedResource)
		}
	})

	t.Run("CanDelete_checks_delete_action", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		var capturedAction, capturedResource string
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			capturedAction = req.Action
			capturedResource = req.Resource
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		authorizer := middleware.NewResourceAuthorizer("/api/users")
		session := NewIAMSession(&sdkiam.User{ID: "user-123", TenantID: "tenant-456"})

		_, _ = authorizer.CanDelete(context.Background(), session, "789")

		if capturedAction != "delete" {
			t.Errorf("expected action 'delete', got %q", capturedAction)
		}
		if capturedResource != "/api/users/789" {
			t.Errorf("expected resource '/api/users/789', got %q", capturedResource)
		}
	})
}

// TestAuthzMiddleware_AuthorizeHandler tests the AuthorizeHandler middleware factory.
func TestAuthzMiddleware_AuthorizeHandler(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("allows_authorized_request", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{Allowed: true}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{ID: "user-123", TenantID: "tenant-456"})

		called := false
		handler := middleware.AuthorizeHandler("read", "/api/users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("expected handler to be called")
		}
	})

	t.Run("denies_unauthorized_request", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()
		pepService.checkFunc = func(ctx context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
			return &sdkiam.CheckResponse{Allowed: false}, nil
		}

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		session := NewIAMSession(&sdkiam.User{ID: "user-123", TenantID: "tenant-456"})

		called := false
		handler := middleware.AuthorizeHandler("delete", "/api/admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodDelete, "/api/admin", nil)
		req = req.WithContext(SetSessionInContext(req.Context(), session))
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError403Count() != 1 {
			t.Error("expected Error403 to be called")
		}
	})

	t.Run("returns_401_without_session", func(t *testing.T) {
		httpWriter := newMockHttpWriter()
		pepService := newMockPEPServiceClient()

		config := AuthzConfig{}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		called := false
		handler := middleware.AuthorizeHandler("read", "/api/users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if called {
			t.Error("expected handler not to be called")
		}
		if httpWriter.getError401Count() != 1 {
			t.Error("expected Error401 to be called")
		}
	})
}

// TestAuthzMiddleware_DefaultDecision tests default authorization decisions.
func TestAuthzMiddleware_DefaultDecision(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	httpWriter := newMockHttpWriter()

	t.Run("default_deny_true_denies_when_no_policy", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		config := AuthzConfig{DefaultDeny: true}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		// Session with nil user to trigger default decision
		session := &iamSession{user: nil}

		allowed, _, _, _ := middleware.checkAuthorization(context.Background(), session, "read", "/test", nil)

		if allowed {
			t.Error("expected default deny to deny access")
		}
	})

	t.Run("default_deny_false_allows_when_no_policy", func(t *testing.T) {
		pepService := newMockPEPServiceClient()
		config := AuthzConfig{DefaultDeny: false}
		middleware, _ := NewAuthzMiddleware(logger, httpWriter, config, pepService)

		// Session with nil user to trigger default decision
		session := &iamSession{user: nil}

		allowed, _, _, _ := middleware.checkAuthorization(context.Background(), session, "read", "/test", nil)

		if !allowed {
			t.Error("expected default allow to allow access")
		}
	})
}
