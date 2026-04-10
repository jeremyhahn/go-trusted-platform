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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewIAMRouter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	router := NewIAMRouter(logger, iamClient, pepClient, writer)

	require.NotNil(t, router)
	assert.NotNil(t, router.handlers)
}

func TestRegisterRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	// Test that routes are registered by checking if router can match them
	tests := []struct {
		name   string
		method string
		path   string
	}{
		// Tenant routes
		{"create tenant", http.MethodPost, "/api/v1/iam/tenants"},
		{"list tenants", http.MethodGet, "/api/v1/iam/tenants"},
		{"get tenant", http.MethodGet, "/api/v1/iam/tenants/tenant-1"},
		{"update tenant", http.MethodPut, "/api/v1/iam/tenants/tenant-1"},
		{"delete tenant", http.MethodDelete, "/api/v1/iam/tenants/tenant-1"},

		// User routes
		{"create user", http.MethodPost, "/api/v1/iam/tenants/tenant-1/users"},
		{"list users", http.MethodGet, "/api/v1/iam/tenants/tenant-1/users"},
		{"get user", http.MethodGet, "/api/v1/iam/tenants/tenant-1/users/user-123"},
		{"update user", http.MethodPut, "/api/v1/iam/tenants/tenant-1/users/user-123"},
		{"delete user", http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/user-123"},
		{"assign role", http.MethodPost, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/admin"},
		{"revoke role", http.MethodDelete, "/api/v1/iam/tenants/tenant-1/users/user-123/roles/admin"},

		// Group routes
		{"create group", http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups"},
		{"list groups", http.MethodGet, "/api/v1/iam/tenants/tenant-1/groups"},
		{"get group", http.MethodGet, "/api/v1/iam/tenants/tenant-1/groups/group-1"},
		{"update group", http.MethodPut, "/api/v1/iam/tenants/tenant-1/groups/group-1"},
		{"delete group", http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/group-1"},
		{"add member", http.MethodPost, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/user-123"},
		{"remove member", http.MethodDelete, "/api/v1/iam/tenants/tenant-1/groups/group-1/members/user-123"},

		// Role routes
		{"create role", http.MethodPost, "/api/v1/iam/tenants/tenant-1/roles"},
		{"list roles", http.MethodGet, "/api/v1/iam/tenants/tenant-1/roles"},
		{"get role", http.MethodGet, "/api/v1/iam/tenants/tenant-1/roles/admin"},
		{"update role", http.MethodPut, "/api/v1/iam/tenants/tenant-1/roles/admin"},
		{"delete role", http.MethodDelete, "/api/v1/iam/tenants/tenant-1/roles/admin"},

		// Policy routes
		{"create policy", http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies"},
		{"list policies", http.MethodGet, "/api/v1/iam/tenants/tenant-1/policies"},
		{"get policy", http.MethodGet, "/api/v1/iam/tenants/tenant-1/policies/policy-1"},
		{"update policy", http.MethodPut, "/api/v1/iam/tenants/tenant-1/policies/policy-1"},
		{"delete policy", http.MethodDelete, "/api/v1/iam/tenants/tenant-1/policies/policy-1"},
		{"validate policy", http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/validate"},
		{"test policy", http.MethodPost, "/api/v1/iam/tenants/tenant-1/policies/test"},

		// App routes
		{"register app", http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps"},
		{"list apps", http.MethodGet, "/api/v1/iam/tenants/tenant-1/apps"},
		{"get app", http.MethodGet, "/api/v1/iam/tenants/tenant-1/apps/client-123"},
		{"update app", http.MethodPut, "/api/v1/iam/tenants/tenant-1/apps/client-123"},
		{"delete app", http.MethodDelete, "/api/v1/iam/tenants/tenant-1/apps/client-123"},
		{"rotate secret", http.MethodPost, "/api/v1/iam/tenants/tenant-1/apps/client-123/rotate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "route should match: %s %s", tt.method, tt.path)
		})
	}
}

func TestTenantRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme",
			expectedVars: map[string]string{"tenant": "acme"},
		},
		{
			method:       http.MethodPut,
			path:         "/api/v1/iam/tenants/test-tenant-123",
			expectedVars: map[string]string{"tenant": "test-tenant-123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestUserRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme/users/user-abc-123",
			expectedVars: map[string]string{"tenant": "acme", "id": "user-abc-123"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/iam/tenants/tenant-1/users/user-1/roles/admin",
			expectedVars: map[string]string{"tenant": "tenant-1", "id": "user-1", "role": "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestGroupRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme/groups/engineering",
			expectedVars: map[string]string{"tenant": "acme", "id": "engineering"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/iam/tenants/tenant-1/groups/dev-team/members/user-123",
			expectedVars: map[string]string{"tenant": "tenant-1", "id": "dev-team", "user": "user-123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestRoleRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme/roles/administrator",
			expectedVars: map[string]string{"tenant": "acme", "id": "administrator"},
		},
		{
			method:       http.MethodDelete,
			path:         "/api/v1/iam/tenants/tenant-1/roles/viewer",
			expectedVars: map[string]string{"tenant": "tenant-1", "id": "viewer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestPolicyRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme/policies/admin-policy",
			expectedVars: map[string]string{"tenant": "acme", "id": "admin-policy"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/iam/tenants/tenant-1/policies/validate",
			expectedVars: map[string]string{"tenant": "tenant-1"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/iam/tenants/tenant-1/policies/test",
			expectedVars: map[string]string{"tenant": "tenant-1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestAppRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	tests := []struct {
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme/apps/client-abc-123",
			expectedVars: map[string]string{"tenant": "acme", "id": "client-abc-123"},
		},
		{
			method:       http.MethodPost,
			path:         "/api/v1/iam/tenants/tenant-1/apps/client-xyz/rotate",
			expectedVars: map[string]string{"tenant": "tenant-1", "id": "client-xyz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestRoutes_MethodNotAllowed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	// Test that wrong methods don't match
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"POST on list tenants path with GET", http.MethodPatch, "/api/v1/iam/tenants"},
		{"GET on create tenant path with POST body expected", http.MethodHead, "/api/v1/iam/tenants"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			// PATCH and HEAD should not match any of our defined routes
			assert.False(t, matched || match.MatchErr == mux.ErrMethodMismatch, "unexpected method should not have a matching handler")
		})
	}
}

func TestRoutes_NotFound(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	// Test paths that should not match
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"non-existent resource", http.MethodGet, "/api/v1/iam/nonexistent"},
		{"missing version", http.MethodGet, "/api/iam/tenants"},
		{"wrong version", http.MethodGet, "/api/v2/iam/tenants"},
		{"incomplete path", http.MethodGet, "/api/v1/iam"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.False(t, matched, "non-existent path should not match: %s", tt.path)
		})
	}
}

func TestBasePath_Constant(t *testing.T) {
	assert.Equal(t, "/api/v1/iam", basePath)
}

func TestRoutes_WithSpecialCharactersInIDs(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	tests := []struct {
		name         string
		method       string
		path         string
		expectedVars map[string]string
	}{
		{
			name:         "tenant with hyphens",
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/my-test-tenant",
			expectedVars: map[string]string{"tenant": "my-test-tenant"},
		},
		{
			name:         "tenant with underscores",
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/my_test_tenant",
			expectedVars: map[string]string{"tenant": "my_test_tenant"},
		},
		{
			name:         "user with UUID format",
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme/users/550e8400-e29b-41d4-a716-446655440000",
			expectedVars: map[string]string{"tenant": "acme", "id": "550e8400-e29b-41d4-a716-446655440000"},
		},
		{
			name:         "role with dots",
			method:       http.MethodGet,
			path:         "/api/v1/iam/tenants/acme/roles/admin.full",
			expectedVars: map[string]string{"tenant": "acme", "id": "admin.full"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			require.True(t, matched)

			for key, expectedVal := range tt.expectedVars {
				actualVal, ok := match.Vars[key]
				assert.True(t, ok, "expected var %s to be present", key)
				assert.Equal(t, expectedVal, actualVal)
			}
		})
	}
}

func TestRoutes_SubrouterIsolation(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	// Register IAM routes
	iamRouter.RegisterRoutes(router)

	// Add a different route to ensure IAM routes don't interfere
	router.HandleFunc("/api/v1/other", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)

	// Verify both IAM and other routes work
	iamReq := httptest.NewRequest(http.MethodGet, "/api/v1/iam/tenants", nil)
	var iamMatch mux.RouteMatch
	assert.True(t, router.Match(iamReq, &iamMatch))

	otherReq := httptest.NewRequest(http.MethodGet, "/api/v1/other", nil)
	var otherMatch mux.RouteMatch
	assert.True(t, router.Match(otherReq, &otherMatch))
}

func TestRoutes_HandlerExecution(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)

	// Create a mock that returns data
	iamClient := &mockIAMClient{
		listTenantsFn: func(ctx context.Context, req *iampb.ListTenantsRequest, opts ...grpc.CallOption) (*iampb.ListTenantsResponse, error) {
			return &iampb.ListTenantsResponse{
				Tenants: []*iampb.Tenant{},
				Total:   0,
			}, nil
		},
	}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := NewIAMRouter(logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router)

	// Create a test server
	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/tenants", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// The handler should have been called
	assert.Equal(t, http.StatusOK, writer.lastStatus)
}
