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
	"strings"
	"testing"

	"github.com/gorilla/mux"
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewIAMRouter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	router := newTestRouter(t, logger, iamClient, pepClient, writer)

	require.NotNil(t, router)
	assert.NotNil(t, router.handlers)
}

func TestRegisterRoutes(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

// quicbaas keeps no groups (a role binding is the grouping it offers), so the
// group routes must stay gone rather than answer with a dead handler.
func TestGroupRoutes_NotRegistered(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	paths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/iam/tenants/acme/groups"},
		{http.MethodGet, "/api/v1/iam/tenants/acme/groups/engineering"},
		{http.MethodPost, "/api/v1/iam/tenants/acme/groups/dev-team/members/user-123"},
		{http.MethodGet, "/api/v1/iam/groups"},
		{http.MethodPost, "/api/v1/iam/groups/dev-team/members/user-123"},
	}

	for _, tt := range paths {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			assert.False(t, router.Match(req, &match), "group route %s must not be registered", tt.path)
		})
	}
}

func TestRoleRoutes_Registration(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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
	assert.Equal(t, "/iam", basePath)
}

func TestRoutes_WithSpecialCharactersInIDs(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	iamClient := &mockIAMClient{}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	// Register IAM routes
	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

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
		listTenantsFn: func(ctx context.Context, limit, offset int32) (*ListTenantsResponse, error) {
			return &ListTenantsResponse{
				Tenants: []TenantResponse{},
			}, nil
		},
	}
	pepClient := &mockPEPClient{}
	writer := &mockHttpWriter{}

	iamRouter := newTestRouter(t, logger, iamClient, pepClient, writer)
	router := mux.NewRouter()

	iamRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

	// Create a test server
	req := httptest.NewRequest(http.MethodGet, "/api/v1/iam/tenants", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// The handler should have been called
	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

// passthroughAuthorization builds an Authorization whose guards record
// that they ran and then admit the request. Routing tests use it so a
// route-table assertion measures routing, not authorization; the gating
// itself is asserted by TestRegisterRoutes_* below with real guards.
func passthroughAuthorization(calls *[]string) Authorization {
	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				*calls = append(*calls, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	return Authorization{
		Authenticate:        mark("authenticate"),
		RequireAdmin:        mark("admin"),
		RequireSystemTenant: mark("system-tenant"),
		RequireOwnTenant:    mark("own-tenant"),
	}
}

// newTestRouter builds an IAMRouter with pass-through guards.
func newTestRouter(
	t *testing.T,
	logger *logging.Logger,
	iamClient IAMClient,
	pepClient PEPClient,
	writer response.HttpWriter,
) *IAMRouter {

	t.Helper()
	calls := []string{}
	router, err := NewIAMRouter(logger, iamClient, pepClient, writer,
		passthroughAuthorization(&calls))
	require.NoError(t, err)
	return router
}

func TestNewIAMRouter_RequiresEveryGuard(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	writer := &mockHttpWriter{}
	calls := []string{}
	complete := passthroughAuthorization(&calls)

	tests := []struct {
		name  string
		authz Authorization
		guard string
	}{
		{"no authenticator", Authorization{
			RequireAdmin:        complete.RequireAdmin,
			RequireSystemTenant: complete.RequireSystemTenant,
			RequireOwnTenant:    complete.RequireOwnTenant,
		}, "Authenticate"},
		{"no admin guard", Authorization{
			Authenticate:        complete.Authenticate,
			RequireSystemTenant: complete.RequireSystemTenant,
			RequireOwnTenant:    complete.RequireOwnTenant,
		}, "RequireAdmin"},
		{"no system tenant guard", Authorization{
			Authenticate:     complete.Authenticate,
			RequireAdmin:     complete.RequireAdmin,
			RequireOwnTenant: complete.RequireOwnTenant,
		}, "RequireSystemTenant"},
		{"no own-tenant guard", Authorization{
			Authenticate:        complete.Authenticate,
			RequireAdmin:        complete.RequireAdmin,
			RequireSystemTenant: complete.RequireSystemTenant,
		}, "RequireOwnTenant"},
		{"nothing at all", Authorization{}, "Authenticate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewIAMRouter(logger, &mockIAMClient{}, &mockPEPClient{}, writer, tt.authz)
			assert.Nil(t, router)
			require.Error(t, err)
			var missing ErrAuthorizationRequired
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, tt.guard, missing.Guard)
		})
	}
}

// TestRegisterRoutes_GuardsEveryRoute proves the gate is mounted on the
// whole subtree — the regression this issue exists to prevent is a route
// that quietly bypasses it.
func TestRegisterRoutes_GuardsEveryRoute(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	calls := []string{}
	iamRouter, err := NewIAMRouter(logger, &mockIAMClient{}, &mockPEPClient{},
		&mockHttpWriter{}, passthroughAuthorization(&calls))
	require.NoError(t, err)

	root := mux.NewRouter()
	iamRouter.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	tests := []struct {
		name         string
		method       string
		path         string
		systemTenant bool
	}{
		{"list users", http.MethodGet, "/api/v1/iam/users", false},
		{"create user", http.MethodPost, "/api/v1/iam/users", false},
		{"list roles", http.MethodGet, "/api/v1/iam/roles", false},
		{"list policies", http.MethodGet, "/api/v1/iam/policies", false},
		{"list apps", http.MethodGet, "/api/v1/iam/apps", false},
		{"tenant-scoped users", http.MethodGet, "/api/v1/iam/tenants/t1/users", false},
		{"tenant-scoped roles", http.MethodGet, "/api/v1/iam/tenants/t1/roles", false},
		{"list tenants", http.MethodGet, "/api/v1/iam/tenants", true},
		{"create tenant", http.MethodPost, "/api/v1/iam/tenants", true},
		{"get tenant", http.MethodGet, "/api/v1/iam/tenants/t1", true},
		{"delete tenant", http.MethodDelete, "/api/v1/iam/tenants/t1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = nil
			req := httptest.NewRequest(tt.method, tt.path, nil)
			root.ServeHTTP(httptest.NewRecorder(), req)

			assert.Contains(t, calls, "authenticate",
				"every IAM route must authenticate first")
			assert.Contains(t, calls, "admin",
				"every IAM route must require the admin role")
			if tt.systemTenant {
				assert.Contains(t, calls, "system-tenant",
					"tenant lifecycle is system-tenant only")
			} else {
				assert.NotContains(t, calls, "system-tenant",
					"tenant-scoped collections must not demand the system tenant")
			}
		})
	}
}

// TestRegisterRoutes_RealGuardsDenyEndToEnd wires the ACTUAL SessionGuard
// and response writer, not pass-throughs, so this measures what a caller
// on the wire gets. It is the regression test for #159: before it, every
// route below answered 200 with no credential at all.
func TestRegisterRoutes_RealGuardsDenyEndToEnd(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	writer := response.NewResponseWriter(logger, nil)
	guard, err := iammw.NewSessionGuard(logger, writer)
	require.NoError(t, err)

	const systemTenant = "system"

	// The authenticator publishes whatever session the test injected via
	// the request context, standing in for a verified token.
	authenticate := func(next http.Handler) http.Handler { return next }

	iamRouter, err := NewIAMRouter(logger, &mockIAMClient{}, &mockPEPClient{}, writer,
		Authorization{
			Authenticate:        authenticate,
			RequireAdmin:        guard.RequireRoles("admin"),
			RequireSystemTenant: guard.RequireTenant(systemTenant),
			RequireOwnTenant: guard.RequireOwnTenant(func(r *http.Request) string {
				return mux.Vars(r)["tenant"]
			}),
		})
	require.NoError(t, err)

	root := mux.NewRouter()
	iamRouter.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	systemAdmin := iammw.NewIAMSession(&iamsdk.User{
		ID: "u1", TenantID: systemTenant, Roles: []string{"admin"}})
	tenantAdmin := iammw.NewIAMSession(&iamsdk.User{
		ID: "u2", TenantID: "acme", Roles: []string{"admin"}})
	ordinaryUser := iammw.NewIAMSession(&iamsdk.User{
		ID: "u3", TenantID: "acme", Roles: []string{"user"}})

	tests := []struct {
		name    string
		method  string
		path    string
		session iammw.IAMSession
		denied  int // 0 means the request must reach the handler
	}{
		{"anonymous cannot list users", http.MethodGet, "/api/v1/iam/users", nil, http.StatusUnauthorized},
		{"anonymous cannot create a user", http.MethodPost, "/api/v1/iam/users", nil, http.StatusUnauthorized},
		{"anonymous cannot list roles", http.MethodGet, "/api/v1/iam/roles", nil, http.StatusUnauthorized},
		{"anonymous cannot list policies", http.MethodGet, "/api/v1/iam/policies", nil, http.StatusUnauthorized},
		{"anonymous cannot list apps", http.MethodGet, "/api/v1/iam/apps", nil, http.StatusUnauthorized},
		{"anonymous cannot list tenants", http.MethodGet, "/api/v1/iam/tenants", nil, http.StatusUnauthorized},
		{"anonymous cannot create a tenant", http.MethodPost, "/api/v1/iam/tenants", nil, http.StatusUnauthorized},
		{"anonymous cannot delete a tenant", http.MethodDelete, "/api/v1/iam/tenants/t1", nil, http.StatusUnauthorized},

		{"an ordinary user cannot list users", http.MethodGet, "/api/v1/iam/users", ordinaryUser, http.StatusForbidden},
		{"an ordinary user cannot list roles", http.MethodGet, "/api/v1/iam/roles", ordinaryUser, http.StatusForbidden},

		{"a tenant admin cannot list tenants", http.MethodGet, "/api/v1/iam/tenants", tenantAdmin, http.StatusForbidden},
		{"a tenant admin cannot create a tenant", http.MethodPost, "/api/v1/iam/tenants", tenantAdmin, http.StatusForbidden},
		{"a tenant admin cannot read a tenant record", http.MethodGet, "/api/v1/iam/tenants/t1", tenantAdmin, http.StatusForbidden},
		{"a tenant admin cannot delete a tenant", http.MethodDelete, "/api/v1/iam/tenants/t1", tenantAdmin, http.StatusForbidden},

		{"a tenant admin cannot read another tenant's users", http.MethodGet, "/api/v1/iam/tenants/other/users", tenantAdmin, http.StatusForbidden},
		{"a tenant admin cannot create a user in another tenant", http.MethodPost, "/api/v1/iam/tenants/other/users", tenantAdmin, http.StatusForbidden},
		{"a tenant admin cannot read another tenant's policies", http.MethodGet, "/api/v1/iam/tenants/other/policies", tenantAdmin, http.StatusForbidden},
		{"a tenant admin cannot rotate another tenant's app secret", http.MethodPost, "/api/v1/iam/tenants/other/apps/a1/rotate", tenantAdmin, http.StatusForbidden},
		{"a tenant admin cannot grant a role in another tenant", http.MethodPost, "/api/v1/iam/tenants/other/users/u9/roles/admin", tenantAdmin, http.StatusForbidden},
		{"the system admin cannot reach tenant data either", http.MethodGet, "/api/v1/iam/tenants/acme/users", systemAdmin, http.StatusForbidden},

		{"a tenant admin still reaches its own users", http.MethodGet, "/api/v1/iam/users", tenantAdmin, 0},
		{"a tenant admin still reaches its own tenant-scoped users", http.MethodGet, "/api/v1/iam/tenants/acme/users", tenantAdmin, 0},
		{"a tenant admin still reaches its own tenant-scoped roles", http.MethodGet, "/api/v1/iam/tenants/acme/roles", tenantAdmin, 0},
		{"the system admin reaches tenant lifecycle", http.MethodGet, "/api/v1/iam/tenants", systemAdmin, 0},
		{"the system admin reaches another tenant's record", http.MethodDelete, "/api/v1/iam/tenants/acme", systemAdmin, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.session != nil {
				req = req.WithContext(iammw.SetSessionInContext(req.Context(), tt.session))
			}
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)

			if tt.denied == 0 {
				assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
				assert.NotEqual(t, http.StatusForbidden, rec.Code)
				return
			}
			assert.Equal(t, tt.denied, rec.Code)
		})
	}
}

// TestRegisterRoutes_EveryTenantScopedRouteIsGuarded walks the registered
// route table rather than a hand-written list, so a route added later
// cannot quietly skip the guard its neighbours carry.
//
// The rule it enforces: a route whose path names a {tenant} must be
// guarded, either by RequireOwnTenant (the tenant's own data plane) or by
// RequireSystemTenant (the tenant records themselves, which the control
// plane drives across tenants).
func TestRegisterRoutes_EveryTenantScopedRouteIsGuarded(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, os.Stdout)
	calls := []string{}
	iamRouter, err := NewIAMRouter(logger, &mockIAMClient{}, &mockPEPClient{},
		&mockHttpWriter{}, passthroughAuthorization(&calls))
	require.NoError(t, err)

	root := mux.NewRouter()
	iamRouter.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	type route struct {
		template string
		methods  []string
	}
	var routes []route
	require.NoError(t, root.Walk(func(r *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := r.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := r.GetMethods()
		if err != nil {
			return nil
		}
		routes = append(routes, route{template: template, methods: methods})
		return nil
	}))
	require.NotEmpty(t, routes, "the route table must not be empty")

	tenantScopedSeen, recordSeen, flatSeen := 0, 0, 0
	for _, rt := range routes {
		if !strings.Contains(rt.template, "{tenant}") {
			// A flat route names its tenant in the tenant_id query, so it
			// needs the own-tenant guard too (#401). The tenant-record
			// collection (/tenants) is system-tenant only instead.
			if !strings.HasPrefix(rt.template, "/api/v1/iam/") ||
				strings.HasPrefix(rt.template, "/api/v1/iam/tenants") {
				continue
			}
			path := strings.NewReplacer(
				"{id}", "x", "{role}", "r", "{user}", "u",
			).Replace(rt.template)
			for _, method := range rt.methods {
				calls = nil
				root.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
				flatSeen++
				assert.Contains(t, calls, "own-tenant",
					"%s %s accepts a tenant_id query and must be tenant-scoped",
					method, rt.template)
			}
			continue
		}
		// Substitute a concrete tenant so the route actually matches.
		path := strings.NewReplacer(
			"{tenant}", "acme", "{id}", "x", "{role}", "r", "{user}", "u",
		).Replace(rt.template)

		for _, method := range rt.methods {
			calls = nil
			root.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))

			isRecord := strings.HasSuffix(rt.template, "/tenants/{tenant}")
			if isRecord {
				recordSeen++
				assert.Contains(t, calls, "system-tenant",
					"%s %s names a tenant record and must be system-tenant only",
					method, rt.template)
				continue
			}
			tenantScopedSeen++
			assert.Contains(t, calls, "own-tenant",
				"%s %s takes its tenant from the URL and must be tenant-scoped",
				method, rt.template)
		}
	}
	// Guard the guard: if the substitution or the walk stops matching, the
	// loop above would silently assert nothing.
	assert.GreaterOrEqual(t, tenantScopedSeen, 20,
		"expected the tenant-scoped collections to be walked")
	assert.Equal(t, 3, recordSeen, "expected the three tenant-record routes")
	assert.GreaterOrEqual(t, flatSeen, 25, "expected the flat collections to be walked")
}
