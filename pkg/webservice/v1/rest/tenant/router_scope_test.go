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

package tenant

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// scopeGrant is a ScopeAuthorizer that grants exactly one scope, so a test
// can show which scope a route takes.
type scopeGrant struct {
	granted string
}

func (a scopeGrant) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope != a.granted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// tenantScopeProbes is one request per route RegisterRoutes mounts, with the
// scope the equivalent TenantService RPC takes on gRPC.
var tenantScopeProbes = []struct{ method, path, scope string }{
	{http.MethodGet, "/api/v1/tenants", "tenant:read"},
	{http.MethodPost, "/api/v1/tenants", "tenant:write"},
	{http.MethodPost, "/api/v1/tenants/sync", "tenant:write"},
	{http.MethodGet, "/api/v1/tenants/by-name/acme", "tenant:read"},
	{http.MethodGet, "/api/v1/tenants/system", "tenant:read"},
	{http.MethodPut, "/api/v1/tenants/system", "tenant:write"},
	{http.MethodDelete, "/api/v1/tenants/system", "tenant:delete"},
	{http.MethodPost, "/api/v1/tenants/system/suspend", "tenant:write"},
	{http.MethodPost, "/api/v1/tenants/system/resume", "tenant:write"},
	{http.MethodGet, "/api/v1/tenants/system/quotas", "tenant:read"},
	{http.MethodPut, "/api/v1/tenants/system/quotas", "tenant:write"},
	{http.MethodGet, "/api/v1/tenants/system/usage", "tenant:read"},
	{http.MethodPost, "/api/v1/tenants/system/quota-check", "tenant:read"},
	{http.MethodPost, "/api/v1/tenants/system/dek/rotate", "tenant:write"},
	{http.MethodGet, "/api/v1/tenants/system/dek", "tenant:read"},
	{http.MethodPost, "/api/v1/tenants/system/barrier/init", "tenant:write"},
	{http.MethodPost, "/api/v1/tenants/system/barrier/unseal", "tenant:write"},
	{http.MethodPost, "/api/v1/tenants/system/barrier/seal", "tenant:write"},
	{http.MethodGet, "/api/v1/tenants/system/barrier", "tenant:read"},
}

// scopedRoot builds the tenant router as newRouter does, with a nil server
// (every admitted request answers 503) and the given scope authorizer.
func scopedRoot(authorizer middleware.ScopeAuthorizer) *mux.Router {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r, err := NewTenantRouter(
		logging.NewLogger(slog.LevelError, io.Discard), nil, w, passthroughAuthorization())
	if err != nil {
		panic(err)
	}
	r.SetScopeAuthorizer(authorizer)
	root := mux.NewRouter()
	r.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

func serveScopeProbe(router *mux.Router, method, path string) int {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

// TestTenantRoutes_TakeTheirRPCScope is the Codex P1 on PR #2372: the admin
// role and the tenant binding are not enough; each REST route takes the scope
// its gRPC RPC takes, so a tenant:read admin cannot seal a barrier.
func TestTenantRoutes_TakeTheirRPCScope(t *testing.T) {
	tenantScopes := []string{"tenant:read", "tenant:write", "tenant:delete"}
	for _, probe := range tenantScopeProbes {
		t.Run(probe.method+" "+probe.path, func(t *testing.T) {
			assert.Equal(t, http.StatusServiceUnavailable,
				serveScopeProbe(scopedRoot(scopeGrant{granted: probe.scope}), probe.method, probe.path),
				"%s must reach the handler", probe.scope)
			for _, other := range tenantScopes {
				if other == probe.scope {
					continue
				}
				assert.Equal(t, http.StatusForbidden,
					serveScopeProbe(scopedRoot(scopeGrant{granted: other}), probe.method, probe.path),
					"%s must not reach the handler", other)
			}
		})
	}
}

// TestTenantRoutes_RoleGateAloneWithoutAScopeAuthorizer: under the legacy JWT
// handler, which carries roles and no scopes, the role gate alone applies.
func TestTenantRoutes_RoleGateAloneWithoutAScopeAuthorizer(t *testing.T) {
	router := scopedRoot(nil)
	for _, probe := range tenantScopeProbes {
		assert.Equal(t, http.StatusServiceUnavailable, serveScopeProbe(router, probe.method, probe.path),
			"%s %s", probe.method, probe.path)
	}
}

// TestTenantRoutes_EveryRouteHasACatalogScope: a route whose RPC has no
// catalog scope would fail closed; every row names a real one.
func TestTenantRoutes_EveryRouteHasACatalogScope(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r, err := NewTenantRouter(
		logging.NewLogger(slog.LevelError, io.Discard), nil, w, passthroughAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	routes := r.routeTable()
	for _, route := range routes {
		assert.NotEmpty(t, grpcapi.ScopeForMethod(tenantServicePrefix+route.rpc),
			"%s %s: %s has no scope in the gRPC catalog", route.method, route.path, route.rpc)
	}
	assert.Len(t, tenantScopeProbes, len(routes), "a scope probe per tenant route")
	assert.Len(t, routes, 19)
}
