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

package pxe

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

// newRouter mounts BOTH halves, the way v1Router.pxeRoutes does, so the
// existing behavioural tests keep exercising every route. Which half
// production hands to the gated router is asserted by the split tests below.
func newRouter() (*PXERouter, *mux.Router) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w, true)
	parent := mux.NewRouter()
	sub := parent.PathPrefix("/api/v1").Subrouter()
	r.RegisterMachineFacingRoutes(sub)
	r.RegisterRoutes(sub)
	return r, parent
}

// registeredPXEPaths returns the "METHOD /path" set one registration method
// installs.
func registeredPXEPaths(register func(*mux.Router)) map[string]bool {
	m := mux.NewRouter()
	register(m.PathPrefix("/api/v1").Subrouter())

	out := map[string]bool{}
	_ = m.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, meth := range methods {
			out[meth+" "+path] = true
		}
		return nil
	})
	return out
}

// TestRegisterMachineFacingRoutes_IsOnlyTheWebhook pins the boundary of what
// #165 could close on this router. The webhook is the ONE PXE route with a
// non-operator caller, and it is outside the operator gate because that
// caller is a booting node with no operator session: it authenticates by its
// device certificate over mTLS instead (#238). Any other route drifting in
// here would be published without the operator gate.
func TestRegisterMachineFacingRoutes_IsOnlyTheWebhook(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w, true)

	assert.Equal(t, map[string]bool{
		"POST /api/v1/pxe/webhook/complete": true,
	}, registeredPXEPaths(r.RegisterMachineFacingRoutes))
}

// TestRegisterMachineFacingRoutes_DisabledRegistersNothing checks the webhook
// is off by default: unless the operator enabled it there is no route for a
// caller to reach.
func TestRegisterMachineFacingRoutes_DisabledRegistersNothing(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w, false)

	assert.Empty(t, registeredPXEPaths(r.RegisterMachineFacingRoutes))
}

// TestRegisterRoutes_CarriesTheOperatorLifecycle asserts the gated half holds
// the routes that decide whether a machine is admitted to the fleet.
func TestRegisterRoutes_CarriesTheOperatorLifecycle(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w, true)

	operator := registeredPXEPaths(r.RegisterRoutes)

	for _, route := range []string{
		"POST /api/v1/pxe/devices/{id}/authorize",
		"POST /api/v1/pxe/devices/{id}/quarantine",
		"POST /api/v1/pxe/devices/{id}/retry",
		"PUT /api/v1/pxe/devices/{id}/state",
		"DELETE /api/v1/pxe/devices/{id}",
		"POST /api/v1/pxe/start",
		"POST /api/v1/pxe/stop",
	} {
		assert.True(t, operator[route], "%s must be on the gated half", route)
	}

	assert.False(t, operator["POST /api/v1/pxe/webhook/complete"],
		"the webhook was registered on the gated half; a booting node cannot hold an operator session")
}

func TestPXERouter_RoutesRegistered(t *testing.T) {
	_, parent := newRouter()
	cases := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/pxe/status"},
		{http.MethodPost, "/api/v1/pxe/start"},
		{http.MethodPost, "/api/v1/pxe/stop"},
		{http.MethodPost, "/api/v1/pxe/webhook/complete"},
		{http.MethodGet, "/api/v1/pxe/devices"},
		{http.MethodPost, "/api/v1/pxe/devices"},
		{http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff"},
		{http.MethodGet, "/api/v1/pxe/devices/d1"},
		{http.MethodDelete, "/api/v1/pxe/devices/d1"},
		{http.MethodPut, "/api/v1/pxe/devices/d1/state"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/enrolled"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/authorize"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/quarantine"},
		{http.MethodPost, "/api/v1/pxe/devices/d1/retry"},
		{http.MethodGet, "/api/v1/pxe/devices/d1/events"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, parent.Match(req, &match))
		})
	}
}

func TestPXERouter_NilServer(t *testing.T) {
	_, parent := newRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/status", nil)
	rec := httptest.NewRecorder()
	parent.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(t, rec.Body.String(), "pxe service is not available")
}

// operatorScopeProbes is every operator route with a concrete path and the
// scope its PXEService RPC takes in the gRPC catalog
// (pkg/api/grpc/method_permissions.go). docs/ipxe/api.md §5 states the same.
var operatorScopeProbes = []struct{ method, path, scope string }{
	{http.MethodGet, "/api/v1/pxe/status", "pxe:read"},
	{http.MethodPost, "/api/v1/pxe/start", "pxe:write"},
	{http.MethodPost, "/api/v1/pxe/stop", "pxe:write"},
	{http.MethodGet, "/api/v1/pxe/devices", "pxe:read"},
	{http.MethodPost, "/api/v1/pxe/devices", "pxe:write"},
	{http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff", "pxe:read"},
	{http.MethodGet, "/api/v1/pxe/devices/d1", "pxe:read"},
	{http.MethodDelete, "/api/v1/pxe/devices/d1", "pxe:delete"},
	{http.MethodPut, "/api/v1/pxe/devices/d1/state", "pxe:write"},
	{http.MethodPost, "/api/v1/pxe/devices/d1/enrolled", "pxe:write"},
	{http.MethodPost, "/api/v1/pxe/devices/d1/authorize", "pxe:write"},
	{http.MethodPost, "/api/v1/pxe/devices/d1/quarantine", "pxe:write"},
	{http.MethodPost, "/api/v1/pxe/devices/d1/retry", "pxe:write"},
	{http.MethodGet, "/api/v1/pxe/devices/d1/events", "pxe:read"},
}

// operatorRoot mounts the operator routes under /api/v1 with no PXE server,
// so a request that passes the scope check answers 503 from the handler.
func operatorRoot(authorizer middleware.ScopeAuthorizer) *mux.Router {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w, false)
	r.SetScopeAuthorizer(authorizer)
	root := mux.NewRouter()
	r.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

func serveProbe(router *mux.Router, method, path string) int {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code
}

// TestOperatorRoutes_TakeTheirRPCScope checks that each operator route
// reaches its handler with its RPC's scope and is refused with any other pxe
// scope, as gRPC refuses the RPC.
func TestOperatorRoutes_TakeTheirRPCScope(t *testing.T) {
	pxeScopes := []string{"pxe:read", "pxe:write", "pxe:delete"}
	for _, probe := range operatorScopeProbes {
		t.Run(probe.method+" "+probe.path, func(t *testing.T) {
			assert.Equal(t, http.StatusServiceUnavailable,
				serveProbe(operatorRoot(scopeGrant{granted: probe.scope}), probe.method, probe.path),
				"%s must reach the handler", probe.scope)
			for _, other := range pxeScopes {
				if other == probe.scope {
					continue
				}
				assert.Equal(t, http.StatusForbidden,
					serveProbe(operatorRoot(scopeGrant{granted: other}), probe.method, probe.path),
					"%s must not reach the handler", other)
			}
		})
	}
}

// TestOperatorRoutes_RoleGateAloneWithoutAScopeAuthorizer pins the legacy
// JWT case: its sessions carry roles and no scopes, so with no authorizer
// every operator route is left on the admin gate the caller mounts.
func TestOperatorRoutes_RoleGateAloneWithoutAScopeAuthorizer(t *testing.T) {
	router := operatorRoot(nil)
	for _, probe := range operatorScopeProbes {
		assert.Equal(t, http.StatusServiceUnavailable, serveProbe(router, probe.method, probe.path),
			"%s %s", probe.method, probe.path)
	}
}

// TestScopedRoutes_EveryRouteHasACatalogScope fails when a PXE or gateway
// route is mounted without a scope from the gRPC catalog: its RPC name does
// not resolve, or the route was registered outside the scoped table.
func TestScopedRoutes_EveryRouteHasACatalogScope(t *testing.T) {
	w := response.NewResponseWriter(logging.NewLogger(slog.LevelError, io.Discard), nil)
	r := NewPXERouter(logging.NewLogger(slog.LevelError, io.Discard), nil, w, false)

	tables := []struct {
		name     string
		base     string
		routes   []scopedRoute
		register func(*mux.Router)
	}{
		{"operator", basePath, r.operatorRoutes(), r.RegisterRoutes},
		{"gateway", gatewayBasePath, r.gatewayRoutes(), r.RegisterGatewayRoutes},
	}
	for _, table := range tables {
		t.Run(table.name, func(t *testing.T) {
			scoped := map[string]bool{}
			for _, route := range table.routes {
				assert.NotEmpty(t, grpcapi.ScopeForMethod(route.rpc),
					"%s %s: %s has no scope in the gRPC catalog", route.method, route.path, route.rpc)
				scoped[route.method+" /api/v1"+table.base+route.path] = true
			}
			assert.Equal(t, scoped, registeredPXEPaths(table.register),
				"a route was mounted outside the scoped table, so it takes no scope")
		})
	}
	assert.Len(t, operatorScopeProbes, len(r.operatorRoutes()), "a scope probe per operator route")
}
