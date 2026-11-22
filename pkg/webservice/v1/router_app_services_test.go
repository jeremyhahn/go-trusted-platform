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

package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	bmcwebsvc "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type countingCacheServer struct {
	platformv1.UnimplementedCacheServiceServer
	calls int
}

func (s *countingCacheServer) GetConfig(context.Context, *platformv1.GetCacheConfigRequest) (*platformv1.GetCacheConfigResponse, error) {
	s.calls++
	return &platformv1.GetCacheConfigResponse{}, nil
}

type countingSchedulerServer struct {
	platformv1.UnimplementedSchedulerServiceServer
	calls int
}

func (s *countingSchedulerServer) GetJob(context.Context, *platformv1.GetSchedulerJobRequest) (*platformv1.GetSchedulerJobResponse, error) {
	s.calls++
	return &platformv1.GetSchedulerJobResponse{}, nil
}

type countingMessagingServer struct {
	platformv1.UnimplementedMessagingServiceServer
	calls int
}

func (s *countingMessagingServer) GetChannel(context.Context, *platformv1.GetMessagingChannelRequest) (*platformv1.GetMessagingChannelResponse, error) {
	s.calls++
	return &platformv1.GetMessagingChannelResponse{}, nil
}

type countingObjectStorageServer struct {
	platformv1.UnimplementedObjectStorageServiceServer
	calls int
}

func (s *countingObjectStorageServer) HeadObject(context.Context, *platformv1.HeadObjectRequest) (*platformv1.HeadObjectResponse, error) {
	s.calls++
	return &platformv1.HeadObjectResponse{}, nil
}

// appServiceProbes are one route of each application service.
var appServiceProbes = []string{
	"/api/v1/cache/config",
	"/api/v1/scheduler/jobs/7",
	"/api/v1/messaging/channels/orders",
	"/api/v1/object-storage/object/metadata?key=docs:a.txt",
}

func appServiceServing(t *testing.T, registry *testHandlerRegistry, target string) int {
	t.Helper()
	recorder := httptest.NewRecorder()
	newGatedTestRouter(t, registry).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
	return recorder.Code
}

// TestAppServiceRoutes_ReachTheSharedServers sends one request per service
// through the webservice router and requires it to land on the server the
// registry hands out: the one gRPC, QUIC, MCP and the Unix socket share.
func TestAppServiceRoutes_ReachTheSharedServers(t *testing.T) {
	cache := &countingCacheServer{}
	scheduler := &countingSchedulerServer{}
	messaging := &countingMessagingServer{}
	objects := &countingObjectStorageServer{}
	registry := &testHandlerRegistry{
		tokenHandler: &allScopesSessionAuth{sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}},
		appServices:  restapi.AppServiceServers{Cache: cache, Scheduler: scheduler, Messaging: messaging, ObjectStorage: objects},
	}

	for _, target := range appServiceProbes {
		assert.Equal(t, http.StatusOK, appServiceServing(t, registry, target), target)
	}
	assert.Equal(t, 1, cache.calls)
	assert.Equal(t, 1, scheduler.calls)
	assert.Equal(t, 1, messaging.calls)
	assert.Equal(t, 1, objects.calls)
}

func TestAppServiceRoutes_AreGated(t *testing.T) {
	servers := restapi.AppServiceServers{
		Cache:         &countingCacheServer{},
		Scheduler:     &countingSchedulerServer{},
		Messaging:     &countingMessagingServer{},
		ObjectStorage: &countingObjectStorageServer{},
	}
	anonymous := &testHandlerRegistry{tokenHandler: &anonymousAuth{}, appServices: servers}
	user := &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{"user"}, tenantID: "system"},
		appServices:  servers,
	}

	for _, target := range appServiceProbes {
		assert.Equal(t, http.StatusUnauthorized, appServiceServing(t, anonymous, target), target)
		assert.Equal(t, http.StatusForbidden, appServiceServing(t, user, target), target)
	}
}

func TestAppServiceRoutes_NotMountedWithoutServers(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)
	registry := &testHandlerRegistry{tokenHandler: &mockTokenHandler{}, responseWriter: respWriter}
	v1 := NewRouter(logger, nil, nil, nil, registry, respWriter).(*Router)
	root := mux.NewRouter()
	v1.router = root

	v1.appServiceRoutes()

	routes := 0
	require.NoError(t, root.Walk(func(*mux.Route, *mux.Router, []*mux.Route) error {
		routes++
		return nil
	}))
	assert.Zero(t, routes)
}

// grantingScopes is a middleware.ScopeAuthorizer granting only the scopes
// it holds.
type grantingScopes map[string]bool

func (g grantingScopes) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !g[scope] {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func TestScopeRouteGuard(t *testing.T) {
	reached := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) }
	serve := func(guard scopeRouteGuard, scope string) int {
		recorder := httptest.NewRecorder()
		guard.Require(scope, reached)(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		return recorder.Code
	}

	t.Run("checks the route's scope", func(t *testing.T) {
		guard := scopeRouteGuard{authorizer: grantingScopes{"cache:read": true}}
		assert.Equal(t, http.StatusTeapot, serve(guard, "cache:read"))
		assert.Equal(t, http.StatusForbidden, serve(guard, "cache:write"))
	})
	t.Run("without an authorizer the route refuses", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden, serve(scopeRouteGuard{}, "cache:read"))
		assert.Equal(t, http.StatusForbidden, serve(scopeRouteGuard{}, "cache:write"))
	})
}

// allScopesSessionAuth is an admin session whose token middleware is also a
// ScopeAuthorizer granting every scope, so the routes reach their servers.
type allScopesSessionAuth struct {
	sessionAuth
}

func (s *allScopesSessionAuth) RequireScope(string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

// TestAppServiceRoutes_RefusedWithoutAScopeAuthorizer pins #1990: an admin
// session under a token handler that checks no scopes is refused on every
// application service route, and no server is reached.
func TestAppServiceRoutes_RefusedWithoutAScopeAuthorizer(t *testing.T) {
	cache := &countingCacheServer{}
	scheduler := &countingSchedulerServer{}
	messaging := &countingMessagingServer{}
	objects := &countingObjectStorageServer{}
	registry := &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
		appServices:  restapi.AppServiceServers{Cache: cache, Scheduler: scheduler, Messaging: messaging, ObjectStorage: objects},
	}

	for _, target := range appServiceProbes {
		assert.Equal(t, http.StatusForbidden, appServiceServing(t, registry, target), target)
	}
	assert.Zero(t, cache.calls+scheduler.calls+messaging.calls+objects.calls)
}

// TestProxyRoutes_RefusedWithoutAScopeAuthorizer pins that the proxy reads,
// like the other scoped routes, fail closed under the legacy JWT handler: an
// admin session without scopes is refused, one with every scope gets through
// to the (stub) service (#2157 Codex).
func TestProxyRoutes_RefusedWithoutAScopeAuthorizer(t *testing.T) {
	targets := []string{"/api/v1/proxy/routes", "/api/v1/proxy/zone-matrix"}

	roleOnly := &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
	}
	for _, target := range targets {
		assert.Equal(t, http.StatusForbidden, appServiceServing(t, roleOnly, target), target)
	}

	scoped := &testHandlerRegistry{
		tokenHandler: &allScopesSessionAuth{sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}},
	}
	for _, target := range targets {
		assert.NotEqual(t, http.StatusForbidden, appServiceServing(t, scoped, target), target)
	}
}

// countingBMCHandler answers the power reads and writes and counts them;
// every other BMC handler method panics through the nil embedded interface.
type countingBMCHandler struct {
	bmcwebsvc.RestHandler
	statusCalls int
	actionCalls int
}

func (h *countingBMCHandler) PowerStatus(w http.ResponseWriter, _ *http.Request) {
	h.statusCalls++
	w.WriteHeader(http.StatusOK)
}

func (h *countingBMCHandler) PowerAction(w http.ResponseWriter, _ *http.Request) {
	h.actionCalls++
	w.WriteHeader(http.StatusOK)
}

// TestBMCRoutes_ServedOnTheConsole pins that the console serves
// /api/v1/bmc through the daemon's BMC handler behind the admin gate and the
// bmc scopes, and mounts nothing when the daemon has no BMC handler.
func TestBMCRoutes_ServedOnTheConsole(t *testing.T) {
	const target = "/api/v1/bmc/7/power"

	handler := &countingBMCHandler{}
	scoped := &testHandlerRegistry{
		tokenHandler: &allScopesSessionAuth{sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}},
		bmcHandler:   handler,
	}
	assert.Equal(t, http.StatusOK, appServiceServing(t, scoped, target))
	assert.Equal(t, 1, handler.statusCalls)

	roleOnly := &testHandlerRegistry{
		tokenHandler: &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
		bmcHandler:   &countingBMCHandler{},
	}
	assert.Equal(t, http.StatusForbidden, appServiceServing(t, roleOnly, target))

	none := &testHandlerRegistry{
		tokenHandler: &allScopesSessionAuth{sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}},
		withoutBMC:   true,
	}
	assert.Equal(t, http.StatusNotFound, appServiceServing(t, none, target))
}
