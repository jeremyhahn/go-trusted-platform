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

package rest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// operatorToken is granted every scope by operatorGuard, the way the daemon
// admits its operator.
const operatorToken = "operator-token"

// operatorGuard admits operatorToken with every scope.
func operatorGuard() *ScopeGuard {
	return NewScopeGuard(&scopedAuthorizer{scopes: map[string][]string{operatorToken: {"*:*"}}}, nil, nil)
}

// operatorRequest builds a request carrying operatorToken.
func operatorRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	return req
}

// TestScopeGuardRequireCaller: the handler receives the caller the guard
// authenticated, and runs only when it holds the scope.
func TestScopeGuardRequireCaller(t *testing.T) {
	var got *platformtoken.AuthorizedContext
	handler := func(w http.ResponseWriter, _ *http.Request, caller *platformtoken.AuthorizedContext) {
		got = caller
		w.WriteHeader(http.StatusNoContent)
	}

	t.Run("passes the authenticated caller", func(t *testing.T) {
		got = nil
		rr := httptest.NewRecorder()
		operatorGuard().RequireCaller("tenant:read", handler)(rr, operatorRequest(http.MethodGet, "/x", nil))
		assert.Equal(t, http.StatusNoContent, rr.Code)
		require.NotNil(t, got)
		assert.Equal(t, operatorToken, got.Subject)
	})

	t.Run("an unauthenticated caller is 401 and never reaches the handler", func(t *testing.T) {
		got = nil
		rr := httptest.NewRecorder()
		operatorGuard().RequireCaller("tenant:read", handler)(rr, httptest.NewRequest(http.MethodGet, "/x", nil))
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.Nil(t, got)
	})

	t.Run("a caller without the scope is 403", func(t *testing.T) {
		got = nil
		guard := NewScopeGuard(&scopedAuthorizer{scopes: map[string][]string{operatorToken: {"tenant:read"}}}, nil, nil)
		rr := httptest.NewRecorder()
		guard.RequireCaller("tenant:write", handler)(rr, operatorRequest(http.MethodPost, "/x", nil))
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Nil(t, got)
	})

	t.Run("a nil guard is 403", func(t *testing.T) {
		got = nil
		var guard *ScopeGuard
		rr := httptest.NewRecorder()
		guard.RequireCaller("tenant:read", handler)(rr, operatorRequest(http.MethodGet, "/x", nil))
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.Nil(t, got)
	})
}

// grantingPeers admits any verified chain with scopes, or fails with err.
type grantingPeers struct {
	scopes []string
	err    error
}

func (p grantingPeers) AuthenticatePeer(_ context.Context, chain []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &platformtoken.AuthorizedContext{Subject: chain[0].Subject.CommonName, Scopes: p.scopes}, nil
}

// guardedRoute is one daemon REST route and the scope it requires.
type guardedRoute struct {
	method string
	path   string
	scope  string
}

// vpnRouteScopes is the VPN route table of docs/vpn/api.md §1.
var vpnRouteScopes = []guardedRoute{
	{http.MethodPost, "/api/v1/vpn/peers", "vpn:write"},
	{http.MethodGet, "/api/v1/vpn/peers", "vpn:read"},
	{http.MethodDelete, "/api/v1/vpn/peers/laptop-1", "vpn:write"},
	{http.MethodGet, "/api/v1/vpn/status", "vpn:read"},
	{http.MethodGet, "/api/v1/vpn/posture-policies", "vpn:admin"},
	{http.MethodGet, "/api/v1/vpn/posture-policies/corp", "vpn:admin"},
	{http.MethodPut, "/api/v1/vpn/posture-policies/corp", "vpn:admin"},
	{http.MethodDelete, "/api/v1/vpn/posture-policies/corp", "vpn:admin"},
}

// ntpRouteScopes is the NTP route table of the gRPC method catalog.
var ntpRouteScopes = []guardedRoute{
	{http.MethodGet, "/api/v1/ntp/status", "ntp:read"},
	{http.MethodGet, "/api/v1/ntp/sources", "ntp:read"},
	{http.MethodPost, "/api/v1/ntp/step", "ntp:write"},
}

// appServiceRouteScopes is the Cache, Scheduler and Messaging route table of
// the gRPC method catalog.
var appServiceRouteScopes = []guardedRoute{
	{http.MethodGet, "/api/v1/cache/stats", "cache:read"},
	{http.MethodGet, "/api/v1/cache/config", "cache:read"},
	{http.MethodPatch, "/api/v1/cache/config", "cache:write"},
	{http.MethodDelete, "/api/v1/cache/entries", "cache:delete"},
	{http.MethodPost, "/api/v1/scheduler/jobs", "scheduler:write"},
	{http.MethodGet, "/api/v1/scheduler/jobs", "scheduler:read"},
	{http.MethodGet, "/api/v1/scheduler/jobs/j1", "scheduler:read"},
	{http.MethodPatch, "/api/v1/scheduler/jobs/j1", "scheduler:write"},
	{http.MethodDelete, "/api/v1/scheduler/jobs/j1", "scheduler:delete"},
	{http.MethodPost, "/api/v1/scheduler/jobs/j1/trigger", "scheduler:write"},
	{http.MethodPost, "/api/v1/scheduler/jobs/j1/pause", "scheduler:write"},
	{http.MethodPost, "/api/v1/scheduler/jobs/j1/resume", "scheduler:write"},
	{http.MethodPost, "/api/v1/scheduler/jobs/j1/cancel", "scheduler:write"},
	{http.MethodGet, "/api/v1/scheduler/jobs/j1/history", "scheduler:read"},
	{http.MethodGet, "/api/v1/scheduler/status", "scheduler:read"},
	{http.MethodPost, "/api/v1/messaging/channels", "messaging:write"},
	{http.MethodGet, "/api/v1/messaging/channels", "messaging:read"},
	{http.MethodGet, "/api/v1/messaging/channels/events", "messaging:read"},
	{http.MethodDelete, "/api/v1/messaging/channels/events", "messaging:delete"},
	{http.MethodPost, "/api/v1/messaging/channels/events/messages", "messaging:write"},
	{http.MethodGet, "/api/v1/messaging/channels/events/stats", "messaging:read"},
	{http.MethodGet, "/api/v1/messaging/stats", "messaging:read"},
	{http.MethodGet, "/api/v1/messaging/dedup-stats", "messaging:read"},
}

// computeRouteScopes is every compute route with the scope of its gRPC twin.
var computeRouteScopes = []guardedRoute{
	{http.MethodPost, "/api/v1/compute/vms", "vm:write"},
	{http.MethodGet, "/api/v1/compute/vms", "vm:read"},
	{http.MethodGet, "/api/v1/compute/vms/vm-1", "vm:read"},
	{http.MethodDelete, "/api/v1/compute/vms/vm-1", "vm:delete"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/start", "vm:write"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/stop", "vm:write"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/reboot", "vm:write"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/suspend", "vm:write"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/resume", "vm:write"},
	{http.MethodGet, "/api/v1/compute/vms/vm-1/metrics", "vm:read"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/migrate", "vm:write"},
	{http.MethodPost, "/api/v1/compute/migrations/prepare", "vm:write"},
	{http.MethodPost, "/api/v1/compute/migrations/recv-1/finalize", "vm:write"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/disks", "vm:write"},
	{http.MethodDelete, "/api/v1/compute/vms/vm-1/disks/disk-1", "vm:write"},
	{http.MethodPatch, "/api/v1/compute/vms/vm-1/disks/disk-1", "vm:write"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/snapshots", "vm:write"},
	{http.MethodGet, "/api/v1/compute/vms/vm-1/snapshots", "vm:read"},
	{http.MethodGet, "/api/v1/compute/vms/vm-1/snapshots/snap-1", "vm:read"},
	{http.MethodDelete, "/api/v1/compute/vms/vm-1/snapshots/snap-1", "vm:delete"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/snapshots/snap-1/restore", "vm:write"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/attest", "vm:read"},
	{http.MethodPost, "/api/v1/compute/vms/vm-1/attest/verify", "vm:read"},
	{http.MethodPost, "/api/v1/compute/containers", "container:write"},
	{http.MethodGet, "/api/v1/compute/containers", "container:read"},
	{http.MethodGet, "/api/v1/compute/containers/ctr-1", "container:read"},
	{http.MethodDelete, "/api/v1/compute/containers/ctr-1", "container:delete"},
	{http.MethodPost, "/api/v1/compute/containers/ctr-1/start", "container:write"},
	{http.MethodPost, "/api/v1/compute/containers/ctr-1/stop", "container:write"},
	{http.MethodPost, "/api/v1/compute/containers/ctr-1/exec", "container:write"},
	{http.MethodPost, "/api/v1/compute/containers/ctr-1/attest", "container:read"},
	{http.MethodGet, "/api/v1/compute/containers/ctr-1/metrics", "container:read"},
}

// guardedRouter mounts the VPN, NTP, application service and compute routes
// with no service behind them, so a request the guard admits answers 503.
func guardedRouter(guard *ScopeGuard) *mux.Router {
	router := mux.NewRouter()
	NewVPNHandlers(nil, guard, nil).RegisterRoutes(router)
	NewNTPHandlers(nil, guard, nil).RegisterRoutes(router)
	NewAppServiceHandlers(AppServiceServers{}, guard, nil).RegisterRoutes(router)
	NewComputeHandlers(nil, guard, nil).RegisterRoutes(router)
	return router
}

func serveWithToken(router http.Handler, route guardedRoute, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestScopeGuard_EachRouteAdmitsItsScopeAndRefusesOthers(t *testing.T) {
	for _, group := range []struct {
		name   string
		routes []guardedRoute
		other  string
	}{
		{"vpn", vpnRouteScopes, "ntp:read"},
		{"ntp", ntpRouteScopes, "vpn:read"},
		{"app services", appServiceRouteScopes, "vpn:read"},
		{"compute", computeRouteScopes, "ntp:read"},
	} {
		t.Run(group.name, func(t *testing.T) {
			for _, route := range group.routes {
				router := guardedRouter(NewScopeGuard(&scopedAuthorizer{scopes: map[string][]string{
					"granted": {route.scope},
					"missing": {group.other},
				}}, nil, nil))

				granted := serveWithToken(router, route, "granted")
				assert.Equal(t, http.StatusServiceUnavailable, granted.Code,
					"%s %s with %s must reach the handler", route.method, route.path, route.scope)

				missing := serveWithToken(router, route, "missing")
				assert.Equal(t, http.StatusForbidden, missing.Code,
					"%s %s without %s must be refused", route.method, route.path, route.scope)
				assert.Contains(t, missing.Body.String(), route.scope)

				anonymous := serveWithToken(router, route, "")
				assert.Equal(t, http.StatusUnauthorized, anonymous.Code,
					"%s %s with no credential must be refused", route.method, route.path)
			}
		})
	}
}

func TestScopeGuard_ReadScopeDoesNotOpenWriteOrAdminRoutes(t *testing.T) {
	router := guardedRouter(NewScopeGuard(&scopedAuthorizer{scopes: map[string][]string{
		"reader": {"vpn:read", "ntp:read", "cache:read", "scheduler:read", "messaging:read", "vm:read", "container:read"},
	}}, nil, nil))
	for _, route := range slices.Concat(vpnRouteScopes, ntpRouteScopes, appServiceRouteScopes, computeRouteScopes) {
		recorder := serveWithToken(router, route, "reader")
		if strings.HasSuffix(route.scope, ":read") {
			assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "%s %s", route.method, route.path)
			continue
		}
		assert.Equal(t, http.StatusForbidden, recorder.Code, "%s %s", route.method, route.path)
	}
}

func TestScopeGuard_NilGuardRefusesEveryRoute(t *testing.T) {
	router := guardedRouter(nil)
	for _, route := range slices.Concat(vpnRouteScopes, ntpRouteScopes, appServiceRouteScopes, computeRouteScopes) {
		recorder := serveWithToken(router, route, operatorToken)
		assert.Equal(t, http.StatusForbidden, recorder.Code, "%s %s", route.method, route.path)

		var body ErrorResponse
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
		assert.Equal(t, http.StatusForbidden, body.Code)
		assert.Contains(t, body.Error, "no authorization is configured")
	}
}

func TestScopeGuard_TokenIsValidatedForThisRequest(t *testing.T) {
	tokens := &scopedAuthorizer{scopes: map[string][]string{"granted": {"vpn:read"}}}
	router := guardedRouter(NewScopeGuard(tokens, nil, nil))

	recorder := serveWithToken(router, guardedRoute{http.MethodGet, "/api/v1/vpn/status", "vpn:read"}, "granted")

	assert.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	assert.Empty(t, tokens.asked, "the guard checks the route scope itself")
	assert.Equal(t, "http://example.com/api/v1/vpn/status", tokens.askedHTU)
}

func TestScopeGuard_RefusesTokensItCannotVerify(t *testing.T) {
	route := guardedRoute{http.MethodGet, "/api/v1/vpn/status", "vpn:read"}

	unknown := serveWithToken(guardedRouter(operatorGuard()), route, "forged")
	assert.Equal(t, http.StatusUnauthorized, unknown.Code)
	assert.Contains(t, unknown.Body.String(), "token invalid")

	noValidator := serveWithToken(guardedRouter(NewScopeGuard(nil, grantingPeers{scopes: []string{"*:*"}}, nil)), route, operatorToken)
	assert.Equal(t, http.StatusUnauthorized, noValidator.Code)
	assert.Contains(t, noValidator.Body.String(), "bearer tokens are not accepted")
}

// certificateRequest is a request whose TLS handshake verified a client
// certificate named cn.
func certificateRequest(method, target, cn string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{Subject: pkix.Name{CommonName: cn}}}}}
	return req
}

func TestScopeGuard_VerifiedClientCertificateIsTheCredential(t *testing.T) {
	router := guardedRouter(NewScopeGuard(nil, grantingPeers{scopes: []string{"*:*"}}, nil))
	for _, route := range slices.Concat(vpnRouteScopes, ntpRouteScopes, computeRouteScopes) {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, certificateRequest(route.method, route.path, "operator"))
		assert.Equal(t, http.StatusServiceUnavailable, recorder.Code, "%s %s", route.method, route.path)
	}
}

func TestScopeGuard_RefusesCertificatesItCannotVerify(t *testing.T) {
	cases := []struct {
		name  string
		guard *ScopeGuard
		want  string
	}{
		{"authenticator refuses", NewScopeGuard(nil, grantingPeers{err: errors.New("unknown issuer")}, nil), "unknown issuer"},
		{"no authenticator", NewScopeGuard(nil, nil, nil), "client certificates are not accepted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			guardedRouter(tc.guard).ServeHTTP(recorder, certificateRequest(http.MethodGet, "/api/v1/vpn/status", "operator"))
			assert.Equal(t, http.StatusUnauthorized, recorder.Code)
			assert.Contains(t, recorder.Body.String(), tc.want)
		})
	}
}

func TestScopeGuard_CertificateWithoutTheScopeIsForbidden(t *testing.T) {
	router := guardedRouter(NewScopeGuard(nil, grantingPeers{scopes: []string{"vpn:read"}}, nil))

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, certificateRequest(http.MethodPost, "/api/v1/ntp/step", "reader"))

	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "ntp:write")
}

func TestScopeGuardErrors(t *testing.T) {
	assert.Equal(t, "authentication required: no token", ErrRouteUnauthenticated{Reason: "no token"}.Error())
	assert.Equal(t, "scope vpn:admin required: missing", ErrRouteForbidden{Scope: "vpn:admin", Reason: "missing"}.Error())
}
