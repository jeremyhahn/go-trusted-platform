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

// guardedRouter mounts the VPN and NTP routes with no service behind them,
// so a request the guard admits answers 503.
func guardedRouter(guard *ScopeGuard) *mux.Router {
	router := mux.NewRouter()
	NewVPNHandlers(nil, guard, nil).RegisterRoutes(router)
	NewNTPHandlers(nil, guard, nil).RegisterRoutes(router)
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
		"reader": {"vpn:read", "ntp:read"},
	}}, nil, nil))
	for _, route := range slices.Concat(vpnRouteScopes, ntpRouteScopes) {
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
	for _, route := range slices.Concat(vpnRouteScopes, ntpRouteScopes) {
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
	for _, route := range slices.Concat(vpnRouteScopes, ntpRouteScopes) {
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
