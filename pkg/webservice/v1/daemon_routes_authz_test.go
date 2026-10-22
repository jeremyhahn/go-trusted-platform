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
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// publicDaemonCARoutes are the replayed daemon CA routes whose webservice
// twins are public; they stay behind the client-certificate gate alone.
var publicDaemonCARoutes = []string{
	"/api/v1/ca/info",
	"/api/v1/ca/crl",
	"/api/v1/ca/bundle",
}

// permitAll is a DaemonRouteAuthorizer that lets every caller through.
func permitAll(string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

// caDaemonRoutes stands in for the daemon's CA route table: one handler
// per CA template, recording each template it serves.
type caDaemonRoutes struct {
	roots  *x509.CertPool
	served []string
}

func (c *caDaemonRoutes) ClientCAs() *x509.CertPool { return c.roots }

func (c *caDaemonRoutes) MountRESTRoutes(api *mux.Router) error {
	templates := append(append([]string{}, publicDaemonCARoutes...), privilegedTemplates()...)
	for _, template := range templates {
		api.HandleFunc(strings.TrimPrefix(template, "/api/v1"), func(w http.ResponseWriter, _ *http.Request) {
			c.served = append(c.served, template)
			w.WriteHeader(http.StatusOK)
		})
	}
	return nil
}

// privilegedTemplates lists the privileged templates sorted, which puts
// /certificates/verify before /certificates/{serial} so the variable never
// shadows the literal path.
func privilegedTemplates() []string {
	return slices.Sorted(maps.Keys(privilegedDaemonRoutes))
}

// concretePath fills the {serial} variable of a CA route template.
func concretePath(template string) string {
	return strings.ReplaceAll(template, "{serial}", "1")
}

func postWithTLS(root http.Handler, path string, state *tls.ConnectionState) int {
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.TLS = state
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec.Code
}

// A client certificate chaining to the platform anchor is not an
// authorization to revoke: the platform anchor also issues user
// certificates. Revoke is served by the daemon alone, so it takes the
// webservice's admin role and certs:revoke scope (#983 P1).
func TestRegisterRoutes_DaemonRevokeTakesAdminAndRevokeScope(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	const revokePath = "/api/v1/ca/certificates/1/revoke"

	tests := []struct {
		name   string
		auth   jwt.TokenHandler
		want   int
		served bool
	}{
		{"no session", &anonymousAuth{}, http.StatusUnauthorized, false},
		{"user role", &sessionAuth{roles: []string{"user"}, tenantID: "system"}, http.StatusForbidden, false},
		{
			"user role holding certs:revoke",
			&scopedSessionAuth{sessionAuth: sessionAuth{roles: []string{"user"}, tenantID: "system"}, scopes: []string{"certs:revoke"}},
			http.StatusForbidden, false,
		},
		{
			"admin without certs:revoke",
			&scopedSessionAuth{sessionAuth: sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}, scopes: []string{"certs:read"}},
			http.StatusForbidden, false,
		},
		{
			"admin holding certs:revoke",
			&scopedSessionAuth{sessionAuth: sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}, scopes: []string{"certs:revoke"}},
			http.StatusOK, true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &caDaemonRoutes{roots: platform.CAPool}
			root := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: tt.auth, daemonRoutes: daemon})

			assert.Equal(t, tt.want, postWithTLS(root, revokePath, verifiedClientState(t, platform)))
			if tt.served {
				assert.Equal(t, []string{"/api/v1/ca/certificates/{serial}/revoke"}, daemon.served)
			} else {
				assert.Empty(t, daemon.served, "the daemon revoke handler must not run")
			}
		})
	}
}

// Every privileged replayed CA route asks the authorizer for the scope of
// its webservice twin, is refused when the authorizer refuses, and is
// served when it permits. The public routes never consult it.
func TestMountDaemonRESTRoutes_PrivilegedCARoutesTakeTheirScope(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)

	for template, scope := range privilegedDaemonRoutes {
		t.Run(template, func(t *testing.T) {
			for _, permit := range []bool{false, true} {
				daemon := &caDaemonRoutes{roots: platform.CAPool}
				var asked []string
				authorize := func(scope string) func(http.Handler) http.Handler {
					asked = append(asked, scope)
					if permit {
						return permitAll(scope)
					}
					return refuseAll(scope)
				}
				api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
				writer := response.NewResponseWriter(testLogger(), nil)
				require.NoError(t, MountDaemonRESTRoutes(api, daemon, writer, authorize))

				assert.Len(t, asked, len(privilegedDaemonRoutes), "one authorizer per privileged route")
				assert.Contains(t, asked, scope)

				code := postWithTLS(api, concretePath(template), verifiedClientState(t, platform))
				if permit {
					assert.Equal(t, http.StatusOK, code)
					assert.Equal(t, []string{template}, daemon.served)
				} else {
					assert.Equal(t, http.StatusForbidden, code)
					assert.Empty(t, daemon.served, "a refused caller must not reach the daemon handler")
				}
			}
		})
	}

	for _, template := range publicDaemonCARoutes {
		t.Run(template, func(t *testing.T) {
			daemon := &caDaemonRoutes{roots: platform.CAPool}
			api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
			writer := response.NewResponseWriter(testLogger(), nil)
			require.NoError(t, MountDaemonRESTRoutes(api, daemon, writer, refuseAll))

			assert.Equal(t, http.StatusOK, getWithTLS(api, template, verifiedClientState(t, platform)))
			assert.Equal(t, []string{template}, daemon.served)
		})
	}
}

func refuseAll(string) func(http.Handler) http.Handler {
	return func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
	}
}

// The daemon's real CA route table is fully classified: a CA route added
// to the daemon without a privileged or public entry here would replay
// behind the client-certificate gate alone.
func TestPrivilegedDaemonRoutes_CoverTheDaemonCATable(t *testing.T) {
	daemon := mux.NewRouter()
	restapi.NewCAHandlers(nil, slog.Default(), nil).RegisterRoutes(daemon)

	registered := map[string]bool{}
	require.NoError(t, daemon.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		require.NoError(t, err)
		registered[template] = true
		return nil
	}))

	for template := range registered {
		_, privileged := privilegedDaemonRoutes[template]
		public := slices.Contains(publicDaemonCARoutes, template)
		assert.Truef(t, privileged != public, "daemon CA route %s must be exactly one of privileged or public", template)
	}
	for template := range privilegedDaemonRoutes {
		assert.Truef(t, registered[template], "privileged entry %s is not a daemon CA route", template)
	}
}

// mfaPolicyTemplate is the daemon's tenant MFA policy route: GET reads the
// policy, PUT changes it.
const mfaPolicyTemplate = "/api/v1/tenants/{id}/security/mfa-policy"

// authFactorDaemonRoutes stands in for the daemon's auth-factor route
// table: the MFA policy routes, one per method, and mTLS cert issuance,
// recording "METHOD template" for each request it serves.
type authFactorDaemonRoutes struct {
	roots  *x509.CertPool
	served []string
}

func (a *authFactorDaemonRoutes) ClientCAs() *x509.CertPool { return a.roots }

func (a *authFactorDaemonRoutes) MountRESTRoutes(api *mux.Router) error {
	routes := map[string]string{
		http.MethodGet:  mfaPolicyTemplate,
		http.MethodPut:  mfaPolicyTemplate,
		http.MethodPost: "/api/v1/users/{id}/factors/mtls/issue-cert",
	}
	for method, template := range routes {
		api.HandleFunc(strings.TrimPrefix(template, "/api/v1"), func(w http.ResponseWriter, _ *http.Request) {
			a.served = append(a.served, method+" "+template)
			w.WriteHeader(http.StatusOK)
		}).Methods(method)
	}
	return nil
}

func serveWithTLS(root http.Handler, method, path string, state *tls.ConnectionState) int {
	req := httptest.NewRequest(method, path, nil)
	req.TLS = state
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)
	return rec.Code
}

// Changing a tenant's MFA policy through the webservice takes the admin
// role, as the client certificate gate admits every user the platform
// anchor issued; reading it stays on the certificate gate.
func TestRegisterRoutes_DaemonMFAPolicyPutTakesAdmin(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	const policyPath = "/api/v1/tenants/system/security/mfa-policy"

	tests := []struct {
		name   string
		auth   jwt.TokenHandler
		method string
		want   int
	}{
		{"PUT without a session", &anonymousAuth{}, http.MethodPut, http.StatusUnauthorized},
		{"PUT with the user role", &sessionAuth{roles: []string{"user"}, tenantID: "system"}, http.MethodPut, http.StatusForbidden},
		{"PUT with the admin role", &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}, http.MethodPut, http.StatusOK},
		{"GET without a session", &anonymousAuth{}, http.MethodGet, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &authFactorDaemonRoutes{roots: platform.CAPool}
			root := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: tt.auth, daemonRoutes: daemon})

			assert.Equal(t, tt.want, serveWithTLS(root, tt.method, policyPath, verifiedClientState(t, platform)))
			if tt.want == http.StatusOK {
				assert.Equal(t, []string{tt.method + " " + mfaPolicyTemplate}, daemon.served)
			} else {
				assert.Empty(t, daemon.served, "the daemon MFA policy handler must not run")
			}
		})
	}
}

// Only the named method of a method entry takes the authorizer: with every
// caller refused, PUT on the MFA policy is refused while GET on the same
// template and cert issuance reach the daemon.
func TestMountDaemonRESTRoutes_MethodEntryGuardsOnlyItsMethod(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	daemon := &authFactorDaemonRoutes{roots: platform.CAPool}
	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(testLogger(), nil)
	require.NoError(t, MountDaemonRESTRoutes(api, daemon, writer, refuseAll))

	state := verifiedClientState(t, platform)
	assert.Equal(t, http.StatusForbidden, serveWithTLS(api, http.MethodPut, "/api/v1/tenants/system/security/mfa-policy", state))
	assert.Equal(t, http.StatusOK, serveWithTLS(api, http.MethodGet, "/api/v1/tenants/system/security/mfa-policy", state))
	assert.Equal(t, http.StatusOK, serveWithTLS(api, http.MethodPost, "/api/v1/users/alice/factors/mtls/issue-cert", state))
	assert.Equal(t, []string{
		http.MethodGet + " " + mfaPolicyTemplate,
		http.MethodPost + " /api/v1/users/{id}/factors/mtls/issue-cert",
	}, daemon.served)
}

// Every method entry names a route the daemon's auth-factor table really
// registers, so a renamed daemon route cannot silently drop its gate.
func TestPrivilegedDaemonMethodRoutes_NameDaemonAuthFactorRoutes(t *testing.T) {
	daemon := mux.NewRouter()
	restapi.NewAuthFactorHandlers(nil, slog.Default()).RegisterRoutes(daemon)

	registered := map[string]bool{}
	require.NoError(t, daemon.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		require.NoError(t, err)
		methods, err := route.GetMethods()
		require.NoError(t, err)
		for _, method := range methods {
			registered[method+" "+template] = true
		}
		return nil
	}))

	require.NotEmpty(t, privilegedDaemonMethodRoutes)
	for key := range privilegedDaemonMethodRoutes {
		assert.Truef(t, registered[key], "privileged method entry %s is not a daemon auth-factor route", key)
	}
}
