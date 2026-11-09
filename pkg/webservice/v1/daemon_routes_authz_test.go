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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
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

// permitCaller is a DaemonCallerAuthenticator that lets every caller through.
func permitCaller(next http.Handler) http.Handler { return next }

// refuseCaller is a DaemonCallerAuthenticator that answers 401 to every
// caller, as the webservice login check does for a request without a session.
func refuseCaller(http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
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
				require.NoError(t, MountDaemonRESTRoutes(api, daemon, writer, authorize, permitCaller))

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
			require.NoError(t, MountDaemonRESTRoutes(api, daemon, writer, refuseAll, permitCaller))

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

// TestRegisterRoutes_DaemonMFAPolicyPutStaysInTheCallersTenant: the admin
// role says the caller administers a tenant, not which one. A tenant-A
// administrator naming tenant B in the path is refused before the daemon
// handler runs; its own tenant, and the system tenant acting on any tenant,
// are admitted, as the tenant router admits them.
func TestRegisterRoutes_DaemonMFAPolicyPutStaysInTheCallersTenant(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)

	tests := []struct {
		name   string
		caller string
		path   string
		want   int
	}{
		{"tenant-a admin writing tenant-b", "tenant-a", "/api/v1/tenants/tenant-b/security/mfa-policy", http.StatusForbidden},
		{"tenant-a admin writing tenant-a", "tenant-a", "/api/v1/tenants/tenant-a/security/mfa-policy", http.StatusOK},
		{"system admin writing tenant-b", "system", "/api/v1/tenants/tenant-b/security/mfa-policy", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			daemon := &authFactorDaemonRoutes{roots: platform.CAPool}
			auth := &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: tt.caller}
			root := newGatedTestRouter(t, &testHandlerRegistry{tokenHandler: auth, daemonRoutes: daemon, tenantID: "system"})

			assert.Equal(t, tt.want, serveWithTLS(root, http.MethodPut, tt.path, verifiedClientState(t, platform)))
			if tt.want == http.StatusOK {
				assert.Equal(t, []string{http.MethodPut + " " + mfaPolicyTemplate}, daemon.served)
			} else {
				assert.Empty(t, daemon.served, "the daemon MFA policy handler must not run")
			}
		})
	}
}

// Only the named method of a method entry takes the authorizer: with every
// caller refused, PUT on the MFA policy is refused while GET on the same
// template reaches the daemon. Cert issuance takes the login check instead
// of the authorizer, so it stops there.
func TestMountDaemonRESTRoutes_MethodEntryGuardsOnlyItsMethod(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	daemon := &authFactorDaemonRoutes{roots: platform.CAPool}
	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(testLogger(), nil)
	require.NoError(t, MountDaemonRESTRoutes(api, daemon, writer, refuseAll, refuseCaller))

	state := verifiedClientState(t, platform)
	assert.Equal(t, http.StatusForbidden, serveWithTLS(api, http.MethodPut, "/api/v1/tenants/system/security/mfa-policy", state))
	assert.Equal(t, http.StatusOK, serveWithTLS(api, http.MethodGet, "/api/v1/tenants/system/security/mfa-policy", state))
	assert.Equal(t, http.StatusUnauthorized, serveWithTLS(api, http.MethodPost, "/api/v1/users/alice/factors/mtls/issue-cert", state))
	assert.Equal(t, []string{http.MethodGet + " " + mfaPolicyTemplate}, daemon.served)
}

// With the login check permitting, cert issuance skips the authorizer and
// reaches the daemon, whose handler decides who may issue for whom.
func TestMountDaemonRESTRoutes_CallerCheckedRouteSkipsTheAuthorizer(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	daemon := &authFactorDaemonRoutes{roots: platform.CAPool}
	api := mux.NewRouter().PathPrefix("/api/v1").Subrouter()
	writer := response.NewResponseWriter(testLogger(), nil)
	require.NoError(t, MountDaemonRESTRoutes(api, daemon, writer, refuseAll, permitCaller))

	state := verifiedClientState(t, platform)
	assert.Equal(t, http.StatusOK, serveWithTLS(api, http.MethodPost, "/api/v1/users/alice/factors/mtls/issue-cert", state))
	assert.Equal(t, http.StatusForbidden, serveWithTLS(api, http.MethodPut, "/api/v1/tenants/system/security/mfa-policy", state))
	assert.Equal(t, []string{http.MethodPost + " /api/v1/users/{id}/factors/mtls/issue-cert"}, daemon.served)
}

// Every method entry names a route the daemon's auth-factor table really
// registers, so a renamed daemon route cannot silently drop its gate.
// gateCase is one caller sent to a gated daemon route: the status the gate
// answers and how many times the daemon handler runs.
type gateCase struct {
	name   string
	auth   jwt.TokenHandler
	want   int
	served int
}

// TestRegisterRoutes_DaemonMethodEntriesTakeAdminAndScope sends every
// per-method entry, behind the real webservice gate, a caller without a
// session, a user holding the entry's scope, an admin without it and an
// admin holding it. Only the last reaches the daemon handler (#983).
func TestRegisterRoutes_DaemonMethodEntriesTakeAdminAndScope(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	session := func(role string, scopes ...string) jwt.TokenHandler {
		return &scopedSessionAuth{sessionAuth: sessionAuth{roles: []string{role}, tenantID: "system"}, scopes: scopes}
	}

	require.NotEmpty(t, privilegedDaemonMethodRoutes)
	for key, scope := range privilegedDaemonMethodRoutes {
		t.Run(key, func(t *testing.T) {
			tests := []gateCase{
				{"no session", &anonymousAuth{}, http.StatusUnauthorized, 0},
				{"user role holding the scope", session("user", scope), http.StatusForbidden, 0},
				{"admin holding the scope", session(common.ROLE_ADMIN, scope), http.StatusOK, 1},
			}
			if scope != "" {
				tests = append(tests, gateCase{"admin without the scope", session(common.ROLE_ADMIN, "other:scope"), http.StatusForbidden, 0})
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					code, served := serveMethodEntry(t, tt.auth, key, platform)
					assert.Equal(t, tt.want, code)
					assert.Equal(t, tt.served, served, "times the daemon handler ran")
				})
			}
		})
	}
}

// methodEntryDaemonRoute is a daemon that registers the one "METHOD template"
// route key names, counting the requests its handler serves.
type methodEntryDaemonRoute struct {
	roots  *x509.CertPool
	key    string
	served int
}

func (d *methodEntryDaemonRoute) ClientCAs() *x509.CertPool { return d.roots }

func (d *methodEntryDaemonRoute) MountRESTRoutes(api *mux.Router) error {
	method, template, _ := strings.Cut(d.key, " ")
	api.HandleFunc(strings.TrimPrefix(template, "/api/v1"), func(w http.ResponseWriter, _ *http.Request) {
		d.served++
		w.WriteHeader(http.StatusOK)
	}).Methods(method)
	return nil
}

// daemonPathVariable matches one gorilla/mux template variable, with or
// without a pattern ({slot}, {profileID:[0-9]+}).
var daemonPathVariable = regexp.MustCompile(`\{[^}]+\}`)

// serveMethodEntry mounts the route key names behind the webservice's own
// daemon-route gate and sends it one request from a verified client
// certificate holding auth's session. It returns the status and how many
// times the daemon handler ran. The route is mounted alone, so no
// webservice route of the same path can answer for it.
func serveMethodEntry(t *testing.T, auth jwt.TokenHandler, key string, platform *testutil.TestTLSBundle) (int, int) {
	t.Helper()

	v1Router := newGatedV1Router(t, &testHandlerRegistry{tokenHandler: auth})
	daemon := &methodEntryDaemonRoute{roots: platform.CAPool, key: key}
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	require.NoError(t, MountDaemonRESTRoutes(api, daemon, v1Router.responseWriter, v1Router.daemonRouteAuthorizer(), v1Router.daemonCallerAuthenticator()))

	method, template, _ := strings.Cut(key, " ")
	path := daemonPathVariable.ReplaceAllString(template, "1")
	return serveWithTLS(root, method, path, verifiedClientState(t, platform)), daemon.served
}

// TestMountDaemonRESTRoutes_AdminGroupRoutesTakeAdminAndScope proves the
// codex P1 on #983: an admin-group write replayed onto the webservice is
// refused before the daemon handler without an admin session holding the
// group's scope, and reaches the handler with one.
func TestMountDaemonRESTRoutes_AdminGroupRoutesTakeAdminAndScope(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	session := func(role string, scopes ...string) jwt.TokenHandler {
		return &scopedSessionAuth{sessionAuth: sessionAuth{roles: []string{role}, tenantID: "system"}, scopes: scopes}
	}
	routes := map[string]string{
		http.MethodPost + " /api/v1/proxy/routes":    proxyWriteScope,
		http.MethodPut + " /api/v1/sdn/gateway/mode": sdnWriteScope,
	}
	for key, scope := range routes {
		t.Run(key, func(t *testing.T) {
			tests := []gateCase{
				{"no session", &anonymousAuth{}, http.StatusUnauthorized, 0},
				{"user role holding the scope", session("user", scope), http.StatusForbidden, 0},
				{"admin without the scope", session(common.ROLE_ADMIN, "other:scope"), http.StatusForbidden, 0},
				{"admin holding the scope", session(common.ROLE_ADMIN, scope), http.StatusOK, 1},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					code, served := serveMethodEntry(t, tt.auth, key, platform)
					assert.Equal(t, tt.want, code)
					assert.Equal(t, tt.served, served, "times the daemon handler ran")
				})
			}
		})
	}
}

// TestMountDaemonRESTRoutes_DaemonScopedGroupTakesAnySession proves a
// daemon-scoped group needs a session but not the admin role: the daemon
// handler enforces its own tenant and scope checks.
func TestMountDaemonRESTRoutes_DaemonScopedGroupTakesAnySession(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	key := http.MethodGet + " /api/v1/compute/vms"
	tests := []gateCase{
		{"no session", &anonymousAuth{}, http.StatusUnauthorized, 0},
		{"non-admin session", &sessionAuth{roles: []string{"user"}, tenantID: "tenant-a"}, http.StatusOK, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, served := serveMethodEntry(t, tt.auth, key, platform)
			assert.Equal(t, tt.want, code)
			assert.Equal(t, tt.served, served, "times the daemon handler ran")
		})
	}
}

// TestMountDaemonRESTRoutes_UnclassifiedRouteIsDenied proves the default
// deny: a replayed route no table classifies answers 403 with
// ErrDaemonRouteUnclassified, even for an admin, and its handler never runs.
func TestMountDaemonRESTRoutes_UnclassifiedRouteIsDenied(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	admin := &scopedSessionAuth{sessionAuth: sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}, scopes: []string{"unknown:read"}}
	v1Router := newGatedV1Router(t, &testHandlerRegistry{tokenHandler: admin})
	daemon := &methodEntryDaemonRoute{roots: platform.CAPool, key: http.MethodGet + " /api/v1/unknown/thing"}
	root := mux.NewRouter()
	api := root.PathPrefix("/api/v1").Subrouter()
	require.NoError(t, MountDaemonRESTRoutes(api, daemon, v1Router.responseWriter, v1Router.daemonRouteAuthorizer(), v1Router.daemonCallerAuthenticator()))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/unknown/thing", nil)
	req.TLS = verifiedClientState(t, platform)
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), ErrDaemonRouteUnclassified{Method: http.MethodGet, Template: "/api/v1/unknown/thing"}.Error())
	assert.Zero(t, daemon.served, "times the daemon handler ran")
}

// TestClassifyDaemonRoute_UnknownGroupIsUnclassified covers the classifier
// directly: a template outside every table, including one with no group
// segment, is unclassified.
func TestClassifyDaemonRoute_UnknownGroupIsUnclassified(t *testing.T) {
	for _, template := range []string{"/api/v1/unknown/thing", "/api/v1", "", "/other/prefix"} {
		assert.Equal(t, daemonRouteAccess{kind: daemonRouteUnclassified}, classifyDaemonRoute(http.MethodGet, template), template)
	}
	assert.Equal(t, daemonRouteAccess{kind: daemonRouteOperator, scope: proxyDeleteScope}, classifyDaemonRoute(http.MethodDelete, "/api/v1/proxy/routes/{id}"))
	assert.Equal(t, daemonRouteAccess{kind: daemonRouteSession}, classifyDaemonRoute(http.MethodPost, "/api/v1/compute/vms"))
	assert.Equal(t, daemonRouteAccess{kind: daemonRouteCertificate}, classifyDaemonRoute(http.MethodGet, "/api/v1/ca/info"))
	assert.Equal(t, daemonRouteAccess{kind: daemonRouteUnclassified}, classifyDaemonRoute("TRACE", "/api/v1/proxy/routes"), "a method no group maps is unclassified")
}

// issueCertCA is the platform CA behind the replayed issue-cert handler: it
// really certifies the CSR and returns its root as the chain.
type issueCertCA struct{ *issuancetest.CA }

func (c issueCertCA) CABundle() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Root.Raw}), nil
}

// issueCertDaemonRoutes replays the daemon's real issue-cert handler, with
// a caller guard that verifies no credential itself: the only caller it can
// see is the one the webservice login check publishes.
type issueCertDaemonRoutes struct {
	roots    *x509.CertPool
	handlers *restapi.AuthFactorHandlers
}

func (d *issueCertDaemonRoutes) ClientCAs() *x509.CertPool { return d.roots }

func (d *issueCertDaemonRoutes) MountRESTRoutes(api *mux.Router) error {
	daemon := mux.NewRouter()
	d.handlers.RegisterRoutes(daemon)
	api.Handle("/users/{id}/factors/mtls/issue-cert", daemon).Methods(http.MethodPost)
	return nil
}

// The replayed issue-cert decides admin from the webservice session's role:
// without a session it is refused, a user issues only for themselves, and
// an admin issues for anyone (#983).
func TestRegisterRoutes_DaemonIssueCertTakesTheSessionCaller(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	key := issuancetest.RSAKey(t)
	session := func(role string) jwt.TokenHandler {
		return &sessionAuth{roles: []string{role}, tenantID: "system"}
	}

	tests := []struct {
		name   string
		auth   jwt.TokenHandler
		userID string
		want   int
	}{
		{"no session", &anonymousAuth{}, "probe-user", http.StatusUnauthorized},
		{"user for themselves", session("user"), "probe-user", http.StatusCreated},
		{"user for another user", session("user"), "alice", http.StatusForbidden},
		{"admin for another user", session(common.ROLE_ADMIN), "alice", http.StatusCreated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := issueCertCA{issuancetest.NewCA(t)}
			guard := restapi.NewScopeGuard(nil, nil, slog.Default())
			daemon := &issueCertDaemonRoutes{
				roots:    platform.CAPool,
				handlers: restapi.NewAuthFactorHandlers(ca, slog.Default()).WithScopeGuard(guard),
			}
			v1Router := newGatedV1Router(t, &testHandlerRegistry{tokenHandler: tt.auth})
			root := mux.NewRouter()
			api := root.PathPrefix("/api/v1").Subrouter()
			require.NoError(t, MountDaemonRESTRoutes(api, daemon, v1Router.responseWriter, v1Router.daemonRouteAuthorizer(), v1Router.daemonCallerAuthenticator()))

			body, err := json.Marshal(restapi.IssueMTLSCertRequest{CSRPEM: string(issuancetest.CSR(t, key, tt.userID))})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+tt.userID+"/factors/mtls/issue-cert", bytes.NewReader(body))
			req.TLS = verifiedClientState(t, platform)
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)

			assert.Equal(t, tt.want, rec.Code, rec.Body.String())
			if tt.want == http.StatusCreated {
				assert.NotNil(t, ca.Opts, "the CA signed the CSR")
			} else {
				assert.Nil(t, ca.Opts, "a refused caller must not reach the CA")
			}
		})
	}
}

// operatorPeer authenticates every verified chain as the daemon's mTLS
// operator: the system tenant holding every scope, as transport_auth does.
type operatorPeer struct{}

func (operatorPeer) AuthenticatePeer(context.Context, []*x509.Certificate) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "operator", TenantID: "system", Roles: []string{common.ROLE_ADMIN}, Scopes: []string{"*:*"}}, nil
}

// oneTenantManager knows a single tenant; every other manager call is
// outside the routes these tests replay.
type oneTenantManager struct {
	restapi.TenantManagerInterface
	tenant *tenant.TenantEntity
}

func (m oneTenantManager) GetTenant(_ context.Context, id string) (*tenant.TenantEntity, error) {
	if id != m.tenant.ID {
		return nil, tenant.ErrTenantNotFound{ID: id}
	}
	return m.tenant, nil
}

func (m oneTenantManager) GetTenantByName(_ context.Context, name string) (*tenant.TenantEntity, error) {
	if name != m.tenant.Name {
		return nil, tenant.ErrTenantNotFound{Name: name}
	}
	return m.tenant, nil
}

// tenantDaemonRoutes replays the daemon's real tenant handlers, guarded by
// a ScopeGuard that would grant the operator certificate everything.
type tenantDaemonRoutes struct {
	roots    *x509.CertPool
	handlers *restapi.TenantHandlers
}

func (d *tenantDaemonRoutes) ClientCAs() *x509.CertPool { return d.roots }

func (d *tenantDaemonRoutes) MountRESTRoutes(api *mux.Router) error {
	daemon := mux.NewRouter()
	d.handlers.RegisterRoutes(daemon)
	api.Handle("/tenants/name/{name}", daemon).Methods(http.MethodGet)
	api.Handle("/tenants/{id}", daemon).Methods(http.MethodGet)
	return nil
}

// A replayed scoped route checks scope and tenant against the webservice
// session, never the operator certificate the request arrived on: a session
// without the scope, or reaching for another tenant, is refused (#983).
func TestMountDaemonRESTRoutes_ScopedRouteChecksTheSessionNotTheTransport(t *testing.T) {
	platform := testutil.GenerateTestTLSBundle(t)
	unscoped := &sessionAuth{roles: []string{"user"}, tenantID: "tenant-a"}
	scoped := &scopedSessionAuth{sessionAuth: sessionAuth{roles: []string{"user"}, tenantID: "tenant-a"}, scopes: []string{"tenant:read"}}

	tests := []struct {
		name string
		auth jwt.TokenHandler
		path string
		want int
	}{
		{"session without the scope", unscoped, "/api/v1/tenants/tenant-a", http.StatusForbidden},
		{"session without the scope by name", unscoped, "/api/v1/tenants/name/alpha", http.StatusForbidden},
		{"scoped session for another tenant", scoped, "/api/v1/tenants/tenant-b", http.StatusForbidden},
		{"scoped session for its own tenant", scoped, "/api/v1/tenants/tenant-a", http.StatusOK},
		{"scoped session for its own tenant by name", scoped, "/api/v1/tenants/name/alpha", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := restapi.NewScopeGuard(nil, operatorPeer{}, slog.Default())
			daemon := &tenantDaemonRoutes{
				roots: platform.CAPool,
				handlers: restapi.NewTenantHandlers(
					restapi.WithTenantGuard(guard),
					restapi.WithTenantSystemTenant("system"),
					restapi.WithTenantManager(oneTenantManager{tenant: &tenant.TenantEntity{ID: "tenant-a", Name: "alpha"}}),
				),
			}
			v1Router := newGatedV1Router(t, &testHandlerRegistry{tokenHandler: tt.auth})
			root := mux.NewRouter()
			api := root.PathPrefix("/api/v1").Subrouter()
			require.NoError(t, MountDaemonRESTRoutes(api, daemon, v1Router.responseWriter, v1Router.daemonRouteAuthorizer(), v1Router.daemonCallerAuthenticator()))

			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.TLS = verifiedClientState(t, platform)
			rec := httptest.NewRecorder()
			root.ServeHTTP(rec, req)

			assert.Equal(t, tt.want, rec.Code, rec.Body.String())
		})
	}
}
