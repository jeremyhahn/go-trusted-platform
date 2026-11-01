package daemon

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

func TestRESTScopeAction_MapsEveryMethod(t *testing.T) {
	cases := []struct {
		method string
		want   string
	}{
		{http.MethodGet, "read"},
		{http.MethodPost, "write"},
		{http.MethodPut, "write"},
		{http.MethodPatch, "write"},
		{http.MethodDelete, "delete"},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			got, err := restScopeAction("kms", nil, tc.method, "/api/v1/kms/keys")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRESTScopeAction_RefusesAnUnservedMethod(t *testing.T) {
	for _, method := range []string{http.MethodHead, http.MethodOptions, http.MethodTrace, http.MethodConnect, "BREW"} {
		t.Run(method, func(t *testing.T) {
			got, err := restScopeAction("secrets", nil, method, "/api/v1/kms/secrets")
			var forbidden restapi.ErrRouteForbidden
			require.ErrorAs(t, err, &forbidden)
			assert.Equal(t, "secrets:*", forbidden.Scope)
			assert.Contains(t, forbidden.Reason, method)
			assert.Empty(t, got)
		})
	}
}

// Each resource's read-only POSTs are reads; any other POST, and any other
// method on a read-only path, keeps its own action.
func TestRESTScopeAction_ReadOnlyPosts(t *testing.T) {
	cases := []struct {
		name          string
		resource      string
		readOnlyPosts []string
		method        string
		route         string
		want          string
	}{
		{"iam validate", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/tenants/{tenant}/policies/validate", "read"},
		{"iam test", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/policies/test", "read"},
		{"iam check", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/permissions/check", "read"},
		{"iam create", iamScopeResource, iamReadOnlyPosts, http.MethodPost, "/api/v1/iam/tenants/{tenant}/policies", "write"},
		{"kms decrypt", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/decrypt/{name}", "read"},
		{"kms verify", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/verify/{name}", "read"},
		{"kms hmac verify", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/hmac/{name}/verify", "read"},
		{"kms hash", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/hash", "read"},
		{"kms random", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/random", "read"},
		{"kms hmac", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/hmac/{name}", "write"},
		{"kms encrypt", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/kms/encrypt/{name}", "write"},
		{"kms read-only path by PUT", kmsScopeResource, kmsReadOnlyPosts, http.MethodPut, "/api/v1/kms/hash", "write"},
		{"iam path under kms rules", kmsScopeResource, kmsReadOnlyPosts, http.MethodPost, "/api/v1/iam/permissions/check", "write"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := restScopeAction(tc.resource, tc.readOnlyPosts, tc.method, tc.route)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRESTRouteTemplate(t *testing.T) {
	t.Run("the matched route's template", func(t *testing.T) {
		router := mux.NewRouter()
		var got string
		router.HandleFunc("/api/v1/kms/keys/{name}", func(_ http.ResponseWriter, r *http.Request) {
			got = restRouteTemplate(r)
		})
		router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/k1", nil))
		assert.Equal(t, "/api/v1/kms/keys/{name}", got)
	})
	t.Run("the request path without a matched route", func(t *testing.T) {
		got := restRouteTemplate(httptest.NewRequest(http.MethodGet, "/api/v1/kms/keys/k1", nil))
		assert.Equal(t, "/api/v1/kms/keys/k1", got)
	})
}

// daemonPreAuthRoutes are the daemon REST routes that answer without a
// credential by design: the health probes (docs/health/api.md §7).
var daemonPreAuthRoutes = []string{
	"/health",        // root probes /health, /health/live, /health/ready (docs/health/api.md §7)
	"/api/v1/health", // the same probe under /api/v1 (docs/health/api.md §7)
}

// daemonMTLSOnlyRoutes are the daemon REST routes that run behind no scope
// guard today and rely on the listener's mTLS handshake alone. This is known
// debt that #997 retires slice by slice (s3 removes the device entries); a
// route leaves this list when its mount gets a guard.
var daemonMTLSOnlyRoutes = []string{
	"/api/v1/status",                             // daemon status (registerRoutes)
	"/api/v1/version",                            // daemon version (registerRoutes)
	"/api/v1/services",                           // service list, get, start, stop, restart (registerRoutes)
	"/api/v1/protocols",                          // transport status (registerRoutes)
	"/api/v1/tpm/idevid",                         // IDevID lifecycle (registerIDevIDRoutes)
	"/api/v1/tpm/iak",                            // IAK lifecycle (registerIDevIDRoutes)
	"/api/v1/tpm/device/attributes",              // TPM device attributes (registerIDevIDRoutes)
	"/api/v1/idevid/ldevid",                      // LDevID issuance (registerIDevIDRoutes)
	"/api/v1/provisioning/",                      // boot-time config delivery (SetConfigDeliveryHandler)
	"/api/v1/bmc/",                               // BMC management (SetBMCHandler)
	"/api/v1/ca/info",                            // CA routes SetCAHandlers mounts without its guard
	"/api/v1/ca/certificates",                    // as above
	"/api/v1/ca/crl",                             // as above
	"/api/v1/ca/bundle",                          // as above
	"/api/v1/auth/factors/aaguid-lookup",         // auth factor route SetCAHandlers mounts without its guard
	"/api/v1/users/{id}/factors/mtls/issue-cert", // as above
	"/api/v1/tenants/{id}/security/mfa-policy",   // tenant MFA policy, outside the tenant guard
}

// templateVariable matches a mux path variable, {name} or {name:pattern}.
var templateVariable = regexp.MustCompile(`\{[^{}]*\}`)

// routeIsExcepted reports whether template is covered by one of the named
// exception prefixes.
func routeIsExcepted(template string, lists ...[]string) bool {
	for _, list := range lists {
		for _, prefix := range list {
			if strings.HasPrefix(template, prefix) {
				return true
			}
		}
	}
	return false
}

// TestDaemonREST_EveryMountedRouteIsGuarded walks the router New builds and
// sends every route a request with no credential: each must answer 401
// unless it is a named exception. A route mounted later without a guard
// fails here.
// serveWithoutCredential sends one request with no credential and returns
// the status it got. The route-table fakes panic when called, so a panic
// means the request got past every middleware to the handler.
func serveWithoutCredential(router http.Handler, method, path string) (answer string) {
	defer func() {
		if recover() != nil {
			answer = "from the handler (no guard ran)"
		}
	}()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return strconv.Itoa(recorder.Code)
}

func TestDaemonREST_EveryMountedRouteIsGuarded(t *testing.T) {
	guard := restapi.NewScopeGuard(nil, nil, nil)
	s, _ := daemonRouteTable(t, guard)
	require.NoError(t, s.SetKMSRouterHandlers(logging.DefaultLogger(), &platformMockKMSClient{}, &platformMockCryptoClient{}, nil, nil, guard))
	iam := newMemIAM()
	require.NoError(t, s.SetIAMHandlers(logging.DefaultLogger(), restiam.NewQuicBaaSIAMAdapter(iam), restiam.NewQuicBaaSPEPAdapter(iam.PEP()), guard, iamRESTSystemTenant))

	var unguarded []string
	checked := 0
	walkErr := s.Router().Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			return nil
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		if routeIsExcepted(template, daemonPreAuthRoutes, daemonMTLSOnlyRoutes) {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			methods = []string{http.MethodGet}
		}
		path := templateVariable.ReplaceAllString(template, "1")
		for _, method := range methods {
			checked++
			if answer := serveWithoutCredential(s.Router(), method, path); answer != "401" {
				unguarded = append(unguarded, method+" "+template+" answered "+answer)
			}
		}
		return nil
	})
	require.NoError(t, walkErr)
	assert.NotZero(t, checked, "the walk sent no request")
	assert.Empty(t, unguarded, "routes neither guarded nor a named exception")
}
