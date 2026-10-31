package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/secrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// kmsRESTCallers are the callers the KMS REST tests authenticate as.
var kmsRESTCallers = iamRESTTokens{
	"kms-reader":     {Subject: "kms-reader", TenantID: iamRESTTenantA, Scopes: []string{"kms:read"}},
	"kms-writer":     {Subject: "kms-writer", TenantID: iamRESTTenantA, Scopes: []string{"kms:write"}},
	"kms-deleter":    {Subject: "kms-deleter", TenantID: iamRESTTenantA, Scopes: []string{"kms:delete"}},
	"kms-all":        {Subject: "kms-all", TenantID: iamRESTTenantA, Scopes: []string{"kms:*"}},
	"secrets-reader": {Subject: "secrets-reader", TenantID: iamRESTTenantA, Scopes: []string{"secrets:read"}},
	"operator":       {Subject: "operator", TenantID: iamRESTTenantA, Scopes: []string{mtlsOperatorScope}},
}

// kmsRESTServer is a RESTServer serving the KMS router over the fake SDK
// KMS and crypto clients; the DEK and secrets clients are absent, so their
// routes answer 503 from the router once the guard admits a request.
func kmsRESTServer(t *testing.T, kmsClient kms.Client) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(kmsRESTCallers, nil, nil)
	require.NoError(t, s.SetKMSRouterHandlers(logging.DefaultLogger(), kmsClient, &platformMockCryptoClient{}, nil, nil, guard))
	return s
}

func TestSetKMSRouterHandlers_RefusesAMissingDependency(t *testing.T) {
	guard := restapi.NewScopeGuard(kmsRESTCallers, nil, nil)
	cases := []struct {
		name   string
		logger *logging.Logger
		guard  *restapi.ScopeGuard
		reason string
	}{
		{"no logger", nil, guard, "no logger"},
		{"no guard", logging.DefaultLogger(), nil, "no REST scope guard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			err := s.SetKMSRouterHandlers(tc.logger, &platformMockKMSClient{}, &platformMockCryptoClient{}, nil, nil, tc.guard)
			var unavailable ErrKMSRESTUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, tc.reason, unavailable.Reason)
			assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/kms/keys/k1", "operator").Code,
				"a refused mount serves no KMS route")
		})
	}
}

// The walk finds every route the KMS router registers, each needing the
// scope its resource and method name.
func TestSetKMSRouterHandlers_MountsEveryKMSRoute(t *testing.T) {
	want := map[string]string{
		"POST /api/v1/kms/keys/import":                      "kms:write",
		"POST /api/v1/kms/keys":                             "kms:write",
		"GET /api/v1/kms/keys":                              "kms:read",
		"GET /api/v1/kms/keys/{name}":                       "kms:read",
		"DELETE /api/v1/kms/keys/{name}":                    "kms:delete",
		"POST /api/v1/kms/keys/{name}/rotate":               "kms:write",
		"POST /api/v1/kms/keys/{name}/revoke":               "kms:write",
		"PUT /api/v1/kms/keys/{name}/status":                "kms:write",
		"GET /api/v1/kms/keys/{name}/versions":              "kms:read",
		"GET /api/v1/kms/keys/{name}/metadata":              "kms:read",
		"PUT /api/v1/kms/keys/{name}/metadata":              "kms:write",
		"GET /api/v1/kms/keys/{name}/policy":                "kms:read",
		"PUT /api/v1/kms/keys/{name}/policy":                "kms:write",
		"GET /api/v1/kms/algorithms":                        "kms:read",
		"GET /api/v1/kms/backend/status":                    "kms:read",
		"POST /api/v1/kms/encrypt/{name}":                   "kms:write",
		"POST /api/v1/kms/decrypt/{name}":                   "kms:read",
		"POST /api/v1/kms/sign/{name}":                      "kms:write",
		"POST /api/v1/kms/verify/{name}":                    "kms:read",
		"POST /api/v1/kms/hmac/{name}/verify":               "kms:read",
		"POST /api/v1/kms/hmac/{name}":                      "kms:write",
		"POST /api/v1/kms/hash":                             "kms:read",
		"POST /api/v1/kms/random":                           "kms:read",
		"POST /api/v1/kms/data-keys":                        "kms:write",
		"POST /api/v1/kms/data-keys/wrapped":                "kms:write",
		"POST /api/v1/kms/deks":                             "kms:write",
		"GET /api/v1/kms/deks":                              "kms:read",
		"GET /api/v1/kms/deks/{path:.+}/status":             "kms:read",
		"POST /api/v1/kms/deks/{path:.+}/rotate":            "kms:write",
		"GET /api/v1/kms/deks/{path:.+}":                    "kms:read",
		"DELETE /api/v1/kms/deks/{path:.+}":                 "kms:delete",
		"POST /api/v1/kms/secrets":                          "secrets:write",
		"GET /api/v1/kms/secrets":                           "secrets:read",
		"GET /api/v1/kms/secrets/{name}/versions/{version}": "secrets:read",
		"GET /api/v1/kms/secrets/{name}/versions":           "secrets:read",
		"POST /api/v1/kms/secrets/{name}/rotate":            "secrets:write",
		"POST /api/v1/kms/secrets/{name}/rollback":          "secrets:write",
		"PUT /api/v1/kms/secrets/{name}/status":             "secrets:write",
		"PUT /api/v1/kms/secrets/{name}/policy":             "secrets:write",
		"GET /api/v1/kms/secrets/{name}/policy":             "secrets:read",
		"GET /api/v1/kms/secrets/{name}":                    "secrets:read",
		"DELETE /api/v1/kms/secrets/{name}":                 "secrets:delete",
	}
	got := map[string]string{}
	for _, route := range kmsRouterRoutes(t, kmsRESTServer(t, &platformMockKMSClient{})) {
		got[route.method+" "+route.template] = route.scope
	}
	assert.Len(t, got, 42)
	assert.Equal(t, want, got)
}

func TestKMSREST_ScopePerRoute(t *testing.T) {
	cases := []struct {
		token  string
		method string
		path   string
		scope  string
		admit  bool
	}{
		{"kms-reader", http.MethodGet, "/api/v1/kms/keys/k1", "kms:read", true},
		{"kms-reader", http.MethodPost, "/api/v1/kms/verify/k1", "kms:read", true},
		{"kms-reader", http.MethodPost, "/api/v1/kms/decrypt/k1", "kms:read", true},
		{"kms-reader", http.MethodPost, "/api/v1/kms/hmac/k1/verify", "kms:read", true},
		{"kms-reader", http.MethodPost, "/api/v1/kms/hash", "kms:read", true},
		{"kms-reader", http.MethodPost, "/api/v1/kms/random", "kms:read", true},
		{"kms-reader", http.MethodGet, "/api/v1/kms/backend/status", "kms:read", true},
		{"kms-reader", http.MethodPost, "/api/v1/kms/encrypt/k1", "kms:write", false},
		{"kms-reader", http.MethodDelete, "/api/v1/kms/keys/k1", "kms:delete", false},
		{"kms-writer", http.MethodPost, "/api/v1/kms/encrypt/k1", "kms:write", true},
		{"kms-writer", http.MethodPut, "/api/v1/kms/keys/k1/metadata", "kms:write", true},
		{"kms-writer", http.MethodGet, "/api/v1/kms/keys/k1", "kms:read", false},
		{"kms-writer", http.MethodDelete, "/api/v1/kms/keys/k1", "kms:delete", false},
		{"kms-deleter", http.MethodDelete, "/api/v1/kms/keys/k1", "kms:delete", true},
		{"kms-deleter", http.MethodDelete, "/api/v1/kms/deks/tenant/app", "kms:delete", true},
		{"kms-deleter", http.MethodPost, "/api/v1/kms/keys", "kms:write", false},
		{"secrets-reader", http.MethodGet, "/api/v1/kms/secrets/db-password", "secrets:read", true},
		{"secrets-reader", http.MethodPost, "/api/v1/kms/secrets", "secrets:write", false},
		{"secrets-reader", http.MethodGet, "/api/v1/kms/keys/k1", "kms:read", false},
		{"kms-all", http.MethodGet, "/api/v1/kms/secrets/db-password", "secrets:read", false},
		{"kms-all", http.MethodDelete, "/api/v1/kms/secrets/db-password", "secrets:delete", false},
	}
	s := kmsRESTServer(t, &platformMockKMSClient{})
	for _, tc := range cases {
		t.Run(tc.token+" "+tc.method+" "+tc.path, func(t *testing.T) {
			recorder := serveIAM(s, tc.method, tc.path, tc.token)
			if tc.admit {
				assertTenantNotBridged(t, recorder, tc.token)
				return
			}
			assert.Equal(t, http.StatusForbidden, recorder.Code)
			assert.Contains(t, recorder.Body.String(), "scope "+tc.scope+" required")
		})
	}
}

// kmsRoute is one method and path template the KMS router mounts, with the
// scope the route needs.
type kmsRoute struct {
	method, template, scope string
}

// kmsRouterRoutes walks the routes the KMS router mounted on s.
func kmsRouterRoutes(t *testing.T, s *RESTServer) []kmsRoute {
	t.Helper()
	var routes []kmsRoute
	require.NoError(t, s.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		template, err := route.GetPathTemplate()
		if err != nil || !strings.HasPrefix(template, "/api/v1/kms") {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil
		}
		for _, method := range methods {
			scope, scopeErr := kmsRouteScope(method, template)
			require.NoError(t, scopeErr, "%s %s", method, template)
			routes = append(routes, kmsRoute{method: method, template: template, scope: scope})
		}
		return nil
	}))
	return routes
}

// kmsRoutePath fills a route template's variables with concrete values.
var kmsRoutePath = strings.NewReplacer("{name}", "k1", "{version}", "1", "{path:.+}", "tenant/app")

// assertTenantNotBridged asserts the caller passed the scope check and was
// refused because its tenant cannot reach the SDK services.
func assertTenantNotBridged(t *testing.T, recorder *httptest.ResponseRecorder, token string) {
	t.Helper()
	assert.Equal(t, http.StatusForbidden, recorder.Code, token)
	assert.Contains(t, recorder.Body.String(), ErrKMSRESTTenantNotBridged{Subject: token, TenantID: iamRESTTenantA}.Error(), token)
}

// kmsTenantCallers are tenant credentials over the read scopes and over every
// scope, plus credentials that name no tenant.
var kmsTenantCallers = iamRESTTokens{
	"a-reader":        {Subject: "a-reader", TenantID: iamRESTTenantA, Scopes: []string{"secrets:read", "kms:read"}},
	"a-operator":      {Subject: "a-operator", TenantID: iamRESTTenantA, Scopes: []string{mtlsOperatorScope}},
	"no-tenant":       {Subject: "no-tenant", Scopes: []string{"secrets:read"}},
	"no-tenant-admin": {Subject: "no-tenant-admin", Scopes: []string{mtlsOperatorScope}},
}

// countingSecretsClient counts the Get calls that reach it.
type countingSecretsClient struct {
	secrets.Client
	gets atomic.Int32
}

func (c *countingSecretsClient) Get(context.Context, string, ...secrets.GetOption) (*secrets.Secret, error) {
	c.gets.Add(1)
	return &secrets.Secret{Path: "db"}, nil
}

func kmsTenantRESTServer(t *testing.T, kmsClient kms.Client, secretsClient secrets.Client) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(kmsTenantCallers, nil, nil)
	require.NoError(t, s.SetKMSRouterHandlers(logging.DefaultLogger(), kmsClient, &platformMockCryptoClient{}, nil, secretsClient, guard))
	return s
}

// countingKMSClient is a KMS fake counting the calls that reach it.
func countingKMSClient(calls *atomic.Int32) *platformMockKMSClient {
	return &platformMockKMSClient{
		deleteKeyFn: func(context.Context, string) error {
			calls.Add(1)
			return nil
		},
		backendStatusFn: func(context.Context) (*kms.BackendStatusResponse, error) {
			calls.Add(1)
			return &kms.BackendStatusResponse{}, nil
		},
	}
}

// Codex 8555 P0: the pinned SDK does not carry the caller's tenant to the
// embedded KMS and secrets services, which would run a tenant call in system
// scope. Every mounted route refuses a tenant caller before any SDK call.
func TestKMSREST_TenantCallerIsRefusedOnEveryRoute(t *testing.T) {
	var kmsCalls atomic.Int32
	secretsClient := &countingSecretsClient{}
	s := kmsTenantRESTServer(t, countingKMSClient(&kmsCalls), secretsClient)
	routes := kmsRouterRoutes(t, s)
	require.Len(t, routes, 42)

	for _, route := range routes {
		path := kmsRoutePath.Replace(route.template)
		assertTenantNotBridged(t, serveIAM(s, route.method, path, "a-operator"), "a-operator")
		if strings.HasSuffix(route.scope, ":read") {
			assertTenantNotBridged(t, serveIAM(s, route.method, path, "a-reader"), "a-reader")
		}
	}
	assert.Zero(t, kmsCalls.Load(), "a tenant caller never reaches the SDK KMS client")
	assert.Zero(t, secretsClient.gets.Load(), "a tenant caller never reaches the SDK secrets client")
}

// A refused tenant caller never reaches the SDK client, whichever check
// refuses it.
func TestKMSREST_TenantCallerNeverReachesTheSDKClient(t *testing.T) {
	var deletes atomic.Int32
	s := kmsRESTServer(t, countingKMSClient(&deletes))
	recorder := serveIAM(s, http.MethodDelete, "/api/v1/kms/keys/k1", "kms-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope kms:delete required")
	assertTenantNotBridged(t, serveIAM(s, http.MethodDelete, "/api/v1/kms/keys/k1", "kms-deleter"), "kms-deleter")
	assert.Zero(t, deletes.Load(), "a refused delete never reaches the client")
}

func TestKMSREST_CallerWithoutTenantIsRefused(t *testing.T) {
	secretsClient := &countingSecretsClient{}
	s := kmsTenantRESTServer(t, &platformMockKMSClient{}, secretsClient)
	for _, token := range []string{"no-tenant", "no-tenant-admin"} {
		recorder := serveIAM(s, http.MethodGet, "/api/v1/kms/secrets/db", token)
		assert.Equal(t, http.StatusForbidden, recorder.Code, token)
		assert.Contains(t, recorder.Body.String(), ErrKMSRESTNoTenant{Subject: token}.Error(), token)
	}
	assert.Zero(t, secretsClient.gets.Load(), "a caller with no tenant never reaches the SDK")
}

func TestErrKMSRESTTenantNotBridged(t *testing.T) {
	err := ErrKMSRESTTenantNotBridged{Subject: "svc", TenantID: "tenant-a"}
	assert.Contains(t, err.Error(), "svc")
	assert.Contains(t, err.Error(), "tenant-a")
	assert.Contains(t, err.Error(), "SDK gap")
	assert.NotContains(t, ErrKMSRESTTenantNotBridged{Subject: "svc", TenantID: "tenant-b"}.Error(), "tenant-a")
}

func TestKMSREST_NoCredentialIsUnauthorized(t *testing.T) {
	s := kmsRESTServer(t, &platformMockKMSClient{})
	for _, token := range []string{"", "forged"} {
		for _, path := range []string{"/api/v1/kms/keys/k1", "/api/v1/kms/secrets/db-password"} {
			recorder := serveIAM(s, http.MethodGet, path, token)
			assert.Equal(t, http.StatusUnauthorized, recorder.Code, "token %q on %s", token, path)
		}
	}
}

// The guarded router mounts before the daemon's own KMS handlers, so it
// answers every path both serve, while the daemon keeps the paths only it
// serves.
func TestKMSREST_RouterTakesPrecedenceOverTheDaemonHandlers(t *testing.T) {
	var statusCalls atomic.Int32
	client := &platformMockKMSClient{backendStatusFn: func(context.Context) (*kms.BackendStatusResponse, error) {
		statusCalls.Add(1)
		return &kms.BackendStatusResponse{}, nil
	}}
	s := kmsRESTServer(t, client)
	guard := restapi.NewScopeGuard(kmsRESTCallers, nil, nil)
	require.NoError(t, s.SetKMSHandlers(NewPlatformKMSRESTFacade(NewPlatformKMSBackend(client, &platformMockCryptoClient{}, slog.Default())), guard))

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/kms/keys/k1", "").Code,
		"the overlapping key route answers through the guard")
	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodPost, "/api/v1/kms/keys", "").Code,
		"the overlapping generate route answers through the guard")

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/kms/status", "").Code,
		"the facade-only status route answers through the guard")
	// The facade calls the same SDK client, so its tenant caller is refused
	// too; the refusal, not a 404, shows the facade-only route is mounted.
	assertTenantNotBridged(t, serveIAM(s, http.MethodGet, "/api/v1/kms/status", "kms-reader"), "kms-reader")
	assert.Zero(t, statusCalls.Load(), "a tenant caller never reaches the facade's SDK client")
}

func TestSetKMSHandlers_NilGuardIsRefused(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	facade := NewPlatformKMSRESTFacade(NewPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{}, slog.Default()))

	err := s.SetKMSHandlers(facade, nil)

	var unavailable ErrKMSRESTUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.NotContains(t, testutil.WalkRoutes(t, s.Router()), "GET /api/v1/kms/status",
		"a refused facade mounts no route")
}

func TestSetKMSHandlers_NilServiceMountsNothing(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}

	require.NoError(t, s.SetKMSHandlers(nil, restapi.NewScopeGuard(kmsRESTCallers, nil, nil)))
	assert.Empty(t, testutil.WalkRoutes(t, s.Router()))
}

func TestSetKMSHandlers_FacadeOnlyPathNeedsScope(t *testing.T) {
	client := &platformMockKMSClient{backendStatusFn: func(context.Context) (*kms.BackendStatusResponse, error) {
		return &kms.BackendStatusResponse{}, nil
	}}
	s := kmsRESTServer(t, client)
	guard := restapi.NewScopeGuard(kmsRESTCallers, nil, nil)
	require.NoError(t, s.SetKMSHandlers(NewPlatformKMSRESTFacade(NewPlatformKMSBackend(client, &platformMockCryptoClient{}, slog.Default())), guard))

	recorder := serveIAM(s, http.MethodPost, "/api/v1/kms/sign", "kms-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope kms:write required")

	assertTenantNotBridged(t, serveIAM(s, http.MethodGet, "/api/v1/kms/status", "kms-reader"), "kms-reader")
}

// A request whose method has no action is refused before the scope check.
func TestKMSRESTAuthorization_RefusesAnUnservedMethod(t *testing.T) {
	authz := kmsRESTAuthorization{
		guard:      restapi.NewScopeGuard(kmsRESTCallers, nil, nil),
		respWriter: response.NewResponseWriter(logging.DefaultLogger(), nil),
	}
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/kms/keys", nil)
	req.Header.Set("Authorization", "Bearer operator")
	recorder := httptest.NewRecorder()
	authz.authorize(next).ServeHTTP(recorder, req)
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "method OPTIONS is not served")
	assert.False(t, reached)
}

func TestKMSRouteScope(t *testing.T) {
	cases := []struct {
		method string
		route  string
		want   string
	}{
		{http.MethodGet, "/api/v1/kms/keys/{name}", "kms:read"},
		{http.MethodPost, "/api/v1/kms/keys", "kms:write"},
		{http.MethodPatch, "/api/v1/kms/keys/{name}", "kms:write"},
		{http.MethodDelete, "/api/v1/kms/keys/{name}", "kms:delete"},
		{http.MethodPost, "/api/v1/kms/verify/{name}", "kms:read"},
		{http.MethodPost, "/api/v1/kms/random", "kms:read"},
		{http.MethodPut, "/api/v1/kms/secrets/{name}/policy", "secrets:write"},
		{http.MethodGet, "/api/v1/kms/secrets", "secrets:read"},
		{http.MethodDelete, "/api/v1/kms/secrets/{name}", "secrets:delete"},
		// The daemon facade paths (SetKMSHandlers), scoped as the gRPC catalog.
		{http.MethodGet, "/api/v1/kms/keys/{id}/export", "kms:read"},
		{http.MethodPost, "/api/v1/kms/encrypt", "kms:write"},
		{http.MethodPost, "/api/v1/kms/decrypt", "kms:read"},
		{http.MethodPost, "/api/v1/kms/batch-encrypt", "kms:write"},
		{http.MethodPost, "/api/v1/kms/batch-decrypt", "kms:read"},
		{http.MethodPost, "/api/v1/kms/rewrap", "kms:write"},
		{http.MethodPost, "/api/v1/kms/sign", "kms:write"},
		{http.MethodPost, "/api/v1/kms/verify", "kms:read"},
		{http.MethodPost, "/api/v1/kms/hmac", "kms:write"},
		{http.MethodGet, "/api/v1/kms/status", "kms:read"},
		{http.MethodPost, "/api/v1/kms/hmac/{name}/verify", "kms:read"},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.route, func(t *testing.T) {
			got, err := kmsRouteScope(tc.method, tc.route)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	got, err := kmsRouteScope(http.MethodHead, "/api/v1/kms/keys")
	var forbidden restapi.ErrRouteForbidden
	require.ErrorAs(t, err, &forbidden)
	assert.Equal(t, "kms:*", forbidden.Scope)
	assert.Empty(t, got)
}

func TestKMSService_RESTClients(t *testing.T) {
	t.Run("returns the adapters' SDK clients", func(t *testing.T) {
		kmsClient, cryptoClient := &platformMockKMSClient{}, &platformMockCryptoClient{}
		dekClient := &fakeDEKClient{}
		svc := &KMSService{
			kmsAdapter:    NewKMSServerAdapter(kmsClient, slog.Default()),
			cryptoServer:  NewCryptoServerAdapter(cryptoClient, slog.Default()),
			dekServer:     NewDEKServerAdapter(dekClient, slog.Default()),
			secretsServer: NewSecretsServerAdapter(nil, slog.Default()),
		}
		svc.initialized.Store(true)
		gotKMS, gotCrypto, gotDEK, gotSecrets, err := svc.RESTClients()
		require.NoError(t, err)
		assert.Same(t, kmsClient, gotKMS)
		assert.Same(t, cryptoClient, gotCrypto)
		assert.Same(t, dekClient, gotDEK)
		assert.Nil(t, gotSecrets)
	})
	t.Run("a datastore that is not QuicBaaS is a typed error", func(t *testing.T) {
		svc := &KMSService{app: testAppWithLogger(), logger: slog.Default()}
		gotKMS, gotCrypto, gotDEK, gotSecrets, err := svc.RESTClients()
		var invalid ErrInvalidConfig
		require.ErrorAs(t, err, &invalid)
		assert.Equal(t, "datastore is not QuicBaaS", invalid.Reason)
		assert.Nil(t, gotKMS)
		assert.Nil(t, gotCrypto)
		assert.Nil(t, gotDEK)
		assert.Nil(t, gotSecrets)
	})
}

func TestErrKMSRESTUnavailable(t *testing.T) {
	assert.Equal(t, "KMS REST routes unavailable: no logger", ErrKMSRESTUnavailable{Reason: "no logger"}.Error())
}
