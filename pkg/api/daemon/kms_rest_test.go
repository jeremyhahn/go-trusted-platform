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
	s := kmsRESTServer(t, &platformMockKMSClient{})
	got := map[string]string{}
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
			got[method+" "+template] = scope
		}
		return nil
	}))
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
				assertReachedHandler(t, recorder, recorder.Body.String())
				return
			}
			assert.Equal(t, http.StatusForbidden, recorder.Code)
			assert.Contains(t, recorder.Body.String(), "scope "+tc.scope+" required")
		})
	}
}

// An admitted request reaches the SDK client; a refused one never does.
func TestKMSREST_AdmittedRequestReachesTheSDKClient(t *testing.T) {
	var deletes atomic.Int32
	client := &platformMockKMSClient{deleteKeyFn: func(context.Context, string) error {
		deletes.Add(1)
		return nil
	}}
	s := kmsRESTServer(t, client)
	assert.Equal(t, http.StatusForbidden, serveIAM(s, http.MethodDelete, "/api/v1/kms/keys/k1", "kms-reader").Code)
	assert.Zero(t, deletes.Load(), "a refused delete never reaches the client")
	recorder := serveIAM(s, http.MethodDelete, "/api/v1/kms/keys/k1", "kms-deleter")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(1), deletes.Load())
}

// The mTLS operator's *:* scope admits every method on every resource.
func TestKMSREST_OperatorPassesEveryMethod(t *testing.T) {
	s := kmsRESTServer(t, &platformMockKMSClient{})
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/kms/keys"},
		{http.MethodPost, "/api/v1/kms/encrypt/k1"},
		{http.MethodPut, "/api/v1/kms/keys/k1/policy"},
		{http.MethodDelete, "/api/v1/kms/keys/k1"},
		{http.MethodGet, "/api/v1/kms/secrets/db-password"},
		{http.MethodDelete, "/api/v1/kms/secrets/db-password"},
		{http.MethodPost, "/api/v1/kms/deks"},
	} {
		recorder := serveIAM(s, route.method, route.path, "operator")
		assertReachedHandler(t, recorder, "%s %s: %s", route.method, route.path, recorder.Body.String())
	}
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
	recorder := serveIAM(s, http.MethodGet, "/api/v1/kms/status", "kms-reader")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(1), statusCalls.Load(), "/api/v1/kms/status still reaches the daemon facade")
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

	recorder = serveIAM(s, http.MethodGet, "/api/v1/kms/status", "kms-reader")
	assertReachedHandler(t, recorder, recorder.Body.String())
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
