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
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
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
	"secrets-lister": {Subject: "secrets-lister", TenantID: iamRESTTenantA, Scopes: []string{"secrets:list"}},
	"operator":       {Subject: "operator", TenantID: iamRESTTenantA, Scopes: []string{mtlsOperatorScope}},
	"tenant-b-all":   {Subject: "tenant-b-all", TenantID: iamRESTTenantB, Scopes: []string{"secrets:*", "kms:*"}},
	"system-all":     {Subject: "system-all", TenantID: iamRESTTenantA, Scopes: []string{"secrets:*", "kms:*"}},
	"no-tenant-all":  {Subject: "no-tenant-all", Scopes: []string{"secrets:*", "kms:*"}},
}

// kmsRESTServer is a RESTServer serving the KMS router over the fake SDK
// KMS and crypto clients; the DEK and secrets clients are absent, so their
// routes answer 503 from the router once the guard admits a request.
func kmsRESTServer(t *testing.T, kmsClient kms.Client) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(kmsRESTCallers, nil, nil)
	require.NoError(t, s.SetKMSRouterHandlers(logging.DefaultLogger(), kmsClient, &platformMockCryptoClient{}, nil, nil, guard, iamRESTTenantA))
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
			err := s.SetKMSRouterHandlers(tc.logger, &platformMockKMSClient{}, &platformMockCryptoClient{}, nil, nil, tc.guard, iamRESTTenantA)
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
		"GET /api/v1/kms/secrets":                           "secrets:list",
		"GET /api/v1/kms/secrets/{name}/versions/{version}": "secrets:read",
		"GET /api/v1/kms/secrets/{name}/versions":           "secrets:list",
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
		{"secrets-reader", http.MethodGet, "/api/v1/kms/secrets", "secrets:list", false},
		{"secrets-reader", http.MethodGet, "/api/v1/kms/secrets/db-password/versions", "secrets:list", false},
		{"secrets-lister", http.MethodGet, "/api/v1/kms/secrets", "secrets:list", true},
		{"secrets-lister", http.MethodGet, "/api/v1/kms/secrets/db-password/versions", "secrets:list", true},
		{"secrets-lister", http.MethodGet, "/api/v1/kms/secrets/db-password", "secrets:read", false},
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

// TestKMSREST_TenantBoundCallerIsRefused pins the fail-closed tenant rule:
// the SDK cannot bind a caller's tenant to the embedded KMS and secrets
// services, so a caller bound to any tenant other than the system tenant
// (tenant A here) must be refused before dispatch, whatever its scopes.
func TestKMSREST_TenantBoundCallerIsRefused(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/kms/secrets"},
		{http.MethodGet, "/api/v1/kms/secrets/db-password"},
		{http.MethodPost, "/api/v1/kms/secrets"},
		{http.MethodGet, "/api/v1/kms/keys/k1"},
	}
	s := kmsRESTServer(t, &platformMockKMSClient{})
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			refused := serveIAM(s, route.method, route.path, "tenant-b-all")
			assert.Equal(t, http.StatusForbidden, refused.Code)
			assert.Contains(t, refused.Body.String(), "serves only the system tenant")

			admitted := serveIAM(s, route.method, route.path, "system-all")
			assertReachedHandler(t, admitted, admitted.Body.String())
		})
	}
}

func TestKMSRouterTenantDecision(t *testing.T) {
	require.NoError(t, kmsRouterTenantDecision(iamRESTTenantA, iamRESTTenantA))
	require.NoError(t, kmsRouterTenantDecision(iamRESTTenantA, ""))

	var unbound ErrKMSRouterTenantUnbound
	require.ErrorAs(t, kmsRouterTenantDecision(iamRESTTenantA, iamRESTTenantB), &unbound)
	assert.Equal(t, iamRESTTenantB, unbound.Tenant)
	assert.Contains(t, unbound.Error(), "serves only the system tenant")
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
// kmsMountedServer mounts the daemon facade and the name-keyed router through
// SetKMSMounts, in the order the daemon mounts them.
func kmsMountedServer(t *testing.T, kmsClient kms.Client, cryptoClient *platformMockCryptoClient) *RESTServer {
	t.Helper()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(kmsRESTCallers, nil, nil)
	facade := NewPlatformKMSRESTFacade(NewPlatformKMSBackend(kmsClient, cryptoClient, slog.Default()))
	router := &KMSRouterClients{KMS: kmsClient, Crypto: cryptoClient}
	require.NoError(t, s.SetKMSMounts(logging.DefaultLogger(), facade, router, guard, iamRESTTenantA))
	return s
}

// TestKMSREST_FacadeTakesPrecedenceOnSharedPaths holds every path both KMS
// mounts serve to the daemon facade's contract, which the SDK REST transport
// decodes: {key, metadata} for a key, random_bytes, and the numeric hash
// algorithm. A router-only path still reaches the router.
func TestKMSREST_FacadeTakesPrecedenceOnSharedPaths(t *testing.T) {
	var statusCalls atomic.Int32
	client := &platformMockKMSClient{
		backendStatusFn: func(context.Context) (*kms.BackendStatusResponse, error) {
			statusCalls.Add(1)
			return &kms.BackendStatusResponse{}, nil
		},
		getKeyMetadataFn: func(_ context.Context, keyID string) (*kms.KeyMetadataResponse, error) {
			return &kms.KeyMetadataResponse{KeyID: keyID}, nil
		},
	}
	var hashAlg atomic.Int32
	var encryptCalls atomic.Int32
	crypto := &platformMockCryptoClient{
		hashFn: func(_ context.Context, req *quicbaas.HashRequest) (*quicbaas.HashResponse, error) {
			hashAlg.Store(int32(req.HashAlg))
			return &quicbaas.HashResponse{HashAlg: req.HashAlg, Hash: []byte("sha512-digest")}, nil
		},
		generateRandomFn: func(_ context.Context, req *quicbaas.GenerateRandomRequest) (*quicbaas.GenerateRandomResponse, error) {
			return &quicbaas.GenerateRandomResponse{RandomBytes: []byte("rand")}, nil
		},
		encryptFn: func(context.Context, *quicbaas.EncryptRequest) (*quicbaas.EncryptResponse, error) {
			encryptCalls.Add(1)
			return &quicbaas.EncryptResponse{Ciphertext: []byte("ciphertext"), KeyVersion: 1}, nil
		},
	}
	s := kmsMountedServer(t, client, crypto)

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/kms/keys/k1", "").Code,
		"the shared key route answers through the guard")
	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodPost, "/api/v1/kms/keys", "").Code,
		"the shared generate route answers through the guard")

	t.Run("GET key answers key and metadata", func(t *testing.T) {
		recorder := serveIAM(s, http.MethodGet, "/api/v1/kms/keys/k1", "system-all")
		assertReachedHandler(t, recorder, recorder.Body.String())
		assert.Contains(t, recorder.Body.String(), `"metadata"`)
		assert.Contains(t, recorder.Body.String(), `"key"`)
	})

	t.Run("POST random answers random_bytes", func(t *testing.T) {
		recorder := serveIAMBody(s, http.MethodPost, "/api/v1/kms/random", "system-all", `{"num_bytes":4}`)
		assertReachedHandler(t, recorder, recorder.Body.String())
		assert.Contains(t, recorder.Body.String(), `"random_bytes"`)
	})

	t.Run("POST hash keeps the numeric algorithm", func(t *testing.T) {
		want, err := platformKMSHashToSDK(4)
		require.NoError(t, err)
		recorder := serveIAMBody(s, http.MethodPost, "/api/v1/kms/hash", "system-all", `{"data":"YQ==","algorithm":4}`)
		assertReachedHandler(t, recorder, recorder.Body.String())
		assert.Equal(t, int32(want), hashAlg.Load(), "the facade hashes with the requested algorithm")
		assert.Contains(t, recorder.Body.String(), "c2hhNTEyLWRpZ2VzdA==", "the facade answers the digest")
	})

	t.Run("router-only encrypt reaches the router", func(t *testing.T) {
		recorder := serveIAMBody(s, http.MethodPost, "/api/v1/kms/encrypt/k1", "system-all", `{"plaintext":"YQ=="}`)
		assertReachedHandler(t, recorder, recorder.Body.String())
		assert.Equal(t, int32(1), encryptCalls.Load())
	})

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/kms/status", "").Code,
		"the facade-only status route answers through the guard")
	recorder := serveIAM(s, http.MethodGet, "/api/v1/kms/status", "kms-reader")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(1), statusCalls.Load(), "/api/v1/kms/status still reaches the daemon facade")
}

func TestSetKMSMounts_SkipsAMissingMountAndRefusesANilGuard(t *testing.T) {
	guard := restapi.NewScopeGuard(kmsRESTCallers, nil, nil)
	facade := NewPlatformKMSRESTFacade(NewPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{}, slog.Default()))

	t.Run("nil facade and nil router mount nothing", func(t *testing.T) {
		s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
		require.NoError(t, s.SetKMSMounts(logging.DefaultLogger(), nil, nil, guard, iamRESTTenantA))
		assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/kms/keys/k1", "system-all").Code)
	})

	t.Run("a nil guard is refused", func(t *testing.T) {
		s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
		assert.Error(t, s.SetKMSMounts(logging.DefaultLogger(), facade, &KMSRouterClients{}, nil, iamRESTTenantA))
	})

	t.Run("a router refusal is returned", func(t *testing.T) {
		s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
		err := s.SetKMSMounts(nil, nil, &KMSRouterClients{}, guard, iamRESTTenantA)
		assert.ErrorAs(t, err, new(ErrKMSRESTUnavailable))
	})
}

// serveIAMBody is serveIAM with a JSON request body.
func serveIAMBody(s *RESTServer, method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	s.router.ServeHTTP(recorder, req)
	return recorder
}

func TestSetKMSHandlers_NilGuardIsRefused(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	facade := NewPlatformKMSRESTFacade(NewPlatformKMSBackend(&platformMockKMSClient{}, &platformMockCryptoClient{}, slog.Default()))

	err := s.SetKMSHandlers(facade, nil, iamRESTTenantA)

	var unavailable ErrKMSRESTUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.NotContains(t, testutil.WalkRoutes(t, s.Router()), "GET /api/v1/kms/status",
		"a refused facade mounts no route")
}

func TestSetKMSHandlers_NilServiceMountsNothing(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}

	require.NoError(t, s.SetKMSHandlers(nil, restapi.NewScopeGuard(kmsRESTCallers, nil, nil), iamRESTTenantA))
	assert.Empty(t, testutil.WalkRoutes(t, s.Router()))
}

func TestSetKMSHandlers_FacadeOnlyPathNeedsScope(t *testing.T) {
	client := &platformMockKMSClient{backendStatusFn: func(context.Context) (*kms.BackendStatusResponse, error) {
		return &kms.BackendStatusResponse{}, nil
	}}
	s := kmsMountedServer(t, client, &platformMockCryptoClient{})

	recorder := serveIAM(s, http.MethodPost, "/api/v1/kms/sign", "kms-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope kms:write required")

	recorder = serveIAM(s, http.MethodGet, "/api/v1/kms/status", "kms-reader")
	assertReachedHandler(t, recorder, recorder.Body.String())
}

// The fallback mount reaches the same unbound SDK clients as the KMS router,
// so a key named in the body must not let another tenant past the router's
// tenant gate.
func TestSetKMSHandlers_FallbackRoutesRefuseUnboundTenant(t *testing.T) {
	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/kms/decrypt"},
		{http.MethodPost, "/api/v1/kms/sign"},
		{http.MethodGet, "/api/v1/kms/keys/k1/export"},
	}
	client := &platformMockKMSClient{}
	s := kmsMountedServer(t, client, &platformMockCryptoClient{})

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			refused := serveIAM(s, route.method, route.path, "tenant-b-all")
			assert.Equal(t, http.StatusForbidden, refused.Code)
			assert.Contains(t, refused.Body.String(), "serves only the system tenant")

			admitted := serveIAM(s, route.method, route.path, "system-all")
			assertReachedHandler(t, admitted, admitted.Body.String())

			untenanted := serveIAM(s, route.method, route.path, "no-tenant-all")
			assertReachedHandler(t, untenanted, untenanted.Body.String())
		})
	}
}

// A request whose method has no action is refused before the scope check.
func TestKMSRESTAuthorization_RefusesAnUnservedMethod(t *testing.T) {
	authz := restScopeAuthorization{
		guard:      restapi.NewScopeGuard(kmsRESTCallers, nil, nil),
		respWriter: response.NewResponseWriter(logging.DefaultLogger(), nil),
		routeScope: kmsRouteScope,
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
		{http.MethodGet, "/api/v1/kms/secrets", "secrets:list"},
		{http.MethodGet, "/api/v1/kms/secrets/{name}/versions", "secrets:list"},
		{http.MethodGet, "/api/v1/kms/secrets/{name}", "secrets:read"},
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
