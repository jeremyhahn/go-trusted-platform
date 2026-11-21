package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// tenantScopedTokenValidator authorizes every token for tenant with scopes.
type tenantScopedTokenValidator struct {
	tenant string
	scopes []string
}

func (v tenantScopedTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	return true, nil
}

func (v tenantScopedTokenValidator) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "u", TenantID: v.tenant, Scopes: v.scopes}, nil
}

// kmsCatalogScopes returns every scope the gRPC catalog gives a KMS route.
func kmsCatalogScopes(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	var scopes []string
	for key := range catalogRouteRPCs {
		parts := strings.SplitN(key, " ", 2)
		if len(parts) != 2 || !strings.HasPrefix(parts[1], "/api/v1/kms") {
			continue
		}
		scope, err := catalogRouteScope(parts[0], parts[1])
		if err != nil || seen[scope] {
			continue
		}
		seen[scope] = true
		scopes = append(scopes, scope)
	}
	if len(scopes) == 0 {
		t.Fatal("the catalog gives the KMS routes no scope")
	}
	return scopes
}

const probePlatformTenant = "platform-tenant"

func withPlatformTenant(cfg *Config) { cfg.PlatformTenantID = probePlatformTenant }

// serveProbe serves req and reports whether a legacy handler ran (the
// routeTableKMS stub panics when called).
func serveProbe(s *RESTServer, w *httptest.ResponseRecorder, req *http.Request) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	s.Router().ServeHTTP(w, req)
	return false
}

// TestDaemonREST_KMSRoutesReachTheirHandlers sends the KMS calls the
// integration REST adapter makes (test/integration/kms/rest_adapter.go)
// through the daemon REST router built with every setter wired, as the
// daemon wires them, with a platform-tenant token that carries the KMS
// scopes. Each must reach its handler: the nil-client router answers 503,
// a legacy handler panics on its stub. 401, 403 and 404 all mean the
// handler never ran (Codex round 1 P1 on #2151).
func TestDaemonREST_KMSRoutesReachTheirHandlers(t *testing.T) {
	guard := restapi.NewScopeGuard(tenantScopedTokenValidator{tenant: probePlatformTenant, scopes: kmsCatalogScopes(t)}, nil, nil)
	s, _ := daemonRouteTable(t, guard, withPlatformTenant)
	calls := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/kms/backend/status"},
		{http.MethodGet, "/api/v1/kms/keys"},
		{http.MethodPost, "/api/v1/kms/keys"},
		{http.MethodGet, "/api/v1/kms/keys/k1"},
		{http.MethodPost, "/api/v1/kms/hash"},
		{http.MethodPost, "/api/v1/kms/sign/k1"},
		{http.MethodPost, "/api/v1/kms/verify/k1"},
		{http.MethodPost, "/api/v1/kms/encrypt/k1"},
		{http.MethodPost, "/api/v1/kms/deks"},
		{http.MethodPost, "/api/v1/kms/secrets"},
	}
	for _, c := range calls {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer t")
			w := httptest.NewRecorder()
			if serveProbe(s, w, req) {
				return
			}
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s did not reach its handler: status %d body %q", c.method, c.path, w.Code, w.Body.String())
			}
		})
	}
}

// TestDaemonREST_KMSSecretsAndDEKsRefuseANonSystemTenant pins Codex round 1
// P0 on #2151: the secrets backend reads the tenant from the request context,
// which the REST listener does not bind, so a caller of another tenant would
// reach the platform namespace. Until the tenant is bound, the secrets and
// DEK routes refuse every tenant but the platform one with 403.
func TestDaemonREST_KMSSecretsAndDEKsRefuseANonSystemTenant(t *testing.T) {
	calls := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/kms/secrets"},
		{http.MethodPost, "/api/v1/kms/secrets"},
		{http.MethodPost, "/api/v1/kms/deks"},
	}
	cases := []struct {
		name   string
		tenant string
		want   int
	}{
		{"another tenant", "tenant-a", http.StatusForbidden},
		{"the platform tenant", probePlatformTenant, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		guard := restapi.NewScopeGuard(tenantScopedTokenValidator{tenant: tc.tenant, scopes: kmsCatalogScopes(t)}, nil, nil)
		s, _ := daemonRouteTable(t, guard, withPlatformTenant)
		for _, c := range calls {
			t.Run(tc.name+" "+c.method+" "+c.path, func(t *testing.T) {
				req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
				req.Header.Set("Authorization", "Bearer t")
				w := httptest.NewRecorder()
				if serveProbe(s, w, req) {
					t.Fatalf("%s %s reached a legacy handler", c.method, c.path)
				}
				if w.Code != tc.want {
					t.Fatalf("%s %s = %d %q, want %d", c.method, c.path, w.Code, w.Body.String(), tc.want)
				}
			})
		}
	}
}

// TestDaemonREST_KMSRoutesNeedTheirCatalogScope pins Codex round 2 P0 on
// #2151: the webservice KMS router serves system secrets and DEKs, so it runs
// behind the catalog scope guard. Without a credential the routes answer
// 401, with a token that lacks the route's scope 403, never the handler.
func TestDaemonREST_KMSRoutesNeedTheirCatalogScope(t *testing.T) {
	calls := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/kms/secrets"},
		{http.MethodPost, "/api/v1/kms/deks"},
	}
	cases := []struct {
		name   string
		guard  *restapi.ScopeGuard
		bearer bool
		want   int
	}{
		{"no credential", restapi.NewScopeGuard(nil, nil, nil), false, http.StatusUnauthorized},
		{"token without the scope", restapi.NewScopeGuard(tenantScopedTokenValidator{tenant: probePlatformTenant, scopes: []string{"ca:read"}}, nil, nil), true, http.StatusForbidden},
	}
	for _, tc := range cases {
		s, _ := daemonRouteTable(t, tc.guard)
		for _, c := range calls {
			t.Run(tc.name+" "+c.method+" "+c.path, func(t *testing.T) {
				req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
				if tc.bearer {
					req.Header.Set("Authorization", "Bearer t")
				}
				w := httptest.NewRecorder()
				func() {
					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("%s %s reached a handler: %v", c.method, c.path, r)
						}
					}()
					s.Router().ServeHTTP(w, req)
				}()
				if w.Code != tc.want {
					t.Fatalf("%s %s = %d %q, want %d", c.method, c.path, w.Code, w.Body.String(), tc.want)
				}
			})
		}
	}
}
