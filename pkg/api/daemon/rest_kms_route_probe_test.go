package daemon

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
)

// TestDaemonREST_KMSRoutesReachTheirHandlers sends the KMS calls the
// integration REST adapter makes (test/integration/kms/rest_adapter.go)
// through the daemon REST router built with every setter wired, as the
// daemon wires them. None may answer the router's plain "404 page not
// found": that body means no route matched, not that a key was missing.
func TestDaemonREST_KMSRoutesReachTheirHandlers(t *testing.T) {
	s, _ := daemonRouteTable(t, restapi.NewScopeGuard(nil, nil, nil))
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
			w := httptest.NewRecorder()
			reached := func() (ok bool) {
				// routeTableKMS has no body: a handler that calls it
				// panics, which proves the route matched.
				defer func() {
					if recover() != nil {
						ok = true
					}
				}()
				s.Router().ServeHTTP(w, httptest.NewRequest(c.method, c.path, strings.NewReader("{}")))
				return false
			}()
			if !reached && strings.Contains(w.Body.String(), "404 page not found") {
				t.Fatalf("%s %s matched no route: status %d body %q", c.method, c.path, w.Code, w.Body.String())
			}
		})
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
		{"token without the scope", restapi.NewScopeGuard(scopedTokenValidator{scopes: []string{"ca:read"}}, nil, nil), true, http.StatusForbidden},
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
