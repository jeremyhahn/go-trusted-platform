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
