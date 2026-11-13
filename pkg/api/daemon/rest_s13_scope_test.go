package daemon

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s13RouteScopes is each daemon status, version and service-control route
// with the scope the gRPC catalog gives its PlatformDaemon rpc.
var s13RouteScopes = []struct {
	method, route, path, scope string
}{
	{http.MethodGet, "/api/v1/status", "/api/v1/status", "platform:read"},
	{http.MethodGet, "/api/v1/version", "/api/v1/version", "platform:read"},
	{http.MethodGet, "/api/v1/services", "/api/v1/services", "platform:read"},
	{http.MethodGet, "/api/v1/services/{service}", "/api/v1/services/test-service", "platform:read"},
	{http.MethodPost, "/api/v1/services/{service}/start", "/api/v1/services/test-service/start", "platform:write"},
	{http.MethodPost, "/api/v1/services/{service}/stop", "/api/v1/services/test-service/stop", "platform:write"},
	{http.MethodPost, "/api/v1/services/{service}/restart", "/api/v1/services/test-service/restart", "platform:write"},
}

// newRESTServerWithS13 builds a REST server over a daemon service holding
// "test-service", with the daemon routes mounted behind s6RESTGuard.
func newRESTServerWithS13(t *testing.T) *RESTServer {
	t.Helper()
	cfg := DefaultConfig()
	svc, err := NewService(cfg)
	require.NoError(t, err)
	svc.RegisterService(newMockService("test-service"))
	s, err := NewRESTServer(cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NoError(t, s.SetDaemonRoutes(s6RESTGuard()))
	return s
}

// serveDaemonRouteAsOperator mounts the daemon routes on s behind
// s6RESTGuard and serves req with the credential that holds every scope.
func serveDaemonRouteAsOperator(t *testing.T, s *RESTServer, w http.ResponseWriter, req *http.Request) {
	t.Helper()
	require.NoError(t, s.SetDaemonRoutes(s6RESTGuard()))
	req.Header.Set("Authorization", "Bearer "+s6OperatorToken)
	s.router.ServeHTTP(w, req)
}

func TestS13REST_EveryRouteNeedsItsCatalogScope(t *testing.T) {
	s := newRESTServerWithS13(t)
	mounted := testWalkHandlers(t, s.router)
	for _, tc := range s13RouteScopes {
		name := tc.method + " " + tc.route
		assert.Contains(t, mounted, name, "the route template is the catalogRouteRPCs key")
		scope, err := catalogRouteScope(tc.method, tc.route)
		require.NoError(t, err, name)
		assert.Equal(t, tc.scope, scope, name)

		assert.Equal(t, http.StatusUnauthorized, serveIAM(s, tc.method, tc.path, "").Code, name)

		recorder := serveIAM(s, tc.method, tc.path, "dns-reader")
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		recorder = serveIAM(s, tc.method, tc.path, "except:"+tc.scope)
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		assertReachedHandler(t, serveIAM(s, tc.method, tc.path, "only:"+tc.scope), name)
	}
}

// The catalog is keyed by the method and the template restRouteTemplate
// gives a request the router matched.
func TestS13REST_RouteTemplateIsTheCatalogKey(t *testing.T) {
	s := newRESTServerWithS13(t)
	var seen []string
	s.router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = append(seen, r.Method+" "+restRouteTemplate(r))
			next.ServeHTTP(w, r)
		})
	})
	for _, tc := range s13RouteScopes {
		serveIAM(s, tc.method, tc.path, "only:"+tc.scope)
	}
	require.Len(t, seen, len(s13RouteScopes))
	for i, tc := range s13RouteScopes {
		assert.Equal(t, tc.method+" "+tc.route, seen[i])
		assert.Contains(t, catalogRouteRPCs, seen[i])
	}
}

func TestS13SetDaemonRoutes_RefusesANilGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	err := s.SetDaemonRoutes(nil)
	var unavailable ErrDaemonRESTUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Empty(t, testWalkHandlers(t, s.router))
}

func TestS13NewRESTServer_MountsNoDaemonRoute(t *testing.T) {
	cfg := DefaultConfig()
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	mounted := testWalkHandlers(t, s.router)
	for _, tc := range s13RouteScopes {
		name := tc.method + " " + tc.route
		assert.NotContains(t, mounted, name)
		recorder := httptest.NewRecorder()
		s.router.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
		assert.Equal(t, http.StatusNotFound, recorder.Code, name)
	}
}
