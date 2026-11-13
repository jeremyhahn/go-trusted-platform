package daemon

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s10RouteScopes is every IDevID, IAK, device-attributes and LDevID route
// on the daemon REST listener with the scope the gRPC catalog gives the
// IDevIDService rpc behind it.
var s10RouteScopes = []struct {
	method, route, scope string
}{
	{http.MethodGet, "/api/v1/tpm/idevid", "idevid:read"},
	{http.MethodGet, "/api/v1/tpm/idevid/exists", "idevid:read"},
	{http.MethodPost, "/api/v1/tpm/idevid/generate", "idevid:write"},
	{http.MethodDelete, "/api/v1/tpm/idevid", "idevid:delete"},
	{http.MethodPost, "/api/v1/tpm/idevid/csr", "idevid:write"},
	{http.MethodGet, "/api/v1/tpm/idevid/cert", "idevid:read"},
	{http.MethodPost, "/api/v1/tpm/idevid/install", "idevid:write"},
	{http.MethodDelete, "/api/v1/tpm/idevid/cert", "idevid:delete"},
	{http.MethodGet, "/api/v1/tpm/iak", "idevid:read"},
	{http.MethodGet, "/api/v1/tpm/iak/exists", "idevid:read"},
	{http.MethodPost, "/api/v1/tpm/iak/generate", "idevid:write"},
	{http.MethodDelete, "/api/v1/tpm/iak", "idevid:delete"},
	{http.MethodPost, "/api/v1/tpm/iak/csr", "idevid:write"},
	{http.MethodGet, "/api/v1/tpm/iak/cert", "idevid:read"},
	{http.MethodPost, "/api/v1/tpm/iak/install", "idevid:write"},
	{http.MethodDelete, "/api/v1/tpm/iak/cert", "idevid:delete"},
	{http.MethodGet, "/api/v1/tpm/device/attributes", "idevid:read"},
	{http.MethodPost, "/api/v1/idevid/ldevid", "idevid:write"},
}

func TestS10REST_EveryRouteNeedsItsCatalogScope(t *testing.T) {
	s := newRESTServerWithS6(t)
	for _, tc := range s10RouteScopes {
		name := tc.method + " " + tc.route
		scope, err := catalogRouteScope(tc.method, tc.route)
		require.NoError(t, err, name)
		assert.Equal(t, tc.scope, scope, name)

		assert.Equal(t, http.StatusUnauthorized, serveIAM(s, tc.method, tc.route, "").Code, name)

		recorder := serveIAM(s, tc.method, tc.route, "dns-reader")
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		// Every other scope is not enough: the route needs the action the
		// catalog gives its rpc, not the one its HTTP method suggests.
		recorder = serveIAM(s, tc.method, tc.route, "except:"+tc.scope)
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		recorder = serveIAM(s, tc.method, tc.route, "only:"+tc.scope)
		assertReachedHandler(t, recorder, name, recorder.Body.String())
	}
}

func TestS10SetIDevIDRoutes_RefusesANilGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}

	err := s.SetIDevIDRoutes(nil)
	assert.Equal(t, ErrIDevIDRESTUnavailable{Reason: "no REST scope guard"}, err)
	assert.Empty(t, testWalkHandlers(t, s.router), "a refused mount leaves no route")
}

// TestS10NewRESTServer_MountsNoIDevIDRoute proves building the REST server
// alone mounts none of the IDevID routes: only SetIDevIDRoutes, behind its
// guard, does.
func TestS10NewRESTServer_MountsNoIDevIDRoute(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RESTListenAddr = "127.0.0.1:0"
	svc, err := NewService(cfg)
	require.NoError(t, err)
	s, err := NewRESTServer(cfg, svc, slog.Default())
	require.NoError(t, err)

	for _, route := range testWalkHandlers(t, s.router) {
		_, template, _ := strings.Cut(route, " ")
		assert.False(t, strings.HasPrefix(template, "/api/v1/tpm/"), route)
		assert.False(t, strings.HasPrefix(template, "/api/v1/idevid/"), route)
	}
}
