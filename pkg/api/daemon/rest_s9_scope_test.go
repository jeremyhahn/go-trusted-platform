package daemon

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s9RouteScopes is every SDN overlay and gateway route on the daemon REST
// listener with the scope the gRPC catalog gives the rpc behind it. ForgetMAC,
// WithdrawPrefix and ReleaseIP are DELETEs the catalog grades as writes.
var s9RouteScopes = []struct {
	method, route, path, scope string
}{
	{http.MethodGet, "/api/v1/sdn/overlay/status", "/api/v1/sdn/overlay/status", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/overlay/vteps", "/api/v1/sdn/overlay/vteps", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/overlay/vteps/{node_id}", "/api/v1/sdn/overlay/vteps/node-1", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/overlay/vnis", "/api/v1/sdn/overlay/vnis", "sdn:read"},
	{http.MethodPost, "/api/v1/sdn/overlay/vnis", "/api/v1/sdn/overlay/vnis", "sdn:write"},
	{http.MethodDelete, "/api/v1/sdn/overlay/vnis/{vni}", "/api/v1/sdn/overlay/vnis/100", "sdn:delete"},
	{http.MethodGet, "/api/v1/sdn/overlay/tunnels", "/api/v1/sdn/overlay/tunnels", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/overlay/macs", "/api/v1/sdn/overlay/macs", "sdn:read"},
	{http.MethodDelete, "/api/v1/sdn/overlay/macs/{mac}", "/api/v1/sdn/overlay/macs/02:00:00:00:00:01", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/status", "/api/v1/sdn/gateway/status", "sdn:read"},
	{http.MethodPut, "/api/v1/sdn/gateway/mode", "/api/v1/sdn/gateway/mode", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/bgp/status", "/api/v1/sdn/gateway/bgp/status", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/gateway/bgp/peers", "/api/v1/sdn/gateway/bgp/peers", "sdn:read"},
	{http.MethodPost, "/api/v1/sdn/gateway/bgp/prefixes", "/api/v1/sdn/gateway/bgp/prefixes", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/bgp/prefixes", "/api/v1/sdn/gateway/bgp/prefixes", "sdn:read"},
	{http.MethodDelete, "/api/v1/sdn/gateway/bgp/prefixes/{prefix:.+}", "/api/v1/sdn/gateway/bgp/prefixes/10.0.0.0/24", "sdn:write"},
	{http.MethodPost, "/api/v1/sdn/gateway/ipam/pools", "/api/v1/sdn/gateway/ipam/pools", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/ipam/pools", "/api/v1/sdn/gateway/ipam/pools", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/gateway/ipam/pools/{id}", "/api/v1/sdn/gateway/ipam/pools/p1", "sdn:read"},
	{http.MethodPut, "/api/v1/sdn/gateway/ipam/pools/{id}", "/api/v1/sdn/gateway/ipam/pools/p1", "sdn:write"},
	{http.MethodDelete, "/api/v1/sdn/gateway/ipam/pools/{id}", "/api/v1/sdn/gateway/ipam/pools/p1", "sdn:delete"},
	{http.MethodPost, "/api/v1/sdn/gateway/ipam/allocations", "/api/v1/sdn/gateway/ipam/allocations", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/ipam/allocations", "/api/v1/sdn/gateway/ipam/allocations", "sdn:read"},
	{http.MethodDelete, "/api/v1/sdn/gateway/ipam/allocations/{ip}", "/api/v1/sdn/gateway/ipam/allocations/10.0.0.5", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/overlay/vteps", "/api/v1/sdn/gateway/overlay/vteps", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/gateway/overlay/vteps/{vtep}", "/api/v1/sdn/gateway/overlay/vteps/10.0.0.9", "sdn:read"},
	{http.MethodPost, "/api/v1/sdn/gateway/lb/vips", "/api/v1/sdn/gateway/lb/vips", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/lb/vips", "/api/v1/sdn/gateway/lb/vips", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}", "/api/v1/sdn/gateway/lb/vips/tcp/10.0.0.1/443", "sdn:read"},
	{http.MethodDelete, "/api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}", "/api/v1/sdn/gateway/lb/vips/tcp/10.0.0.1/443", "sdn:delete"},
	{http.MethodPut, "/api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}/backends", "/api/v1/sdn/gateway/lb/vips/tcp/10.0.0.1/443/backends", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/lb/status", "/api/v1/sdn/gateway/lb/status", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/gateway/nat64/status", "/api/v1/sdn/gateway/nat64/status", "sdn:read"},
	{http.MethodPost, "/api/v1/sdn/gateway/perf/flows", "/api/v1/sdn/gateway/perf/flows", "sdn:write"},
	{http.MethodGet, "/api/v1/sdn/gateway/perf/datapath", "/api/v1/sdn/gateway/perf/datapath", "sdn:read"},
	{http.MethodGet, "/api/v1/sdn/gateway/perf/conntrack", "/api/v1/sdn/gateway/perf/conntrack", "sdn:read"},
}

func TestS9REST_EveryRouteNeedsItsCatalogScope(t *testing.T) {
	s := newRESTServerWithS6(t)
	for _, tc := range s9RouteScopes {
		name := tc.method + " " + tc.route
		scope, err := catalogRouteScope(tc.method, tc.route)
		require.NoError(t, err, name)
		assert.Equal(t, tc.scope, scope, name)

		assert.Equal(t, http.StatusUnauthorized, serveIAM(s, tc.method, tc.path, "").Code, name)

		recorder := serveIAM(s, tc.method, tc.path, "dns-reader")
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		// Every other scope is not enough: the route needs the action the
		// catalog gives its rpc, not the one its HTTP method suggests.
		recorder = serveIAM(s, tc.method, tc.path, "except:"+tc.scope)
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		recorder = serveIAM(s, tc.method, tc.path, "only:"+tc.scope)
		assertReachedHandler(t, recorder, name, recorder.Body.String())
	}
}

func TestS9Setters_RefuseANilGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}

	err := s.SetOverlayHandlers(routeTableOverlay{}, nil)
	require.ErrorAs(t, err, new(ErrOverlayRESTUnavailable))

	err = s.SetGatewayIPAMService(nil, nil, nil)
	require.ErrorAs(t, err, new(ErrGatewayRESTUnavailable))

	assert.Nil(t, s.gatewayService)
	assert.Empty(t, testWalkHandlers(t, s.router))
}

func TestS9Setters_NilOverlayServiceMountsNothing(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetOverlayHandlers(nil, s6RESTGuard()))
	assert.Empty(t, testWalkHandlers(t, s.router))
}

// TestS9GatewaySetters_NeverMountUnguarded checks that the setters wiring a
// service into the gateway routes refuse before the guarded mount, mounting
// nothing, and wire the service once the routes are mounted.
func TestS9GatewaySetters_NeverMountUnguarded(t *testing.T) {
	gateway := NewGatewayService()
	setters := map[string]func(*RESTServer) error{
		"snapshot": func(s *RESTServer) error { return s.SetGatewaySnapshotService(gateway) },
		"bgp":      func(s *RESTServer) error { return s.SetGatewayBGPService(gateway) },
		"backends": func(s *RESTServer) error { return s.SetGatewayBackends(gateway) },
	}
	for name, set := range setters {
		t.Run(name+" before the mount", func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			require.ErrorAs(t, set(s), new(ErrGatewayRESTUnavailable))
			assert.Nil(t, s.gatewayService)
			assert.Empty(t, testWalkHandlers(t, s.router))
		})
		t.Run(name+" after the mount", func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			require.NoError(t, s.SetGatewayIPAMService(nil, nil, s6RESTGuard()))
			require.NoError(t, set(s))
			assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/sdn/gateway/status", "").Code)
		})
	}
}
