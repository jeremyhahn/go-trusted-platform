package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// dnsRESTCallers are the callers the DNS REST tests authenticate as.
var dnsRESTCallers = iamRESTTokens{
	"dns-reader":  {Subject: "dns-reader", TenantID: iamRESTTenantA, Scopes: []string{"dns:read"}},
	"dns-deleter": {Subject: "dns-deleter", TenantID: iamRESTTenantA, Scopes: []string{"dns:delete"}},
	"pxe-reader":  {Subject: "pxe-reader", TenantID: iamRESTTenantA, Scopes: []string{"pxe:read"}},
}

// recordingDNSServer counts the DNS calls that reach the gRPC servicer.
type recordingDNSServer struct {
	platformv1.UnimplementedDNSServiceServer
	lists   atomic.Int32
	deletes atomic.Int32
}

func (r *recordingDNSServer) ListZones(context.Context, *platformv1.ListZonesRequest) (*platformv1.ListZonesResponse, error) {
	r.lists.Add(1)
	return &platformv1.ListZonesResponse{}, nil
}

func (r *recordingDNSServer) DeleteZone(context.Context, *platformv1.DeleteZoneRequest) (*platformv1.DeleteZoneResponse, error) {
	r.deletes.Add(1)
	return &platformv1.DeleteZoneResponse{}, nil
}

func TestSetDNSRouterHandlers_RefusesAMissingDependency(t *testing.T) {
	guard := restapi.NewScopeGuard(dnsRESTCallers, nil, nil)
	cases := []struct {
		name   string
		logger *logging.Logger
		server platformv1.DNSServiceServer
		guard  *restapi.ScopeGuard
		reason string
	}{
		{"no logger", nil, &recordingDNSServer{}, guard, "no logger"},
		{"no server", logging.DefaultLogger(), nil, guard, "no DNS service"},
		{"no guard", logging.DefaultLogger(), &recordingDNSServer{}, nil, "no REST scope guard"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			err := s.SetDNSRouterHandlers(tc.logger, tc.server, tc.guard)
			var unavailable ErrDNSRESTUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, tc.reason, unavailable.Reason)
			assert.Equal(t, http.StatusNotFound, serveIAM(s, http.MethodGet, "/api/v1/dns/zones", "dns-reader").Code,
				"a refused mount serves no DNS route")
		})
	}
}

func TestDNSRouterREST_ScopePerRoute(t *testing.T) {
	server := &recordingDNSServer{}
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetDNSRouterHandlers(logging.DefaultLogger(), server, restapi.NewScopeGuard(dnsRESTCallers, nil, nil)))

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/dns/zones", "").Code)
	assert.Equal(t, http.StatusForbidden, serveIAM(s, http.MethodGet, "/api/v1/dns/zones", "pxe-reader").Code)
	assert.Zero(t, server.lists.Load())

	recorder := serveIAM(s, http.MethodGet, "/api/v1/dns/zones", "dns-reader")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(1), server.lists.Load())

	recorder = serveIAM(s, http.MethodDelete, "/api/v1/dns/zones/example.com", "dns-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "dns:delete")
	assert.Zero(t, server.deletes.Load())

	recorder = serveIAM(s, http.MethodDelete, "/api/v1/dns/zones/example.com", "dns-deleter")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(1), server.deletes.Load())
}

func TestDNSRouteScope(t *testing.T) {
	cases := []struct{ method, route, scope string }{
		{http.MethodGet, "/api/v1/dns/resolve", "dns:read"},
		{http.MethodPost, "/api/v1/dns/zones/{zone}/sign", "dns:write"},
		{http.MethodPut, "/api/v1/dns/zones/{zone}/records", "dns:write"},
		{http.MethodDelete, "/api/v1/dns/zones/{zone}/records/{type}/{name}", "dns:delete"},
	}
	for _, tc := range cases {
		scope, err := dnsRouteScope(tc.method, tc.route)
		require.NoError(t, err, "%s %s", tc.method, tc.route)
		assert.Equal(t, tc.scope, scope, "%s %s", tc.method, tc.route)
	}
	_, err := dnsRouteScope(http.MethodOptions, "/api/v1/dns/zones")
	var forbidden restapi.ErrRouteForbidden
	require.ErrorAs(t, err, &forbidden)
	assert.Equal(t, "dns:*", forbidden.Scope)
}
