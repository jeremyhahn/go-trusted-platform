package daemon

import (
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// s6OperatorToken holds every PIV, LUKS and FIDO2 scope; tests that drive
// those routes for their handler behaviour authenticate with it.
const s6OperatorToken = "s6-operator"

// s6RouteScopes is every PIV, LUKS and FIDO2 route on the daemon REST
// listener with the scope the gRPC catalog gives the rpc behind it.
var s6RouteScopes = []struct {
	method, route, path, scope string
}{
	{http.MethodPost, "/api/v1/ceremony/init", "/api/v1/ceremony/init", "ceremony:initialize"},
	{http.MethodGet, "/api/v1/ceremony/status", "/api/v1/ceremony/status", "ceremony:status"},
	{http.MethodPost, "/api/v1/ceremony/claim-cert/begin", "/api/v1/ceremony/claim-cert/begin", "ceremony:claim_cert"},
	{http.MethodPost, "/api/v1/ceremony/claim-cert/complete", "/api/v1/ceremony/claim-cert/complete", "ceremony:claim_cert"},
	{http.MethodPost, "/api/v1/ceremony/claim-share/begin", "/api/v1/ceremony/claim-share/begin", "ceremony:claim_share_begin"},
	{http.MethodPost, "/api/v1/ceremony/claim-share/complete", "/api/v1/ceremony/claim-share/complete", "ceremony:claim_share_complete"},
	{http.MethodPost, "/api/v1/ceremony/sign-csr", "/api/v1/ceremony/sign-csr", "ceremony:sign_csr"},
	{http.MethodGet, "/api/v1/piv/devices", "/api/v1/piv/devices", "piv:read"},
	{http.MethodGet, "/api/v1/piv/devices/{device}/slots", "/api/v1/piv/devices/yk5/slots", "piv:read"},
	{http.MethodGet, "/api/v1/piv/slots/{slot}", "/api/v1/piv/slots/9a", "piv:read"},
	{http.MethodPost, "/api/v1/piv/slots/{slot}/attest", "/api/v1/piv/slots/9a/attest", "piv:read"},
	{http.MethodPost, "/api/v1/piv/slots/{slot}/generate", "/api/v1/piv/slots/9a/generate", "piv:write"},
	{http.MethodPost, "/api/v1/piv/slots/{slot}/import", "/api/v1/piv/slots/9a/import", "piv:write"},
	{http.MethodPost, "/api/v1/piv/slots/{slot}/sign", "/api/v1/piv/slots/9a/sign", "piv:use"},
	{http.MethodPost, "/api/v1/piv/devices/{device}/reset", "/api/v1/piv/devices/yk5/reset", "piv:delete"},
	{http.MethodGet, "/api/v1/luks/status", "/api/v1/luks/status?device=/dev/x", "luks:read"},
	{http.MethodGet, "/api/v1/luks/slots", "/api/v1/luks/slots?device=/dev/x", "luks:read"},
	{http.MethodGet, "/api/v1/luks/info", "/api/v1/luks/info?device=/dev/x", "luks:read"},
	{http.MethodPost, "/api/v1/luks/keys/test-unlock", "/api/v1/luks/keys/test-unlock", "luks:read"},
	{http.MethodPost, "/api/v1/luks/enroll/passphrase", "/api/v1/luks/enroll/passphrase", "luks:write"},
	{http.MethodPost, "/api/v1/luks/enroll/fido2", "/api/v1/luks/enroll/fido2", "luks:write"},
	{http.MethodPost, "/api/v1/luks/enroll/tpm", "/api/v1/luks/enroll/tpm", "luks:write"},
	{http.MethodPost, "/api/v1/luks/enroll/recovery", "/api/v1/luks/enroll/recovery", "luks:write"},
	{http.MethodPost, "/api/v1/luks/passphrase/change", "/api/v1/luks/passphrase/change", "luks:write"},
	{http.MethodPost, "/api/v1/luks/keys/remove", "/api/v1/luks/keys/remove", "luks:delete"},
	{http.MethodGet, "/api/v1/fido2/devices", "/api/v1/fido2/devices", "fido2:read"},
	{http.MethodGet, "/api/v1/fido2/devices/wait", "/api/v1/fido2/devices/wait", "fido2:read"},
	{http.MethodGet, "/api/v1/fido2/devices/{device}", "/api/v1/fido2/devices/key0", "fido2:read"},
	{http.MethodPost, "/api/v1/fido2/register", "/api/v1/fido2/register", "fido2:write"},
	{http.MethodPost, "/api/v1/fido2/authenticate", "/api/v1/fido2/authenticate", "fido2:write"},
	{http.MethodPost, "/api/v1/vtpm/bundles", "/api/v1/vtpm/bundles", "vtpm:write"},
	{http.MethodGet, "/api/v1/vtpm/bundles", "/api/v1/vtpm/bundles", "vtpm:read"},
	{http.MethodGet, "/api/v1/vtpm/bundles/{id}", "/api/v1/vtpm/bundles/b1", "vtpm:read"},
	{http.MethodDelete, "/api/v1/vtpm/bundles/{id}", "/api/v1/vtpm/bundles/b1", "vtpm:delete"},
	{http.MethodPost, "/api/v1/vtpm/bundles/{id}/start", "/api/v1/vtpm/bundles/b1/start", "vtpm:write"},
	{http.MethodPost, "/api/v1/vtpm/bundles/{id}/stop", "/api/v1/vtpm/bundles/b1/stop", "vtpm:write"},
	{http.MethodGet, "/api/v1/vtpm/bundles/{id}/state", "/api/v1/vtpm/bundles/b1/state", "vtpm:read"},
	{http.MethodPost, "/api/v1/vtpm/bundles/{id}/validate", "/api/v1/vtpm/bundles/b1/validate", "vtpm:read"},
	{http.MethodGet, "/api/v1/vtpm/bundles/{id}/path", "/api/v1/vtpm/bundles/b1/path", "vtpm:read"},
	{http.MethodGet, "/api/v1/vtpm/bundles/{id}/tpm-socket", "/api/v1/vtpm/bundles/b1/tpm-socket", "vtpm:read"},
	{http.MethodGet, "/api/v1/vtpm/bundles/{id}/nvram", "/api/v1/vtpm/bundles/b1/nvram", "vtpm:read"},
	{http.MethodPost, "/api/v1/vtpm/bundles/{id}/quote", "/api/v1/vtpm/bundles/b1/quote", "vtpm:read"},
	{http.MethodGet, "/api/v1/vtpm/bundles/{id}/pcr/{index}", "/api/v1/vtpm/bundles/b1/pcr/7", "vtpm:read"},
	{http.MethodPost, "/api/v1/vtpm/bundles/{id}/pcr/{index}/extend", "/api/v1/vtpm/bundles/b1/pcr/7/extend", "vtpm:write"},
	{http.MethodPost, "/api/v1/vtpm/bundles/{id}/seal", "/api/v1/vtpm/bundles/b1/seal", "vtpm:write"},
	{http.MethodPost, "/api/v1/vtpm/bundles/{id}/unseal", "/api/v1/vtpm/bundles/b1/unseal", "vtpm:read"},
	{http.MethodGet, "/api/v1/vtpm/bundles/{id}/export", "/api/v1/vtpm/bundles/b1/export", "vtpm:read"},
	{http.MethodPost, "/api/v1/vtpm/bundles/import", "/api/v1/vtpm/bundles/import", "vtpm:write"},
	{http.MethodPost, "/api/v1/vtpm/templates", "/api/v1/vtpm/templates", "vtpm:write"},
	{http.MethodGet, "/api/v1/vtpm/templates", "/api/v1/vtpm/templates", "vtpm:read"},
	{http.MethodGet, "/api/v1/vtpm/templates/{id}", "/api/v1/vtpm/templates/t1", "vtpm:read"},
	{http.MethodDelete, "/api/v1/vtpm/templates/{id}", "/api/v1/vtpm/templates/t1", "vtpm:delete"},
	{http.MethodPost, "/api/v1/vtpm/templates/{id}/clone", "/api/v1/vtpm/templates/t1/clone", "vtpm:write"},
	{http.MethodPost, "/api/v1/proxy/routes", "/api/v1/proxy/routes", "proxy:write"},
	{http.MethodGet, "/api/v1/proxy/routes", "/api/v1/proxy/routes", "proxy:read"},
	{http.MethodGet, "/api/v1/proxy/routes/{id}", "/api/v1/proxy/routes/r1", "proxy:read"},
	{http.MethodPut, "/api/v1/proxy/routes/{id}", "/api/v1/proxy/routes/r1", "proxy:write"},
	{http.MethodDelete, "/api/v1/proxy/routes/{id}", "/api/v1/proxy/routes/r1", "proxy:delete"},
	{http.MethodPost, "/api/v1/proxy/pools", "/api/v1/proxy/pools", "proxy:write"},
	{http.MethodGet, "/api/v1/proxy/pools", "/api/v1/proxy/pools", "proxy:read"},
	{http.MethodGet, "/api/v1/proxy/pools/{id}", "/api/v1/proxy/pools/p1", "proxy:read"},
	{http.MethodPut, "/api/v1/proxy/pools/{id}", "/api/v1/proxy/pools/p1", "proxy:write"},
	{http.MethodDelete, "/api/v1/proxy/pools/{id}", "/api/v1/proxy/pools/p1", "proxy:delete"},
	{http.MethodGet, "/api/v1/proxy/config", "/api/v1/proxy/config", "proxy:read"},
	{http.MethodGet, "/api/v1/proxy/status", "/api/v1/proxy/status", "proxy:read"},
	{http.MethodPost, "/api/v1/proxy/reload", "/api/v1/proxy/reload", "proxy:write"},
	{http.MethodGet, "/api/v1/proxy/zone-matrix", "/api/v1/proxy/zone-matrix", "proxy:read"},
	{http.MethodGet, "/api/v1/cluster/status", "/api/v1/cluster/status", "cluster:read"},
	{http.MethodGet, "/api/v1/cluster/nodes", "/api/v1/cluster/nodes", "cluster:read"},
	{http.MethodPost, "/api/v1/cluster/bootstrap", "/api/v1/cluster/bootstrap", "cluster:write"},
	{http.MethodPost, "/api/v1/cluster/join", "/api/v1/cluster/join", "cluster:write"},
	{http.MethodPost, "/api/v1/cluster/leave", "/api/v1/cluster/leave", "cluster:write"},
}

// s6Scopes is every scope the PIV, LUKS and FIDO2 routes use.
var s6Scopes = []string{
	"ceremony:initialize", "ceremony:status", "ceremony:claim_cert",
	"ceremony:claim_share_begin", "ceremony:claim_share_complete", "ceremony:sign_csr",
	"piv:read", "piv:write", "piv:use", "piv:delete",
	"luks:read", "luks:write", "luks:delete",
	"fido2:read", "fido2:write",
	"vtpm:read", "vtpm:write", "vtpm:delete",
	"proxy:read", "proxy:write", "proxy:delete",
	"cluster:read", "cluster:write",
	"sdn:read", "sdn:write", "sdn:delete",
	"idevid:read", "idevid:write", "idevid:delete",
	"certs:read", "certs:list", "certs:generate", "certs:revoke",
	"bmc:read", "bmc:write", "bmc:power", "bmc:media", "bmc:admin",
	"platform:read", "platform:write",
}

// s6RESTCallers grants s6OperatorToken every scope, "dns-reader" none of
// them, "only:<scope>" exactly that scope and "except:<scope>" every other.
func s6RESTCallers() iamRESTTokens {
	caller := func(subject string, scopes []string) platformtoken.AuthorizedContext {
		return platformtoken.AuthorizedContext{Subject: subject, TenantID: iamRESTTenantA, Scopes: scopes}
	}
	tokens := iamRESTTokens{
		s6OperatorToken: caller(s6OperatorToken, s6Scopes),
		"dns-reader":    caller("dns-reader", []string{"dns:read"}),
	}
	for _, scope := range s6Scopes {
		var others []string
		for _, other := range s6Scopes {
			if other != scope {
				others = append(others, other)
			}
		}
		tokens["only:"+scope] = caller("only:"+scope, []string{scope})
		tokens["except:"+scope] = caller("except:"+scope, others)
	}
	return tokens
}

func s6RESTGuard() *restapi.ScopeGuard {
	return restapi.NewScopeGuard(s6RESTCallers(), nil, nil)
}

// newRESTServerWithS6 mounts the PIV, LUKS and FIDO2 routes, each on a
// service without a backend, behind s6RESTGuard.
func newRESTServerWithS6(t *testing.T) *RESTServer {
	t.Helper()
	log := logging.DefaultLogger()
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := s6RESTGuard()
	require.NoError(t, s.SetCeremonyService(NewCeremonyService(log, nil), guard))
	require.NoError(t, s.SetPIVService(NewPIVService(log, nil), guard))
	require.NoError(t, s.SetLUKSService(NewLUKSService(log, nil, rootYes()), guard))
	require.NoError(t, s.SetFIDO2Service(NewFIDO2Service(log, nil), guard))
	require.NoError(t, s.SetVTPMService(&mockVTPMService{}, guard))
	require.NoError(t, s.SetProxyService(NewProxyGRPCServiceWithStore(log, NewProxyStore(), nil), guard))
	cluster, _ := registerClusterGRPCService(log)
	require.NoError(t, s.SetClusterService(cluster, guard))
	require.NoError(t, s.SetOverlayHandlers(newOverlayControllerRESTAdapter(&stubOverlayController{}), guard))
	require.NoError(t, s.SetGatewayIPAMService(nil, nil, guard))
	require.NoError(t, s.SetIDevIDRoutes(guard))
	s.mountCACertificateRoutes(restapi.NewCAHandlers(restapi.NewCAAuthorityAdapter(&fakeRESTCA{}), slog.Default(), nil), guard)
	require.NoError(t, s.SetBMCHandler(s12BMCHandler{}, guard))
	require.NoError(t, s.SetDaemonRoutes(guard))
	return s
}

// mustMountS6 fails the test when a PIV, LUKS or FIDO2 setter refused to
// mount its routes.
func mustMountS6(t *testing.T, err error) {
	t.Helper()
	require.NoError(t, err)
}

func TestS6REST_EveryRouteNeedsItsCatalogScope(t *testing.T) {
	s := newRESTServerWithS6(t)
	for _, tc := range s6RouteScopes {
		name := tc.method + " " + tc.route
		assert.Equal(t, http.StatusUnauthorized, serveIAM(s, tc.method, tc.path, "").Code, name)

		recorder := serveIAM(s, tc.method, tc.path, "dns-reader")
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		// Every other ceremony, PIV, LUKS and FIDO2 scope is not enough: the route
		// needs its own action, not the one its HTTP method suggests.
		recorder = serveIAM(s, tc.method, tc.path, "except:"+tc.scope)
		assert.Equal(t, http.StatusForbidden, recorder.Code, name)
		assert.Contains(t, recorder.Body.String(), tc.scope, name)

		recorder = serveIAM(s, tc.method, tc.path, "only:"+tc.scope)
		assertReachedHandler(t, recorder, name, recorder.Body.String())
	}
}

// TestCatalogRouteRPCs_CoverEveryMountedRoute walks the router the three
// setters build: every mounted route has a catalog entry with a scope, and
// the map names no route that is not mounted.
func TestCatalogRouteRPCs_CoverEveryMountedRoute(t *testing.T) {
	s := newRESTServerWithS6(t)
	mounted := testWalkHandlers(t, s.router)
	for _, route := range mounted {
		method, template, _ := strings.Cut(route, " ")
		if catalogRouteRPCs[route] == bmcPowerActionRPCSet {
			// The body picks the rpc: every rpc it can pick needs a scope.
			for action, rpc := range bmcPowerActionRPCs {
				_, err := catalogRPCScope(method, template, rpc)
				assert.NoError(t, err, route+" "+action)
			}
			continue
		}
		scope, err := catalogRouteScope(method, template)
		assert.NoError(t, err, route)
		assert.NotEmpty(t, scope, route)
	}

	mapped := make([]string, 0, len(catalogRouteRPCs))
	for route := range catalogRouteRPCs {
		mapped = append(mapped, route)
	}
	sort.Strings(mounted)
	sort.Strings(mapped)
	assert.Equal(t, mapped, mounted)
	assert.Len(t, mounted, len(s6RouteScopes)+len(s9RouteScopes)+len(s10RouteScopes)+len(s11RouteScopes)+len(s12RouteScopes)+len(s13RouteScopes)+1)
}

func TestCatalogRouteScope(t *testing.T) {
	for _, tc := range s6RouteScopes {
		scope, err := catalogRouteScope(tc.method, tc.route)
		require.NoError(t, err, tc.route)
		assert.Equal(t, tc.scope, scope, tc.method+" "+tc.route)
	}
}

func TestCatalogRouteScope_FailsClosed(t *testing.T) {
	const unscopedRoute = "/api/v1/piv/unscoped"
	catalogRouteRPCs["POST "+unscopedRoute] = "/platform.v1.PIVService/NoSuchMethod"
	t.Cleanup(func() { delete(catalogRouteRPCs, "POST "+unscopedRoute) })

	cases := []struct {
		name, method, route, reason string
	}{
		{"route not in the map", http.MethodDelete, "/api/v1/piv/devices", "has no gRPC method"},
		{"rpc without a catalog scope", http.MethodPost, unscopedRoute, "NoSuchMethod no scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := catalogRouteScope(tc.method, tc.route)
			assert.Empty(t, scope)
			var unscoped ErrRESTRouteUnscoped
			require.ErrorAs(t, err, &unscoped)
			assert.Equal(t, tc.method, unscoped.Method)
			assert.Equal(t, tc.route, unscoped.Route)
			assert.True(t, strings.Contains(err.Error(), tc.reason), err.Error())
		})
	}
}

func TestS6Setters_RefuseANilGuard(t *testing.T) {
	log := logging.DefaultLogger()
	cases := []struct {
		name  string
		mount func(s *RESTServer) error
		want  error
	}{
		{"Ceremony", func(s *RESTServer) error { return s.SetCeremonyService(NewCeremonyService(log, nil), nil) },
			ErrCeremonyRESTUnavailable{Reason: "no REST scope guard"}},
		{"PIV", func(s *RESTServer) error { return s.SetPIVService(NewPIVService(log, nil), nil) },
			ErrPIVRESTUnavailable{Reason: "no REST scope guard"}},
		{"LUKS", func(s *RESTServer) error { return s.SetLUKSService(NewLUKSService(log, nil, rootYes()), nil) },
			ErrLUKSRESTUnavailable{Reason: "no REST scope guard"}},
		{"FIDO2", func(s *RESTServer) error { return s.SetFIDO2Service(NewFIDO2Service(log, nil), nil) },
			ErrFIDO2RESTUnavailable{Reason: "no REST scope guard"}},
		{"vTPM", func(s *RESTServer) error { return s.SetVTPMService(&mockVTPMService{}, nil) },
			ErrVTPMRESTUnavailable{Reason: "no REST scope guard"}},
		{"Proxy", func(s *RESTServer) error {
			return s.SetProxyService(NewProxyGRPCServiceWithStore(log, NewProxyStore(), nil), nil)
		}, ErrProxyRESTUnavailable{Reason: "no REST scope guard"}},
		{"Cluster", func(s *RESTServer) error { return s.SetClusterService(nil, nil) },
			ErrClusterRESTUnavailable{Reason: "no REST scope guard"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			assert.Equal(t, tc.want, tc.mount(s))
			assert.Empty(t, testWalkHandlers(t, s.router), "a refused mount leaves no route")
		})
	}
}

// TestCatalogGuardedRoot_GuardsOnlyItsOwnRoutes proves the matcher-less
// subrouter the vTPM and proxy routes mount on runs its guard only for its
// own routes: a root route mounted beside it, and a vTPM path it does not
// serve, answer as they did before, without a credential.
func TestCatalogGuardedRoot_GuardsOnlyItsOwnRoutes(t *testing.T) {
	s := newRESTServerWithS6(t)
	s.router.HandleFunc("/api/v1/s8-open", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}).Methods(http.MethodGet)

	assert.Equal(t, http.StatusTeapot, serveIAM(s, http.MethodGet, "/api/v1/s8-open", "").Code)

	recorder := serveIAM(s, http.MethodGet, "/api/v1/vtpm/unserved", "")
	assert.Equal(t, http.StatusNotFound, recorder.Code)
	assert.Equal(t, "404 page not found\n", recorder.Body.String())

	// A guarded route still refuses the same anonymous caller.
	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/vtpm/bundles", "").Code)
}

// testWalkHandlers lists, as "METHOD template", the routes on router that
// carry a handler; the subrouters' prefix routes carry none.
func testWalkHandlers(t *testing.T, router *mux.Router) []string {
	t.Helper()
	var routes []string
	require.NoError(t, router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if route.GetHandler() == nil {
			return nil
		}
		template, err := route.GetPathTemplate()
		require.NoError(t, err)
		methods, err := route.GetMethods()
		require.NoError(t, err, template)
		for _, method := range methods {
			routes = append(routes, method+" "+template)
		}
		return nil
	}))
	return routes
}
