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
}

// s6Scopes is every scope the PIV, LUKS and FIDO2 routes use.
var s6Scopes = []string{
	"ceremony:initialize", "ceremony:status", "ceremony:claim_cert",
	"ceremony:claim_share_begin", "ceremony:claim_share_complete", "ceremony:sign_csr",
	"piv:read", "piv:write", "piv:use", "piv:delete",
	"luks:read", "luks:write", "luks:delete",
	"fido2:read", "fido2:write",
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
	assert.Len(t, s6RouteScopes, len(mounted))
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
			assert.Equal(t, tc.want, tc.mount(s))
			assert.Empty(t, testWalkHandlers(t, s.router), "a refused mount leaves no route")
		})
	}
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
