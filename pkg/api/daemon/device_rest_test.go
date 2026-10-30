package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// deviceRESTCallers are the callers the device REST tests authenticate as.
var deviceRESTCallers = iamRESTTokens{
	"device-reader": {Subject: "device-reader", TenantID: iamRESTTenantA, Scopes: []string{"device:read"}},
	"device-writer": {Subject: "device-writer", TenantID: iamRESTTenantA, Scopes: []string{"device:write"}},
}

// countingTokens authorizes deviceRESTCallers and counts the authorizations.
type countingTokens struct {
	authorizations atomic.Int32
}

func (c *countingTokens) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	c.authorizations.Add(1)
	return deviceRESTCallers.AuthorizeToken(ctx, token, requiredPerm, dpopProof, htm, htu)
}

// deviceRESTProfiles resolves a booting machine's profile by MAC, as
// ProfileService.FindConfigForDevice does over its DAO.
type deviceRESTProfiles struct {
	device.DeviceProfileService
	byMAC map[string]*entities.DeviceProfile
}

func (p deviceRESTProfiles) FindConfigForDevice(_ context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	if ekSerial == "" && mac == "" {
		return nil, device.ErrDeviceIdentityRequired{}
	}
	profile, ok := p.byMAC[mac]
	if !ok {
		return nil, device.ErrNoMatchingConfig{EKSerial: ekSerial, MAC: mac}
	}
	return profile, nil
}

// recordingLifecycleServer counts the disables that reach it.
type recordingLifecycleServer struct {
	platformv1.UnimplementedDeviceServiceServer
	disables atomic.Int32
}

func (s *recordingLifecycleServer) DisableDevice(context.Context, *platformv1.DisableDeviceRequest) (*platformv1.DeviceLifecycleResponse, error) {
	s.disables.Add(1)
	return &platformv1.DeviceLifecycleResponse{}, nil
}

// deviceRESTServer is a RESTServer serving the device router over the
// profile finder and lifecycle server.
func deviceRESTServer(t *testing.T, tokens restapi.TokenAuthorizer, lifecycle platformv1.DeviceServiceServer) *RESTServer {
	t.Helper()
	profiles := deviceRESTProfiles{byMAC: map[string]*entities.DeviceProfile{
		"52:54:00:12:34:56": {ID: 7, Name: "edge"},
	}}
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(tokens, nil, nil)
	require.NoError(t, s.SetDeviceRouterHandlers(logging.DefaultLogger(), routeTableDeviceService{}, profiles,
		routeTableDeviceTemplates{}, lifecycle, guard))
	return s
}

func TestSetDeviceRouterHandlers_RefusesAMissingDependency(t *testing.T) {
	guard := restapi.NewScopeGuard(deviceRESTCallers, nil, nil)
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
			err := s.SetDeviceRouterHandlers(tc.logger, routeTableDeviceService{}, deviceRESTProfiles{},
				routeTableDeviceTemplates{}, &recordingLifecycleServer{}, tc.guard)
			var unavailable ErrDeviceRESTUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, tc.reason, unavailable.Reason)
			assert.Equal(t, http.StatusNotFound,
				serveIAM(s, http.MethodGet, "/api/v1/device/profiles/find-config?mac=52:54:00:12:34:56", "device-reader").Code,
				"a refused mount serves no device route")
		})
	}
}

// Without a template service the device router has no handlers to mount.
func TestSetDeviceRouterHandlers_MountsNothingWithoutServices(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	guard := restapi.NewScopeGuard(deviceRESTCallers, nil, nil)
	require.NoError(t, s.SetDeviceRouterHandlers(logging.DefaultLogger(), routeTableDeviceService{}, deviceRESTProfiles{},
		nil, &recordingLifecycleServer{}, guard))
	assert.Empty(t, restRouteTemplates(t, s, "/api/v1/"))
}

func TestSetDeviceHandlers_RefusesAMissingGuard(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	err := s.SetDeviceHandlers(routeTableDevices{}, routeTableProfiles{}, nil, nil)
	var unavailable ErrDeviceRESTUnavailable
	require.ErrorAs(t, err, &unavailable)
	assert.Equal(t, "no REST scope guard", unavailable.Reason)
	assert.Empty(t, restRouteTemplates(t, s, "/api/v1/"))
}

// The device facade's routes need the device scope of their method.
func TestSetDeviceHandlers_ScopePerRoute(t *testing.T) {
	s := &RESTServer{router: mux.NewRouter(), logger: slog.Default()}
	require.NoError(t, s.SetDeviceHandlers(routeTableDevices{}, routeTableProfiles{}, nil,
		restapi.NewScopeGuard(deviceRESTCallers, nil, nil)))
	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/devices/7", "").Code)
	recorder := serveIAM(s, http.MethodPost, "/api/v1/devices/7/activate", "device-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope device:write required")
	recorder = serveIAM(s, http.MethodDelete, "/api/v1/devices/profiles/7", "device-writer")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope device:delete required")
}

// A device:read caller reads a booting machine's profile but cannot disable
// a device; the disable never reaches the service.
func TestDeviceRouterREST_ScopePerRoute(t *testing.T) {
	lifecycle := &recordingLifecycleServer{}
	s := deviceRESTServer(t, deviceRESTCallers, lifecycle)

	recorder := serveIAM(s, http.MethodGet, "/api/v1/device/profiles/find-config?mac=52:54:00:12:34:56", "device-reader")
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Contains(t, recorder.Body.String(), "edge")

	recorder = serveIAM(s, http.MethodPost, "/api/v1/devices/7/disable", "device-reader")
	assert.Equal(t, http.StatusForbidden, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "scope device:write required")
	assert.Zero(t, lifecycle.disables.Load())

	recorder = serveIAM(s, http.MethodPost, "/api/v1/devices/7/disable", "device-writer")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(1), lifecycle.disables.Load())

	assert.Equal(t, http.StatusUnauthorized, serveIAM(s, http.MethodGet, "/api/v1/device/profiles/find-config?mac=x", "").Code)
}

// The per-route authorizer checks the caller in the request context: 401
// without one, even when the request carries a valid credential, because it
// never authenticates again; 403 for a caller without the scope. Only an
// admitted request reaches the handler.
func TestRestScopeAuthorizer_RequireScope(t *testing.T) {
	authorizer := restScopeAuthorizer{guard: restapi.NewScopeGuard(deviceRESTCallers, nil, nil)}
	reached := 0
	handler := authorizer.RequireScope("device:write")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }))
	serve := func(caller *platformtoken.AuthorizedContext) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/7/disable", nil)
		req.Header.Set("Authorization", "Bearer device-writer")
		if caller != nil {
			req = req.WithContext(restapi.ContextWithCaller(req.Context(), caller))
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	reader, err := deviceRESTCallers.AuthorizeToken(context.Background(), "device-reader", "", "", "", "")
	require.NoError(t, err)
	writer, err := deviceRESTCallers.AuthorizeToken(context.Background(), "device-writer", "", "", "", "")
	require.NoError(t, err)

	assert.Equal(t, http.StatusUnauthorized, serve(nil))
	assert.Equal(t, http.StatusForbidden, serve(reader))
	assert.Zero(t, reached)
	serve(writer)
	assert.Equal(t, 1, reached)
}

func TestDeviceRouteScope(t *testing.T) {
	cases := []struct{ method, route, scope string }{
		{http.MethodGet, "/api/v1/device/profiles/find-config", "device:read"},
		{http.MethodPost, "/api/v1/device/profiles/match", "device:read"},
		{http.MethodPost, "/api/v1/devices/{id:[0-9]+}/disable", "device:write"},
		{http.MethodPut, "/api/v1/device/templates/{id:[0-9]+}", "device:write"},
		{http.MethodDelete, "/api/v1/devices/{id}", "device:delete"},
	}
	for _, tc := range cases {
		scope, err := deviceRouteScope(tc.method, tc.route)
		require.NoError(t, err, "%s %s", tc.method, tc.route)
		assert.Equal(t, tc.scope, scope, "%s %s", tc.method, tc.route)
	}
	_, err := deviceRouteScope(http.MethodOptions, "/api/v1/devices")
	var forbidden restapi.ErrRouteForbidden
	require.ErrorAs(t, err, &forbidden)
	assert.Equal(t, "device:*", forbidden.Scope)
}

// restRouteTemplates are the route templates under prefix the server's
// router holds.
func restRouteTemplates(t *testing.T, s *RESTServer, prefix string) []string {
	t.Helper()
	var templates []string
	require.NoError(t, s.router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if template, err := route.GetPathTemplate(); err == nil && strings.HasPrefix(template, prefix) {
			templates = append(templates, template)
		}
		return nil
	}))
	return templates
}

// The router's own per-route check runs behind the path guard on the caller
// the path guard authenticated: an admitted request authenticates once.
func TestDeviceRouterREST_RouterChecksItsOwnScope(t *testing.T) {
	tokens := &countingTokens{}
	s := deviceRESTServer(t, tokens, &recordingLifecycleServer{})
	recorder := serveIAM(s, http.MethodPost, "/api/v1/devices/7/disable", "device-writer")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(1), tokens.authorizations.Load())
}

// signDPoPBound mints a device:read token bound by cnf.jkt to the DPoP key
// jkt, signed by key so the shared validator verifies it.
func signDPoPBound(t *testing.T, key *ptIssuerKey, jkt string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       testPTIssuer,
		"aud":       []string{testPTAudience},
		"sub":       "device-reader",
		"tenant_id": iamRESTTenantA,
		"scp":       []string{"device:read"},
		"exp":       now.Add(10 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"jti":       "jti-dpop-device-reader",
		"cnf":       map[string]string{"jkt": jkt},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = key.kid
	token.Header["typ"] = "at+jwt"
	signed, err := token.SignedString(key.priv)
	require.NoError(t, err)
	return signed
}

// A DPoP-bound token reaches a device route through the daemon's real
// platform-token validator: the path guard and the router's own scope check
// verify its proof once, so the proof is not refused as its own replay. The
// same proof sent again is the replay, and is refused with 401.
func TestDeviceRouterREST_DPoPProofVerifiedOnce(t *testing.T) {
	issuer := newPTIssuerKey(t)
	validator := newSharedValidator(t, issuer.jwksHandler(t).URL, false)
	s := deviceRESTServer(t, validator, &recordingLifecycleServer{})

	dpopKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jkt, err := quicbaas.DPoPThumbprint(dpopKey.Public())
	require.NoError(t, err)
	token := signDPoPBound(t, issuer, jkt)
	const path = "/api/v1/device/profiles/find-config?mac=52:54:00:12:34:56"
	proof, err := quicbaas.NewDPoPProof(dpopKey, http.MethodGet, "http://example.com/api/v1/device/profiles/find-config")
	require.NoError(t, err)
	serve := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("DPoP", proof)
		recorder := httptest.NewRecorder()
		s.router.ServeHTTP(recorder, req)
		return recorder
	}

	recorder := serve()
	assert.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
	assert.Contains(t, recorder.Body.String(), "edge")

	recorder = serve()
	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "replay")
}
