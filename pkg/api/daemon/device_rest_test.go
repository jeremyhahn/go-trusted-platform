package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/mux"
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
	"device-writer":  {Subject: "device-writer", TenantID: iamRESTTenantA, Scopes: []string{"device:write"}},
	"device-deleter": {Subject: "device-deleter", TenantID: iamRESTTenantA, Scopes: []string{"device:delete"}},
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

// TestDeviceRouterREST_ServesTheIntegrationLeaves pins every route the
// integration REST adapter calls for devices, profiles and templates: each
// must be mounted, so the router answers with something other than 404 or 405.
func TestDeviceRouterREST_ServesTheIntegrationLeaves(t *testing.T) {
	s := deviceRESTServer(t, deviceRESTCallers, &recordingLifecycleServer{})

	leaves := []struct {
		leaf, method, path, token string
	}{
		{"OperatorLifecycle CreateDevice", http.MethodPost, "/api/v1/devices", "device-writer"},
		{"OperatorLifecycle ListDevices", http.MethodGet, "/api/v1/devices?limit=10&offset=0", "device-reader"},
		{"OperatorLifecycle GetDevice", http.MethodGet, "/api/v1/devices/7", "device-reader"},
		{"OperatorLifecycle UpdateDevice", http.MethodPut, "/api/v1/devices/7", "device-writer"},
		{"OperatorLifecycle DeleteDevice", http.MethodDelete, "/api/v1/devices/7", "device-deleter"},
		{"OperatorLifecycle FindDeviceBySerial", http.MethodGet, "/api/v1/devices/serial/SN-1", "device-reader"},
		{"OperatorLifecycle DisableDevice", http.MethodPost, "/api/v1/devices/7/disable", "device-writer"},
		{"OperatorLifecycle EnableDevice", http.MethodPost, "/api/v1/devices/7/enable", "device-writer"},
		{"Attestation RecordAttestCert", http.MethodPost, "/api/v1/devices/7/attest-cert/record", "device-writer"},
		{"ConfigForDevice FindConfigByEKSerial", http.MethodGet, "/api/v1/device/profiles/find-config?ek_serial=EK-1", "device-reader"},
		{"ConfigForDevice FindConfigByMAC", http.MethodGet, "/api/v1/device/profiles/find-config?mac=52:54:00:12:34:56", "device-reader"},
		{"ProfileAssignment AssignProfileToDevice", http.MethodPost, "/api/v1/device/profiles/7/assign", "device-writer"},
		{"ProfileLookups FindMatchingProfile", http.MethodPost, "/api/v1/device/profiles/match", "device-reader"},
		{"ProfileLookups FindProfileByMACAddress", http.MethodGet, "/api/v1/device/profiles/mac/52:54:00:12:34:56", "device-reader"},
		{"ProfileLookups FindProfileBySerial", http.MethodGet, "/api/v1/device/profiles/serial/SN-1", "device-reader"},
		{"TemplateCRUD CreateTemplate", http.MethodPost, "/api/v1/device/templates", "device-writer"},
		{"TemplateCRUD GetTemplate", http.MethodGet, "/api/v1/device/templates/7", "device-reader"},
		{"TemplateCRUD UpdateTemplate", http.MethodPut, "/api/v1/device/templates/7", "device-writer"},
		{"TemplateCRUD DeleteTemplate", http.MethodDelete, "/api/v1/device/templates/7", "device-deleter"},
		{"TemplateCRUD ListTemplates", http.MethodGet, "/api/v1/device/templates?limit=10&offset=0", "device-reader"},
		{"TemplateToProfile CreateProfileFromTemplate", http.MethodPost, "/api/v1/device/templates/7/create-profile", "device-writer"},
	}
	for _, leaf := range leaves {
		t.Run(leaf.leaf, func(t *testing.T) {
			// Match routes without running the handler: the route-table
			// fakes answer only the calls the scope tests make.
			req, err := http.NewRequest(leaf.method, leaf.path, nil)
			require.NoError(t, err)
			var match mux.RouteMatch
			assert.True(t, s.router.Match(req, &match), "%s %s is not served", leaf.method, leaf.path)
			assert.NoError(t, match.MatchErr)
		})
	}
}

// The per-route authorizer answers 401 without a credential and 403 without
// the scope, and only an admitted request reaches the handler.
func TestRestScopeAuthorizer_RequireScope(t *testing.T) {
	authorizer := restScopeAuthorizer{guard: restapi.NewScopeGuard(deviceRESTCallers, nil, nil)}
	reached := 0
	handler := authorizer.RequireScope("device:write")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached++ }))
	serve := func(token string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/7/disable", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		return recorder.Code
	}
	assert.Equal(t, http.StatusUnauthorized, serve(""))
	assert.Equal(t, http.StatusForbidden, serve("device-reader"))
	assert.Zero(t, reached)
	serve("device-writer")
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

// The router's own per-route check runs behind the path guard: the mount
// installs the scope authorizer, so an admitted request is authorized twice,
// once by the path-level check and once by the route's own.
func TestDeviceRouterREST_RouterChecksItsOwnScope(t *testing.T) {
	tokens := &countingTokens{}
	s := deviceRESTServer(t, tokens, &recordingLifecycleServer{})
	recorder := serveIAM(s, http.MethodPost, "/api/v1/devices/7/disable", "device-writer")
	assertReachedHandler(t, recorder, recorder.Body.String())
	assert.Equal(t, int32(2), tokens.authorizations.Load())
}
