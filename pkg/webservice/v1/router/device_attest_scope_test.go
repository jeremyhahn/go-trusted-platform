// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package router

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// grantingValidator accepts any bearer token and grants a fixed scope set,
// so a test controls exactly what the caller may do.
type grantingValidator struct {
	scopes []string
}

func (v grantingValidator) Validate(context.Context, string, string, string, string) (*platformtoken.AuthorizedContext, error) {
	return &platformtoken.AuthorizedContext{Subject: "operator", TenantID: "t1", Scopes: v.scopes}, nil
}

// attestOK answers the attestation and lifecycle routes with 200, standing
// in for the real handlers so a test sees only whether the scope check let
// it through.
type attestOK struct{}

func (attestOK) HandleDisable(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (attestOK) HandleEnable(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (attestOK) HandleAttestDevice(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (attestOK) HandleRecordAttestCert(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// newAttestMux mounts the attestation routes behind the platform token
// middleware granting scopes, as router.go wires them.
func newAttestMux(t *testing.T, scopes ...string) http.Handler {
	t.Helper()
	return newScopedDeviceMux(t, &MockDeviceCRUDHandler{}, scopes...)
}

// newScopedDeviceMux is newAttestMux with the device CRUD handler supplied,
// so a test can assert whether a scoped CRUD route reached it.
func newScopedDeviceMux(t *testing.T, crud *MockDeviceCRUDHandler, scopes ...string) http.Handler {
	t.Helper()
	logger := logging.NewLogger(slog.LevelDebug, nil)
	mw, err := iammw.NewPlatformTokenMiddleware(logger, response.NewResponseWriter(logger, nil),
		grantingValidator{scopes: scopes}, iammw.PlatformTokenConfig{AllowBearer: true})
	require.NoError(t, err)

	deviceRouter := newOperatorDeviceRouter(t, crud)
	deviceRouter.SetScopeAuthorizer(mw)
	m := mux.NewRouter()
	deviceRouter.RegisterRoutes(m)
	return mw.Handler(m)
}

// newOperatorDeviceRouter builds a device router with every operator
// capability present, so RegisterRoutes mounts the whole operator surface.
func newOperatorDeviceRouter(t *testing.T, crud *MockDeviceCRUDHandler) *DeviceRouter {
	t.Helper()
	deviceRouter, err := NewDeviceRouter(&MockMTLSMiddleware{}, nil,
		crud, &MockTemplateCRUDHandler{}, &MockConfigDeliveryHandler{}, attestOK{})
	require.NoError(t, err)
	deviceRouter.SetAttestCertHandler(attestOK{})
	deviceRouter.SetLifecycleHandler(attestOK{})
	return deviceRouter
}

// attestRoutes are the device writes the webservice scope-checks: the two
// attestation routes, the two lifecycle transitions (#250) and template
// create, which needs device:write on every other transport (#873).
var attestRoutes = map[string]string{
	"AttestDevice":          "/devices/7/attest",
	"RecordAttestationCert": "/devices/7/attest-cert/record",
	"DisableDevice":         "/devices/7/disable",
	"EnableDevice":          "/devices/7/enable",
	"CreateTemplate":        "/device/templates",
}

func postAttest(handler http.Handler, path string) int {
	return serveDeviceRoute(handler, http.MethodPost, path)
}

func TestDeviceRouter_AttestRoutes_RefuseAReadOnlyToken(t *testing.T) {
	handler := newAttestMux(t, "device:read")
	for name, path := range attestRoutes {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, http.StatusForbidden, postAttest(handler, path),
				"a device:read token must not reach a device write")
		})
	}
}

func TestDeviceRouter_AttestRoutes_AllowDeviceWrite(t *testing.T) {
	handler := newAttestMux(t, "device:write")
	for name, path := range attestRoutes {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, postAttest(handler, path))
		})
	}
}

// TestDeviceRouter_AttestRoutes_RoleGateAloneWithoutScopes pins the legacy
// JWT path: with no scope authorizer the routes are left to the admin role
// gate instead of refusing every request.
func TestDeviceRouter_AttestRoutes_RoleGateAloneWithoutScopes(t *testing.T) {
	m := mux.NewRouter()
	newOperatorDeviceRouter(t, &MockDeviceCRUDHandler{}).RegisterRoutes(m)
	for name, path := range attestRoutes {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, postAttest(m, path))
		})
	}
}

// scopedOperatorRoutes is every device CRUD, profile, template and
// provisioning-session route RegisterRoutes mounts, with the scope its gRPC
// twin takes in pkg/api/grpc/method_permissions.go (#484). The template get,
// update, delete and list routes are REST-only and take the device
// resource's matching action. crud names the MockDeviceCRUDHandler method
// behind the route; it is empty for the template and provisioning routes,
// whose mock handlers record nothing and answer 200.
var scopedOperatorRoutes = []struct {
	method, path, scope, crud string
}{
	{http.MethodPost, "/devices", "device:write", "CreateDevice"},
	{http.MethodGet, "/devices", "device:read", "ListDevices"},
	{http.MethodGet, "/devices/count", "device:read", "CountDevices"},
	{http.MethodGet, "/devices/serial/SN1", "device:read", "FindDeviceBySerial"},
	{http.MethodGet, "/devices/7", "device:read", "GetDevice"},
	{http.MethodPut, "/devices/7", "device:write", "UpdateDevice"},
	{http.MethodDelete, "/devices/7", "device:delete", "DeleteDevice"},

	{http.MethodPost, "/device/profiles", "device:write", "CreateProfile"},
	{http.MethodGet, "/device/profiles", "device:read", "ListProfiles"},
	{http.MethodGet, "/device/profiles/count", "device:read", "CountProfiles"},
	{http.MethodPost, "/device/profiles/match", "device:read", "FindMatchingProfile"},
	{http.MethodGet, "/device/profiles/serial/SN1", "device:read", "FindProfileBySerial"},
	{http.MethodGet, "/device/profiles/mac/00:11:22:33:44:55", "device:read", "FindProfileByMAC"},
	{http.MethodGet, "/device/profiles/7", "device:read", "GetProfileByID"},
	{http.MethodPut, "/device/profiles/7", "device:write", "UpdateProfile"},
	{http.MethodDelete, "/device/profiles/7", "device:delete", "DeleteProfile"},
	{http.MethodPost, "/device/activate-json", "device:write", "ActivateDevice"},

	{http.MethodGet, "/device/profiles/find-config", "device:read", ""},
	{http.MethodPost, "/device/profiles/7/assign", "device:write", ""},
	{http.MethodPost, "/device/profiles/7/unassign", "device:write", ""},

	{http.MethodPost, "/device/templates", "device:write", ""},
	{http.MethodGet, "/device/templates", "device:read", ""},
	{http.MethodGet, "/device/templates/name/edge", "device:read", ""},
	{http.MethodGet, "/device/templates/7", "device:read", ""},
	{http.MethodPut, "/device/templates/7", "device:write", ""},
	{http.MethodDelete, "/device/templates/7", "device:delete", ""},
	{http.MethodPost, "/device/templates/7/create-profile", "device:write", ""},

	{http.MethodPost, "/provisioning/sessions/s1/fulfill", "provisioning:write", ""},
	{http.MethodGet, "/provisioning/sessions", "provisioning:read", ""},
	{http.MethodGet, "/provisioning/sessions/s1", "provisioning:read", ""},
}

// allScopesBut returns every device and provisioning scope except scope, so a
// refusal proves the route needs exactly that scope and no neighbour of it.
func allScopesBut(scope string) []string {
	all := []string{"device:read", "device:write", "device:delete",
		"provisioning:read", "provisioning:write"}
	others := make([]string, 0, len(all)-1)
	for _, s := range all {
		if s != scope {
			others = append(others, s)
		}
	}
	return others
}

// serveDeviceRoute sends a bearer-token request and returns the status.
func serveDeviceRoute(handler http.Handler, method, path string) int {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(iammw.AuthorizationHeader, iammw.BearerPrefix+"t")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Code
}

// expectCRUDCall arms crud for the route's handler, if it has one.
func expectCRUDCall(crud *MockDeviceCRUDHandler, method string) {
	if method != "" {
		crud.On(method, mock.Anything, mock.Anything).Return()
	}
}

func TestDeviceRouter_OperatorRoutes_AllowTheirScope(t *testing.T) {
	for _, route := range scopedOperatorRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			crud := &MockDeviceCRUDHandler{}
			expectCRUDCall(crud, route.crud)
			handler := newScopedDeviceMux(t, crud, route.scope)

			code := serveDeviceRoute(handler, route.method, route.path)
			assert.True(t, code == http.StatusOK || code == http.StatusCreated,
				"%s %s with %s answered %d", route.method, route.path, route.scope, code)
			crud.AssertExpectations(t)
		})
	}
}

func TestDeviceRouter_OperatorRoutes_RefuseEveryOtherScope(t *testing.T) {
	for _, route := range scopedOperatorRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			crud := &MockDeviceCRUDHandler{}
			handler := newScopedDeviceMux(t, crud, allScopesBut(route.scope)...)

			assert.Equal(t, http.StatusForbidden, serveDeviceRoute(handler, route.method, route.path))
			crud.AssertNotCalled(t, route.crud, mock.Anything, mock.Anything)
		})
	}
}

// Under the legacy JWT handler no scope authorizer is configured, and the
// admin role gate in front of the router is the whole check.
func TestDeviceRouter_OperatorRoutes_RoleGateAloneWithoutScopes(t *testing.T) {
	for _, route := range scopedOperatorRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			crud := &MockDeviceCRUDHandler{}
			expectCRUDCall(crud, route.crud)
			m := mux.NewRouter()
			newOperatorDeviceRouter(t, crud).RegisterRoutes(m)

			code := serveDeviceRoute(m, route.method, route.path)
			assert.True(t, code == http.StatusOK || code == http.StatusCreated,
				"%s %s answered %d", route.method, route.path, code)
			crud.AssertExpectations(t)
		})
	}
}
