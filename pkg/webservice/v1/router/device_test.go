// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
)

// MockMTLSMiddleware implements middleware.MTLSMiddleware
type MockMTLSMiddleware struct {
	mock.Mock
}

func (m *MockMTLSMiddleware) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	m.Called(w, r, next)
	if next != nil {
		next(w, r)
	}
}

// MockDeviceRestHandler implements device.RestHandler
type MockDeviceRestHandler struct {
	mock.Mock
}

func (m *MockDeviceRestHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"profile":"test"}`))
}

func (m *MockDeviceRestHandler) Activate(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"activated":true}`))
}

func (m *MockDeviceRestHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"received_at":"2026-01-01T00:00:00Z"}`))
}

// MockDeviceCRUDHandler implements device.DeviceCRUDHandler
type MockDeviceCRUDHandler struct {
	mock.Mock
}

func (m *MockDeviceCRUDHandler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusCreated)
}

func (m *MockDeviceCRUDHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) CountDevices(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) FindDeviceBySerial(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusCreated)
}

func (m *MockDeviceCRUDHandler) GetProfileByID(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) CountProfiles(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) FindMatchingProfile(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) FindProfileBySerial(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) FindProfileByMAC(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

func (m *MockDeviceCRUDHandler) ActivateDevice(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
}

// registerAllDeviceRoutes mounts BOTH halves of the device surface, the way
// v1Router.deviceRoutes does, so these behavioural tests keep exercising
// every route they were written for. Which half production hands to the
// gated router is asserted by the split tests below, not by this helper.
func registerAllDeviceRoutes(r *DeviceRouter, m *mux.Router) {
	r.RegisterMachineFacingRoutes(m)
	r.RegisterRoutes(m)
}

// newTestDeviceRouter builds a DeviceRouter whose required template handler is
// an inert mock, for tests that exercise the other route groups.
func newTestDeviceRouter(t *testing.T, mtls *MockMTLSMiddleware, deviceHandler *MockDeviceRestHandler, crud *MockDeviceCRUDHandler) *DeviceRouter {
	t.Helper()
	r, err := NewDeviceRouter(mtls, deviceHandler, crud, &MockTemplateCRUDHandler{}, nil, nil)
	require.NoError(t, err)
	return r
}

func TestNewDeviceRouter(t *testing.T) {
	deviceRouter, err := NewDeviceRouter(&MockMTLSMiddleware{}, &MockDeviceRestHandler{},
		&MockDeviceCRUDHandler{}, &MockTemplateCRUDHandler{}, nil, nil)

	require.NoError(t, err)
	require.NotNil(t, deviceRouter)
	assert.NotNil(t, deviceRouter.mtlsMiddleware)
	assert.NotNil(t, deviceRouter.deviceHandler)
	assert.NotNil(t, deviceRouter.crudHandler)
	assert.NotNil(t, deviceRouter.templateHandler)
	assert.Nil(t, deviceRouter.configDeliveryHandler)

	// It still satisfies WebServiceRouter; the concrete return type exists
	// only so the caller can reach RegisterMachineFacingRoutes (#165).
	var _ WebServiceRouter = deviceRouter
}

// TestNewDeviceRouter_RequiresTheHandlersRegisterRoutesDereferences pins
// #320: RegisterRoutes mounts the device, profile and template routes without
// a nil check, so the constructor must refuse a router that would serve them
// with no handler behind them.
func TestNewDeviceRouter_RequiresTheHandlersRegisterRoutesDereferences(t *testing.T) {
	tests := []struct {
		name     string
		crud     wsdevice.DeviceCRUDHandler
		template wsdevice.TemplateCRUDHandler
		missing  string
	}{
		{"no CRUD handler", nil, &MockTemplateCRUDHandler{}, "DeviceCRUDHandler"},
		{"no template handler", &MockDeviceCRUDHandler{}, nil, "TemplateCRUDHandler"},
		{"neither", nil, nil, "DeviceCRUDHandler"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceRouter, err := NewDeviceRouter(&MockMTLSMiddleware{}, &MockDeviceRestHandler{},
				tt.crud, tt.template, &MockConfigDeliveryHandler{}, nil)

			assert.Nil(t, deviceRouter)
			var required ErrDeviceHandlerRequired
			require.ErrorAs(t, err, &required)
			assert.Equal(t, tt.missing, required.Handler)
		})
	}
}

func TestErrDeviceHandlerRequired_Error(t *testing.T) {
	assert.Equal(t, "device router: missing required handler: TemplateCRUDHandler",
		ErrDeviceHandlerRequired{Handler: "TemplateCRUDHandler"}.Error())
}

func TestDeviceRouter_RegisterRoutes(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}

	deviceRouter := newTestDeviceRouter(t, mockMTLS, mockHandler, &MockDeviceCRUDHandler{})
	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		registerAllDeviceRoutes(deviceRouter, muxRouter)
	})
}

func TestDeviceRouter_ProfileEndpoint(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}
	mockMTLS.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockHandler.On("GetProfile", mock.Anything, mock.Anything).Return()

	deviceRouter := newTestDeviceRouter(t, mockMTLS, mockHandler, &MockDeviceCRUDHandler{})
	muxRouter := mux.NewRouter()
	registerAllDeviceRoutes(deviceRouter, muxRouter)

	req := httptest.NewRequest(http.MethodGet, "/device/profile", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDeviceRouter_ActivateEndpoint(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}
	mockMTLS.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockHandler.On("Activate", mock.Anything, mock.Anything).Return()

	deviceRouter := newTestDeviceRouter(t, mockMTLS, mockHandler, &MockDeviceCRUDHandler{})
	muxRouter := mux.NewRouter()
	registerAllDeviceRoutes(deviceRouter, muxRouter)

	req := httptest.NewRequest(http.MethodPost, "/device/activate", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestDeviceRouter_HeartbeatEndpoint proves the heartbeat route is
// registered behind the mTLS verifier like the other device-facing
// routes.
func TestDeviceRouter_HeartbeatEndpoint(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}
	mockMTLS.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockHandler.On("Heartbeat", mock.Anything, mock.Anything).Return()

	deviceRouter := newTestDeviceRouter(t, mockMTLS, mockHandler, &MockDeviceCRUDHandler{})
	muxRouter := mux.NewRouter()
	registerAllDeviceRoutes(deviceRouter, muxRouter)

	req := httptest.NewRequest(http.MethodPost, "/device/heartbeat", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	mockMTLS.AssertCalled(t, "Verify", mock.Anything, mock.Anything, mock.Anything)
	mockHandler.AssertCalled(t, "Heartbeat", mock.Anything, mock.Anything)
}

func TestDeviceRouter_CRUDDeviceEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		handler    string
		wantStatus int
	}{
		{
			name:       "create device",
			method:     http.MethodPost,
			path:       "/devices",
			handler:    "CreateDevice",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "list devices",
			method:     http.MethodGet,
			path:       "/devices",
			handler:    "ListDevices",
			wantStatus: http.StatusOK,
		},
		{
			name:       "count devices",
			method:     http.MethodGet,
			path:       "/devices/count",
			handler:    "CountDevices",
			wantStatus: http.StatusOK,
		},
		{
			name:       "find device by serial",
			method:     http.MethodGet,
			path:       "/devices/serial/SN12345",
			handler:    "FindDeviceBySerial",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get device",
			method:     http.MethodGet,
			path:       "/devices/123",
			handler:    "GetDevice",
			wantStatus: http.StatusOK,
		},
		{
			name:       "update device",
			method:     http.MethodPut,
			path:       "/devices/123",
			handler:    "UpdateDevice",
			wantStatus: http.StatusOK,
		},
		{
			name:       "delete device",
			method:     http.MethodDelete,
			path:       "/devices/123",
			handler:    "DeleteDevice",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMTLS := &MockMTLSMiddleware{}
			mockHandler := &MockDeviceRestHandler{}
			mockCRUD := &MockDeviceCRUDHandler{}
			mockMTLS.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
			mockCRUD.On(tt.handler, mock.Anything, mock.Anything).Return()

			deviceRouter := newTestDeviceRouter(t, mockMTLS, mockHandler, mockCRUD)
			muxRouter := mux.NewRouter()
			registerAllDeviceRoutes(deviceRouter, muxRouter)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			mockCRUD.AssertExpectations(t)
		})
	}
}

func TestDeviceRouter_CRUDProfileEndpoints(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		handler    string
		wantStatus int
	}{
		{
			name:       "create profile",
			method:     http.MethodPost,
			path:       "/device/profiles",
			handler:    "CreateProfile",
			wantStatus: http.StatusCreated,
		},
		{
			name:       "list profiles",
			method:     http.MethodGet,
			path:       "/device/profiles",
			handler:    "ListProfiles",
			wantStatus: http.StatusOK,
		},
		{
			name:       "count profiles",
			method:     http.MethodGet,
			path:       "/device/profiles/count",
			handler:    "CountProfiles",
			wantStatus: http.StatusOK,
		},
		{
			name:       "find profile by serial",
			method:     http.MethodGet,
			path:       "/device/profiles/serial/SN12345",
			handler:    "FindProfileBySerial",
			wantStatus: http.StatusOK,
		},
		{
			name:       "find profile by MAC",
			method:     http.MethodGet,
			path:       "/device/profiles/mac/aa:bb:cc:dd:ee:ff",
			handler:    "FindProfileByMAC",
			wantStatus: http.StatusOK,
		},
		{
			name:       "get profile by ID",
			method:     http.MethodGet,
			path:       "/device/profiles/42",
			handler:    "GetProfileByID",
			wantStatus: http.StatusOK,
		},
		{
			name:       "update profile",
			method:     http.MethodPut,
			path:       "/device/profiles/42",
			handler:    "UpdateProfile",
			wantStatus: http.StatusOK,
		},
		{
			name:       "delete profile",
			method:     http.MethodDelete,
			path:       "/device/profiles/42",
			handler:    "DeleteProfile",
			wantStatus: http.StatusOK,
		},
		{
			name:       "activate device via JSON",
			method:     http.MethodPost,
			path:       "/device/activate-json",
			handler:    "ActivateDevice",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMTLS := &MockMTLSMiddleware{}
			mockHandler := &MockDeviceRestHandler{}
			mockCRUD := &MockDeviceCRUDHandler{}
			mockMTLS.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
			mockCRUD.On(tt.handler, mock.Anything, mock.Anything).Return()

			deviceRouter := newTestDeviceRouter(t, mockMTLS, mockHandler, mockCRUD)
			muxRouter := mux.NewRouter()
			registerAllDeviceRoutes(deviceRouter, muxRouter)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			mockCRUD.AssertExpectations(t)
		})
	}
}

// TestRegisterRoutes_MountsTheTemplateRoutes is the other half of #320: with
// the template handler guaranteed by the constructor, every template and
// profile-assignment route is on the operator half.
func TestRegisterRoutes_MountsTheTemplateRoutes(t *testing.T) {
	r := newTestDeviceRouter(t, &MockMTLSMiddleware{}, &MockDeviceRestHandler{}, &MockDeviceCRUDHandler{})
	operator := registeredDevicePaths(r.RegisterRoutes)

	for _, route := range []string{
		"POST /device/templates",
		"GET /device/templates",
		"GET /device/templates/name/{name}",
		"GET /device/templates/{id:[0-9]+}",
		"PUT /device/templates/{id:[0-9]+}",
		"DELETE /device/templates/{id:[0-9]+}",
		"POST /device/templates/{id:[0-9]+}/create-profile",
		"GET /device/profiles/find-config",
		"POST /device/profiles/{id:[0-9]+}/assign",
		"POST /device/profiles/{id:[0-9]+}/unassign",
	} {
		assert.True(t, operator[route], "%s is not registered", route)
	}
}

func TestDeviceRouter_ImplementsInterface(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}

	var router = newTestDeviceRouter(t, mockMTLS, mockHandler, &MockDeviceCRUDHandler{})
	assert.NotNil(t, router)
	assert.Implements(t, (*WebServiceRouter)(nil), router)
}

// =============================================================================
// The by-principal split (#165 slice 3)
// =============================================================================

// MockTemplateCRUDHandler and MockConfigDeliveryHandler exist so the
// by-principal split tests can register EVERY device route. Registration
// takes method values off the handler, so an embedded nil interface would
// panic; these are no-ops because the split tests assert the route TABLE,
// never handler behaviour.
type MockTemplateCRUDHandler struct{}

func (m *MockTemplateCRUDHandler) CreateTemplate(http.ResponseWriter, *http.Request)            {}
func (m *MockTemplateCRUDHandler) GetTemplate(http.ResponseWriter, *http.Request)               {}
func (m *MockTemplateCRUDHandler) UpdateTemplate(http.ResponseWriter, *http.Request)            {}
func (m *MockTemplateCRUDHandler) DeleteTemplate(http.ResponseWriter, *http.Request)            {}
func (m *MockTemplateCRUDHandler) ListTemplates(http.ResponseWriter, *http.Request)             {}
func (m *MockTemplateCRUDHandler) FindTemplateByName(http.ResponseWriter, *http.Request)        {}
func (m *MockTemplateCRUDHandler) CreateProfileFromTemplate(http.ResponseWriter, *http.Request) {}
func (m *MockTemplateCRUDHandler) FindConfigForDevice(http.ResponseWriter, *http.Request)       {}
func (m *MockTemplateCRUDHandler) AssignProfileToDevice(http.ResponseWriter, *http.Request)     {}
func (m *MockTemplateCRUDHandler) UnassignProfileFromDevice(http.ResponseWriter, *http.Request) {}

type MockConfigDeliveryHandler struct{}

func (m *MockConfigDeliveryHandler) GetNonce(http.ResponseWriter, *http.Request)       {}
func (m *MockConfigDeliveryHandler) FetchConfig(http.ResponseWriter, *http.Request)    {}
func (m *MockConfigDeliveryHandler) SignDigest(http.ResponseWriter, *http.Request)     {}
func (m *MockConfigDeliveryHandler) PollSession(http.ResponseWriter, *http.Request)    {}
func (m *MockConfigDeliveryHandler) FulfillSession(http.ResponseWriter, *http.Request) {}
func (m *MockConfigDeliveryHandler) ListSessions(http.ResponseWriter, *http.Request)   {}
func (m *MockConfigDeliveryHandler) GetSession(http.ResponseWriter, *http.Request)     {}

// registeredDevicePaths returns the "METHOD /path" set one registration
// method installs, so the split is asserted by its effect on the route table
// rather than by reading the source.
func registeredDevicePaths(register func(*mux.Router)) map[string]bool {
	m := mux.NewRouter()
	register(m)

	out := map[string]bool{}
	_ = m.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil || len(methods) == 0 {
			methods = []string{http.MethodGet}
		}
		for _, meth := range methods {
			out[meth+" "+path] = true
		}
		return nil
	})
	return out
}

// TestRegisterMachineFacingRoutes_IsExactlyTheDeviceFacingSet pins the half
// that must stay off the role gate. A route drifting OUT of here starts
// demanding an operator session from a machine that has none — for
// /provisioning/{config,sign} that is a device at boot with no client
// certificate at all, so the failure is "provisioning impossible", not
// "request denied".
func TestRegisterMachineFacingRoutes_IsExactlyTheDeviceFacingSet(t *testing.T) {
	r, err := NewDeviceRouter(
		&MockMTLSMiddleware{},
		&MockDeviceRestHandler{},
		&MockDeviceCRUDHandler{},
		&MockTemplateCRUDHandler{},
		&MockConfigDeliveryHandler{},
		nil,
	)
	require.NoError(t, err)

	assert.Equal(t, map[string]bool{
		"GET /device/profile":                         true,
		"POST /device/activate":                       true,
		"POST /device/heartbeat":                      true,
		"POST /provisioning/config":                   true,
		"GET /provisioning/config/nonce":              true,
		"POST /provisioning/sign":                     true,
		"GET /provisioning/sessions/{sessionID}/poll": true,
	}, registeredDevicePaths(r.RegisterMachineFacingRoutes))
}

// TestRegisterRoutes_ExcludesEveryMachineFacingRoute is the assertion that
// matters for the gate: nothing a device calls may appear in the half the
// caller mounts behind the admin guard.
func TestRegisterRoutes_ExcludesEveryMachineFacingRoute(t *testing.T) {
	r, err := NewDeviceRouter(
		&MockMTLSMiddleware{},
		&MockDeviceRestHandler{},
		&MockDeviceCRUDHandler{},
		&MockTemplateCRUDHandler{},
		&MockConfigDeliveryHandler{},
		nil,
	)
	require.NoError(t, err)

	operator := registeredDevicePaths(r.RegisterRoutes)
	machine := registeredDevicePaths(r.RegisterMachineFacingRoutes)

	for route := range machine {
		assert.False(t, operator[route],
			"%s is device-facing but was registered on the gated half", route)
	}

	// And the operator half must carry the session surface, including
	// fulfilment — binding a profile to a waiting device decides what
	// configuration that machine boots with.
	assert.True(t, operator["POST /provisioning/sessions/{sessionID}/fulfill"])
	assert.True(t, operator["GET /provisioning/sessions"])
	assert.True(t, operator["GET /provisioning/sessions/{sessionID}"])
	assert.True(t, operator["POST /devices"])
	assert.True(t, operator["DELETE /devices/{id:[0-9]+}"])
}
