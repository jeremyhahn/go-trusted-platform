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

func TestNewDeviceRouter(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}

	router := NewDeviceRouter(mockMTLS, mockHandler, nil, nil, nil)

	require.NotNil(t, router)
	deviceRouter, ok := router.(*DeviceRouter)
	require.True(t, ok)
	assert.NotNil(t, deviceRouter.mtlsMiddleware)
	assert.NotNil(t, deviceRouter.deviceHandler)
	assert.Nil(t, deviceRouter.crudHandler)
}

func TestNewDeviceRouterWithCRUD(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}
	mockCRUD := &MockDeviceCRUDHandler{}

	router := NewDeviceRouter(mockMTLS, mockHandler, mockCRUD, nil, nil)

	require.NotNil(t, router)
	deviceRouter, ok := router.(*DeviceRouter)
	require.True(t, ok)
	assert.NotNil(t, deviceRouter.mtlsMiddleware)
	assert.NotNil(t, deviceRouter.deviceHandler)
	assert.NotNil(t, deviceRouter.crudHandler)
}

func TestDeviceRouter_RegisterRoutes(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}

	deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, nil, nil, nil)
	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		deviceRouter.RegisterRoutes(muxRouter)
	})
}

func TestDeviceRouter_RegisterRoutes_WithCRUD(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}
	mockCRUD := &MockDeviceCRUDHandler{}

	deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, mockCRUD, nil, nil)
	muxRouter := mux.NewRouter()

	require.NotPanics(t, func() {
		deviceRouter.RegisterRoutes(muxRouter)
	})
}

func TestDeviceRouter_ProfileEndpoint(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}
	mockMTLS.On("Verify", mock.Anything, mock.Anything, mock.Anything).Return()
	mockHandler.On("GetProfile", mock.Anything, mock.Anything).Return()

	deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, nil, nil, nil)
	muxRouter := mux.NewRouter()
	deviceRouter.RegisterRoutes(muxRouter)

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

	deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, nil, nil, nil)
	muxRouter := mux.NewRouter()
	deviceRouter.RegisterRoutes(muxRouter)

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

	deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, nil, nil, nil)
	muxRouter := mux.NewRouter()
	deviceRouter.RegisterRoutes(muxRouter)

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

			deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, mockCRUD, nil, nil)
			muxRouter := mux.NewRouter()
			deviceRouter.RegisterRoutes(muxRouter)

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

			deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, mockCRUD, nil, nil)
			muxRouter := mux.NewRouter()
			deviceRouter.RegisterRoutes(muxRouter)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			muxRouter.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			mockCRUD.AssertExpectations(t)
		})
	}
}

func TestDeviceRouter_WithoutCRUD_NoCRUDRoutes(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}

	deviceRouter := NewDeviceRouter(mockMTLS, mockHandler, nil, nil, nil)
	muxRouter := mux.NewRouter()
	deviceRouter.RegisterRoutes(muxRouter)

	// CRUD endpoints should return 404 when no CRUD handler
	req := httptest.NewRequest(http.MethodPost, "/devices", nil)
	rec := httptest.NewRecorder()
	muxRouter.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDeviceRouter_ImplementsInterface(t *testing.T) {
	mockMTLS := &MockMTLSMiddleware{}
	mockHandler := &MockDeviceRestHandler{}

	var router = NewDeviceRouter(mockMTLS, mockHandler, nil, nil, nil)
	assert.NotNil(t, router)
	assert.Implements(t, (*WebServiceRouter)(nil), router)
}
