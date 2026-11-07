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

package device

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgdevice "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newTestLogger creates a test logger with minimal output
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

// newTestResponseWriter creates a real response writer for testing
func newTestResponseWriter() response.HttpWriter {
	logger := newTestLogger()
	return response.NewResponseWriter(logger, nil)
}

// activatedResult is the activator result for a clean activation on vlan.
func activatedResult(vlan uint16) *policy.ActivationResult {
	return &policy.ActivationResult{
		Status: policy.ActivationStatusActivated,
		PortID: "port1",
		VLAN:   vlan,
		Zone:   "control-plane",
	}
}

// quarantinedResult is the activator result for an enforced quarantine on
// vlan — the quarantine VLAN, never the admitted one.
func quarantinedResult(vlan uint16) *policy.ActivationResult {
	return &policy.ActivationResult{
		Status: policy.ActivationStatusQuarantined,
		PortID: "port1",
		VLAN:   vlan,
		Zone:   "quarantine",
		ZoneMismatch: &policy.ErrZoneMismatch{
			CertZone:    "tenant-a",
			ProfileZone: "tenant-b",
			Serial:      "DEVICE-12345",
		},
	}
}

func TestNewHandler(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	require.NotNil(t, handler)
	h, ok := handler.(*Handler)
	require.True(t, ok)
	assert.NotNil(t, h.logger)
	assert.NotNil(t, h.responseWriter)
	assert.NotNil(t, h.activator)
	assert.NotNil(t, h.profileService)
}

func TestGetProfile_Success(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		AdmittedNetwork: NetworkConfig{
			VLAN:    100,
			UseDHCP: true,
			DNS:     []string{"10.99.99.2"},
		},
		ACLs: []ACLConfig{
			{
				Name:     "allow-https",
				Priority: 100,
				Match:    map[string]string{"tcp_dst": "443"},
				Action:   "allow",
			},
		},
	}

	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)

	// Create request with device serial in context
	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.GetProfile(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ProfileResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "DEVICE-12345", response.SerialNumber)
	assert.Equal(t, uint16(100), response.AdmittedNetwork.VLAN)
	assert.True(t, response.AdmittedNetwork.UseDHCP)
	assert.Len(t, response.ACLs, 1)

	mockProfileService.AssertExpectations(t)
}

func TestGetProfile_MissingSerial(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	mockResponseWriter.On("Error400", mock.Anything, mock.Anything, ErrMissingSerial).Return()

	// Create request without device serial in context
	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.GetProfile(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockProfileService.AssertNotCalled(t, "GetBySerial")
}

func TestGetProfile_EmptySerial(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	mockResponseWriter.On("Error400", mock.Anything, mock.Anything, ErrMissingSerial).Return()

	// Create request with empty serial
	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.GetProfile(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockProfileService.AssertNotCalled(t, "GetBySerial")
}

func TestGetProfile_ProfileNotFound(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	mockProfileService.On("GetBySerial", mock.Anything, "UNKNOWN-DEVICE").Return(nil, ErrProfileNotFoundBySerial)
	mockResponseWriter.On("Error404", mock.Anything, mock.Anything, ErrProfileNotFound).Return()

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "UNKNOWN-DEVICE")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.GetProfile(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
}

func TestGetProfile_NonStringContextValue(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	mockResponseWriter.On("Error400", mock.Anything, mock.Anything, ErrMissingSerial).Return()

	// Create request with non-string context value
	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, []byte("test"))
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.GetProfile(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockProfileService.AssertNotCalled(t, "GetBySerial")
}

func TestActivate_Success(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(200), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)
	assert.Equal(t, uint16(200), response.VLAN)
	assert.False(t, response.TransitionedAt.IsZero())

	mockProfileService.AssertNotCalled(t, "GetBySerial", mock.Anything, mock.Anything)
	mockActivator.AssertExpectations(t)
}

// TestActivate_DeferredManagementLANDevice_RoutesThroughHook proves that
// the public activation route runs the SDN enrollment hook's ActivateDevice
// for a device that enrolled over the management LAN: the handler passes
// the mTLS-derived serial straight to the activator, which owns the
// deferred port resolution, and requires no ARP or port knowledge of its own.
func TestActivate_DeferredManagementLANDevice_RoutesThroughHook(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	plan := newSwitchTestPlan("SRV-MGMT-01", 300)
	mockActivator.On("PrecheckActivation", "SRV-MGMT-01").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(300), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.100.50:40000"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "SRV-MGMT-01")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)
	assert.Equal(t, uint16(300), response.VLAN)

	mockActivator.AssertExpectations(t)
}

// TestActivate_HookFailureNotSwallowed verifies that an activator error is
// surfaced to the client as a 500 rather than logged and ignored.
func TestActivate_HookFailureNotSwallowed(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	hookErr := errors.New("flow installation failed")

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(nil, hookErr).Once()
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything, hookErr).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_NoPendingActivation_Returns404 verifies the typed
// no-pending-activation error maps to a 404 response.
func TestActivate_NoPendingActivation_Returns404(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	hookErr := policy.ErrNoPendingActivation{Serial: "DEVICE-12345"}

	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(nil, hookErr).Once()
	mockResponseWriter.On("Error404", mock.Anything, mock.Anything, hookErr).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_PortNotRegistered_Returns404 verifies that a device whose
// port is still unknown (it has not attached to the fabric) receives a 404
// and the failure is not swallowed; the client can retry after attaching.
func TestActivate_PortNotRegistered_Returns404(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	hookErr := policy.ErrPortNotRegisteredForDevice{MAC: "3c:ec:ef:00:00:ec"}

	mockActivator.On("PrecheckActivation", "SRV-MGMT-01").Return(nil, hookErr).Once()
	mockResponseWriter.On("Error404", mock.Anything, mock.Anything, hookErr).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.100.50:40000"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "SRV-MGMT-01")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_ZoneMismatch_ReturnsQuarantined verifies that a plan
// carrying a zone mismatch — where the hook applies the quarantine policy —
// reports the device as quarantined rather than activated or failed.
func TestActivate_ZoneMismatch_ReturnsQuarantined(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	plan := newQuarantineTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(quarantinedResult(666), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "quarantined", response.Status)
	assert.Equal(t, uint16(666), response.VLAN, "the response carries the VLAN actually applied, not the admitted VLAN")

	mockActivator.AssertExpectations(t)
}

func TestActivate_MissingSerial(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	mockResponseWriter.On("Error400", mock.Anything, mock.Anything, ErrMissingSerial).Return()

	// Create request without serial
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertNotCalled(t, "ActivateDevice")
}

func TestActivate_EmptySerial(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	mockResponseWriter.On("Error400", mock.Anything, mock.Anything, ErrMissingSerial).Return()

	// Create request with empty serial
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertNotCalled(t, "ActivateDevice")
}

// TestActivate_SupersededPlan_Error500 verifies the handler surface of the
// concurrent re-enrollment backstop: a plan whose reserved version was
// replaced before consumption is refused by the activator and surfaced as
// a 500 — never reported as an activation.
func TestActivate_SupersededPlan_Error500(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	hookErr := policy.ErrPendingActivationSuperseded{Serial: "DEVICE-12345"}

	plan := newSwitchTestPlan("DEVICE-12345", 200)
	mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(nil, hookErr).Once()
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything, hookErr).Return()

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertExpectations(t)
}

// TestActivate_ActivationRefusal_Returns404 verifies that the hook's
// retryable refusals at the commit step — the pending activation gone
// (an already-activated device) or the port still unregistered — are 404s,
// not server faults, matching the precheck mapping
// (docs/sdn/provisioning.md, "POST /api/v1/device/activate" errors).
func TestActivate_ActivationRefusal_Returns404(t *testing.T) {
	tests := []struct {
		name    string
		hookErr error
	}{
		{"no pending activation", policy.ErrNoPendingActivation{Serial: "DEVICE-12345"}},
		{"port not registered", policy.ErrPortNotRegisteredForDevice{MAC: "52:54:00:12:34:56"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockResponseWriter := &MockHttpWriter{}
			mockActivator := &MockDeviceActivator{}
			handler := NewHandler(newTestLogger(), mockResponseWriter, mockActivator, &MockProfileService{})

			plan := newSwitchTestPlan("DEVICE-12345", 200)
			mockActivator.On("PrecheckActivation", "DEVICE-12345").Return(plan, nil).Once()
			mockActivator.On("ActivateDevice", plan).Return(nil, tt.hookErr).Once()
			mockResponseWriter.On("Error404", mock.Anything, mock.Anything, tt.hookErr).Return()

			req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
			req = req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345"))

			handler.Activate(httptest.NewRecorder(), req)

			mockResponseWriter.AssertExpectations(t)
			mockResponseWriter.AssertNotCalled(t, "Error500", mock.Anything, mock.Anything, mock.Anything)
			mockActivator.AssertExpectations(t)
			mockActivator.AssertNotCalled(t, "FinalizeActivation", mock.Anything)
		})
	}
}

func TestActivate_NonSerialContextValue(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockActivator,
		mockProfileService,
	)

	mockResponseWriter.On("Error400", mock.Anything, mock.Anything, ErrMissingSerial).Return()

	// Create request with non-string context value
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, 12345) // Integer instead of string
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockActivator.AssertNotCalled(t, "ActivateDevice")
}

func TestGetProfile_WithRateLimit(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-WITH-RATELIMIT",
		AdmittedNetwork: NetworkConfig{
			VLAN:    150,
			UseDHCP: true,
		},
		RateLimit: &RateLimitConfig{
			IngressMbps: 100,
			EgressMbps:  50,
		},
	}

	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-WITH-RATELIMIT").Return(expectedProfile, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-WITH-RATELIMIT")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.GetProfile(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ProfileResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	require.NotNil(t, response.RateLimit)
	assert.Equal(t, 100, response.RateLimit.IngressMbps)
	assert.Equal(t, 50, response.RateLimit.EgressMbps)

	mockProfileService.AssertExpectations(t)
}

func TestGetProfile_WithStaticIP(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-STATIC",
		AdmittedNetwork: NetworkConfig{
			VLAN:     200,
			UseDHCP:  false,
			StaticIP: "10.100.1.50",
			Gateway:  "10.100.1.1",
			DNS:      []string{"10.100.1.2", "8.8.8.8"},
		},
	}

	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-STATIC").Return(expectedProfile, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-STATIC")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.GetProfile(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ProfileResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.False(t, response.AdmittedNetwork.UseDHCP)
	assert.Equal(t, "10.100.1.50", response.AdmittedNetwork.StaticIP)
	assert.Equal(t, "10.100.1.1", response.AdmittedNetwork.Gateway)
	assert.Len(t, response.AdmittedNetwork.DNS, 2)

	mockProfileService.AssertExpectations(t)
}

func TestGetProfile_MultipleACLs(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-ACLS",
		AdmittedNetwork: NetworkConfig{
			VLAN:    100,
			UseDHCP: true,
		},
		ACLs: []ACLConfig{
			{Name: "allow-https", Priority: 100, Match: map[string]string{"tcp_dst": "443"}, Action: "allow"},
			{Name: "allow-dns", Priority: 90, Match: map[string]string{"udp_dst": "53"}, Action: "allow"},
			{Name: "deny-all", Priority: 10, Match: map[string]string{}, Action: "deny"},
		},
	}

	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-ACLS").Return(expectedProfile, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/device/profile", nil)
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-ACLS")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.GetProfile(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ProfileResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Len(t, response.ACLs, 3)
	assert.Equal(t, "allow-https", response.ACLs[0].Name)
	assert.Equal(t, "deny-all", response.ACLs[2].Name)
	assert.Equal(t, "deny", response.ACLs[2].Action)

	mockProfileService.AssertExpectations(t)
}

// TestErrorVariables verifies error variable definitions

func TestActivate_ResponseContainsCorrectFields(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockActivator := &MockDeviceActivator{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockActivator,
		mockProfileService,
	)

	plan := newSwitchTestPlan("DEVICE-999", 777)
	mockActivator.On("PrecheckActivation", "DEVICE-999").Return(plan, nil).Once()
	mockActivator.On("ActivateDevice", plan).Return(activatedResult(777), nil).Once()
	mockActivator.On("FinalizeActivation", plan).Return().Once()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-999")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	beforeActivation := time.Now().UTC()
	handler.Activate(w, req)
	afterActivation := time.Now().UTC()

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)

	// Verify all response fields
	assert.Equal(t, "activated", response.Status)
	assert.Equal(t, uint16(777), response.VLAN)
	assert.False(t, response.TransitionedAt.IsZero())
	assert.True(t, response.TransitionedAt.After(beforeActivation) || response.TransitionedAt.Equal(beforeActivation))
	assert.True(t, response.TransitionedAt.Before(afterActivation) || response.TransitionedAt.Equal(afterActivation))
}

// mockHeartbeatRecorder is a testify mock for the heartbeat seam.
type mockHeartbeatRecorder struct {
	mock.Mock
	peerAddr string
}

func (m *mockHeartbeatRecorder) RecordHeartbeat(ctx context.Context, identity string, peerAddr string) (*deviceentities.Device, error) {
	m.peerAddr = peerAddr
	args := m.Called(ctx, identity)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*deviceentities.Device), args.Error(1)
}

func TestHeartbeat_Success(t *testing.T) {
	recorder := new(mockHeartbeatRecorder)
	now := time.Now().UTC()
	recorder.On("RecordHeartbeat", mock.Anything, "DEVICE-12345").
		Return(&deviceentities.Device{ID: 42, Serial: "DEVICE-12345", LastHeartbeatAt: now}, nil)

	handler := NewHandler(newTestLogger(), newTestResponseWriter(), nil, nil,
		WithHeartbeatRecorder(recorder))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/heartbeat", nil)
	req.RemoteAddr = "10.4.2.143:51234"
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345"))
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp HeartbeatResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, uint64(42), resp.DeviceID)
	assert.Equal(t, "DEVICE-12345", resp.Serial)
	assert.Equal(t, now, resp.ReceivedAt)
	// The transport peer address — never anything from the body — is what
	// the recorder receives (#377).
	assert.Equal(t, "10.4.2.143:51234", recorder.peerAddr)
	recorder.AssertExpectations(t)
}

func TestHeartbeat_MissingSerial(t *testing.T) {
	recorder := new(mockHeartbeatRecorder)
	handler := NewHandler(newTestLogger(), newTestResponseWriter(), nil, nil,
		WithHeartbeatRecorder(recorder))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/heartbeat", nil)
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	recorder.AssertNotCalled(t, "RecordHeartbeat", mock.Anything, mock.Anything)
}

func TestHeartbeat_RecorderNotConfigured(t *testing.T) {
	handler := NewHandler(newTestLogger(), newTestResponseWriter(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/heartbeat", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345"))
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHeartbeat_DeviceNotFound(t *testing.T) {
	recorder := new(mockHeartbeatRecorder)
	recorder.On("RecordHeartbeat", mock.Anything, "GHOST-1").
		Return(nil, &pkgdevice.IdentityNotFoundError{Identity: "GHOST-1", Cause: errors.New("no record")})

	handler := NewHandler(newTestLogger(), newTestResponseWriter(), nil, nil,
		WithHeartbeatRecorder(recorder))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/heartbeat", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "GHOST-1"))
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	recorder.AssertExpectations(t)
}

// TestHeartbeat_StorageFailure proves a post-resolution failure surfaces
// as a 500, never as a misleading 404.
func TestHeartbeat_StorageFailure(t *testing.T) {
	recorder := new(mockHeartbeatRecorder)
	recorder.On("RecordHeartbeat", mock.Anything, "DEVICE-12345").
		Return(nil, errors.New("kv backend unavailable"))

	handler := NewHandler(newTestLogger(), newTestResponseWriter(), nil, nil,
		WithHeartbeatRecorder(recorder))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/heartbeat", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345"))
	w := httptest.NewRecorder()

	handler.Heartbeat(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestActivate_NotConfigured proves an SDN-less deployment answers the
// typed not-configured error instead of panicking on a nil activator.
func TestActivate_NotConfigured(t *testing.T) {
	handler := NewHandler(newTestLogger(), newTestResponseWriter(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req = req.WithContext(context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345"))
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
