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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
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

func TestNewHandler(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	require.NotNil(t, handler)
	h, ok := handler.(*Handler)
	require.True(t, ok)
	assert.NotNil(t, h.logger)
	assert.NotNil(t, h.responseWriter)
	assert.NotNil(t, h.policyEngine)
	assert.NotNil(t, h.profileService)
	assert.NotNil(t, h.arpTable)
}

func TestGetProfile_Success(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		TrustedNetwork: NetworkConfig{
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
	assert.Equal(t, uint16(100), response.TrustedNetwork.VLAN)
	assert.True(t, response.TrustedNetwork.UseDHCP)
	assert.Len(t, response.ACLs, 1)

	mockProfileService.AssertExpectations(t)
}

func TestGetProfile_MissingSerial(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
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
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
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
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
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
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
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
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		TrustedNetwork: NetworkConfig{
			VLAN:    200,
			UseDHCP: false,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", "aa:bb:cc:dd:ee:ff", policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", "aa:bb:cc:dd:ee:ff", mock.AnythingOfType("*policy.PortPolicy")).Return(nil)

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

	mockARPTable.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
}

func TestActivate_MissingSerial(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	mockResponseWriter.On("Error400", mock.Anything, mock.Anything, ErrMissingSerial).Return()

	// Create request without serial
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
}

func TestActivate_EmptySerial(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
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
}

func TestActivate_ARPLookupFailed(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(nil, errors.New("ARP entry not found"))
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything, ErrARPLookupFailed).Return()

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
	mockARPTable.AssertExpectations(t)
	mockProfileService.AssertNotCalled(t, "GetBySerial")
}

func TestActivate_ProfileNotFound(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "UNKNOWN-DEVICE").Return(nil, ErrProfileNotFoundBySerial)
	mockResponseWriter.On("Error404", mock.Anything, mock.Anything, ErrProfileNotFound).Return()

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "UNKNOWN-DEVICE")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	mockResponseWriter.AssertExpectations(t)
	mockARPTable.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
	mockPolicyEngine.AssertNotCalled(t, "SetPortState")
}

func TestActivate_PortTransitionFailed(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		TrustedNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", "aa:bb:cc:dd:ee:ff", policy.PortStateAuthorized).Return(errors.New("port transition failed"))
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything, ErrPortTransitionFailed).Return()

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
	mockARPTable.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
}

func TestActivate_PolicyApplicationFails_ContinuesAnyway(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		TrustedNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", "aa:bb:cc:dd:ee:ff", policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", "aa:bb:cc:dd:ee:ff", mock.AnythingOfType("*policy.PortPolicy")).Return(errors.New("policy application failed"))

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert - Should still succeed even though policy application failed
	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)

	mockARPTable.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
}

func TestExtractClientIP_XForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractClientIP(req)
	assert.Equal(t, "10.0.0.5", ip)
}

func TestExtractClientIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:54321"

	ip := extractClientIP(req)
	assert.Equal(t, "192.168.1.100", ip)
}

func TestExtractClientIP_RemoteAddrWithoutPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100"

	ip := extractClientIP(req)
	assert.Equal(t, "192.168.1.100", ip)
}

func TestExtractClientIP_IPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "[2001:db8::1]:8080"

	ip := extractClientIP(req)
	assert.Equal(t, "2001:db8::1", ip)
}

func TestExtractClientIP_XForwardedForWithMultipleIPs(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 192.168.1.1")
	req.RemoteAddr = "127.0.0.1:8080"

	ip := extractClientIP(req)
	// Returns the full header value - first IP is typically the client
	assert.Equal(t, "10.0.0.5, 192.168.1.1", ip)
}

func TestActivate_WithXForwardedFor(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		TrustedNetwork: NetworkConfig{
			VLAN: 300,
		},
	}

	macAddr, _ := net.ParseMAC("11:22:33:44:55:66")

	// Should use X-Forwarded-For IP for ARP lookup
	mockARPTable.On("LookupMAC", "10.5.5.5").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", "11:22:33:44:55:66", policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", "11:22:33:44:55:66", mock.AnythingOfType("*policy.PortPolicy")).Return(nil)

	// Create request with X-Forwarded-For
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.Header.Set("X-Forwarded-For", "10.5.5.5")
	req.RemoteAddr = "192.168.1.1:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Execute
	handler.Activate(w, req)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)

	mockARPTable.AssertExpectations(t)
	mockProfileService.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
}

func TestActivate_PortPolicyCorrectlySet(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		TrustedNetwork: NetworkConfig{
			VLAN: 500,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", "aa:bb:cc:dd:ee:ff", policy.PortStateAuthorized).Return(nil)

	// Capture the policy argument
	var capturedPolicy *policy.PortPolicy
	mockPolicyEngine.On("ApplyPolicy", "aa:bb:cc:dd:ee:ff", mock.AnythingOfType("*policy.PortPolicy")).
		Run(func(args mock.Arguments) {
			capturedPolicy = args.Get(1).(*policy.PortPolicy)
		}).Return(nil)

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	beforeTime := time.Now().UTC()

	// Execute
	handler.Activate(w, req)

	afterTime := time.Now().UTC()

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedPolicy)
	assert.Equal(t, uint16(500), capturedPolicy.VLAN)
	assert.True(t, capturedPolicy.IssuedAt.After(beforeTime) || capturedPolicy.IssuedAt.Equal(beforeTime))
	assert.True(t, capturedPolicy.IssuedAt.Before(afterTime) || capturedPolicy.IssuedAt.Equal(afterTime))

	mockPolicyEngine.AssertExpectations(t)
}

func TestActivate_NonSerialContextValue(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
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
}

func TestGetProfile_WithRateLimit(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-WITH-RATELIMIT",
		TrustedNetwork: NetworkConfig{
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
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-STATIC",
		TrustedNetwork: NetworkConfig{
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
	assert.False(t, response.TrustedNetwork.UseDHCP)
	assert.Equal(t, "10.100.1.50", response.TrustedNetwork.StaticIP)
	assert.Equal(t, "10.100.1.1", response.TrustedNetwork.Gateway)
	assert.Len(t, response.TrustedNetwork.DNS, 2)

	mockProfileService.AssertExpectations(t)
}

func TestGetProfile_MultipleACLs(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-ACLS",
		TrustedNetwork: NetworkConfig{
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
func TestErrorVariables(t *testing.T) {
	assert.NotNil(t, ErrMissingSerial)
	assert.NotNil(t, ErrProfileNotFound)
	assert.NotNil(t, ErrARPLookupFailed)
	assert.NotNil(t, ErrPortTransitionFailed)

	assert.Contains(t, ErrMissingSerial.Error(), "serial")
	assert.Contains(t, ErrProfileNotFound.Error(), "profile")
	assert.Contains(t, ErrARPLookupFailed.Error(), "MAC")
	assert.Contains(t, ErrPortTransitionFailed.Error(), "port")
}

func TestActivate_UsesCorrectPortID(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		TrustedNetwork: NetworkConfig{
			VLAN: 100,
		},
	}

	// Use a specific MAC address to verify portID is set correctly
	macAddr, _ := net.ParseMAC("de:ad:be:ef:ca:fe")
	expectedPortID := "de:ad:be:ef:ca:fe"

	mockARPTable.On("LookupMAC", "10.0.0.1").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", expectedPortID, policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", expectedPortID, mock.AnythingOfType("*policy.PortPolicy")).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockARPTable.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
}

func TestActivate_ResponseContainsCorrectFields(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-999",
		TrustedNetwork: NetworkConfig{
			VLAN: 777,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", mock.Anything).Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-999").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", mock.Anything, policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", mock.Anything, mock.Anything).Return(nil)

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

func TestActivate_RealARPTable(t *testing.T) {
	// Test with real ARP table interface implementation
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	realARPTable := arp.NewTable()

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		realARPTable,
	)

	require.NotNil(t, handler)
	h, ok := handler.(*Handler)
	require.True(t, ok)
	assert.NotNil(t, h.arpTable)
}
