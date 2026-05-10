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
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestActivate_WithSwitchService_VLANTransition(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
		WithSwitchService(mockSwitchService),
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		ProductionNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).Return(nil)
	mockPolicyEngine.On("SetPortState", "aa:bb:cc:dd:ee:ff", policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", "aa:bb:cc:dd:ee:ff", mock.AnythingOfType("*policy.PortPolicy")).Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	ctx = context.WithValue(ctx, contextKeySwitchName, "spine-01")
	ctx = context.WithValue(ctx, contextKeySwitchPort, "Eth1/3")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)
	assert.Equal(t, uint16(200), response.VLAN)

	mockSwitchService.AssertExpectations(t)
	mockSwitchManager.AssertExpectations(t)
	mockPolicyEngine.AssertExpectations(t)
}

func TestActivate_SwitchVLANFailed_ReturnsError(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}
	mockSwitchService := &MockSwitchService{}
	mockSwitchManager := &MockSwitchManager{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
		WithSwitchService(mockSwitchService),
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		ProductionNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockSwitchService.On("Manager", "spine-01").Return(mockSwitchManager, nil)
	mockSwitchManager.On("SetPortVLAN", mock.Anything, "Eth1/3", uint16(200)).
		Return(errors.New("SSH connection refused"))

	// The handler returns a 500 error when VLAN transition fails.
	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchVLANTransitionFailed)
			return ok
		})).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	ctx = context.WithValue(ctx, contextKeySwitchName, "spine-01")
	ctx = context.WithValue(ctx, contextKeySwitchPort, "Eth1/3")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	mockResponseWriter.AssertExpectations(t)
	// Port state should NOT be transitioned when VLAN move fails.
	mockPolicyEngine.AssertNotCalled(t, "SetPortState")
}

func TestActivate_SwitchNotConfigured_ReturnsError(t *testing.T) {
	logger := newTestLogger()
	mockResponseWriter := &MockHttpWriter{}
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		mockResponseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
		WithSwitchService(mockSwitchService),
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		ProductionNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockSwitchService.On("Manager", "unknown-switch").
		Return(nil, errors.New("manager not found"))

	mockResponseWriter.On("Error500", mock.Anything, mock.Anything,
		mock.MatchedBy(func(err error) bool {
			_, ok := err.(ErrSwitchNotConfigured)
			return ok
		})).Return()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	ctx = context.WithValue(ctx, contextKeySwitchName, "unknown-switch")
	ctx = context.WithValue(ctx, contextKeySwitchPort, "Eth1/5")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	mockResponseWriter.AssertExpectations(t)
	mockPolicyEngine.AssertNotCalled(t, "SetPortState")
}

func TestActivate_NoSwitchInfo_SkipsVLANMove(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
		WithSwitchService(mockSwitchService),
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		ProductionNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", "aa:bb:cc:dd:ee:ff", policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", "aa:bb:cc:dd:ee:ff", mock.AnythingOfType("*policy.PortPolicy")).Return(nil)

	// No switch context values set - VLAN move should be skipped.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Switch service Manager should never be called when context has no switch info.
	mockSwitchService.AssertNotCalled(t, "Manager")
}

func TestActivate_NilSwitchService_SkipsVLANMove(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}

	// No WithSwitchService option - handler has nil switchService.
	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
	)

	expectedProfile := &ProfileResponse{
		SerialNumber: "DEVICE-12345",
		ProductionNetwork: NetworkConfig{
			VLAN: 200,
		},
	}

	macAddr, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	mockARPTable.On("LookupMAC", "192.168.1.100").Return(macAddr, nil)
	mockProfileService.On("GetBySerial", mock.Anything, "DEVICE-12345").Return(expectedProfile, nil)
	mockPolicyEngine.On("SetPortState", "aa:bb:cc:dd:ee:ff", policy.PortStateAuthorized).Return(nil)
	mockPolicyEngine.On("ApplyPolicy", "aa:bb:cc:dd:ee:ff", mock.AnythingOfType("*policy.PortPolicy")).Return(nil)

	// Context has switch info but handler has no switch service.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/device/activate", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ctx := context.WithValue(req.Context(), ContextKeyDeviceSerial, "DEVICE-12345")
	ctx = context.WithValue(ctx, contextKeySwitchName, "spine-01")
	ctx = context.WithValue(ctx, contextKeySwitchPort, "Eth1/3")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.Activate(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response ActivateResponse
	err := json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "activated", response.Status)
}

func TestWithSwitchService_SetsField(t *testing.T) {
	logger := newTestLogger()
	responseWriter := newTestResponseWriter()
	mockProfileService := &MockProfileService{}
	mockPolicyEngine := &MockPolicyEngine{}
	mockARPTable := &MockARPTable{}
	mockSwitchService := &MockSwitchService{}

	handler := NewHandler(
		logger,
		responseWriter,
		mockPolicyEngine,
		mockProfileService,
		mockARPTable,
		WithSwitchService(mockSwitchService),
	)

	require.NotNil(t, handler)
	h, ok := handler.(*Handler)
	require.True(t, ok)
	assert.NotNil(t, h.switchService)
	assert.Equal(t, mockSwitchService, h.switchService)
}

func TestErrSwitchNotConfigured(t *testing.T) {
	err := ErrSwitchNotConfigured{SwitchName: "spine-01"}
	assert.Contains(t, err.Error(), "switch not configured")
	assert.Contains(t, err.Error(), "spine-01")
}

func TestErrSwitchVLANTransitionFailed(t *testing.T) {
	cause := errors.New("SSH connection refused")
	err := ErrSwitchVLANTransitionFailed{
		SwitchName: "spine-01",
		Port:       "Eth1/3",
		VLAN:       200,
		Cause:      cause,
	}
	assert.Contains(t, err.Error(), "switch vlan transition failed")
	assert.Contains(t, err.Error(), "spine-01")
	assert.Contains(t, err.Error(), "Eth1/3")
	assert.Contains(t, err.Error(), "SSH connection refused")
	assert.Equal(t, cause, errors.Unwrap(err))
}

func TestErrSwitchVLANTransitionFailed_NilCause(t *testing.T) {
	err := ErrSwitchVLANTransitionFailed{
		SwitchName: "spine-01",
		Port:       "Eth1/3",
		VLAN:       200,
	}
	assert.Contains(t, err.Error(), "switch vlan transition failed")
	assert.NotContains(t, err.Error(), "cause=")
	assert.Nil(t, errors.Unwrap(err))
}
