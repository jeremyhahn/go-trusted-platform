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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock PXE Service
// =============================================================================

type mockPXEService struct {
	devices map[string]*pxe.DeviceInfo
	running bool
	status  *pxe.ServiceStatus

	registerDeviceErr    error
	getDeviceErr         error
	getDeviceByMACErr    error
	listDevicesErr       error
	removeDeviceErr      error
	updateDeviceStateErr error
	authorizeDeviceErr   error
	quarantineDeviceErr  error
	retryDeviceErr       error
	setDeviceEnrolledErr error
	getEventsErr         error
	startErr             error
	stopErr              error
}

func newMockPXEService() *mockPXEService {
	return &mockPXEService{
		devices: make(map[string]*pxe.DeviceInfo),
		running: false,
		status: &pxe.ServiceStatus{
			Running:          false,
			DeviceCount:      0,
			QuarantineVLAN:   100,
			ProvisioningVLAN: 200,
		},
	}
}

func (m *mockPXEService) Initialize(ctx context.Context, config *pxe.ServiceConfig) error {
	return nil
}

func (m *mockPXEService) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.running = true
	m.status.Running = true
	m.status.StartTime = time.Now()
	return nil
}

func (m *mockPXEService) Stop(ctx context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running = false
	m.status.Running = false
	return nil
}

func (m *mockPXEService) IsRunning() bool {
	return m.running
}

func (m *mockPXEService) Close() error {
	return nil
}

func (m *mockPXEService) RegisterDevice(ctx context.Context, macAddress, portID string) (*pxe.DeviceInfo, error) {
	if m.registerDeviceErr != nil {
		return nil, m.registerDeviceErr
	}

	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, pxe.ErrInvalidMACAddress{MACAddress: macAddress, Reason: err.Error()}
	}

	for _, d := range m.devices {
		if d.MACAddress.String() == mac.String() {
			return nil, pxe.ErrDeviceAlreadyExists{MACAddress: mac.String()}
		}
	}

	now := time.Now()
	device := &pxe.DeviceInfo{
		ID:             "device-" + macAddress,
		MACAddress:     mac,
		PortID:         portID,
		State:          pxe.StateDiscovered,
		StateReason:    "device registered",
		CurrentVLAN:    100,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
		Events:         []*pxe.ProvisioningEvent{},
	}

	m.devices[device.ID] = device
	m.status.DeviceCount = len(m.devices)
	return device, nil
}

func (m *mockPXEService) GetDevice(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
	if m.getDeviceErr != nil {
		return nil, m.getDeviceErr
	}

	device, exists := m.devices[deviceID]
	if !exists {
		return nil, pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	return device, nil
}

func (m *mockPXEService) GetDeviceByMAC(ctx context.Context, mac string) (*pxe.DeviceInfo, error) {
	if m.getDeviceByMACErr != nil {
		return nil, m.getDeviceByMACErr
	}

	parsedMAC, err := net.ParseMAC(mac)
	if err != nil {
		return nil, pxe.ErrInvalidMACAddress{MACAddress: mac, Reason: err.Error()}
	}

	for _, device := range m.devices {
		if device.MACAddress.String() == parsedMAC.String() {
			return device, nil
		}
	}
	return nil, pxe.ErrDeviceNotFound{MACAddress: mac}
}

func (m *mockPXEService) ListDevices(ctx context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error) {
	if m.listDevicesErr != nil {
		return nil, m.listDevicesErr
	}

	result := make([]*pxe.DeviceInfo, 0, len(m.devices))
	for _, device := range m.devices {
		if filter != nil && !filter.Matches(device) {
			continue
		}
		result = append(result, device)
	}
	return result, nil
}

func (m *mockPXEService) RemoveDevice(ctx context.Context, deviceID string) error {
	if m.removeDeviceErr != nil {
		return m.removeDeviceErr
	}

	if _, exists := m.devices[deviceID]; !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}

	delete(m.devices, deviceID)
	m.status.DeviceCount = len(m.devices)
	return nil
}

func (m *mockPXEService) UpdateDeviceState(ctx context.Context, deviceID string, state pxe.ProvisioningState, reason string) error {
	if m.updateDeviceStateErr != nil {
		return m.updateDeviceStateErr
	}

	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(state) {
		return pxe.ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(state),
		}
	}

	device.State = state
	device.StateReason = reason
	device.UpdatedAt = time.Now()
	device.StateChangedAt = time.Now()
	return nil
}

func (m *mockPXEService) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) error {
	if m.setDeviceEnrolledErr != nil {
		return m.setDeviceEnrolledErr
	}

	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(pxe.StateEnrolled) {
		return pxe.ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(pxe.StateEnrolled),
		}
	}

	device.CertificateSerial = certSerial
	device.State = pxe.StateEnrolled
	device.UpdatedAt = time.Now()
	device.StateChangedAt = time.Now()
	return nil
}

func (m *mockPXEService) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) error {
	if m.authorizeDeviceErr != nil {
		return m.authorizeDeviceErr
	}

	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(pxe.StateAuthorized) {
		return pxe.ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(pxe.StateAuthorized),
		}
	}

	device.TargetVLAN = targetVLAN
	device.CurrentVLAN = targetVLAN
	device.State = pxe.StateAuthorized
	return nil
}

func (m *mockPXEService) QuarantineDevice(ctx context.Context, deviceID string, reason string) error {
	if m.quarantineDeviceErr != nil {
		return m.quarantineDeviceErr
	}

	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(pxe.StateQuarantined) {
		return pxe.ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(pxe.StateQuarantined),
		}
	}

	device.State = pxe.StateQuarantined
	device.StateReason = reason
	return nil
}

func (m *mockPXEService) RetryDevice(ctx context.Context, deviceID string) error {
	if m.retryDeviceErr != nil {
		return m.retryDeviceErr
	}

	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}

	if !device.State.CanTransitionTo(pxe.StateDiscovered) {
		return pxe.ErrInvalidStateTransition{
			DeviceID:  deviceID,
			FromState: string(device.State),
			ToState:   string(pxe.StateDiscovered),
		}
	}

	device.State = pxe.StateDiscovered
	device.RetryCount++
	return nil
}

func (m *mockPXEService) GetEvents(ctx context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error) {
	if m.getEventsErr != nil {
		return nil, m.getEventsErr
	}

	device, exists := m.devices[deviceID]
	if !exists {
		return nil, pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	return device.Events, nil
}

func (m *mockPXEService) RegisterEventHandler(handler pxe.EventHandler) {}

func (m *mockPXEService) Status() *pxe.ServiceStatus {
	return m.status
}

// Helper methods for test setup
func (m *mockPXEService) addTestDevice(id, macStr, portID string, state pxe.ProvisioningState) *pxe.DeviceInfo {
	mac, _ := net.ParseMAC(macStr)
	now := time.Now()
	device := &pxe.DeviceInfo{
		ID:             id,
		MACAddress:     mac,
		PortID:         portID,
		State:          state,
		StateReason:    "test device",
		CurrentVLAN:    100,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
		Events:         []*pxe.ProvisioningEvent{},
	}
	m.devices[id] = device
	m.status.DeviceCount = len(m.devices)
	return device
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupPXETestHandler(svc *mockPXEService) (*PXEHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewPXEHandlers(svc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodePXEResponse(t *testing.T, body *bytes.Buffer, v interface{}) {
	t.Helper()
	err := json.NewDecoder(body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestPXEHandlerErrors(t *testing.T) {
	t.Run("ErrPXEServiceNotAvailable", func(t *testing.T) {
		err := ErrPXEServiceNotAvailable{}
		assert.Equal(t, "PXE service not available", err.Error())
	})

	t.Run("ErrPXEServiceNotRunning", func(t *testing.T) {
		err := ErrPXEServiceNotRunning{}
		assert.Equal(t, "PXE service is not running", err.Error())
	})

	t.Run("ErrInvalidPXEDeviceID with empty ID", func(t *testing.T) {
		err := ErrInvalidPXEDeviceID{}
		assert.Equal(t, "device ID is required", err.Error())
	})

	t.Run("ErrInvalidPXEDeviceID with ID", func(t *testing.T) {
		err := ErrInvalidPXEDeviceID{ID: "bad-id"}
		assert.Equal(t, "invalid device ID: bad-id", err.Error())
	})

	t.Run("ErrInvalidMACAddressFormat with empty", func(t *testing.T) {
		err := ErrInvalidMACAddressFormat{}
		assert.Equal(t, "invalid MAC address format", err.Error())
	})

	t.Run("ErrInvalidMACAddressFormat with MAC", func(t *testing.T) {
		err := ErrInvalidMACAddressFormat{MACAddress: "invalid"}
		assert.Equal(t, "invalid MAC address format: invalid", err.Error())
	})

	t.Run("ErrInvalidMACAddressFormat with reason", func(t *testing.T) {
		err := ErrInvalidMACAddressFormat{MACAddress: "invalid", Reason: "bad format"}
		assert.Equal(t, "invalid MAC address format: invalid (bad format)", err.Error())
	})

	t.Run("ErrPXEDeviceNotFound", func(t *testing.T) {
		err := ErrPXEDeviceNotFound{ID: "device-123"}
		assert.Equal(t, "PXE device not found: device-123", err.Error())
	})

	t.Run("ErrPXEDeviceAlreadyExists", func(t *testing.T) {
		err := ErrPXEDeviceAlreadyExists{MACAddress: "aa:bb:cc:dd:ee:ff"}
		assert.Equal(t, "PXE device already exists with MAC: aa:bb:cc:dd:ee:ff", err.Error())
	})

	t.Run("ErrPXEInvalidStateTransition", func(t *testing.T) {
		err := ErrPXEInvalidStateTransition{
			DeviceID:  "device-1",
			FromState: "discovered",
			ToState:   "authorized",
		}
		assert.Equal(t, "invalid state transition from discovered to authorized for device device-1", err.Error())
	})

	t.Run("ErrPXEOperationFailed", func(t *testing.T) {
		cause := pxe.ErrDeviceNotFound{DeviceID: "test"}
		err := ErrPXEOperationFailed{Operation: "get_device", Cause: cause}
		assert.Contains(t, err.Error(), "PXE operation get_device failed")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrMissingMACAddress", func(t *testing.T) {
		err := ErrMissingMACAddress{}
		assert.Equal(t, "MAC address is required", err.Error())
	})
}

// =============================================================================
// Device Handler Tests
// =============================================================================

func TestPXEListDevices(t *testing.T) {
	t.Run("success_empty", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEListDevicesResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, 0, resp.Total)
		assert.Empty(t, resp.Devices)
	})

	t.Run("success_with_devices", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:01", "port-1", pxe.StateDiscovered)
		svc.addTestDevice("device-2", "aa:bb:cc:dd:ee:02", "port-2", pxe.StateBooting)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEListDevicesResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, 2, resp.Total)
		assert.Len(t, resp.Devices, 2)
	})

	t.Run("with_filters", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:01", "port-1", pxe.StateDiscovered)
		svc.addTestDevice("device-2", "aa:bb:cc:dd:ee:02", "port-2", pxe.StateBooting)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices?state=discovered&limit=10&offset=0", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEListDevicesResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, 1, resp.Total)
		assert.Equal(t, 10, resp.Limit)
		assert.Equal(t, 0, resp.Offset)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXEGetDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:01", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/device-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEDeviceResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, device.ID, resp.ID)
		assert.Equal(t, device.MACAddress.String(), resp.MACAddress)
		assert.Equal(t, string(device.State), resp.State)
	})

	t.Run("not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/device-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXEGetDeviceByMAC(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:01", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:01", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEDeviceResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, device.ID, resp.ID)
		assert.Equal(t, device.MACAddress.String(), resp.MACAddress)
		assert.Equal(t, string(device.State), resp.State)
	})

	t.Run("not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid_mac_address", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/mac/invalid-mac", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("service_error", func(t *testing.T) {
		svc := newMockPXEService()
		svc.getDeviceByMACErr = pxe.ErrProvisioningFailed{Reason: "test error"}
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestPXERegisterDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXERegisterDeviceRequest{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			PortID:     "port-1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp PXEDeviceResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", resp.MACAddress)
		assert.Equal(t, "port-1", resp.PortID)
		assert.Equal(t, "discovered", resp.State)
	})

	t.Run("missing_mac_address", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXERegisterDeviceRequest{
			PortID: "port-1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing_port_id", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXERegisterDeviceRequest{
			MACAddress: "aa:bb:cc:dd:ee:ff",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid_mac_address", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXERegisterDeviceRequest{
			MACAddress: "invalid-mac",
			PortID:     "port-1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("device_already_exists", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXERegisterDeviceRequest{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			PortID:     "port-2",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("invalid_json", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := PXERegisterDeviceRequest{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			PortID:     "port-1",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXERemoveDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/pxe/devices/device-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "remove", resp.Action)
		assert.Equal(t, "device-1", resp.DeviceID)
	})

	t.Run("not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/pxe/devices/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/pxe/devices/device-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXEUpdateState(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEUpdateStateRequest{
			State:  "booting",
			Reason: "PXE boot started",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/pxe/devices/device-1/state", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "update_state", resp.Action)
	})

	t.Run("missing_state", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEUpdateStateRequest{
			Reason: "some reason",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/pxe/devices/device-1/state", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid_state", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEUpdateStateRequest{
			State: "invalid_state",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/pxe/devices/device-1/state", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid_state_transition", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEUpdateStateRequest{
			State: "authorized",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/pxe/devices/device-1/state", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("device_not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXEUpdateStateRequest{
			State: "booting",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/pxe/devices/nonexistent/state", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := PXEUpdateStateRequest{
			State: "booting",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/pxe/devices/device-1/state", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXEAuthorizeDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateAuthorizing)
		device.State = pxe.StateAuthorizing
		_, router := setupPXETestHandler(svc)

		reqBody := PXEAuthorizeDeviceRequest{
			TargetVLAN: 300,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "authorize", resp.Action)
	})

	t.Run("missing_target_vlan", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateAuthorizing)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEAuthorizeDeviceRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("device_not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXEAuthorizeDeviceRequest{
			TargetVLAN: 300,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/nonexistent/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid_state_transition", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEAuthorizeDeviceRequest{
			TargetVLAN: 300,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := PXEAuthorizeDeviceRequest{
			TargetVLAN: 300,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/authorize", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXEQuarantineDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEQuarantineDeviceRequest{
			Reason: "security violation detected",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/quarantine", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "quarantine", resp.Action)
	})

	t.Run("missing_reason", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXEQuarantineDeviceRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/quarantine", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("device_not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXEQuarantineDeviceRequest{
			Reason: "test reason",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/nonexistent/quarantine", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := PXEQuarantineDeviceRequest{
			Reason: "test reason",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/quarantine", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXERetryDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateFailed)
		device.State = pxe.StateFailed
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/retry", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "retry", resp.Action)
	})

	t.Run("device_not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/nonexistent/retry", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid_state_transition", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/retry", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/retry", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXESetDeviceEnrolled(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateEnrolling)
		device.State = pxe.StateEnrolling
		_, router := setupPXETestHandler(svc)

		reqBody := PXESetDeviceEnrolledRequest{
			CertSerial: "cert-serial-12345",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/enrolled", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "set_enrolled", resp.Action)
		assert.Equal(t, "device-1", resp.DeviceID)
		assert.Contains(t, resp.Message, "cert-serial-12345")
	})

	t.Run("missing_cert_serial", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateEnrolling)
		_, router := setupPXETestHandler(svc)

		reqBody := PXESetDeviceEnrolledRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/enrolled", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("device_not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		reqBody := PXESetDeviceEnrolledRequest{
			CertSerial: "cert-serial-12345",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/nonexistent/enrolled", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid_state_transition", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		reqBody := PXESetDeviceEnrolledRequest{
			CertSerial: "cert-serial-12345",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/enrolled", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("invalid_json", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateEnrolling)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/enrolled", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := PXESetDeviceEnrolledRequest{
			CertSerial: "cert-serial-12345",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/enrolled", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("service_error", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateEnrolling)
		svc.setDeviceEnrolledErr = pxe.ErrProvisioningFailed{Reason: "test error"}
		_, router := setupPXETestHandler(svc)

		reqBody := PXESetDeviceEnrolledRequest{
			CertSerial: "cert-serial-12345",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/devices/device-1/enrolled", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestPXEGetEvents(t *testing.T) {
	t.Run("success_empty_events", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/device-1/events", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEEventsResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, "device-1", resp.DeviceID)
		assert.Equal(t, 0, resp.Total)
		assert.Empty(t, resp.Events)
	})

	t.Run("success_with_events", func(t *testing.T) {
		svc := newMockPXEService()
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		device.Events = []*pxe.ProvisioningEvent{
			{
				ID:        "event-1",
				DeviceID:  "device-1",
				Timestamp: time.Now(),
				EventType: pxe.EventDeviceDiscovered,
				FromState: pxe.StateUnknown,
				ToState:   pxe.StateDiscovered,
				Details:   map[string]string{"key": "value"},
			},
			{
				ID:        "event-2",
				DeviceID:  "device-1",
				Timestamp: time.Now(),
				EventType: pxe.EventPXEBootStarted,
				FromState: pxe.StateDiscovered,
				ToState:   pxe.StateBooting,
				Details:   map[string]string{"reason": "PXE boot started"},
			},
		}
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/device-1/events", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEEventsResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.Equal(t, "device-1", resp.DeviceID)
		assert.Equal(t, 2, resp.Total)
		assert.Len(t, resp.Events, 2)
		assert.Equal(t, "event-1", resp.Events[0].ID)
		assert.Equal(t, "device_discovered", resp.Events[0].EventType)
		assert.Equal(t, "unknown", resp.Events[0].FromState)
		assert.Equal(t, "discovered", resp.Events[0].ToState)
		assert.Equal(t, "value", resp.Events[0].Details["key"])
	})

	t.Run("device_not_found", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/nonexistent/events", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/device-1/events", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("service_error", func(t *testing.T) {
		svc := newMockPXEService()
		svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateDiscovered)
		svc.getEventsErr = pxe.ErrProvisioningFailed{Reason: "test error"}
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/devices/device-1/events", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// =============================================================================
// Service Handler Tests
// =============================================================================

func TestPXEStatus(t *testing.T) {
	t.Run("success_not_running", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEStatusResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.False(t, resp.Running)
		assert.Equal(t, uint16(100), resp.QuarantineVLAN)
		assert.Equal(t, uint16(200), resp.ProvisioningVLAN)
	})

	t.Run("success_running", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		svc.status.Running = true
		svc.status.StartTime = time.Now()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEStatusResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Running)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/pxe/status", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXEStart(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "start", resp.Action)
		assert.True(t, svc.running)
	})

	t.Run("already_running", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("start_error", func(t *testing.T) {
		svc := newMockPXEService()
		svc.startErr = pxe.ErrServiceNotInitialized{}
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/start", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestPXEStop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "stop", resp.Action)
		assert.False(t, svc.running)
	})

	t.Run("not_running", func(t *testing.T) {
		svc := newMockPXEService()
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("stop_error", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		svc.stopErr = pxe.ErrProvisioningFailed{Reason: "test error"}
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/stop", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// =============================================================================
// Webhook Handler Tests
// =============================================================================

func TestPXEWebhookComplete(t *testing.T) {
	t.Run("success_install_complete", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateInstalling)
		device.State = pxe.StateInstalling
		_, router := setupPXETestHandler(svc)

		payload := pxe.WebhookPayload{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			Hostname:   "server-01",
			Success:    true,
			Message:    "installation completed",
			Timestamp:  time.Now(),
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "webhook_complete", resp.Action)
	})

	t.Run("success_install_failed", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		device := svc.addTestDevice("device-1", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateInstalling)
		device.State = pxe.StateInstalling
		_, router := setupPXETestHandler(svc)

		payload := pxe.WebhookPayload{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			Hostname:   "server-01",
			Success:    false,
			Message:    "installation failed: disk error",
			Timestamp:  time.Now(),
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PXEActionResponse
		decodePXEResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
	})

	t.Run("missing_mac_address", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		_, router := setupPXETestHandler(svc)

		payload := pxe.WebhookPayload{
			Hostname: "server-01",
			Success:  true,
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("device_not_found", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		_, router := setupPXETestHandler(svc)

		payload := pxe.WebhookPayload{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			Success:    true,
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service_not_running", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = false
		_, router := setupPXETestHandler(svc)

		payload := pxe.WebhookPayload{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			Success:    true,
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("invalid_json", func(t *testing.T) {
		svc := newMockPXEService()
		svc.running = true
		_, router := setupPXETestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service_not_available", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		payload := pxe.WebhookPayload{
			MACAddress: "aa:bb:cc:dd:ee:ff",
			Success:    true,
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/pxe/webhook/complete", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestPXEDeviceToResponse(t *testing.T) {
	t.Run("basic_conversion", func(t *testing.T) {
		svc := newMockPXEService()
		handlers := NewPXEHandlers(svc, nil)

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		now := time.Now()
		device := &pxe.DeviceInfo{
			ID:                "device-1",
			MACAddress:        mac,
			PortID:            "port-1",
			State:             pxe.StateDiscovered,
			StateReason:       "test reason",
			CertificateSerial: "cert-123",
			CurrentVLAN:       100,
			TargetVLAN:        200,
			RetryCount:        2,
			CreatedAt:         now,
			UpdatedAt:         now,
			StateChangedAt:    now,
			Events:            []*pxe.ProvisioningEvent{},
		}

		resp := handlers.deviceToResponse(device)

		assert.Equal(t, "device-1", resp.ID)
		assert.Equal(t, "aa:bb:cc:dd:ee:ff", resp.MACAddress)
		assert.Equal(t, "port-1", resp.PortID)
		assert.Equal(t, "discovered", resp.State)
		assert.Equal(t, "test reason", resp.StateReason)
		assert.Equal(t, "cert-123", resp.CertificateSerial)
		assert.Equal(t, uint16(100), resp.CurrentVLAN)
		assert.Equal(t, uint16(200), resp.TargetVLAN)
		assert.Equal(t, 2, resp.RetryCount)
	})

	t.Run("with_events", func(t *testing.T) {
		svc := newMockPXEService()
		handlers := NewPXEHandlers(svc, nil)

		mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
		now := time.Now()
		device := &pxe.DeviceInfo{
			ID:         "device-1",
			MACAddress: mac,
			PortID:     "port-1",
			State:      pxe.StateDiscovered,
			CreatedAt:  now,
			UpdatedAt:  now,
			Events: []*pxe.ProvisioningEvent{
				{
					ID:        "event-1",
					DeviceID:  "device-1",
					Timestamp: now,
					EventType: pxe.EventDeviceDiscovered,
					FromState: pxe.StateUnknown,
					ToState:   pxe.StateDiscovered,
					Details:   map[string]string{"key": "value"},
				},
			},
		}

		resp := handlers.deviceToResponse(device)

		assert.Len(t, resp.Events, 1)
		assert.Equal(t, "event-1", resp.Events[0].ID)
		assert.Equal(t, "device_discovered", resp.Events[0].EventType)
		assert.Equal(t, "unknown", resp.Events[0].FromState)
		assert.Equal(t, "discovered", resp.Events[0].ToState)
		assert.Equal(t, "value", resp.Events[0].Details["key"])
	})
}

func TestPXEWritePXEError(t *testing.T) {
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"device_not_found", pxe.ErrDeviceNotFound{DeviceID: "test"}, http.StatusNotFound},
		{"device_already_exists", pxe.ErrDeviceAlreadyExists{MACAddress: "aa:bb:cc:dd:ee:ff"}, http.StatusConflict},
		{"invalid_mac_address", pxe.ErrInvalidMACAddress{MACAddress: "invalid"}, http.StatusBadRequest},
		{"invalid_state", pxe.ErrInvalidState{State: "bad"}, http.StatusBadRequest},
		{"invalid_state_transition", pxe.ErrInvalidStateTransition{FromState: "a", ToState: "b"}, http.StatusConflict},
		{"invalid_configuration", pxe.ErrInvalidConfiguration{Reason: "bad config"}, http.StatusBadRequest},
		{"service_not_initialized", pxe.ErrServiceNotInitialized{}, http.StatusServiceUnavailable},
		{"service_not_running", pxe.ErrServiceNotRunning{}, http.StatusServiceUnavailable},
		{"service_already_running", pxe.ErrServiceAlreadyRunning{}, http.StatusConflict},
		{"max_retries_exceeded", pxe.ErrMaxRetriesExceeded{MaxRetries: 3}, http.StatusConflict},
		{"vlan_transition_failed", pxe.ErrVLANTransitionFailed{FromVLAN: 100, ToVLAN: 200}, http.StatusInternalServerError},
		{"provisioning_failed", pxe.ErrProvisioningFailed{Reason: "error"}, http.StatusInternalServerError},
		{"timeout", pxe.ErrTimeout{Operation: "test"}, http.StatusGatewayTimeout},
		{"webhook_validation_failed", pxe.ErrWebhookValidationFailed{Reason: "bad"}, http.StatusBadRequest},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newMockPXEService()
			handlers := NewPXEHandlers(svc, nil)
			w := httptest.NewRecorder()

			handlers.writePXEError(w, "test_operation", tc.err)

			assert.Equal(t, tc.expectedStatus, w.Code)

			var resp PXEErrorResponse
			err := json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)
			assert.Contains(t, resp.Error, "PXE operation test_operation failed")
		})
	}
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewPXEHandlers(t *testing.T) {
	t.Run("with_service_and_logger", func(t *testing.T) {
		svc := newMockPXEService()
		logger := slog.Default()

		handlers := NewPXEHandlers(svc, logger)

		assert.NotNil(t, handlers)
		assert.NotNil(t, handlers.service)
		assert.NotNil(t, handlers.logger)
	})

	t.Run("with_nil_logger", func(t *testing.T) {
		svc := newMockPXEService()

		handlers := NewPXEHandlers(svc, nil)

		assert.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger) // Should use default logger
	})

	t.Run("with_nil_service", func(t *testing.T) {
		handlers := NewPXEHandlers(nil, nil)

		assert.NotNil(t, handlers)
		assert.Nil(t, handlers.service)
	})
}

func TestPXERegisterRoutes(t *testing.T) {
	// Verify routes are registered by making requests to each endpoint
	// Each subtest creates its own mock service to avoid state sharing issues
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/pxe/devices"},
		{http.MethodPost, "/api/v1/pxe/devices"},
		{http.MethodGet, "/api/v1/pxe/devices/mac/aa:bb:cc:dd:ee:ff"},
		{http.MethodGet, "/api/v1/pxe/devices/test-id"},
		{http.MethodDelete, "/api/v1/pxe/devices/test-id"},
		{http.MethodPut, "/api/v1/pxe/devices/test-id/state"},
		{http.MethodPost, "/api/v1/pxe/devices/test-id/authorize"},
		{http.MethodPost, "/api/v1/pxe/devices/test-id/quarantine"},
		{http.MethodPost, "/api/v1/pxe/devices/test-id/retry"},
		{http.MethodPost, "/api/v1/pxe/devices/test-id/enrolled"},
		{http.MethodGet, "/api/v1/pxe/devices/test-id/events"},
		{http.MethodGet, "/api/v1/pxe/status"},
		{http.MethodPost, "/api/v1/pxe/start"},
		{http.MethodPost, "/api/v1/pxe/stop"},
		{http.MethodPost, "/api/v1/pxe/webhook/complete"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+"_"+ep.path, func(t *testing.T) {
			// Create fresh mock service for each test to avoid state sharing
			svc := newMockPXEService()
			// Add a test device with state that allows most transitions
			device := svc.addTestDevice("test-id", "aa:bb:cc:dd:ee:ff", "port-1", pxe.StateFailed)
			device.State = pxe.StateFailed // Allows retry transition
			handlers := NewPXEHandlers(svc, nil)
			router := mux.NewRouter()
			handlers.RegisterRoutes(router)

			req := httptest.NewRequest(ep.method, ep.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			// Should not return 404 (route exists)
			// Note: Some routes may return other errors (400, 409, etc.) due to missing
			// request body or invalid state, but they should not return 404
			assert.NotEqual(t, http.StatusNotFound, w.Code, "Route should be registered: %s %s", ep.method, ep.path)
		})
	}
}
