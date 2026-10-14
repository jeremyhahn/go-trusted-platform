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

package mcp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Mock PXE Service
// =============================================================================

// mockPXEService implements pxe.Service for testing.
type mockPXEService struct {
	initializeFunc        func(ctx context.Context, config *pxe.ServiceConfig) error
	startFunc             func(ctx context.Context) error
	stopFunc              func(ctx context.Context) error
	isRunningFunc         func() bool
	closeFunc             func() error
	registerDeviceFunc    func(ctx context.Context, macAddress, portID string) (*pxe.DeviceInfo, error)
	getDeviceFunc         func(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error)
	getDeviceByMACFunc    func(ctx context.Context, mac string) (*pxe.DeviceInfo, error)
	listDevicesFunc       func(ctx context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error)
	removeDeviceFunc      func(ctx context.Context, deviceID string) error
	updateDeviceStateFunc func(ctx context.Context, deviceID string, state pxe.ProvisioningState, reason string) error
	setDeviceEnrolledFunc func(ctx context.Context, deviceID, certSerial string) error
	authorizeDeviceFunc   func(ctx context.Context, deviceID string, targetVLAN uint16) error
	quarantineDeviceFunc  func(ctx context.Context, deviceID string, reason string) error
	retryDeviceFunc       func(ctx context.Context, deviceID string) error
	getEventsFunc         func(ctx context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error)
	registerEventHandler  func(handler pxe.EventHandler)
	statusFunc            func() *pxe.ServiceStatus
}

func newMockPXEService() *mockPXEService {
	now := time.Now()
	testMAC, _ := net.ParseMAC("00:11:22:33:44:55")

	testDevice := &pxe.DeviceInfo{
		ID:             "device-abc123",
		MACAddress:     testMAC,
		PortID:         "port1",
		State:          pxe.StateDiscovered,
		StateReason:    "device registered",
		CurrentVLAN:    100,
		TargetVLAN:     0,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
		RetryCount:     0,
		Events:         make([]*pxe.ProvisioningEvent, 0),
	}

	return &mockPXEService{
		initializeFunc: func(ctx context.Context, config *pxe.ServiceConfig) error {
			return nil
		},
		startFunc: func(ctx context.Context) error {
			return nil
		},
		stopFunc: func(ctx context.Context) error {
			return nil
		},
		isRunningFunc: func() bool {
			return true
		},
		closeFunc: func() error {
			return nil
		},
		registerDeviceFunc: func(ctx context.Context, macAddress, portID string) (*pxe.DeviceInfo, error) {
			mac, err := net.ParseMAC(macAddress)
			if err != nil {
				return nil, err
			}
			return &pxe.DeviceInfo{
				ID:             "device-new123",
				MACAddress:     mac,
				PortID:         portID,
				State:          pxe.StateDiscovered,
				StateReason:    "device registered",
				CurrentVLAN:    100,
				CreatedAt:      now,
				UpdatedAt:      now,
				StateChangedAt: now,
			}, nil
		},
		getDeviceFunc: func(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
			if deviceID == "device-abc123" {
				return testDevice, nil
			}
			return nil, errors.New("device not found")
		},
		getDeviceByMACFunc: func(ctx context.Context, mac string) (*pxe.DeviceInfo, error) {
			if mac == "00:11:22:33:44:55" {
				return testDevice, nil
			}
			return nil, errors.New("device not found")
		},
		listDevicesFunc: func(ctx context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error) {
			return []*pxe.DeviceInfo{testDevice}, nil
		},
		removeDeviceFunc: func(ctx context.Context, deviceID string) error {
			if deviceID == "device-abc123" {
				return nil
			}
			return errors.New("device not found")
		},
		updateDeviceStateFunc: func(ctx context.Context, deviceID string, state pxe.ProvisioningState, reason string) error {
			if deviceID != "device-abc123" {
				return errors.New("device not found")
			}
			return nil
		},
		setDeviceEnrolledFunc: func(ctx context.Context, deviceID, certSerial string) error {
			if deviceID != "device-abc123" {
				return errors.New("device not found")
			}
			return nil
		},
		authorizeDeviceFunc: func(ctx context.Context, deviceID string, targetVLAN uint16) error {
			if deviceID != "device-abc123" {
				return errors.New("device not found")
			}
			return nil
		},
		quarantineDeviceFunc: func(ctx context.Context, deviceID string, reason string) error {
			if deviceID != "device-abc123" {
				return errors.New("device not found")
			}
			return nil
		},
		retryDeviceFunc: func(ctx context.Context, deviceID string) error {
			if deviceID != "device-abc123" {
				return errors.New("device not found")
			}
			return nil
		},
		getEventsFunc: func(ctx context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error) {
			if deviceID != "device-abc123" {
				return nil, errors.New("device not found")
			}
			return []*pxe.ProvisioningEvent{
				{
					ID:        "event-1",
					DeviceID:  deviceID,
					Timestamp: now,
					EventType: pxe.EventDeviceDiscovered,
					FromState: pxe.StateUnknown,
					ToState:   pxe.StateDiscovered,
					Details:   map[string]string{"mac_address": "00:11:22:33:44:55"},
				},
			}, nil
		},
		registerEventHandler: func(handler pxe.EventHandler) {},
		statusFunc: func() *pxe.ServiceStatus {
			return &pxe.ServiceStatus{
				Running:          true,
				DeviceCount:      5,
				StartTime:        now,
				IPXEServerAddr:   "192.168.1.1:8080",
				QuarantineVLAN:   100,
				ProvisioningVLAN: 200,
			}
		},
	}
}

// Implement pxe.Service interface
func (m *mockPXEService) Initialize(ctx context.Context, config *pxe.ServiceConfig) error {
	return m.initializeFunc(ctx, config)
}

func (m *mockPXEService) Start(ctx context.Context) error {
	return m.startFunc(ctx)
}

func (m *mockPXEService) Stop(ctx context.Context) error {
	return m.stopFunc(ctx)
}

func (m *mockPXEService) IsRunning() bool {
	return m.isRunningFunc()
}

func (m *mockPXEService) Close() error {
	return m.closeFunc()
}

func (m *mockPXEService) RegisterDevice(ctx context.Context, macAddress, portID string) (*pxe.DeviceInfo, error) {
	return m.registerDeviceFunc(ctx, macAddress, portID)
}

func (m *mockPXEService) GetDevice(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
	return m.getDeviceFunc(ctx, deviceID)
}

func (m *mockPXEService) GetDeviceByMAC(ctx context.Context, mac string) (*pxe.DeviceInfo, error) {
	return m.getDeviceByMACFunc(ctx, mac)
}

func (m *mockPXEService) ListDevices(ctx context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error) {
	return m.listDevicesFunc(ctx, filter)
}

func (m *mockPXEService) RemoveDevice(ctx context.Context, deviceID string) error {
	return m.removeDeviceFunc(ctx, deviceID)
}

func (m *mockPXEService) UpdateDeviceState(ctx context.Context, deviceID string, state pxe.ProvisioningState, reason string) error {
	return m.updateDeviceStateFunc(ctx, deviceID, state, reason)
}

func (m *mockPXEService) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) error {
	return m.setDeviceEnrolledFunc(ctx, deviceID, certSerial)
}

func (m *mockPXEService) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) error {
	return m.authorizeDeviceFunc(ctx, deviceID, targetVLAN)
}

func (m *mockPXEService) QuarantineDevice(ctx context.Context, deviceID string, reason string) error {
	return m.quarantineDeviceFunc(ctx, deviceID, reason)
}

func (m *mockPXEService) RetryDevice(ctx context.Context, deviceID string) error {
	return m.retryDeviceFunc(ctx, deviceID)
}

func (m *mockPXEService) GetEvents(ctx context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error) {
	return m.getEventsFunc(ctx, deviceID)
}

func (m *mockPXEService) RegisterEventHandler(handler pxe.EventHandler) {
	m.registerEventHandler(handler)
}

func (m *mockPXEService) Status() *pxe.ServiceStatus {
	return m.statusFunc()
}

// =============================================================================
// Mock Service Provider with PXE Support
// =============================================================================

// mockPXEServiceProvider wraps mockServiceProvider and adds PXE support.
type mockPXEServiceProvider struct {
	*mockServiceProvider
	pxeService pxe.Service
}

func (m *mockPXEServiceProvider) PXEService() pxe.Service {
	return m.pxeService
}

// =============================================================================
// Test Helper
// =============================================================================

// newPXETestRegistry creates a ToolRegistry with a mock PXE service provider.
func newPXETestRegistry(pxeSvc pxe.Service) *ToolRegistry {
	mockSvc := newMockServiceProvider()
	pxeProvider := &mockPXEServiceProvider{
		mockServiceProvider: mockSvc,
		pxeService:          pxeSvc,
	}

	return &ToolRegistry{
		service: pxeProvider,
		logger:  newTestLogger(),
		tools:   make([]mcpwire.ToolDefinition, 0),
	}
}

// =============================================================================
// PXE Error Tests
// =============================================================================

func TestPXEError_Error(t *testing.T) {
	err := &PXEError{
		Code:    "TEST_CODE",
		Message: "test message",
	}

	expected := "TEST_CODE: test message"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestPXEErrorVariables(t *testing.T) {
	tests := []struct {
		name     string
		err      *PXEError
		wantCode string
	}{
		{
			name:     "ErrPXEServiceUnavailable",
			err:      ErrPXEServiceUnavailable,
			wantCode: "PXE_SERVICE_UNAVAILABLE",
		},
		{
			name:     "ErrPXEDeviceIDRequired",
			err:      ErrPXEDeviceIDRequired,
			wantCode: "PXE_DEVICE_ID_REQUIRED",
		},
		{
			name:     "ErrPXEMACAddressRequired",
			err:      ErrPXEMACAddressRequired,
			wantCode: "PXE_MAC_ADDRESS_REQUIRED",
		},
		{
			name:     "ErrPXEPortIDRequired",
			err:      ErrPXEPortIDRequired,
			wantCode: "PXE_PORT_ID_REQUIRED",
		},
		{
			name:     "ErrPXEStateRequired",
			err:      ErrPXEStateRequired,
			wantCode: "PXE_STATE_REQUIRED",
		},
		{
			name:     "ErrPXEDeviceNotFound",
			err:      ErrPXEDeviceNotFound,
			wantCode: "PXE_DEVICE_NOT_FOUND",
		},
		{
			name:     "ErrPXEInvalidState",
			err:      ErrPXEInvalidState,
			wantCode: "PXE_INVALID_STATE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Code != tt.wantCode {
				t.Errorf("expected code %q, got %q", tt.wantCode, tt.err.Code)
			}
			if tt.err.Message == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}

// =============================================================================
// PXE Tool Handler Tests
// =============================================================================

// =============================================================================
// Tool Execution Tests
// =============================================================================

func TestExecutePXEListDevices_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"state": "discovered",
		"limit": 10,
	}

	result, err := registry.executePXEListDevices(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	devices, ok := resultMap["devices"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected devices array")
	}

	if len(devices) != 1 {
		t.Errorf("expected 1 device, got %d", len(devices))
	}
}

func TestExecutePXEListDevices_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	_, err := registry.executePXEListDevices(ctx, map[string]interface{}{})
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEListDevices_AllFilters(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	// Test with all filter parameters: state, mac_address, vlan
	args := map[string]interface{}{
		"state":       "authorized",
		"mac_address": "00:11:22:33:44:55",
		"vlan":        100,
		"limit":       50,
		"offset":      10,
	}

	result, err := registry.executePXEListDevices(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if _, exists := resultMap["devices"]; !exists {
		t.Error("expected devices field in result")
	}
	if _, exists := resultMap["count"]; !exists {
		t.Error("expected count field in result")
	}
}

func TestExecutePXEGetDevice_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	result, err := registry.executePXEGetDevice(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["id"] != "device-abc123" {
		t.Errorf("expected device ID 'device-abc123', got %v", resultMap["id"])
	}
}

func TestExecutePXEGetDevice_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	_, err := registry.executePXEGetDevice(ctx, map[string]interface{}{})
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXEGetDeviceByMAC_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "00:11:22:33:44:55",
	}

	result, err := registry.executePXEGetDeviceByMAC(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["mac_address"] != "00:11:22:33:44:55" {
		t.Errorf("expected MAC address '00:11:22:33:44:55', got %v", resultMap["mac_address"])
	}
}

func TestExecutePXEGetDeviceByMAC_MissingMACAddress(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	_, err := registry.executePXEGetDeviceByMAC(ctx, map[string]interface{}{})
	if err != ErrPXEMACAddressRequired {
		t.Errorf("expected ErrPXEMACAddressRequired, got %v", err)
	}
}

func TestExecutePXEGetDeviceByMAC_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "00:11:22:33:44:55",
	}

	_, err := registry.executePXEGetDeviceByMAC(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEGetDeviceByMAC_NotFound(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "aa:bb:cc:dd:ee:ff",
	}

	_, err := registry.executePXEGetDeviceByMAC(ctx, args)
	if err == nil {
		t.Fatal("expected error for device not found")
	}
}

func TestExecutePXERegisterDevice_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "aa:bb:cc:dd:ee:ff",
		"port_id":     "port2",
	}

	result, err := registry.executePXERegisterDevice(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["port_id"] != "port2" {
		t.Errorf("expected port_id 'port2', got %v", resultMap["port_id"])
	}
}

func TestExecutePXERegisterDevice_MissingMACAddress(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"port_id": "port1",
	}

	_, err := registry.executePXERegisterDevice(ctx, args)
	if err != ErrPXEMACAddressRequired {
		t.Errorf("expected ErrPXEMACAddressRequired, got %v", err)
	}
}

func TestExecutePXERegisterDevice_MissingPortID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "aa:bb:cc:dd:ee:ff",
	}

	_, err := registry.executePXERegisterDevice(ctx, args)
	if err != ErrPXEPortIDRequired {
		t.Errorf("expected ErrPXEPortIDRequired, got %v", err)
	}
}

func TestExecutePXEUpdateState_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"state":     "booting",
		"reason":    "PXE boot initiated",
	}

	result, err := registry.executePXEUpdateState(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["id"] != "device-abc123" {
		t.Errorf("expected device ID 'device-abc123', got %v", resultMap["id"])
	}
}

func TestExecutePXEUpdateState_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"state": "booting",
	}

	_, err := registry.executePXEUpdateState(ctx, args)
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXEUpdateState_MissingState(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXEUpdateState(ctx, args)
	if err != ErrPXEStateRequired {
		t.Errorf("expected ErrPXEStateRequired, got %v", err)
	}
}

func TestExecutePXEUpdateState_DefaultReason(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	// Test without reason - should use default
	args := map[string]interface{}{
		"device_id": "device-abc123",
		"state":     "booting",
		// No reason - should default to "state updated via MCP"
	}

	result, err := registry.executePXEUpdateState(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestExecutePXEUpdateState_GetDeviceError(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.getDeviceFunc = func(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
		return nil, errors.New("failed to get device after state update")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"state":     "booting",
		"reason":    "test",
	}

	_, err := registry.executePXEUpdateState(ctx, args)
	if err == nil {
		t.Error("expected error from get device after state update")
	}
}

func TestExecutePXEUpdateState_InvalidState(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"state":     "invalid_state",
	}

	_, err := registry.executePXEUpdateState(ctx, args)
	if err != ErrPXEInvalidState {
		t.Errorf("expected ErrPXEInvalidState, got %v", err)
	}
}

func TestExecutePXEAuthorizeDevice_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id":   "device-abc123",
		"target_zone": "control-plane",
	}

	result, err := registry.executePXEAuthorizeDevice(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["id"] != "device-abc123" {
		t.Errorf("expected device ID 'device-abc123', got %v", resultMap["id"])
	}
}

func TestExecutePXEAuthorizeDevice_MissingZone(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	// Omit target_zone entirely — should return PXE_TARGET_ZONE_REQUIRED.
	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXEAuthorizeDevice(ctx, args)
	if err == nil {
		t.Fatal("expected error for missing target_zone")
	}

	pxeErr, ok := err.(*PXEError)
	if !ok {
		t.Fatalf("expected PXEError, got %T", err)
	}
	if pxeErr.Code != "PXE_TARGET_ZONE_REQUIRED" {
		t.Errorf("expected code PXE_TARGET_ZONE_REQUIRED, got %s", pxeErr.Code)
	}
}

func TestExecutePXEQuarantineDevice_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"reason":    "failed attestation",
	}

	result, err := registry.executePXEQuarantineDevice(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["id"] != "device-abc123" {
		t.Errorf("expected device ID 'device-abc123', got %v", resultMap["id"])
	}
}

func TestExecutePXEQuarantineDevice_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"reason": "test reason",
	}

	_, err := registry.executePXEQuarantineDevice(ctx, args)
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXEQuarantineDevice_DefaultReason(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	// Test without reason - should use default
	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	result, err := registry.executePXEQuarantineDevice(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestExecutePXEQuarantineDevice_GetDeviceError(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.getDeviceFunc = func(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
		return nil, errors.New("failed to get device after quarantine")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"reason":    "test reason",
	}

	_, err := registry.executePXEQuarantineDevice(ctx, args)
	if err == nil {
		t.Error("expected error from get device after quarantine")
	}
}

func TestExecutePXERetryDevice_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	result, err := registry.executePXERetryDevice(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["id"] != "device-abc123" {
		t.Errorf("expected device ID 'device-abc123', got %v", resultMap["id"])
	}
}

func TestExecutePXEServiceStatus_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	result, err := registry.executePXEServiceStatus(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["running"] != true {
		t.Error("expected running to be true")
	}
	if resultMap["device_count"] != 5 {
		t.Errorf("expected device_count 5, got %v", resultMap["device_count"])
	}
	if resultMap["quarantine_vlan"] != uint16(100) {
		t.Errorf("expected quarantine_vlan 100, got %v", resultMap["quarantine_vlan"])
	}
	if resultMap["provisioning_vlan"] != uint16(200) {
		t.Errorf("expected provisioning_vlan 200, got %v", resultMap["provisioning_vlan"])
	}
}

func TestExecutePXEStartService_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	result, err := registry.executePXEStartService(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["success"] != true {
		t.Error("expected success to be true")
	}
	if resultMap["message"] != "PXE service started successfully" {
		t.Errorf("unexpected message: %v", resultMap["message"])
	}
}

func TestExecutePXEStartService_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	_, err := registry.executePXEStartService(ctx, map[string]interface{}{})
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEStartService_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.startFunc = func(ctx context.Context) error {
		return errors.New("service already running")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	_, err := registry.executePXEStartService(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecutePXEStopService_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	result, err := registry.executePXEStopService(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["success"] != true {
		t.Error("expected success to be true")
	}
	if resultMap["message"] != "PXE service stopped successfully" {
		t.Errorf("unexpected message: %v", resultMap["message"])
	}
}

func TestExecutePXEStopService_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	_, err := registry.executePXEStopService(ctx, map[string]interface{}{})
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEStopService_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.stopFunc = func(ctx context.Context) error {
		return errors.New("service not running")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	_, err := registry.executePXEStopService(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecutePXEGetDeviceEvents_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	result, err := registry.executePXEGetDeviceEvents(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	events, ok := resultMap["events"].([]map[string]interface{})
	if !ok {
		t.Fatal("expected events array")
	}

	if len(events) != 1 {
		t.Errorf("expected 1 event, got %d", len(events))
	}

	if events[0]["event_type"] != "device_discovered" {
		t.Errorf("expected event_type 'device_discovered', got %v", events[0]["event_type"])
	}
}

func TestExecutePXERemoveDevice_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	result, err := registry.executePXERemoveDevice(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["success"] != true {
		t.Error("expected success to be true")
	}
	if resultMap["device_id"] != "device-abc123" {
		t.Errorf("expected device_id 'device-abc123', got %v", resultMap["device_id"])
	}
}

func TestExecutePXESetDeviceEnrolled_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id":          "device-abc123",
		"certificate_serial": "ABCD1234",
	}

	result, err := registry.executePXESetDeviceEnrolled(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["id"] != "device-abc123" {
		t.Errorf("expected device ID 'device-abc123', got %v", resultMap["id"])
	}
}

func TestExecutePXESetDeviceEnrolled_MissingCertSerial(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXESetDeviceEnrolled(ctx, args)
	if err == nil {
		t.Fatal("expected error for missing certificate_serial")
	}

	pxeErr, ok := err.(*PXEError)
	if !ok {
		t.Fatalf("expected PXEError, got %T", err)
	}
	if pxeErr.Code != "PXE_CERT_SERIAL_REQUIRED" {
		t.Errorf("expected code PXE_CERT_SERIAL_REQUIRED, got %s", pxeErr.Code)
	}
}

func TestExecutePXEWebhookComplete_Success(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "00:11:22:33:44:55",
		"hostname":    "new-server",
		"success":     true,
		"message":     "Installation completed",
	}

	result, err := registry.executePXEWebhookComplete(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["success"] != true {
		t.Error("expected success to be true")
	}

	device, ok := resultMap["device"].(map[string]interface{})
	if !ok {
		t.Fatal("expected device in result")
	}
	if device["id"] != "device-abc123" {
		t.Errorf("expected device ID 'device-abc123', got %v", device["id"])
	}
}

func TestExecutePXEWebhookComplete_Failure(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "00:11:22:33:44:55",
		"success":     false,
		"message":     "Disk error during installation",
	}

	result, err := registry.executePXEWebhookComplete(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	if resultMap["success"] != true {
		t.Error("expected success to be true (webhook processed)")
	}

	message, ok := resultMap["message"].(string)
	if !ok {
		t.Fatal("expected message in result")
	}
	if message != "OS installation failed: Disk error during installation" {
		t.Errorf("unexpected message: %v", message)
	}
}

func TestExecutePXEWebhookComplete_MissingMACAddress(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"success": true,
	}

	_, err := registry.executePXEWebhookComplete(ctx, args)
	if err != ErrPXEMACAddressRequired {
		t.Errorf("expected ErrPXEMACAddressRequired, got %v", err)
	}
}

func TestExecutePXEWebhookComplete_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "00:11:22:33:44:55",
		"success":     true,
	}

	_, err := registry.executePXEWebhookComplete(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEWebhookComplete_DeviceNotFound(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "aa:bb:cc:dd:ee:ff",
		"success":     true,
	}

	_, err := registry.executePXEWebhookComplete(ctx, args)
	if err == nil {
		t.Fatal("expected error for device not found")
	}
}

// =============================================================================
// Format Helper Tests
// =============================================================================

func TestFormatDeviceInfo(t *testing.T) {
	now := time.Now()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &pxe.DeviceInfo{
		ID:                "device-test",
		MACAddress:        mac,
		PortID:            "port1",
		State:             pxe.StateDiscovered,
		StateReason:       "test reason",
		CertificateSerial: "CERT123",
		CurrentVLAN:       100,
		TargetVLAN:        200,
		CreatedAt:         now,
		UpdatedAt:         now,
		StateChangedAt:    now,
		RetryCount:        2,
	}

	result := formatDeviceInfo(device)

	if result["id"] != "device-test" {
		t.Errorf("expected id 'device-test', got %v", result["id"])
	}
	if result["mac_address"] != "00:11:22:33:44:55" {
		t.Errorf("expected mac_address '00:11:22:33:44:55', got %v", result["mac_address"])
	}
	if result["state"] != "discovered" {
		t.Errorf("expected state 'discovered', got %v", result["state"])
	}
	if result["certificate_serial"] != "CERT123" {
		t.Errorf("expected certificate_serial 'CERT123', got %v", result["certificate_serial"])
	}
	if result["retry_count"] != 2 {
		t.Errorf("expected retry_count 2, got %v", result["retry_count"])
	}
}

func TestFormatDeviceInfo_Nil(t *testing.T) {
	result := formatDeviceInfo(nil)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}
}

func TestFormatDeviceList(t *testing.T) {
	mac1, _ := net.ParseMAC("00:11:22:33:44:55")
	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	now := time.Now()

	devices := []*pxe.DeviceInfo{
		{
			ID:             "device-1",
			MACAddress:     mac1,
			PortID:         "port1",
			State:          pxe.StateDiscovered,
			CreatedAt:      now,
			UpdatedAt:      now,
			StateChangedAt: now,
		},
		{
			ID:             "device-2",
			MACAddress:     mac2,
			PortID:         "port2",
			State:          pxe.StateBooting,
			CreatedAt:      now,
			UpdatedAt:      now,
			StateChangedAt: now,
		},
	}

	result := formatDeviceList(devices)

	if len(result) != 2 {
		t.Errorf("expected 2 devices, got %d", len(result))
	}
	if result[0]["id"] != "device-1" {
		t.Errorf("expected first device id 'device-1', got %v", result[0]["id"])
	}
	if result[1]["id"] != "device-2" {
		t.Errorf("expected second device id 'device-2', got %v", result[1]["id"])
	}
}

func TestFormatEventList(t *testing.T) {
	now := time.Now()

	events := []*pxe.ProvisioningEvent{
		{
			ID:        "event-1",
			DeviceID:  "device-test",
			Timestamp: now,
			EventType: pxe.EventDeviceDiscovered,
			FromState: pxe.StateUnknown,
			ToState:   pxe.StateDiscovered,
			Details:   map[string]string{"mac_address": "00:11:22:33:44:55"},
		},
		{
			ID:        "event-2",
			DeviceID:  "device-test",
			Timestamp: now,
			EventType: pxe.EventFailed,
			FromState: pxe.StateBooting,
			ToState:   pxe.StateFailed,
			Error:     "PXE boot timeout",
		},
	}

	result := formatEventList(events)

	if len(result) != 2 {
		t.Errorf("expected 2 events, got %d", len(result))
	}

	// Check first event
	if result[0]["event_type"] != "device_discovered" {
		t.Errorf("expected event_type 'device_discovered', got %v", result[0]["event_type"])
	}
	if result[0]["details"] == nil {
		t.Error("expected details to be present")
	}

	// Check second event
	if result[1]["event_type"] != "failed" {
		t.Errorf("expected event_type 'failed', got %v", result[1]["event_type"])
	}
	if result[1]["error"] != "PXE boot timeout" {
		t.Errorf("expected error 'PXE boot timeout', got %v", result[1]["error"])
	}
}

// =============================================================================
// Tool Registration Tests
// =============================================================================

func TestRegisterPXETools(t *testing.T) {
	registry := &ToolRegistry{
		tools: make([]mcpwire.ToolDefinition, 0),
	}

	registry.registerPXETools()

	expectedTools := []string{
		"pxe_list_devices",
		"pxe_get_device",
		"pxe_get_device_by_mac",
		"pxe_register_device",
		"pxe_update_state",
		"pxe_authorize_device",
		"pxe_quarantine_device",
		"pxe_retry_device",
		"pxe_service_status",
		"pxe_start_service",
		"pxe_stop_service",
		"pxe_get_device_events",
		"pxe_remove_device",
		"pxe_set_device_enrolled",
		"pxe_webhook_complete",
	}

	if len(registry.tools) != len(expectedTools) {
		t.Errorf("expected %d tools, got %d", len(expectedTools), len(registry.tools))
	}

	toolNames := make(map[string]bool)
	for _, tool := range registry.tools {
		toolNames[tool.Name] = true
	}

	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("missing expected tool: %s", name)
		}
	}
}

func TestPXEToolDefinitions_HaveDescriptions(t *testing.T) {
	registry := &ToolRegistry{
		tools: make([]mcpwire.ToolDefinition, 0),
	}

	registry.registerPXETools()

	for _, tool := range registry.tools {
		if tool.Description == "" {
			t.Errorf("tool %s has empty description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %s has nil input schema", tool.Name)
		}
	}
}

func TestPXEToolDefinitions_RequiredFields(t *testing.T) {
	registry := &ToolRegistry{
		tools: make([]mcpwire.ToolDefinition, 0),
	}

	registry.registerPXETools()

	// Tools that should have required fields
	toolsWithRequired := map[string][]string{
		"pxe_get_device":          {"device_id"},
		"pxe_get_device_by_mac":   {"mac_address"},
		"pxe_register_device":     {"mac_address", "port_id"},
		"pxe_update_state":        {"device_id", "state"},
		"pxe_authorize_device":    {"device_id", "target_zone"},
		"pxe_quarantine_device":   {"device_id", "reason"},
		"pxe_retry_device":        {"device_id"},
		"pxe_get_device_events":   {"device_id"},
		"pxe_remove_device":       {"device_id"},
		"pxe_set_device_enrolled": {"device_id", "certificate_serial"},
		"pxe_webhook_complete":    {"mac_address", "success"},
	}

	for _, tool := range registry.tools {
		expectedRequired, hasRequired := toolsWithRequired[tool.Name]
		if !hasRequired {
			continue
		}

		schema := tool.InputSchema
		required, ok := schema["required"].([]string)
		if !ok {
			t.Errorf("tool %s: expected required field to be []string", tool.Name)
			continue
		}

		for _, field := range expectedRequired {
			found := false
			for _, r := range required {
				if r == field {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("tool %s: missing required field %s", tool.Name, field)
			}
		}
	}
}

// =============================================================================
// Service Provider Interface Tests
// =============================================================================

func TestGetPXEService_WithPXEProvider(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)

	svc := registry.getPXEService()
	if svc == nil {
		t.Fatal("expected non-nil PXE service")
	}
	if svc != mockPXE {
		t.Error("expected returned service to match mock service")
	}
}

func TestGetPXEService_WithoutPXEProvider(t *testing.T) {
	mockSvc := newMockServiceProvider()
	registry := &ToolRegistry{
		service: mockSvc,
		logger:  newTestLogger(),
		tools:   make([]mcpwire.ToolDefinition, 0),
	}

	svc := registry.getPXEService()
	if svc != nil {
		t.Error("expected nil PXE service when provider doesn't implement PXEServiceProvider")
	}
}

// =============================================================================
// Additional Service Error Tests for PXE Tools
// =============================================================================

func TestExecutePXERetryDevice_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXERetryDevice(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXERetryDevice_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{}

	_, err := registry.executePXERetryDevice(ctx, args)
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXERetryDevice_RetryError(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.retryDeviceFunc = func(ctx context.Context, deviceID string) error {
		return errors.New("retry failed")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXERetryDevice(ctx, args)
	if err == nil {
		t.Error("expected error from retry")
	}
}

func TestExecutePXERetryDevice_GetDeviceError(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.retryDeviceFunc = func(ctx context.Context, deviceID string) error {
		return nil
	}
	mockPXE.getDeviceFunc = func(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
		return nil, errors.New("device not found after retry")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXERetryDevice(ctx, args)
	if err == nil {
		t.Error("expected error from get device after retry")
	}
}

func TestExecutePXEGetDeviceEvents_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXEGetDeviceEvents(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEGetDeviceEvents_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{}

	_, err := registry.executePXEGetDeviceEvents(ctx, args)
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXEGetDeviceEvents_GetEventsError(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.getEventsFunc = func(ctx context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error) {
		return nil, errors.New("failed to get events")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXEGetDeviceEvents(ctx, args)
	if err == nil {
		t.Error("expected error from get events")
	}
}

func TestExecutePXERemoveDevice_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXERemoveDevice(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXERemoveDevice_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{}

	_, err := registry.executePXERemoveDevice(ctx, args)
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXERemoveDevice_RemoveError(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.removeDeviceFunc = func(ctx context.Context, deviceID string) error {
		return errors.New("failed to remove device")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXERemoveDevice(ctx, args)
	if err == nil {
		t.Error("expected error from remove device")
	}
}

func TestExecutePXESetDeviceEnrolled_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id":          "device-abc123",
		"certificate_serial": "serial123",
	}

	_, err := registry.executePXESetDeviceEnrolled(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXESetDeviceEnrolled_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"certificate_serial": "serial123",
	}

	_, err := registry.executePXESetDeviceEnrolled(ctx, args)
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXESetDeviceEnrolled_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.setDeviceEnrolledFunc = func(ctx context.Context, deviceID, certSerial string) error {
		return errors.New("failed to set enrolled")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id":          "device-abc123",
		"certificate_serial": "serial123",
	}

	_, err := registry.executePXESetDeviceEnrolled(ctx, args)
	if err == nil {
		t.Error("expected error from set enrolled")
	}
}

func TestExecutePXEAuthorizeDevice_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id":   "device-abc123",
		"target_vlan": float64(200),
	}

	_, err := registry.executePXEAuthorizeDevice(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEAuthorizeDevice_MissingDeviceID(t *testing.T) {
	mockPXE := newMockPXEService()
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"target_vlan": float64(200),
	}

	_, err := registry.executePXEAuthorizeDevice(ctx, args)
	if err != ErrPXEDeviceIDRequired {
		t.Errorf("expected ErrPXEDeviceIDRequired, got %v", err)
	}
}

func TestExecutePXEAuthorizeDevice_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.authorizeDeviceFunc = func(ctx context.Context, deviceID string, targetVLAN uint16) error {
		return errors.New("failed to authorize")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id":   "device-abc123",
		"target_vlan": float64(200),
	}

	_, err := registry.executePXEAuthorizeDevice(ctx, args)
	if err == nil {
		t.Error("expected error from authorize")
	}
}

func TestExecutePXEQuarantineDevice_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"reason":    "test reason",
	}

	_, err := registry.executePXEQuarantineDevice(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEQuarantineDevice_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.quarantineDeviceFunc = func(ctx context.Context, deviceID string, reason string) error {
		return errors.New("failed to quarantine")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"reason":    "test reason",
	}

	_, err := registry.executePXEQuarantineDevice(ctx, args)
	if err == nil {
		t.Error("expected error from quarantine")
	}
}

func TestExecutePXEServiceStatus_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	_, err := registry.executePXEServiceStatus(ctx, map[string]interface{}{})
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEListDevices_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.listDevicesFunc = func(ctx context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error) {
		return nil, errors.New("failed to list devices")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	_, err := registry.executePXEListDevices(ctx, map[string]interface{}{})
	if err == nil {
		t.Error("expected error from list devices")
	}
}

func TestExecutePXEGetDevice_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXEGetDevice(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEGetDevice_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.getDeviceFunc = func(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
		return nil, errors.New("failed to get device")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
	}

	_, err := registry.executePXEGetDevice(ctx, args)
	if err == nil {
		t.Error("expected error from get device")
	}
}

func TestExecutePXERegisterDevice_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "00:11:22:33:44:55",
		"port_id":     "port1",
	}

	_, err := registry.executePXERegisterDevice(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXERegisterDevice_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.registerDeviceFunc = func(ctx context.Context, macAddress, portID string) (*pxe.DeviceInfo, error) {
		return nil, errors.New("failed to register device")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"mac_address": "00:11:22:33:44:55",
		"port_id":     "port1",
	}

	_, err := registry.executePXERegisterDevice(ctx, args)
	if err == nil {
		t.Error("expected error from register device")
	}
}

func TestExecutePXEUpdateState_ServiceUnavailable(t *testing.T) {
	registry := newPXETestRegistry(nil)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"state":     "discovered",
		"reason":    "test reason",
	}

	_, err := registry.executePXEUpdateState(ctx, args)
	if err != ErrPXEServiceUnavailable {
		t.Errorf("expected ErrPXEServiceUnavailable, got %v", err)
	}
}

func TestExecutePXEUpdateState_Error(t *testing.T) {
	mockPXE := newMockPXEService()
	mockPXE.updateDeviceStateFunc = func(ctx context.Context, deviceID string, state pxe.ProvisioningState, reason string) error {
		return errors.New("failed to update state")
	}
	registry := newPXETestRegistry(mockPXE)
	ctx := context.Background()

	args := map[string]interface{}{
		"device_id": "device-abc123",
		"state":     "discovered",
		"reason":    "test reason",
	}

	_, err := registry.executePXEUpdateState(ctx, args)
	if err == nil {
		t.Error("expected error from update state")
	}
}

func TestFormatDeviceInfo_WithProfile(t *testing.T) {
	now := time.Now()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	device := &pxe.DeviceInfo{
		ID:             "device-with-profile",
		MACAddress:     mac,
		PortID:         "port1",
		State:          pxe.StateEnrolling,
		StateReason:    "provisioning started",
		CurrentVLAN:    200,
		TargetVLAN:     300,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
		RetryCount:     0,
		Profile: &entities.DeviceProfile{
			ID:   123,
			Name: "Default Profile",
		},
	}

	result := formatDeviceInfo(device)

	if result["id"] != "device-with-profile" {
		t.Errorf("expected id 'device-with-profile', got %v", result["id"])
	}

	profile, ok := result["profile"].(map[string]interface{})
	if !ok {
		t.Fatal("expected profile to be a map")
	}
	if profile["id"] != uint64(123) {
		t.Errorf("expected profile id 'profile-123', got %v", profile["id"])
	}
	if profile["name"] != "Default Profile" {
		t.Errorf("expected profile name 'Default Profile', got %v", profile["name"])
	}
}
