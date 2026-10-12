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

//go:build codec_msgpack

package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock PXE Service
// =============================================================================

// MockPXEService implements pxe.Service for testing
type MockPXEService struct {
	mu sync.RWMutex

	// State
	devices      map[string]*pxe.DeviceInfo
	devicesByMAC map[string]*pxe.DeviceInfo
	running      atomic.Bool
	initialized  atomic.Bool
	startTime    time.Time
	config       *pxe.ServiceConfig

	// Error injection
	registerDeviceErr    error
	getDeviceErr         error
	getDeviceByMACErr    error
	listDevicesErr       error
	removeDeviceErr      error
	updateDeviceStateErr error
	setDeviceEnrolledErr error
	authorizeDeviceErr   error
	quarantineDeviceErr  error
	retryDeviceErr       error
	getEventsErr         error
	initializeErr        error
	startErr             error
	stopErr              error
}

// NewMockPXEService creates a new mock PXE service
func NewMockPXEService() *MockPXEService {
	return &MockPXEService{
		devices:      make(map[string]*pxe.DeviceInfo),
		devicesByMAC: make(map[string]*pxe.DeviceInfo),
	}
}

func (m *MockPXEService) Initialize(ctx context.Context, config *pxe.ServiceConfig) error {
	if m.initializeErr != nil {
		return m.initializeErr
	}
	m.config = config
	m.initialized.Store(true)
	return nil
}

func (m *MockPXEService) Start(ctx context.Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.running.Store(true)
	m.startTime = time.Now()
	return nil
}

func (m *MockPXEService) Stop(ctx context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running.Store(false)
	return nil
}

func (m *MockPXEService) IsRunning() bool {
	return m.running.Load()
}

func (m *MockPXEService) Close() error {
	m.running.Store(false)
	m.initialized.Store(false)
	return nil
}

func (m *MockPXEService) RegisterDevice(ctx context.Context, macAddress, portID string) (*pxe.DeviceInfo, error) {
	if m.registerDeviceErr != nil {
		return nil, m.registerDeviceErr
	}

	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

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
		RetryCount:     0,
	}

	m.devices[device.ID] = device
	m.devicesByMAC[macAddress] = device

	return device, nil
}

func (m *MockPXEService) GetDevice(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
	if m.getDeviceErr != nil {
		return nil, m.getDeviceErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return nil, errors.New("device not found")
	}

	return device, nil
}

func (m *MockPXEService) GetDeviceByMAC(ctx context.Context, mac string) (*pxe.DeviceInfo, error) {
	if m.getDeviceByMACErr != nil {
		return nil, m.getDeviceByMACErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	device, ok := m.devicesByMAC[mac]
	if !ok {
		return nil, errors.New("device not found")
	}

	return device, nil
}

func (m *MockPXEService) ListDevices(ctx context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error) {
	if m.listDevicesErr != nil {
		return nil, m.listDevicesErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	var devices []*pxe.DeviceInfo
	for _, device := range m.devices {
		if filter == nil || filter.Matches(device) {
			devices = append(devices, device)
		}
	}

	return devices, nil
}

func (m *MockPXEService) RemoveDevice(ctx context.Context, deviceID string) error {
	if m.removeDeviceErr != nil {
		return m.removeDeviceErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return errors.New("device not found")
	}

	delete(m.devices, deviceID)
	delete(m.devicesByMAC, device.MACAddress.String())

	return nil
}

func (m *MockPXEService) UpdateDeviceState(ctx context.Context, deviceID string, state pxe.ProvisioningState, reason string) error {
	if m.updateDeviceStateErr != nil {
		return m.updateDeviceStateErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return errors.New("device not found")
	}

	device.State = state
	device.StateReason = reason
	device.StateChangedAt = time.Now()
	device.UpdatedAt = time.Now()

	return nil
}

func (m *MockPXEService) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) error {
	if m.setDeviceEnrolledErr != nil {
		return m.setDeviceEnrolledErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return errors.New("device not found")
	}

	device.CertificateSerial = certSerial
	device.State = pxe.StateEnrolled
	device.UpdatedAt = time.Now()

	return nil
}

func (m *MockPXEService) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) error {
	if m.authorizeDeviceErr != nil {
		return m.authorizeDeviceErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return errors.New("device not found")
	}

	device.TargetVLAN = targetVLAN
	device.CurrentVLAN = targetVLAN
	device.State = pxe.StateAuthorized
	device.UpdatedAt = time.Now()

	return nil
}

func (m *MockPXEService) QuarantineDevice(ctx context.Context, deviceID string, reason string) error {
	if m.quarantineDeviceErr != nil {
		return m.quarantineDeviceErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return errors.New("device not found")
	}

	device.State = pxe.StateQuarantined
	device.StateReason = reason
	device.CurrentVLAN = 100 // quarantine VLAN
	device.UpdatedAt = time.Now()

	return nil
}

func (m *MockPXEService) RetryDevice(ctx context.Context, deviceID string) error {
	if m.retryDeviceErr != nil {
		return m.retryDeviceErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return errors.New("device not found")
	}

	device.State = pxe.StateDiscovered
	device.RetryCount++
	device.UpdatedAt = time.Now()

	return nil
}

func (m *MockPXEService) GetEvents(ctx context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error) {
	if m.getEventsErr != nil {
		return nil, m.getEventsErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	device, ok := m.devices[deviceID]
	if !ok {
		return nil, errors.New("device not found")
	}

	return device.Events, nil
}

func (m *MockPXEService) RegisterEventHandler(handler pxe.EventHandler) {}

func (m *MockPXEService) Status() *pxe.ServiceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &pxe.ServiceStatus{
		Running:          m.running.Load(),
		DeviceCount:      len(m.devices),
		StartTime:        m.startTime,
		IPXEServerAddr:   "10.0.0.1:8080",
		QuarantineVLAN:   100,
		ProvisioningVLAN: 200,
	}
}

// AddTestDevice adds a device directly to the mock for testing
func (m *MockPXEService) AddTestDevice(device *pxe.DeviceInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[device.ID] = device
	m.devicesByMAC[device.MACAddress.String()] = device
}

// AddTestDeviceWithEvents adds a device with events for testing
func (m *MockPXEService) AddTestDeviceWithEvents(device *pxe.DeviceInfo, events []*pxe.ProvisioningEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	device.Events = events
	m.devices[device.ID] = device
	m.devicesByMAC[device.MACAddress.String()] = device
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func createTestPXEHandler() (*QUICServiceHandler, *MockPXEService) {
	logger := logging.DefaultLogger()
	mockPXE := NewMockPXEService()

	handler := newTestQUICServiceHandler(logger,
		WithQUICPXEService(mockPXE),
	)

	return handler, mockPXE
}

func createTestDevice() *pxe.DeviceInfo {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	now := time.Now()
	return &pxe.DeviceInfo{
		ID:             "device-00:11:22:33:44:55",
		MACAddress:     mac,
		PortID:         "port-1",
		State:          pxe.StateDiscovered,
		StateReason:    "device registered",
		CurrentVLAN:    100,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
		RetryCount:     0,
	}
}

// =============================================================================
// PXE List Devices Tests
// =============================================================================

func TestHandlePXEListDevices_Success(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	// Add test devices
	device1 := createTestDevice()
	device1.ID = "device-1"
	mockPXE.AddTestDevice(device1)

	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	device2 := &pxe.DeviceInfo{
		ID:             "device-2",
		MACAddress:     mac2,
		PortID:         "port-2",
		State:          pxe.StateBooting,
		CurrentVLAN:    200,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		StateChangedAt: time.Now(),
	}
	mockPXE.AddTestDevice(device2)

	// Create request with no filter
	req := &quicwire.Request{
		Opcode:  OpPXEListDevices,
		Payload: nil,
	}

	resp := handler.handlePXEListDevices(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)
	assert.NotNil(t, resp.Payload)

	var listResp PXEListDevicesResponse
	err := quicwire.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)
	assert.Equal(t, 2, listResp.Total)
	assert.Len(t, listResp.Devices, 2)
}

func TestHandlePXEListDevices_WithFilter(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	// Add test devices with different states
	device1 := createTestDevice()
	device1.State = pxe.StateDiscovered
	mockPXE.AddTestDevice(device1)

	mac2, _ := net.ParseMAC("00:11:22:33:44:66")
	device2 := &pxe.DeviceInfo{
		ID:             "device-2",
		MACAddress:     mac2,
		PortID:         "port-2",
		State:          pxe.StateBooting,
		CurrentVLAN:    200,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		StateChangedAt: time.Now(),
	}
	mockPXE.AddTestDevice(device2)

	// Filter by state
	filterReq := &PXEListDevicesRequest{
		State: string(pxe.StateDiscovered),
	}
	payload, err := quicwire.EncodePayload(filterReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEListDevices,
		Payload: payload,
	}

	resp := handler.handlePXEListDevices(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var listResp PXEListDevicesResponse
	err = quicwire.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)
	assert.Equal(t, 1, listResp.Total)
}

func TestHandlePXEListDevices_ServiceError(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	mockPXE.listDevicesErr = errors.New("database error")

	req := &quicwire.Request{
		Opcode:  OpPXEListDevices,
		Payload: nil,
	}

	resp := handler.handlePXEListDevices(ctx, req)

	assert.Equal(t, quicwire.StatusInternalError, resp.Status)
}

func TestHandlePXEListDevices_ServiceUnavailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger) // No PXE service configured
	ctx := context.Background()

	req := &quicwire.Request{
		Opcode:  OpPXEListDevices,
		Payload: nil,
	}

	resp := handler.handlePXEOperation(ctx, req)

	assert.Equal(t, quicwire.StatusUnavailable, resp.Status)
}

// =============================================================================
// PXE Get Device Tests
// =============================================================================

func TestHandlePXEGetDevice_ByID(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)

	getReq := &PXEGetDeviceRequest{
		DeviceID: device.ID,
	}
	payload, err := quicwire.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEGetDevice,
		Payload: payload,
	}

	resp := handler.handlePXEGetDevice(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var getResp PXEGetDeviceResponse
	err = quicwire.DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)
	assert.NotNil(t, getResp.Device)
	assert.Equal(t, device.ID, getResp.Device.ID)
	assert.Equal(t, device.MACAddress.String(), getResp.Device.MACAddress)
}

func TestHandlePXEGetDevice_NotFound(t *testing.T) {
	handler, _ := createTestPXEHandler()
	ctx := context.Background()

	getReq := &PXEGetDeviceRequest{
		DeviceID: "nonexistent-device",
	}
	payload, err := quicwire.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEGetDevice,
		Payload: payload,
	}

	resp := handler.handlePXEGetDevice(ctx, req)

	assert.Equal(t, quicwire.StatusNotFound, resp.Status)
}

func TestHandlePXEGetDevice_MissingParameters(t *testing.T) {
	handler, _ := createTestPXEHandler()
	ctx := context.Background()

	getReq := &PXEGetDeviceRequest{} // No device_id
	payload, err := quicwire.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEGetDevice,
		Payload: payload,
	}

	resp := handler.handlePXEGetDevice(ctx, req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// PXE Register Device Tests
// =============================================================================

func TestHandlePXERegisterDevice_Success(t *testing.T) {
	handler, _ := createTestPXEHandler()
	ctx := context.Background()

	regReq := &PXERegisterDeviceRequest{
		MACAddress: "00:11:22:33:44:55",
		PortID:     "port-1",
	}
	payload, err := quicwire.EncodePayload(regReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXERegisterDevice,
		Payload: payload,
	}

	resp := handler.handlePXERegisterDevice(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var regResp PXERegisterDeviceResponse
	err = quicwire.DecodePayload(resp.Payload, &regResp)
	require.NoError(t, err)
	assert.NotNil(t, regResp.Device)
	assert.Equal(t, "00:11:22:33:44:55", regResp.Device.MACAddress)
	assert.Equal(t, "port-1", regResp.Device.PortID)
	assert.Equal(t, string(pxe.StateDiscovered), regResp.Device.State)
}

func TestHandlePXERegisterDevice_MissingMAC(t *testing.T) {
	handler, _ := createTestPXEHandler()
	ctx := context.Background()

	regReq := &PXERegisterDeviceRequest{
		PortID: "port-1",
	}
	payload, err := quicwire.EncodePayload(regReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXERegisterDevice,
		Payload: payload,
	}

	resp := handler.handlePXERegisterDevice(ctx, req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestHandlePXERegisterDevice_MissingPortID(t *testing.T) {
	handler, _ := createTestPXEHandler()
	ctx := context.Background()

	regReq := &PXERegisterDeviceRequest{
		MACAddress: "00:11:22:33:44:55",
	}
	payload, err := quicwire.EncodePayload(regReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXERegisterDevice,
		Payload: payload,
	}

	resp := handler.handlePXERegisterDevice(ctx, req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestHandlePXERegisterDevice_ServiceError(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	mockPXE.registerDeviceErr = errors.New("registration failed")

	regReq := &PXERegisterDeviceRequest{
		MACAddress: "00:11:22:33:44:55",
		PortID:     "port-1",
	}
	payload, err := quicwire.EncodePayload(regReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXERegisterDevice,
		Payload: payload,
	}

	resp := handler.handlePXERegisterDevice(ctx, req)

	assert.Equal(t, quicwire.StatusInternalError, resp.Status)
}

// =============================================================================
// PXE Update State Tests
// =============================================================================

func TestHandlePXEUpdateState_Success(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)

	updateReq := &PXEUpdateStateRequest{
		DeviceID: device.ID,
		State:    string(pxe.StateBooting),
		Reason:   "PXE boot started",
	}
	payload, err := quicwire.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEUpdateState,
		Payload: payload,
	}

	resp := handler.handlePXEUpdateState(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var updateResp PXEUpdateStateResponse
	err = quicwire.DecodePayload(resp.Payload, &updateResp)
	require.NoError(t, err)
	assert.Equal(t, device.ID, updateResp.DeviceID)
	assert.Equal(t, string(pxe.StateDiscovered), updateResp.OldState)
	assert.Equal(t, string(pxe.StateBooting), updateResp.NewState)
	assert.True(t, updateResp.Success)
}

func TestHandlePXEUpdateState_InvalidState(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)

	updateReq := &PXEUpdateStateRequest{
		DeviceID: device.ID,
		State:    "invalid_state",
	}
	payload, err := quicwire.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEUpdateState,
		Payload: payload,
	}

	resp := handler.handlePXEUpdateState(ctx, req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

func TestHandlePXEUpdateState_MissingDeviceID(t *testing.T) {
	handler, _ := createTestPXEHandler()
	ctx := context.Background()

	updateReq := &PXEUpdateStateRequest{
		State: string(pxe.StateBooting),
	}
	payload, err := quicwire.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEUpdateState,
		Payload: payload,
	}

	resp := handler.handlePXEUpdateState(ctx, req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// PXE Authorize Tests
// =============================================================================

func TestHandlePXEAuthorize_Success(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	device.State = pxe.StateAuthorizing
	mockPXE.AddTestDevice(device)

	authReq := &PXEAuthorizeRequest{
		DeviceID:   device.ID,
		TargetVLAN: 300,
	}
	payload, err := quicwire.EncodePayload(authReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEAuthorize,
		Payload: payload,
	}

	resp := handler.handlePXEAuthorize(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var authResp PXEAuthorizeResponse
	err = quicwire.DecodePayload(resp.Payload, &authResp)
	require.NoError(t, err)
	assert.Equal(t, device.ID, authResp.DeviceID)
	assert.Equal(t, uint16(300), authResp.TargetVLAN)
	assert.True(t, authResp.Success)
}

func TestHandlePXEAuthorize_MissingVLAN(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)

	authReq := &PXEAuthorizeRequest{
		DeviceID: device.ID,
	}
	payload, err := quicwire.EncodePayload(authReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEAuthorize,
		Payload: payload,
	}

	resp := handler.handlePXEAuthorize(ctx, req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// PXE Quarantine Tests
// =============================================================================

func TestHandlePXEQuarantine_Success(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)

	quarReq := &PXEQuarantineRequest{
		DeviceID: device.ID,
		Reason:   "Security policy violation",
	}
	payload, err := quicwire.EncodePayload(quarReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEQuarantine,
		Payload: payload,
	}

	resp := handler.handlePXEQuarantine(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var quarResp PXEQuarantineResponse
	err = quicwire.DecodePayload(resp.Payload, &quarResp)
	require.NoError(t, err)
	assert.Equal(t, device.ID, quarResp.DeviceID)
	assert.True(t, quarResp.Success)
}

func TestHandlePXEQuarantine_MissingReason(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)

	quarReq := &PXEQuarantineRequest{
		DeviceID: device.ID,
	}
	payload, err := quicwire.EncodePayload(quarReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXEQuarantine,
		Payload: payload,
	}

	resp := handler.handlePXEQuarantine(ctx, req)

	assert.Equal(t, quicwire.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// PXE Retry Tests
// =============================================================================

func TestHandlePXERetry_Success(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	device.State = pxe.StateFailed
	mockPXE.AddTestDevice(device)

	retryReq := &PXERetryRequest{
		DeviceID: device.ID,
	}
	payload, err := quicwire.EncodePayload(retryReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXERetry,
		Payload: payload,
	}

	resp := handler.handlePXERetry(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var retryResp PXERetryResponse
	err = quicwire.DecodePayload(resp.Payload, &retryResp)
	require.NoError(t, err)
	assert.Equal(t, device.ID, retryResp.DeviceID)
	assert.Equal(t, 1, retryResp.RetryCount)
	assert.True(t, retryResp.Success)
}

func TestHandlePXERetry_ServiceError(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)
	mockPXE.retryDeviceErr = errors.New("max retries exceeded")

	retryReq := &PXERetryRequest{
		DeviceID: device.ID,
	}
	payload, err := quicwire.EncodePayload(retryReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXERetry,
		Payload: payload,
	}

	resp := handler.handlePXERetry(ctx, req)

	assert.Equal(t, quicwire.StatusInternalError, resp.Status)
}

// =============================================================================
// PXE Remove Device Tests
// =============================================================================

func TestHandlePXERemoveDevice_Success(t *testing.T) {
	handler, mockPXE := createTestPXEHandler()
	ctx := context.Background()

	device := createTestDevice()
	mockPXE.AddTestDevice(device)

	removeReq := &PXERemoveDeviceRequest{
		DeviceID: device.ID,
	}
	payload, err := quicwire.EncodePayload(removeReq)
	require.NoError(t, err)

	req := &quicwire.Request{
		Opcode:  OpPXERemoveDevice,
		Payload: payload,
	}

	resp := handler.handlePXERemoveDevice(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var removeResp PXERemoveDeviceResponse
	err = quicwire.DecodePayload(resp.Payload, &removeResp)
	require.NoError(t, err)
	assert.Equal(t, device.ID, removeResp.DeviceID)
	assert.True(t, removeResp.Success)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestPXEErrorTypes(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrPXEDeviceNotFound_ByID",
			err:      ErrPXEDeviceNotFound{DeviceID: "device-123"},
			expected: "PXE device not found: device-123",
		},
		{
			name:     "ErrPXEDeviceNotFound_ByMAC",
			err:      ErrPXEDeviceNotFound{MACAddress: "00:11:22:33:44:55"},
			expected: "PXE device not found with MAC: 00:11:22:33:44:55",
		},
		{
			name:     "ErrPXERegistrationFailed",
			err:      ErrPXERegistrationFailed{MACAddress: "00:11:22:33:44:55", Cause: errors.New("already exists")},
			expected: "PXE device registration failed for 00:11:22:33:44:55: already exists",
		},
		{
			name:     "ErrPXEInvalidState",
			err:      ErrPXEInvalidState{State: "invalid"},
			expected: "invalid PXE provisioning state: invalid",
		},
		{
			name:     "ErrPXEStateTransitionFailed",
			err:      ErrPXEStateTransitionFailed{DeviceID: "dev-1", FromState: "discovered", ToState: "authorized", Cause: errors.New("not allowed")},
			expected: "PXE state transition failed for dev-1 from discovered to authorized: not allowed",
		},
		{
			name:     "ErrPXEEnrollmentFailed",
			err:      ErrPXEEnrollmentFailed{DeviceID: "dev-1", Cause: errors.New("cert error")},
			expected: "PXE device enrollment failed for dev-1: cert error",
		},
		{
			name:     "ErrPXEAuthorizationFailed",
			err:      ErrPXEAuthorizationFailed{DeviceID: "dev-1", Cause: errors.New("vlan error")},
			expected: "PXE device authorization failed for dev-1: vlan error",
		},
		{
			name:     "ErrPXEQuarantineFailed",
			err:      ErrPXEQuarantineFailed{DeviceID: "dev-1", Cause: errors.New("flow error")},
			expected: "PXE device quarantine failed for dev-1: flow error",
		},
		{
			name:     "ErrPXERetryFailed",
			err:      ErrPXERetryFailed{DeviceID: "dev-1", Cause: errors.New("max retries")},
			expected: "PXE device retry failed for dev-1: max retries",
		},
		{
			name:     "ErrPXEServiceStartFailed",
			err:      ErrPXEServiceStartFailed{Cause: errors.New("port in use")},
			expected: "PXE service failed to start: port in use",
		},
		{
			name:     "ErrPXEServiceStopFailed",
			err:      ErrPXEServiceStopFailed{Cause: errors.New("timeout")},
			expected: "PXE service failed to stop: timeout",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

func TestPXEErrorUnwrap(t *testing.T) {
	causeErr := errors.New("root cause")

	testCases := []struct {
		name string
		err  error
	}{
		{"ErrPXERegistrationFailed", ErrPXERegistrationFailed{Cause: causeErr}},
		{"ErrPXEStateTransitionFailed", ErrPXEStateTransitionFailed{Cause: causeErr}},
		{"ErrPXEEnrollmentFailed", ErrPXEEnrollmentFailed{Cause: causeErr}},
		{"ErrPXEAuthorizationFailed", ErrPXEAuthorizationFailed{Cause: causeErr}},
		{"ErrPXEQuarantineFailed", ErrPXEQuarantineFailed{Cause: causeErr}},
		{"ErrPXERetryFailed", ErrPXERetryFailed{Cause: causeErr}},
		{"ErrPXEServiceStartFailed", ErrPXEServiceStartFailed{Cause: causeErr}},
		{"ErrPXEServiceStopFailed", ErrPXEServiceStopFailed{Cause: causeErr}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			unwrapped := errors.Unwrap(tc.err)
			assert.Equal(t, causeErr, unwrapped)
		})
	}
}

// =============================================================================
// WithQUICPXEService Option Test
// =============================================================================

func TestWithQUICPXEService(t *testing.T) {
	logger := logging.DefaultLogger()
	mockPXE := NewMockPXEService()

	handler := newTestQUICServiceHandler(logger,
		WithQUICPXEService(mockPXE),
	)

	assert.NotNil(t, handler.pxeService)
}

func TestSetPXEService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := newTestQUICServiceHandler(logger)

	assert.Nil(t, handler.pxeService)

	mockPXE := NewMockPXEService()
	handler.SetPXEService(mockPXE)

	assert.NotNil(t, handler.pxeService)
}

// =============================================================================
// Conversion Helper Tests
// =============================================================================

func TestConvertDeviceInfoToPXEDevice(t *testing.T) {
	t.Run("nil device", func(t *testing.T) {
		result := convertDeviceInfoToPXEDevice(nil)
		assert.Nil(t, result)
	})

	t.Run("valid device", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		now := time.Now()

		device := &pxe.DeviceInfo{
			ID:                "device-123",
			MACAddress:        mac,
			PortID:            "port-1",
			State:             pxe.StateDiscovered,
			StateReason:       "test reason",
			CertificateSerial: "12345",
			CurrentVLAN:       100,
			TargetVLAN:        200,
			CreatedAt:         now,
			UpdatedAt:         now,
			StateChangedAt:    now,
			RetryCount:        2,
		}

		result := convertDeviceInfoToPXEDevice(device)

		assert.NotNil(t, result)
		assert.Equal(t, "device-123", result.ID)
		assert.Equal(t, "00:11:22:33:44:55", result.MACAddress)
		assert.Equal(t, "port-1", result.PortID)
		assert.Equal(t, string(pxe.StateDiscovered), result.State)
		assert.Equal(t, "test reason", result.StateReason)
		assert.Equal(t, "12345", result.CertificateSerial)
		assert.Equal(t, uint16(100), result.CurrentVLAN)
		assert.Equal(t, uint16(200), result.TargetVLAN)
		assert.Equal(t, now.Unix(), result.CreatedAt)
		assert.Equal(t, 2, result.RetryCount)
	})
}

// =============================================================================
// Readiness Check PXE Component Test
// =============================================================================

func TestHandleReadiness_WithPXEService(t *testing.T) {
	handler, _ := createTestPXEHandler()
	ctx := context.Background()

	req := &quicwire.Request{
		Opcode:  quicwire.OpReadiness,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)

	assert.Equal(t, quicwire.StatusOK, resp.Status)

	var healthResp HealthCheckResponse
	err := quicwire.DecodePayload(resp.Payload, &healthResp)
	require.NoError(t, err)
	assert.Equal(t, "ready", healthResp.Components["pxe"])
}
