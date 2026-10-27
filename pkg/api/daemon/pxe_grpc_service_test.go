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

package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockPXEService is a mock implementation of the pxe.Service interface for testing.
type mockPXEService struct {
	devices        map[string]*pxe.DeviceInfo
	running        bool
	startErr       error
	stopErr        error
	registerErr    error
	getErr         error
	listErr        error
	removeErr      error
	updateStateErr error
	authorizeErr   error
	quarantineErr  error
	retryErr       error
	eventsErr      error
	enrollErr      error
}

func newMockPXEService() *mockPXEService {
	return &mockPXEService{
		devices: make(map[string]*pxe.DeviceInfo),
		running: false,
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
	return nil
}

func (m *mockPXEService) Stop(ctx context.Context) error {
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running = false
	return nil
}

func (m *mockPXEService) IsRunning() bool {
	return m.running
}

func (m *mockPXEService) Close() error {
	m.running = false
	return nil
}

func (m *mockPXEService) RegisterDevice(ctx context.Context, macAddress, portID string) (*pxe.DeviceInfo, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}

	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return nil, pxe.ErrInvalidMACAddress{MACAddress: macAddress, Reason: err.Error()}
	}

	deviceID := "device-" + macAddress
	if _, exists := m.devices[deviceID]; exists {
		return nil, pxe.ErrDeviceAlreadyExists{DeviceID: deviceID, MACAddress: macAddress}
	}

	now := time.Now()
	device := &pxe.DeviceInfo{
		ID:             deviceID,
		MACAddress:     mac,
		PortID:         portID,
		State:          pxe.StateDiscovered,
		StateReason:    "device registered",
		CurrentVLAN:    100,
		CreatedAt:      now,
		UpdatedAt:      now,
		StateChangedAt: now,
		Events:         make([]*pxe.ProvisioningEvent, 0),
	}
	m.devices[deviceID] = device
	return device, nil
}

func (m *mockPXEService) GetDevice(ctx context.Context, deviceID string) (*pxe.DeviceInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return nil, pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	return device, nil
}

func (m *mockPXEService) GetDeviceByMAC(ctx context.Context, mac string) (*pxe.DeviceInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	for _, device := range m.devices {
		if device.MACAddress.String() == mac {
			return device, nil
		}
	}
	return nil, pxe.ErrDeviceNotFound{MACAddress: mac}
}

func (m *mockPXEService) ListDevices(ctx context.Context, filter *pxe.DeviceFilter) ([]*pxe.DeviceInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	devices := make([]*pxe.DeviceInfo, 0, len(m.devices))
	for _, device := range m.devices {
		if filter == nil || filter.Matches(device) {
			devices = append(devices, device)
		}
	}
	return devices, nil
}

func (m *mockPXEService) RemoveDevice(ctx context.Context, deviceID string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	if _, exists := m.devices[deviceID]; !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	delete(m.devices, deviceID)
	return nil
}

func (m *mockPXEService) UpdateDeviceState(ctx context.Context, deviceID string, state pxe.ProvisioningState, reason string) error {
	if m.updateStateErr != nil {
		return m.updateStateErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	device.State = state
	device.StateReason = reason
	device.StateChangedAt = time.Now()
	device.UpdatedAt = time.Now()
	return nil
}

func (m *mockPXEService) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) error {
	if m.enrollErr != nil {
		return m.enrollErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	device.CertificateSerial = certSerial
	device.State = pxe.StateEnrolled
	device.UpdatedAt = time.Now()
	return nil
}

func (m *mockPXEService) SetDeviceInstalling(ctx context.Context, deviceID, installCertSHA256, reason string) error {
	if m.updateStateErr != nil {
		return m.updateStateErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	device.InstallCertificateSHA256 = installCertSHA256
	device.State = pxe.StateInstalling
	device.StateReason = reason
	device.UpdatedAt = time.Now()
	return nil
}

func (m *mockPXEService) CompleteInstallation(ctx context.Context, deviceID, installCertSHA256 string, success bool, reason string) error {
	if m.updateStateErr != nil {
		return m.updateStateErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	if device.State != pxe.StateInstalling || device.InstallCertificateSHA256 != installCertSHA256 {
		return pxe.ErrInstallationNotBound{DeviceID: deviceID, State: string(device.State), CertificateSHA256: installCertSHA256}
	}
	device.State = pxe.StateFailed
	if success {
		device.State = pxe.StateInstallComplete
	}
	device.InstallCertificateSHA256 = ""
	device.StateReason = reason
	device.UpdatedAt = time.Now()
	return nil
}

func (m *mockPXEService) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) error {
	if m.authorizeErr != nil {
		return m.authorizeErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	device.TargetVLAN = targetVLAN
	device.CurrentVLAN = targetVLAN
	device.State = pxe.StateAuthorized
	device.UpdatedAt = time.Now()
	return nil
}

func (m *mockPXEService) QuarantineDevice(ctx context.Context, deviceID string, reason string) error {
	if m.quarantineErr != nil {
		return m.quarantineErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	device.State = pxe.StateQuarantined
	device.StateReason = reason
	device.UpdatedAt = time.Now()
	return nil
}

func (m *mockPXEService) RetryDevice(ctx context.Context, deviceID string) error {
	if m.retryErr != nil {
		return m.retryErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	device.State = pxe.StateDiscovered
	device.RetryCount++
	device.UpdatedAt = time.Now()
	return nil
}

func (m *mockPXEService) GetEvents(ctx context.Context, deviceID string) ([]*pxe.ProvisioningEvent, error) {
	if m.eventsErr != nil {
		return nil, m.eventsErr
	}
	device, exists := m.devices[deviceID]
	if !exists {
		return nil, pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	return device.Events, nil
}

func (m *mockPXEService) RegisterEventHandler(handler pxe.EventHandler) {}

func (m *mockPXEService) Status() *pxe.ServiceStatus {
	return &pxe.ServiceStatus{
		Running:          m.running,
		DeviceCount:      len(m.devices),
		StartTime:        time.Now().Add(-time.Hour),
		IPXEServerAddr:   "192.168.1.1:69",
		QuarantineVLAN:   100,
		ProvisioningVLAN: 200,
	}
}

// TestPXEGRPCService_NewPXEGRPCService tests the constructor.
func TestPXEGRPCService_NewPXEGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()

	svc := NewPXEGRPCService(logger, mockService)

	require.NotNil(t, svc)
	assert.NotNil(t, svc.logger)
	assert.NotNil(t, svc.pxeService)
}

// TestPXEGRPCService_RegisterDevice tests device registration.
func TestPXEGRPCService_RegisterDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.RegisterPXEDeviceRequest{
			MacAddress: "00:11:22:33:44:55",
			PortId:     "port-1",
		}

		resp, err := svc.RegisterDevice(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.NotNil(t, resp.GetDevice())
		assert.Equal(t, "00:11:22:33:44:55", resp.GetDevice().GetMacAddress())
	})

	t.Run("missing MAC address", func(t *testing.T) {
		req := &platformv1.RegisterPXEDeviceRequest{
			PortId: "port-1",
		}

		resp, err := svc.RegisterDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing port ID", func(t *testing.T) {
		req := &platformv1.RegisterPXEDeviceRequest{
			MacAddress: "00:11:22:33:44:66",
		}

		resp, err := svc.RegisterDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("service not initialized", func(t *testing.T) {
		svcNil := NewPXEGRPCService(logger, nil)
		req := &platformv1.RegisterPXEDeviceRequest{
			MacAddress: "00:11:22:33:44:77",
			PortId:     "port-1",
		}

		resp, err := svcNil.RegisterDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, "pxe", notConfiguredServiceName(t, st))
	})

	t.Run("duplicate device", func(t *testing.T) {
		req := &platformv1.RegisterPXEDeviceRequest{
			MacAddress: "00:11:22:33:44:55",
			PortId:     "port-2",
		}

		resp, err := svc.RegisterDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.AlreadyExists, st.Code())
	})
}

// TestPXEGRPCService_GetDevice tests getting a device by ID.
func TestPXEGRPCService_GetDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:88",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.GetPXEDeviceRequest{
			DeviceId: deviceID,
		}

		resp, err := svc.GetDevice(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, deviceID, resp.GetDevice().GetId())
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.GetPXEDeviceRequest{}

		resp, err := svc.GetDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("device not found", func(t *testing.T) {
		req := &platformv1.GetPXEDeviceRequest{
			DeviceId: "non-existent",
		}

		resp, err := svc.GetDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// TestPXEGRPCService_GetDeviceByMAC tests getting a device by MAC address.
func TestPXEGRPCService_GetDeviceByMAC(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	macAddress := "00:11:22:33:44:99"
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: macAddress,
		PortId:     "port-1",
	}
	_, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		req := &platformv1.GetPXEDeviceByMACRequest{
			MacAddress: macAddress,
		}

		resp, err := svc.GetDeviceByMAC(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, macAddress, resp.GetDevice().GetMacAddress())
	})

	t.Run("missing MAC address", func(t *testing.T) {
		req := &platformv1.GetPXEDeviceByMACRequest{}

		resp, err := svc.GetDeviceByMAC(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("device not found", func(t *testing.T) {
		req := &platformv1.GetPXEDeviceByMACRequest{
			MacAddress: "aa:bb:cc:dd:ee:ff",
		}

		resp, err := svc.GetDeviceByMAC(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// TestPXEGRPCService_ListDevices tests listing devices.
func TestPXEGRPCService_ListDevices(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register some devices
	for i := 0; i < 3; i++ {
		mac := "00:11:22:33:44:a" + string(rune('0'+i))
		req := &platformv1.RegisterPXEDeviceRequest{
			MacAddress: mac,
			PortId:     "port-" + string(rune('0'+i)),
		}
		_, err := svc.RegisterDevice(ctx, req)
		require.NoError(t, err)
	}

	t.Run("success", func(t *testing.T) {
		req := &platformv1.ListPXEDevicesRequest{}

		resp, err := svc.ListDevices(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Len(t, resp.GetDevices(), 3)
	})

	t.Run("with filter", func(t *testing.T) {
		req := &platformv1.ListPXEDevicesRequest{
			Filter: &platformv1.PXEDeviceFilter{
				State: platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED,
			},
		}

		resp, err := svc.ListDevices(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		// RegisterDevice leaves every device discovered, so a discovered
		// filter has to return all three of them.
		assert.Len(t, resp.GetDevices(), 3)
		for _, d := range resp.GetDevices() {
			assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED, d.GetState())
		}
	})

	t.Run("service not initialized", func(t *testing.T) {
		svcNil := NewPXEGRPCService(logger, nil)
		req := &platformv1.ListPXEDevicesRequest{}

		resp, err := svcNil.ListDevices(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, "pxe", notConfiguredServiceName(t, st))
	})
}

// TestPXEGRPCService_RemoveDevice tests removing a device.
func TestPXEGRPCService_RemoveDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:bb",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.RemovePXEDeviceRequest{
			DeviceId: deviceID,
		}

		resp, err := svc.RemoveDevice(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.RemovePXEDeviceRequest{}

		resp, err := svc.RemoveDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("device not found", func(t *testing.T) {
		req := &platformv1.RemovePXEDeviceRequest{
			DeviceId: "non-existent",
		}

		resp, err := svc.RemoveDevice(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// TestPXEGRPCService_UpdateState tests updating device state.
func TestPXEGRPCService_UpdateState(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:cc",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.UpdatePXEStateRequest{
			DeviceId: deviceID,
			State:    platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
			Reason:   "PXE boot started",
		}

		resp, err := svc.UpdateState(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING, resp.GetDevice().GetState())
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.UpdatePXEStateRequest{
			State:  platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
			Reason: "test",
		}

		resp, err := svc.UpdateState(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// TestPXEGRPCService_SetDeviceEnrolled tests setting device enrolled.
func TestPXEGRPCService_SetDeviceEnrolled(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:dd",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.SetPXEDeviceEnrolledRequest{
			DeviceId:          deviceID,
			CertificateSerial: "ABCD1234",
		}

		resp, err := svc.SetDeviceEnrolled(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, "ABCD1234", resp.GetDevice().GetCertificateSerial())
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.SetPXEDeviceEnrolledRequest{
			CertificateSerial: "ABCD1234",
		}

		resp, err := svc.SetDeviceEnrolled(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing certificate serial", func(t *testing.T) {
		req := &platformv1.SetPXEDeviceEnrolledRequest{
			DeviceId: deviceID,
		}

		resp, err := svc.SetDeviceEnrolled(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// TestPXEGRPCService_Authorize tests authorizing a device.
func TestPXEGRPCService_Authorize(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:ee",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.AuthorizePXEDeviceRequest{
			DeviceId:   deviceID,
			TargetVlan: 300,
		}

		resp, err := svc.Authorize(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, uint32(300), resp.GetDevice().GetTargetVlan())
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.AuthorizePXEDeviceRequest{
			TargetVlan: 300,
		}

		resp, err := svc.Authorize(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing target VLAN", func(t *testing.T) {
		req := &platformv1.AuthorizePXEDeviceRequest{
			DeviceId: deviceID,
		}

		resp, err := svc.Authorize(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// TestPXEGRPCService_Quarantine tests quarantining a device.
func TestPXEGRPCService_Quarantine(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:f0",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.QuarantinePXEDeviceRequest{
			DeviceId: deviceID,
			Reason:   "security violation",
		}

		resp, err := svc.Quarantine(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
		assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED, resp.GetDevice().GetState())
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.QuarantinePXEDeviceRequest{
			Reason: "security violation",
		}

		resp, err := svc.Quarantine(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("missing reason", func(t *testing.T) {
		req := &platformv1.QuarantinePXEDeviceRequest{
			DeviceId: deviceID,
		}

		resp, err := svc.Quarantine(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// TestPXEGRPCService_Retry tests retrying a device.
func TestPXEGRPCService_Retry(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device and quarantine it
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:f1",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	// Quarantine the device first
	mockService.devices[deviceID].State = pxe.StateFailed

	t.Run("success", func(t *testing.T) {
		req := &platformv1.RetryPXEDeviceRequest{
			DeviceId: deviceID,
		}

		resp, err := svc.Retry(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.RetryPXEDeviceRequest{}

		resp, err := svc.Retry(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// TestPXEGRPCService_GetEvents tests getting device events.
func TestPXEGRPCService_GetEvents(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: "00:11:22:33:44:f2",
		PortId:     "port-1",
	}
	regResp, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)
	deviceID := regResp.GetDevice().GetId()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.GetPXEEventsRequest{
			DeviceId: deviceID,
		}

		resp, err := svc.GetEvents(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
	})

	t.Run("missing device ID", func(t *testing.T) {
		req := &platformv1.GetPXEEventsRequest{}

		resp, err := svc.GetEvents(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}

// TestPXEGRPCService_GetStatus tests getting service status.
func TestPXEGRPCService_GetStatus(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.GetPXEStatusRequest{}

		resp, err := svc.GetStatus(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.NotNil(t, resp.GetStatus())
	})

	t.Run("service not initialized", func(t *testing.T) {
		svcNil := NewPXEGRPCService(logger, nil)
		req := &platformv1.GetPXEStatusRequest{}

		resp, err := svcNil.GetStatus(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, "pxe", notConfiguredServiceName(t, st))
	})
}

// TestPXEGRPCService_StartService tests starting the service.
func TestPXEGRPCService_StartService(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		req := &platformv1.StartPXEServiceRequest{}

		resp, err := svc.StartService(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("service not initialized", func(t *testing.T) {
		svcNil := NewPXEGRPCService(logger, nil)
		req := &platformv1.StartPXEServiceRequest{}

		resp, err := svcNil.StartService(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, "pxe", notConfiguredServiceName(t, st))
	})

	t.Run("start error", func(t *testing.T) {
		mockWithErr := newMockPXEService()
		mockWithErr.startErr = pxe.ErrServiceAlreadyRunning{}
		svcWithErr := NewPXEGRPCService(logger, mockWithErr)
		req := &platformv1.StartPXEServiceRequest{}

		resp, err := svcWithErr.StartService(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})
}

// TestPXEGRPCService_StopService tests stopping the service.
func TestPXEGRPCService_StopService(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Start the service first
	_, err := svc.StartService(ctx, &platformv1.StartPXEServiceRequest{})
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		req := &platformv1.StopPXEServiceRequest{}

		resp, err := svc.StopService(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("service not initialized", func(t *testing.T) {
		svcNil := NewPXEGRPCService(logger, nil)
		req := &platformv1.StopPXEServiceRequest{}

		resp, err := svcNil.StopService(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unavailable, st.Code())
		assert.Equal(t, "pxe", notConfiguredServiceName(t, st))
	})

	t.Run("stop error", func(t *testing.T) {
		mockWithErr := newMockPXEService()
		mockWithErr.stopErr = pxe.ErrServiceNotRunning{}
		svcWithErr := NewPXEGRPCService(logger, mockWithErr)
		req := &platformv1.StopPXEServiceRequest{}

		resp, err := svcWithErr.StopService(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})
}

// TestPXEGRPCService_StateConversions tests state conversion functions.
func TestPXEGRPCService_StateConversions(t *testing.T) {
	svc := &PXEGRPCService{}

	testCases := []struct {
		pxeState   pxe.ProvisioningState
		protoState platformv1.ProvisioningState
	}{
		{pxe.StateUnknown, platformv1.ProvisioningState_PROVISIONING_STATE_UNKNOWN},
		{pxe.StateDiscovered, platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED},
		{pxe.StateBooting, platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING},
		{pxe.StateInstalling, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING},
		{pxe.StateInstallComplete, platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE},
		{pxe.StateEnrolling, platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLING},
		{pxe.StateEnrolled, platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLED},
		{pxe.StateAuthorizing, platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZING},
		{pxe.StateAuthorized, platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZED},
		{pxe.StateFailed, platformv1.ProvisioningState_PROVISIONING_STATE_FAILED},
		{pxe.StateQuarantined, platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED},
	}

	for _, tc := range testCases {
		t.Run(string(tc.pxeState), func(t *testing.T) {
			// Test to proto
			protoState := svc.stateToProto(tc.pxeState)
			assert.Equal(t, tc.protoState, protoState)

			// Test from proto
			pxeState := svc.stateFromProto(tc.protoState)
			assert.Equal(t, tc.pxeState, pxeState)
		})
	}
}

// TestPXEGRPCService_EventTypeConversions tests event type conversion functions.
func TestPXEGRPCService_EventTypeConversions(t *testing.T) {
	svc := &PXEGRPCService{}

	testCases := []struct {
		pxeType   pxe.ProvisioningEventType
		protoType platformv1.ProvisioningEventType
	}{
		{pxe.EventDeviceDiscovered, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_DEVICE_DISCOVERED},
		{pxe.EventPXEBootStarted, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_PXE_BOOT_STARTED},
		{pxe.EventInstallStarted, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_INSTALL_STARTED},
		{pxe.EventInstallCompleted, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_INSTALL_COMPLETED},
		{pxe.EventEnrollmentStarted, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_ENROLLMENT_STARTED},
		{pxe.EventEnrollmentCompleted, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_ENROLLMENT_COMPLETED},
		{pxe.EventAuthorizationStarted, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_AUTHORIZATION_STARTED},
		{pxe.EventAuthorizationCompleted, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_AUTHORIZATION_COMPLETED},
		{pxe.EventQuarantined, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_QUARANTINED},
		{pxe.EventFailed, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_FAILED},
		{pxe.EventRetry, platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_RETRY},
	}

	for _, tc := range testCases {
		t.Run(string(tc.pxeType), func(t *testing.T) {
			protoType := svc.eventTypeToProto(tc.pxeType)
			assert.Equal(t, tc.protoType, protoType)
		})
	}
}

// TestPXEGRPCService_ErrorMapping tests error mapping to gRPC status codes.
func TestPXEGRPCService_ErrorMapping(t *testing.T) {
	svc := &PXEGRPCService{}

	testCases := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{
			name:     "nil error",
			err:      nil,
			wantCode: codes.OK,
		},
		{
			name:     "device not found",
			err:      pxe.ErrDeviceNotFound{DeviceID: "test"},
			wantCode: codes.NotFound,
		},
		{
			name:     "device already exists",
			err:      pxe.ErrDeviceAlreadyExists{MACAddress: "00:11:22:33:44:55"},
			wantCode: codes.AlreadyExists,
		},
		{
			name:     "invalid MAC address",
			err:      pxe.ErrInvalidMACAddress{MACAddress: "invalid"},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "invalid state",
			err:      pxe.ErrInvalidState{State: "invalid"},
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "invalid state transition",
			err:      pxe.ErrInvalidStateTransition{FromState: "a", ToState: "b"},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "service not initialized",
			err:      pxe.ErrServiceNotInitialized{},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "service already running",
			err:      pxe.ErrServiceAlreadyRunning{},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "service not running",
			err:      pxe.ErrServiceNotRunning{},
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "max retries exceeded",
			err:      pxe.ErrMaxRetriesExceeded{MaxRetries: 3},
			wantCode: codes.ResourceExhausted,
		},
		{
			name:     "VLAN transition failed",
			err:      pxe.ErrVLANTransitionFailed{DeviceID: "test"},
			wantCode: codes.Internal,
		},
		{
			name:     "provisioning failed",
			err:      pxe.ErrProvisioningFailed{Reason: "test"},
			wantCode: codes.Internal,
		},
		{
			name:     "invalid configuration",
			err:      pxe.ErrInvalidConfiguration{Reason: "test"},
			wantCode: codes.InvalidArgument,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			grpcErr := svc.mapPXEError(tc.err, "test operation")
			if tc.wantCode == codes.OK {
				assert.Nil(t, grpcErr)
			} else {
				require.NotNil(t, grpcErr)
				st, ok := status.FromError(grpcErr)
				require.True(t, ok)
				assert.Equal(t, tc.wantCode, st.Code())
			}
		})
	}
}

// TestPXEGRPCService_SetPXEService tests the SetPXEService setter.
func TestPXEGRPCService_SetPXEService(t *testing.T) {
	logger := logging.DefaultLogger()
	svc := NewPXEGRPCService(logger, nil)

	assert.Nil(t, svc.pxeService)

	mockService := newMockPXEService()
	svc.SetPXEService(mockService)

	assert.NotNil(t, svc.pxeService)
}

// TestPXEGRPCService_FilterFromProto tests filter conversion from proto.
func TestPXEGRPCService_FilterFromProto(t *testing.T) {
	svc := &PXEGRPCService{}

	t.Run("nil filter", func(t *testing.T) {
		result := svc.filterFromProto(nil)
		assert.Nil(t, result)
	})

	t.Run("populated filter", func(t *testing.T) {
		protoFilter := &platformv1.PXEDeviceFilter{
			State:      platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED,
			MacAddress: "00:11:22:33:44:55",
			Vlan:       100,
			Limit:      10,
			Offset:     5,
		}

		result := svc.filterFromProto(protoFilter)

		require.NotNil(t, result)
		assert.Equal(t, pxe.StateDiscovered, result.State)
		assert.Equal(t, "00:11:22:33:44:55", result.MACAddress)
		assert.Equal(t, uint16(100), result.VLAN)
		assert.Equal(t, 10, result.Limit)
		assert.Equal(t, 5, result.Offset)
	})

	t.Run("unset state matches any state", func(t *testing.T) {
		result := svc.filterFromProto(&platformv1.PXEDeviceFilter{Vlan: 100})

		require.NotNil(t, result)
		assert.Empty(t, result.State, "an unset state must not narrow to the unknown state")
		mac, err := net.ParseMAC("00:11:22:33:44:55")
		require.NoError(t, err)
		discovered := &pxe.DeviceInfo{MACAddress: mac, State: pxe.StateDiscovered, CurrentVLAN: 100}
		assert.True(t, result.Matches(discovered))
	})
}

// TestPXEGRPCService_DeviceToProto tests device conversion to proto.
func TestPXEGRPCService_DeviceToProto(t *testing.T) {
	svc := &PXEGRPCService{}

	t.Run("nil device", func(t *testing.T) {
		result := svc.deviceToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("populated device", func(t *testing.T) {
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		now := time.Now()
		device := &pxe.DeviceInfo{
			ID:                "device-123",
			MACAddress:        mac,
			PortID:            "port-1",
			State:             pxe.StateDiscovered,
			StateReason:       "test reason",
			CertificateSerial: "CERT123",
			CurrentVLAN:       100,
			TargetVLAN:        200,
			CreatedAt:         now,
			UpdatedAt:         now,
			StateChangedAt:    now,
			RetryCount:        2,
			Events: []*pxe.ProvisioningEvent{
				{
					ID:        "event-1",
					DeviceID:  "device-123",
					Timestamp: now,
					EventType: pxe.EventDeviceDiscovered,
					FromState: pxe.StateUnknown,
					ToState:   pxe.StateDiscovered,
				},
			},
		}

		result := svc.deviceToProto(device)

		require.NotNil(t, result)
		assert.Equal(t, "device-123", result.GetId())
		assert.Equal(t, "00:11:22:33:44:55", result.GetMacAddress())
		assert.Equal(t, "port-1", result.GetPortId())
		assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED, result.GetState())
		assert.Equal(t, "test reason", result.GetStateReason())
		assert.Equal(t, "CERT123", result.GetCertificateSerial())
		assert.Equal(t, uint32(100), result.GetCurrentVlan())
		assert.Equal(t, uint32(200), result.GetTargetVlan())
		assert.Equal(t, int32(2), result.GetRetryCount())
		assert.Len(t, result.GetEvents(), 1)
	})
}

// TestPXEGRPCService_StatusToProto tests status conversion to proto.
func TestPXEGRPCService_StatusToProto(t *testing.T) {
	svc := &PXEGRPCService{}

	t.Run("nil status", func(t *testing.T) {
		result := svc.statusToProto(nil)
		assert.Nil(t, result)
	})

	t.Run("populated status", func(t *testing.T) {
		now := time.Now()
		svcStatus := &pxe.ServiceStatus{
			Running:          true,
			DeviceCount:      5,
			StartTime:        now,
			IPXEServerAddr:   "192.168.1.1:69",
			QuarantineVLAN:   100,
			ProvisioningVLAN: 200,
		}

		result := svc.statusToProto(svcStatus)

		require.NotNil(t, result)
		assert.True(t, result.GetRunning())
		assert.Equal(t, int32(5), result.GetDeviceCount())
		assert.Equal(t, "192.168.1.1:69", result.GetIpxeServerAddr())
		assert.Equal(t, uint32(100), result.GetQuarantineVlan())
		assert.Equal(t, uint32(200), result.GetProvisioningVlan())
	})
}
