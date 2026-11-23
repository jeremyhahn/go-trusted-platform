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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
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

func (m *mockPXEService) UpdateDeviceStateForIDevID(ctx context.Context, deviceID, fingerprint string, state pxe.ProvisioningState, reason string) error {
	if d, ok := m.devices[deviceID]; ok && d.IDevIDFingerprint != fingerprint {
		return pxe.ErrIDevIDMismatch{DeviceID: deviceID}
	}
	return m.UpdateDeviceState(ctx, deviceID, state, reason)
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

func (m *mockPXEService) RecordIDevIDFingerprint(ctx context.Context, deviceID, fingerprint string) error {
	device, ok := m.devices[deviceID]
	if !ok {
		return pxe.ErrDeviceNotFound{DeviceID: deviceID}
	}
	device.IDevIDFingerprint = fingerprint
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

	// Out-of-range VLANs are refused before the service is called: a
	// uint16 conversion would otherwise turn 65556 into VLAN 20.
	for _, vlan := range []uint32{4095, 65556} {
		t.Run(fmt.Sprintf("target VLAN %d out of range", vlan), func(t *testing.T) {
			before := mockService.devices[deviceID].TargetVLAN
			resp, err := svc.Authorize(ctx, &platformv1.AuthorizePXEDeviceRequest{
				DeviceId:   deviceID,
				TargetVlan: vlan,
			})

			require.Error(t, err)
			assert.Nil(t, resp)
			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.Contains(t, st.Message(), "1-4094")
			assert.Equal(t, before, mockService.devices[deviceID].TargetVLAN, "AuthorizeDevice must not be called")
		})
	}

	for _, vlan := range []uint32{1, 4094} {
		t.Run(fmt.Sprintf("target VLAN %d accepted", vlan), func(t *testing.T) {
			resp, err := svc.Authorize(ctx, &platformv1.AuthorizePXEDeviceRequest{
				DeviceId:   deviceID,
				TargetVlan: vlan,
			})

			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, vlan, resp.GetDevice().GetTargetVlan())
		})
	}
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

// TestPXEGRPCService_WebhookComplete tests the webhook completion handler.
func TestPXEGRPCService_WebhookComplete(t *testing.T) {
	logger := logging.DefaultLogger()
	mockService := newMockPXEService()
	svc := NewPXEGRPCService(logger, mockService)

	ctx := context.Background()

	// Register a device first
	macAddress := "00:11:22:33:44:f3"
	regReq := &platformv1.RegisterPXEDeviceRequest{
		MacAddress: macAddress,
		PortId:     "port-1",
	}
	_, err := svc.RegisterDevice(ctx, regReq)
	require.NoError(t, err)

	t.Run("success", func(t *testing.T) {
		req := &platformv1.PXEWebhookCompleteRequest{
			MacAddress: macAddress,
			Hostname:   "test-host",
			Success:    true,
			Message:    "Installation completed",
		}

		resp, err := svc.WebhookComplete(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("failure webhook", func(t *testing.T) {
		req := &platformv1.PXEWebhookCompleteRequest{
			MacAddress: macAddress,
			Hostname:   "test-host",
			Success:    false,
			Message:    "Installation failed",
		}

		resp, err := svc.WebhookComplete(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, resp.GetStatus().GetSuccess())
	})

	t.Run("missing MAC address", func(t *testing.T) {
		req := &platformv1.PXEWebhookCompleteRequest{
			Hostname: "test-host",
			Success:  true,
		}

		resp, err := svc.WebhookComplete(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})

	t.Run("device not found", func(t *testing.T) {
		req := &platformv1.PXEWebhookCompleteRequest{
			MacAddress: "ff:ff:ff:ff:ff:ff",
			Hostname:   "test-host",
			Success:    true,
		}

		resp, err := svc.WebhookComplete(ctx, req)

		require.Error(t, err)
		assert.Nil(t, resp)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
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

// pxeSectionApp is an app whose sdn: section numbers the zones the PXE
// backend's VLANs come from.
func pxeSectionApp() *app.App {
	return &app.App{SDNConfig: &sdn.Config{
		Enabled:     true,
		Environment: &netplan.Environment{ID: 4},
		Zones:       zone.Defaults(),
	}}
}

// isPXEServiceNotConfigured reports whether err carries the typed
// SERVICE_NOT_CONFIGURED ErrorInfo detail.
func isPXEServiceNotConfigured(err error) bool {
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == response.ReasonServiceNotConfigured {
			return true
		}
	}
	return false
}

// TestPXEGRPCServiceFromConfig_DaemonPXESection pins the daemon side of the
// pxe: section (#1694): no section or enabled: false leaves the service with
// no backend (every verb answers SERVICE_NOT_CONFIGURED, as before), a valid
// enabled section reaches a real backend, and an invalid enabled section
// fails daemon start with a typed error.
func TestPXEGRPCServiceFromConfig_DaemonPXESection(t *testing.T) {
	ctx := context.Background()
	logger := logging.DefaultLogger()

	notConfigured := func(t *testing.T, svc *PXEGRPCService) {
		t.Helper()
		_, err := svc.ListDevices(ctx, &platformv1.ListPXEDevicesRequest{})
		require.Error(t, err)
		assert.Equal(t, codes.Unavailable, status.Code(err))
		assert.True(t, isPXEServiceNotConfigured(err), "want SERVICE_NOT_CONFIGURED, got %v", err)
	}

	t.Run("no section", func(t *testing.T) {
		svc, err := pxeGRPCServiceFromConfig(ctx, logger, pxeSectionApp(), nil, nil)
		require.NoError(t, err)
		notConfigured(t, svc)
	})

	t.Run("enabled false", func(t *testing.T) {
		svc, err := pxeGRPCServiceFromConfig(ctx, logger, pxeSectionApp(), &pxe.DaemonConfig{BridgeName: "br-pxe"}, nil)
		require.NoError(t, err)
		notConfigured(t, svc)
	})

	t.Run("enabled reaches the backend", func(t *testing.T) {
		section := &pxe.DaemonConfig{
			Enabled:         true,
			BridgeName:      "br-pxe",
			BindHost:        "127.0.0.1",
			LocalFilesDir:   t.TempDir(),
			InstallsDir:     t.TempDir(),
			FirmwareDir:     t.TempDir(),
			FirmwareOffline: true,
			BootEntries:     []ipxe.BootEntry{{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"}},
		}
		svc, err := pxeGRPCServiceFromConfig(ctx, logger, pxeSectionApp(), section, pxeTestFlowManager(t, &pxeRecordingPort{}))
		require.NoError(t, err)
		resp, err := svc.ListDevices(ctx, &platformv1.ListPXEDevicesRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.GetDevices())
	})

	t.Run("invalid enabled section fails start", func(t *testing.T) {
		svc, err := pxeGRPCServiceFromConfig(ctx, logger, pxeSectionApp(), &pxe.DaemonConfig{Enabled: true}, nil)
		require.Error(t, err)
		assert.Nil(t, svc)
		assert.True(t, errors.Is(err, pxe.ErrInvalidConfig), "got %v", err)
	})

	t.Run("enabled without a network plan fails start", func(t *testing.T) {
		svc, err := pxeGRPCServiceFromConfig(ctx, logger, &app.App{}, &pxe.DaemonConfig{Enabled: true, BridgeName: "br-pxe"}, nil)
		require.Error(t, err)
		assert.Nil(t, svc)
		var want pxe.ErrNetworkPlanRequired
		assert.True(t, errors.As(err, &want), "got %v", err)
	})
}

// pxeRecordingPort is an OVS port controller that records the access VLANs
// the zone flow manager sets.
type pxeRecordingPort struct {
	vlans []int64
	// flows records every rule installed, in order.
	flows []zoneflows.FlowRule
	// fail makes every flow and VLAN move fail, as an unreachable switch.
	fail bool
}

var errPXEPortDown = errors.New("switch unreachable")

func (p *pxeRecordingPort) InstallFlow(string, int, string, string) error { return nil }
func (p *pxeRecordingPort) InstallFlows(_ string, rules []zoneflows.FlowRule) error {
	if p.fail {
		return errPXEPortDown
	}
	p.flows = append(p.flows, rules...)
	return nil
}
func (p *pxeRecordingPort) DeleteFlow(string, string) error                              { return nil }
func (p *pxeRecordingPort) DeleteFlowsByPort(string, string) error                       { return nil }
func (p *pxeRecordingPort) ListFlows(string) ([]string, error)                           { return nil, nil }
func (p *pxeRecordingPort) SetPortTrunk(context.Context, string, []uint16, uint16) error { return nil }
func (p *pxeRecordingPort) SetPortState(context.Context, string, ovs.PortState) error    { return nil }
func (p *pxeRecordingPort) GetOFPort(context.Context, string) (int32, error)             { return 1, nil }
func (p *pxeRecordingPort) SetPortVLAN(_ context.Context, _ string, v int64) error {
	if p.fail {
		return errPXEPortDown
	}
	p.vlans = append(p.vlans, v)
	return nil
}

// pxeTestFlowManager builds a zone flow manager on the network plan of
// pxeSectionApp, driving port.
func pxeTestFlowManager(t *testing.T, port *pxeRecordingPort) *policy.ZoneFlowManager {
	t.Helper()
	zones, env := zoneServiceSeed(pxeSectionApp())
	require.NotNil(t, env)
	if len(zones) == 0 {
		zones = zone.Defaults()
	}
	plan, err := netplan.New(*env, zones)
	require.NoError(t, err)
	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName: "br-pxe", FlowController: port, PortController: port, Plan: plan,
	})
	require.NoError(t, err)
	return zfm
}

// pxeEnabledSection is a valid, enabled pxe: section on temporary dirs.
func pxeEnabledSection(t *testing.T) *pxe.DaemonConfig {
	t.Helper()
	return &pxe.DaemonConfig{
		Enabled:         true,
		BridgeName:      "br-pxe",
		BindHost:        "127.0.0.1",
		LocalFilesDir:   t.TempDir(),
		InstallsDir:     t.TempDir(),
		FirmwareDir:     t.TempDir(),
		FirmwareOffline: true,
		BootEntries:     []ipxe.BootEntry{{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"}},
	}
}

// TestDaemonPXEBackendRequiresFlowManager: an enabled pxe: section with no
// zone flow manager is refused at start rather than running with no-op
// quarantine, provisioning and authorization flows; with one, a quarantine
// reaches the flow manager (Codex P1 on #1896).
func TestDaemonPXEBackendRequiresFlowManager(t *testing.T) {
	ctx := context.Background()
	logger := logging.DefaultLogger()

	t.Run("no flow manager fails start", func(t *testing.T) {
		svc, err := pxeGRPCServiceFromConfig(ctx, logger, pxeSectionApp(), pxeEnabledSection(t), nil)
		require.Error(t, err)
		assert.Nil(t, svc)
		var want pxe.ErrInvalidConfiguration
		assert.True(t, errors.As(err, &want), "got %v", err)
	})

	t.Run("quarantine reaches the flow manager", func(t *testing.T) {
		port := &pxeRecordingPort{}
		svc, err := pxeGRPCServiceFromConfig(ctx, logger, pxeSectionApp(), pxeEnabledSection(t), pxeTestFlowManager(t, port))
		require.NoError(t, err)
		t.Cleanup(func() { _ = svc.Close() })

		reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "52:54:00:12:34:56", PortId: "port-1"})
		require.NoError(t, err)
		before := len(port.vlans)
		_, err = svc.Quarantine(ctx, &platformv1.QuarantinePXEDeviceRequest{DeviceId: reg.GetDevice().GetId(), Reason: "test"})
		require.NoError(t, err)
		assert.Greater(t, len(port.vlans), before, "the quarantine set no VLAN through the flow manager")
	})
}

// pxeFreePort asks the OS for a loopback port nothing listens on.
func pxeFreePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// pxeStartedBackend builds the PXEGRPCService a daemon holds around a
// started backend whose iPXE HTTP listener is on the returned port.
func pxeStartedBackend(t *testing.T) (*PXEGRPCService, string) {
	t.Helper()
	section := pxeEnabledSection(t)
	require.NoError(t, os.WriteFile(filepath.Join(section.FirmwareDir, "ipxe.efi"), []byte("test firmware"), 0o600))
	zones, env := zoneServiceSeed(pxeSectionApp())
	require.NotNil(t, env)
	if len(zones) == 0 {
		zones = zone.Defaults()
	}
	plan, err := netplan.New(*env, zones)
	require.NoError(t, err)
	cfg, err := section.ToServiceConfig(plan)
	require.NoError(t, err)
	httpPort := pxeFreePort(t, "tcp")
	cfg.IPXEConfig.HTTPPort = httpPort
	cfg.IPXEConfig.TFTPPort = pxeFreePort(t, "udp")

	backend := pxe.NewService(pxe.WithVLANIntegration(pxe.NewNoopVLANIntegration(plan)))
	require.NoError(t, backend.Initialize(context.Background(), cfg))
	require.NoError(t, backend.Start(context.Background()))
	t.Cleanup(func() { _ = backend.Close() })

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort))
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err, "the started backend is not listening")
	_ = conn.Close()

	svc := NewPXEGRPCService(logging.DefaultLogger(), nil)
	svc.SetPXEService(backend)
	return svc, addr
}

// TestDaemonStopStopsPXEBackend: Stop, ForceStop and startup rollback stop
// the PXE backend, so its iPXE listener port is free afterwards (#1694).
func TestDaemonStopStopsPXEBackend(t *testing.T) {
	cases := map[string]func(d *Daemon){
		"Stop":      func(d *Daemon) { _ = d.Stop(context.Background()) },
		"ForceStop": func(d *Daemon) { _ = d.ForceStop() },
		"rollback":  func(d *Daemon) { d.rollbackPartialStart(context.Background()) },
	}
	for name, stop := range cases {
		t.Run(name, func(t *testing.T) {
			svc, addr := pxeStartedBackend(t)
			config := DefaultConfig()
			config.Logger = logging.DefaultLogger()
			service, err := NewService(config)
			require.NoError(t, err)
			d := &Daemon{logger: config.Logger, config: config, service: service, pxeGRPCService: svc}
			d.running.Store(true)

			stop(d)

			l, err := net.Listen("tcp", addr)
			require.NoError(t, err, "the PXE listener is still bound after %s", name)
			_ = l.Close()
		})
	}
}

// TestDaemonRollbackKeepsPXEBackendUsable: startup rollback frees the iPXE
// listener but keeps the backend initialized, so a Start retry serves PXE
// device operations and StartService (#1896 P1).
func TestDaemonRollbackKeepsPXEBackendUsable(t *testing.T) {
	svc, addr := pxeStartedBackend(t)
	config := DefaultConfig()
	config.Logger = logging.DefaultLogger()
	service, err := NewService(config)
	require.NoError(t, err)
	d := &Daemon{logger: config.Logger, config: config, service: service, pxeGRPCService: svc}
	d.running.Store(true)

	d.rollbackPartialStart(context.Background())

	l, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the PXE listener is still bound after rollback")
	_ = l.Close()

	ctx := context.Background()
	_, err = svc.ListDevices(ctx, &platformv1.ListPXEDevicesRequest{})
	require.NoError(t, err)
	_, err = svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:ee", PortId: "port-1"})
	require.NoError(t, err)
	_, err = svc.StartService(ctx, &platformv1.StartPXEServiceRequest{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })
}

// startingPXEService models a backend whose Start is still binding its
// listeners: IsRunning is false, and Stop is the call that waits on the
// lifecycle lock Start holds. It records each Stop and what the daemon's
// transports looked like at that moment.
type startingPXEService struct {
	pxe.Service
	stops             int
	grpcListenerAlive bool
	daemon            *Daemon
}

func (s *startingPXEService) IsRunning() bool { return false }

func (s *startingPXEService) Stop(context.Context) error {
	s.stops++
	if s.daemon != nil {
		s.grpcListenerAlive = s.daemon.grpcListener != nil
	}
	return pxe.ErrServiceNotRunning{}
}

func TestPXEStopBackendWaitsForAnInFlightStart(t *testing.T) {
	backend := &startingPXEService{}
	svc := NewPXEGRPCService(logging.DefaultLogger(), nil)
	svc.SetPXEService(backend)

	require.NoError(t, svc.StopBackend(context.Background()), "a backend Start left not running is not an error")
	assert.Equal(t, 1, backend.stops, "StopBackend must call Stop, which serialises with an in-flight Start, even while IsRunning is false")
}

func TestPXEStopBackendStopsTheRunAConcurrentStartLeft(t *testing.T) {
	svc, addr := pxeStartedBackend(t)

	require.NoError(t, svc.StopBackend(context.Background()))
	l, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the iPXE listener is still bound after StopBackend")
	_ = l.Close()
	require.NoError(t, svc.StopBackend(context.Background()), "a second StopBackend on a stopped backend is not an error")
}

func TestDaemonRollbackStopsPXEAfterTheTransports(t *testing.T) {
	config := DefaultConfig()
	config.Logger = logging.DefaultLogger()
	service, err := NewService(config)
	require.NoError(t, err)
	backend := &startingPXEService{}
	svc := NewPXEGRPCService(logging.DefaultLogger(), nil)
	svc.SetPXEService(backend)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	d := &Daemon{logger: config.Logger, config: config, service: service, pxeGRPCService: svc, grpcListener: l}
	backend.daemon = d

	d.rollbackPartialStart(context.Background())

	require.Equal(t, 1, backend.stops, "rollback must stop the PXE backend")
	assert.False(t, backend.grpcListenerAlive, "rollback stopped the PXE backend while the gRPC transport still accepted StartService")
}

// TestPXEGRPC_UpdateStateFailsWhenTheVLANMoveFails checks that the
// UpdateState RPC on the configured backend fails, and the device keeps
// its state, when the flow manager cannot move the device (#1694).
func TestPXEGRPC_UpdateStateFailsWhenTheVLANMoveFails(t *testing.T) {
	ctx := context.Background()
	port := &pxeRecordingPort{}
	svc, err := pxeGRPCServiceFromConfig(ctx, logging.DefaultLogger(), pxeSectionApp(), pxeEnabledSection(t), pxeTestFlowManager(t, port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:dd", PortId: "port-1"})
	require.NoError(t, err)
	deviceID := reg.GetDevice().GetId()

	port.fail = true
	resp, err := svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: deviceID,
		State:    platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED,
		Reason:   "quarantine",
	})
	require.Error(t, err, "UpdateState succeeded although the VLAN move failed: %v", resp)

	got, err := svc.GetDevice(ctx, &platformv1.GetPXEDeviceRequest{DeviceId: deviceID})
	require.NoError(t, err)
	assert.Equal(t, platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED, got.GetDevice().GetState())
}

// TestPXEGRPC_BootingAllowsTheIPXEHTTPPort checks that moving a device to
// booting on the configured backend installs an allow rule for the iPXE
// server's HTTP port, from which the device fetches its boot script and
// payloads (docs/SPEC.md provisioning ports, #1694).
func TestPXEGRPC_BootingAllowsTheIPXEHTTPPort(t *testing.T) {
	ctx := context.Background()
	port := &pxeRecordingPort{}
	svc, err := pxeGRPCServiceFromConfig(ctx, logging.DefaultLogger(), pxeSectionApp(), pxeEnabledSection(t), pxeTestFlowManager(t, port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:de", PortId: "port-1"})
	require.NoError(t, err)

	port.flows = nil
	_, err = svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: reg.GetDevice().GetId(),
		State:    platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
		Reason:   "boot",
	})
	require.NoError(t, err)

	want := fmt.Sprintf("tp_dst=%d", ipxe.DefaultHTTPPort)
	allowed := false
	for _, f := range port.flows {
		if strings.Contains(f.Match, "nw_proto=6") && strings.Contains(f.Match, want) && f.Actions != "drop" {
			allowed = true
		}
	}
	assert.True(t, allowed, "no provisioning allow rule for the iPXE HTTP port %d", ipxe.DefaultHTTPPort)
}

// Codex round 5 P1 on #1896: docs/SPEC.md (ipxe row) requires the
// provisioning-zone rules to admit TCP 8080 (iPXE HTTP), 8081 (the
// bootstrap device-script and UKI server) and 10809 (NBD). A provisioning
// transition replaces the port's flows, so each must be carried into the
// generator and installed as an allow rule.
func TestPXEGRPC_BootingAllowsEveryProvisioningBootPort(t *testing.T) {
	ctx := context.Background()
	port := &pxeRecordingPort{}
	svc, err := pxeGRPCServiceFromConfig(ctx, logging.DefaultLogger(), pxeSectionApp(), pxeEnabledSection(t), pxeTestFlowManager(t, port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:df", PortId: "port-1"})
	require.NoError(t, err)

	port.flows = nil
	_, err = svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: reg.GetDevice().GetId(),
		State:    platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
		Reason:   "boot",
	})
	require.NoError(t, err)

	for _, p := range []int{8080, 8081, 10809} {
		want := fmt.Sprintf("tp_dst=%d", p)
		allowed := false
		for _, f := range port.flows {
			if strings.Contains(f.Match, "nw_proto=6") && strings.Contains(f.Match, want) && f.Actions != "drop" {
				allowed = true
			}
		}
		assert.True(t, allowed, "no provisioning allow rule for TCP port %d", p)
	}
}

// TestPXEGRPC_BootPortsReachOnlyTheBootServer pins that a booting device's
// boot-port allowances name only the boot server: the bind host when it is a
// usable address, otherwise the provisioning zone's own addresses, never a
// destination in another zone.
func TestPXEGRPC_BootPortsReachOnlyTheBootServer(t *testing.T) {
	zones, env := zoneServiceSeed(pxeSectionApp())
	require.NotNil(t, env)
	if len(zones) == 0 {
		zones = zone.Defaults()
	}
	plan, err := netplan.New(*env, zones)
	require.NoError(t, err)
	prov, err := plan.MustZone(zone.ZoneProvisioning)
	require.NoError(t, err)
	cp, err := plan.MustZone(zone.ZoneControlPlane)
	require.NoError(t, err)

	bootRules := func(t *testing.T, bindHost string) map[int][]string {
		t.Helper()
		ctx := context.Background()
		section := pxeEnabledSection(t)
		section.BindHost = bindHost
		port := &pxeRecordingPort{}
		svc, err := pxeGRPCServiceFromConfig(ctx, logging.DefaultLogger(), pxeSectionApp(), section, pxeTestFlowManager(t, port))
		require.NoError(t, err)
		t.Cleanup(func() { _ = svc.Close() })
		reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:e0", PortId: "port-1"})
		require.NoError(t, err)
		port.flows = nil
		_, err = svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
			DeviceId: reg.GetDevice().GetId(),
			State:    platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
			Reason:   "boot",
		})
		require.NoError(t, err)

		out := map[int][]string{}
		for _, p := range []int{8080, 8081, 10809} {
			want := fmt.Sprintf("tp_dst=%d", p)
			for _, f := range port.flows {
				if f.Actions == "drop" || !strings.Contains(f.Match, "nw_proto=6") {
					continue
				}
				hasPort, dst := false, ""
				for _, field := range strings.Split(f.Match, ",") {
					if field == want {
						hasPort = true
					}
					if k, v, ok := strings.Cut(field, "="); ok && (k == "nw_dst" || k == "ipv6_dst") {
						dst = v
					}
				}
				if hasPort {
					out[p] = append(out[p], dst)
				}
			}
		}
		return out
	}

	t.Run("loopback bind host scopes to the provisioning zone", func(t *testing.T) {
		rules := bootRules(t, "127.0.0.1")
		for _, p := range []int{8080, 8081, 10809} {
			require.NotEmpty(t, rules[p], "no allow rule for TCP port %d", p)
			for _, dst := range rules[p] {
				a, err := netip.ParseAddr(dst)
				require.NoError(t, err, "port %d allow rule has destination %q, want a boot server address", p, dst)
				assert.True(t, prov.Subnet4.Contains(a) || (prov.Subnet6.IsValid() && prov.Subnet6.Contains(a)),
					"port %d allows %s, outside the provisioning zone", p, dst)
				assert.NotEqual(t, cp.Gateway, a, "port %d allows the control-plane gateway", p)
			}
		}
	})

	t.Run("routable bind host is the only destination", func(t *testing.T) {
		rules := bootRules(t, "192.0.2.10")
		for _, p := range []int{8080, 8081, 10809} {
			require.NotEmpty(t, rules[p], "no allow rule for TCP port %d", p)
			for _, dst := range rules[p] {
				assert.Equal(t, "192.0.2.10", dst, "port %d allow rule destination", p)
			}
		}
	})

	t.Run("wildcard bind host allows the address iPXE advertises", func(t *testing.T) {
		for _, bindHost := range []string{"", "0.0.0.0"} {
			// ipxe.NewServer advertises this address in its boot URL.
			want, err := (&ipxe.ServerConfig{BindHost: bindHost}).GetServerIP()
			if err != nil {
				t.Skipf("no host address to advertise for bind host %q: %v", bindHost, err)
			}
			if want == prov.Gateway.String() {
				t.Skipf("the detected host address is the provisioning gateway %s, so it cannot tell the two apart", want)
			}
			rules := bootRules(t, bindHost)
			for _, p := range []int{8080, 8081, 10809} {
				require.NotEmpty(t, rules[p], "bind host %q: no allow rule for TCP port %d", bindHost, p)
				for _, dst := range rules[p] {
					assert.Equal(t, want, dst, "bind host %q: port %d allow rule destination", bindHost, p)
				}
			}
		}
	})
}

// TestPXEGRPC_BootingDeviceReachesNoStorageAddressOverHTTP pins, through the
// daemon's own PXE wiring, that a Booting device's HTTP(S) allowances do not
// reach the storage zone, which the default matrix denies to provisioning
// (#1896 Codex round 1).
func TestPXEGRPC_BootingDeviceReachesNoStorageAddressOverHTTP(t *testing.T) {
	zones, env := zoneServiceSeed(pxeSectionApp())
	require.NotNil(t, env)
	if len(zones) == 0 {
		zones = zone.Defaults()
	}
	plan, err := netplan.New(*env, zones)
	require.NoError(t, err)
	storage, err := plan.MustZone(zone.ZoneStorage)
	require.NoError(t, err)
	target := storage.Gateway
	require.True(t, target.IsValid(), "storage zone has no gateway address")

	ctx := context.Background()
	port := &pxeRecordingPort{}
	svc, err := pxeGRPCServiceFromConfig(ctx, logging.DefaultLogger(), pxeSectionApp(), pxeEnabledSection(t), pxeTestFlowManager(t, port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = svc.Close() })

	reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:e1", PortId: "port-1"})
	require.NoError(t, err)
	port.flows = nil
	_, err = svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: reg.GetDevice().GetId(),
		State:    platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
		Reason:   "boot",
	})
	require.NoError(t, err)

	covers := func(dst string) bool {
		if pfx, err := netip.ParsePrefix(dst); err == nil {
			return pfx.Contains(target)
		}
		a, err := netip.ParseAddr(dst)
		return err == nil && a == target
	}
	for _, p := range []int{80, 443, 8443, 9443} {
		want := fmt.Sprintf("tp_dst=%d", p)
		for _, f := range port.flows {
			if f.Actions == "drop" || !strings.Contains(f.Match, "nw_proto=6") {
				continue
			}
			hasPort, dst := false, ""
			for _, field := range strings.Split(f.Match, ",") {
				if field == want {
					hasPort = true
				}
				if k, v, ok := strings.Cut(field, "="); ok && (k == "nw_dst" || k == "ipv6_dst") {
					dst = v
				}
			}
			if !hasPort {
				continue
			}
			assert.False(t, dst == "" || covers(dst),
				"TCP %d: Booting device reaches the storage gateway %s through %q", p, target, f.Match)
		}
	}
}

// TestPXEGRPC_BootingDeviceReachesConfiguredDNSAndACME drives the pxe:
// section's dns-servers and acme-servers through pxeGRPCServiceFromConfig
// and the shared flow manager (Codex round 2 P1): a Booting device gets a
// destination-scoped UDP 53 allow to the configured resolver and a TCP 443
// allow to the configured ACME server, none open to any destination or to
// the storage gateway; with no acme-servers TCP 443 opens to the boot
// server addresses, the same destinations the boot HTTP port got.
func TestPXEGRPC_BootingDeviceReachesConfiguredDNSAndACME(t *testing.T) {
	zones, env := zoneServiceSeed(pxeSectionApp())
	require.NotNil(t, env)
	if len(zones) == 0 {
		zones = zone.Defaults()
	}
	plan, err := netplan.New(*env, zones)
	require.NoError(t, err)
	storage, err := plan.MustZone(zone.ZoneStorage)
	require.NoError(t, err)
	target := storage.Gateway
	require.True(t, target.IsValid(), "storage zone has no gateway address")

	covers := func(dst string) bool {
		if pfx, err := netip.ParsePrefix(dst); err == nil {
			return pfx.Contains(target)
		}
		a, err := netip.ParseAddr(dst)
		return err == nil && a == target
	}
	type allow struct{ proto, port, dst string }
	booting := func(t *testing.T, section *pxe.DaemonConfig) []allow {
		t.Helper()
		ctx := context.Background()
		port := &pxeRecordingPort{}
		svc, err := pxeGRPCServiceFromConfig(ctx, logging.DefaultLogger(), pxeSectionApp(), section, pxeTestFlowManager(t, port))
		require.NoError(t, err)
		t.Cleanup(func() { _ = svc.Close() })
		reg, err := svc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:e2", PortId: "port-1"})
		require.NoError(t, err)
		port.flows = nil
		_, err = svc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
			DeviceId: reg.GetDevice().GetId(),
			State:    platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING,
			Reason:   "boot",
		})
		require.NoError(t, err)
		var out []allow
		for _, f := range port.flows {
			if f.Actions == "drop" {
				continue
			}
			var a allow
			for _, field := range strings.Split(f.Match, ",") {
				k, v, ok := strings.Cut(field, "=")
				if !ok {
					continue
				}
				switch k {
				case "nw_proto":
					a.proto = v
				case "tp_dst":
					a.port = v
				case "nw_dst", "ipv6_dst":
					a.dst = v
				}
			}
			if a.port != "" {
				out = append(out, a)
			}
		}
		return out
	}
	check := func(t *testing.T, allows []allow, proto, port string) map[string]bool {
		t.Helper()
		dsts := map[string]bool{}
		for _, a := range allows {
			if a.proto != proto || a.port != port {
				continue
			}
			assert.False(t, a.dst == "" || covers(a.dst),
				"proto %s port %s: Booting device reaches %q (storage gateway %s)", proto, port, a.dst, target)
			dsts[a.dst] = true
		}
		return dsts
	}

	t.Run("configured servers", func(t *testing.T) {
		section := pxeEnabledSection(t)
		section.DNSServers = []string{"192.0.2.53"}
		section.ACMEServers = []string{"192.0.2.10"}
		allows := booting(t, section)
		assert.True(t, check(t, allows, "17", "53")["192.0.2.53"], "no UDP 53 allow to the configured DNS server: %v", allows)
		assert.True(t, check(t, allows, "6", "443")["192.0.2.10"], "no TCP 443 allow to the configured ACME server: %v", allows)
	})

	t.Run("no acme-servers opens 443 to the boot servers", func(t *testing.T) {
		section := pxeEnabledSection(t)
		section.DNSServers = []string{"192.0.2.53"}
		allows := booting(t, section)
		boot := check(t, allows, "6", "8080")
		require.NotEmpty(t, boot, "no boot HTTP allow: %v", allows)
		assert.Equal(t, boot, check(t, allows, "6", "443"), "TCP 443 destinations differ from the boot HTTP port's")
	})
}

// TestDaemonPXEBackendRefusesABridgeMismatch: the VLAN wrapper only
// delegates to the shared flow manager, so a pxe.bridge-name other than
// the manager's sdn.ovs.bridge is refused at startup (#1694).
func TestDaemonPXEBackendRefusesABridgeMismatch(t *testing.T) {
	ctx := context.Background()
	zones, env := zoneServiceSeed(pxeSectionApp())
	require.NotNil(t, env)
	if len(zones) == 0 {
		zones = zone.Defaults()
	}
	plan, err := netplan.New(*env, zones)
	require.NoError(t, err)
	port := &pxeRecordingPort{}
	flows, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName: "br-int", FlowController: port, PortController: port, Plan: plan,
	})
	require.NoError(t, err)

	section := pxeEnabledSection(t)
	require.Equal(t, "br-pxe", section.BridgeName)
	svc, err := pxeGRPCServiceFromConfig(ctx, logging.DefaultLogger(), pxeSectionApp(), section, flows)
	require.Error(t, err)
	assert.Nil(t, svc)
	var cfgErr pxe.ErrInvalidConfiguration
	require.ErrorAs(t, err, &cfgErr)
	assert.Equal(t, "pxe.bridge-name", cfgErr.Field)
}

// pxeBlockingVLAN blocks ApplyQuarantineFlows until release is closed.
type pxeBlockingVLAN struct {
	pxe.VLANIntegration
	entered chan struct{}
	release chan struct{}
}

func (b *pxeBlockingVLAN) ApplyQuarantineFlows(context.Context, string, net.HardwareAddr) error {
	close(b.entered)
	<-b.release
	return nil
}

// TestDaemonStopWaitsForAPXECallInFlight checks, under -race, that a
// RegisterDevice blocked mid-call while Stop or ForceStop closes the PXE
// backend returns cleanly, and that the stop waits for it (#1694).
func TestDaemonStopWaitsForAPXECallInFlight(t *testing.T) {
	cases := map[string]func(d *Daemon){
		"Stop":      func(d *Daemon) { _ = d.Stop(context.Background()) },
		"ForceStop": func(d *Daemon) { _ = d.ForceStop() },
	}
	for name, stop := range cases {
		t.Run(name, func(t *testing.T) {
			zones, env := zoneServiceSeed(pxeSectionApp())
			require.NotNil(t, env)
			if len(zones) == 0 {
				zones = zone.Defaults()
			}
			plan, err := netplan.New(*env, zones)
			require.NoError(t, err)
			cfg, err := pxeEnabledSection(t).ToServiceConfig(plan)
			require.NoError(t, err)

			vlan := &pxeBlockingVLAN{
				VLANIntegration: pxe.NewNoopVLANIntegration(plan),
				entered:         make(chan struct{}),
				release:         make(chan struct{}),
			}
			backend := pxe.NewService(pxe.WithVLANIntegration(vlan))
			require.NoError(t, backend.Initialize(context.Background(), cfg))
			svc := NewPXEGRPCService(logging.DefaultLogger(), nil)
			svc.SetPXEService(backend)

			config := DefaultConfig()
			config.Logger = logging.DefaultLogger()
			service, err := NewService(config)
			require.NoError(t, err)
			d := &Daemon{logger: config.Logger, config: config, service: service, pxeGRPCService: svc}
			d.running.Store(true)

			registered := make(chan error, 1)
			go func() {
				_, err := svc.RegisterDevice(context.Background(), &platformv1.RegisterPXEDeviceRequest{MacAddress: "00:11:22:33:44:ee", PortId: "port-1"})
				registered <- err
			}()
			<-vlan.entered

			stopped := make(chan struct{})
			go func() { stop(d); close(stopped) }()
			select {
			case <-stopped:
				t.Fatalf("%s returned while a PXE call was in flight", name)
			case <-time.After(100 * time.Millisecond):
			}

			close(vlan.release)
			require.NoError(t, <-registered)
			<-stopped
		})
	}
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
