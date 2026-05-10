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

package bmc

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
)

// =============================================================================
// Fake BMCServiceClient
// =============================================================================

// fakeBMCClient is a test double for platformv1.BMCServiceClient that
// records the requests it receives and returns configurable responses.
// Unused methods delegate to the embedded interface (nil) so calling
// them in a test that did not configure them will panic quickly --
// this is deliberate: tests must wire only what they exercise.
type fakeBMCClient struct {
	platformv1.BMCServiceClient // nil — exercises record patterns below

	// Configured responses.
	powerOnResp    *platformv1.BMCPowerResponse
	powerOnErr     error
	powerOffResp   *platformv1.BMCPowerResponse
	powerOffErr    error
	powerResetResp *platformv1.BMCPowerResponse
	powerResetErr  error
	powerCycleResp *platformv1.BMCPowerResponse
	powerCycleErr  error
	powerStatResp  *platformv1.BMCPowerStatusResponse
	powerStatErr   error

	setBootResp       *platformv1.BMCSetBootDeviceResponse
	setBootErr        error
	getBootResp       *platformv1.BMCGetBootDeviceResponse
	getBootErr        error
	mountISOResp      *platformv1.BMCMountISOResponse
	mountISOErr       error
	unmountISOResp    *platformv1.BMCUnmountISOResponse
	unmountISOErr     error
	vmediaStatusResp  *platformv1.BMCVirtualMediaStatusResponse
	vmediaStatusErr   error
	sensorsResp       *platformv1.BMCGetSensorsResponse
	sensorsErr        error
	systemInfoResp    *platformv1.BMCGetSystemInfoResponse
	systemInfoErr     error
	provisionResp     *platformv1.BMCProvisionResponse
	provisionErr      error
	provisionStatResp *platformv1.BMCProvisionStatusResponse
	provisionStatErr  error
	certResp          *platformv1.BMCGetWebCertificateResponse
	certErr           error
	replaceCertResp   *platformv1.BMCReplaceWebCertificateResponse
	replaceCertErr    error

	listUsersResp *platformv1.BMCListUsersResponse
	listUsersErr  error
	createResp    *platformv1.BMCCreateUserResponse
	createErr     error
	deleteResp    *platformv1.BMCDeleteUserResponse
	deleteErr     error
	setPwResp     *platformv1.BMCSetUserPasswordResponse
	setPwErr      error
	setPrivResp   *platformv1.BMCSetUserPrivilegeResponse
	setPrivErr    error

	// Last request captured (used for assertions on wire payloads).
	lastPowerOn       *platformv1.BMCPowerRequest
	lastPowerOff      *platformv1.BMCPowerRequest
	lastPowerReset    *platformv1.BMCPowerRequest
	lastPowerCycle    *platformv1.BMCPowerRequest
	lastPowerStatus   *platformv1.BMCPowerStatusRequest
	lastSetBoot       *platformv1.BMCSetBootDeviceRequest
	lastGetBoot       *platformv1.BMCGetBootDeviceRequest
	lastMountISO      *platformv1.BMCMountISORequest
	lastUnmountISO    *platformv1.BMCUnmountISORequest
	lastVMediaStatus  *platformv1.BMCVirtualMediaStatusRequest
	lastSensors       *platformv1.BMCGetSensorsRequest
	lastSystemInfo    *platformv1.BMCGetSystemInfoRequest
	lastProvision     *platformv1.BMCProvisionRequest
	lastProvisionStat *platformv1.BMCProvisionStatusRequest
	lastCert          *platformv1.BMCGetWebCertificateRequest
	lastReplaceCert   *platformv1.BMCReplaceWebCertificateRequest
	lastListUsers     *platformv1.BMCListUsersRequest
	lastCreateUser    *platformv1.BMCCreateUserRequest
	lastDeleteUser    *platformv1.BMCDeleteUserRequest
	lastSetPassword   *platformv1.BMCSetUserPasswordRequest
	lastSetPriv       *platformv1.BMCSetUserPrivilegeRequest
}

func (f *fakeBMCClient) PowerOn(ctx context.Context, in *platformv1.BMCPowerRequest, opts ...grpc.CallOption) (*platformv1.BMCPowerResponse, error) {
	f.lastPowerOn = in
	return f.powerOnResp, f.powerOnErr
}

func (f *fakeBMCClient) PowerOff(ctx context.Context, in *platformv1.BMCPowerRequest, opts ...grpc.CallOption) (*platformv1.BMCPowerResponse, error) {
	f.lastPowerOff = in
	return f.powerOffResp, f.powerOffErr
}

func (f *fakeBMCClient) PowerReset(ctx context.Context, in *platformv1.BMCPowerRequest, opts ...grpc.CallOption) (*platformv1.BMCPowerResponse, error) {
	f.lastPowerReset = in
	return f.powerResetResp, f.powerResetErr
}

func (f *fakeBMCClient) PowerCycle(ctx context.Context, in *platformv1.BMCPowerRequest, opts ...grpc.CallOption) (*platformv1.BMCPowerResponse, error) {
	f.lastPowerCycle = in
	return f.powerCycleResp, f.powerCycleErr
}

func (f *fakeBMCClient) PowerStatus(ctx context.Context, in *platformv1.BMCPowerStatusRequest, opts ...grpc.CallOption) (*platformv1.BMCPowerStatusResponse, error) {
	f.lastPowerStatus = in
	return f.powerStatResp, f.powerStatErr
}

func (f *fakeBMCClient) SetBootDevice(ctx context.Context, in *platformv1.BMCSetBootDeviceRequest, opts ...grpc.CallOption) (*platformv1.BMCSetBootDeviceResponse, error) {
	f.lastSetBoot = in
	return f.setBootResp, f.setBootErr
}

func (f *fakeBMCClient) GetBootDevice(ctx context.Context, in *platformv1.BMCGetBootDeviceRequest, opts ...grpc.CallOption) (*platformv1.BMCGetBootDeviceResponse, error) {
	f.lastGetBoot = in
	return f.getBootResp, f.getBootErr
}

func (f *fakeBMCClient) MountISO(ctx context.Context, in *platformv1.BMCMountISORequest, opts ...grpc.CallOption) (*platformv1.BMCMountISOResponse, error) {
	f.lastMountISO = in
	return f.mountISOResp, f.mountISOErr
}

func (f *fakeBMCClient) UnmountISO(ctx context.Context, in *platformv1.BMCUnmountISORequest, opts ...grpc.CallOption) (*platformv1.BMCUnmountISOResponse, error) {
	f.lastUnmountISO = in
	return f.unmountISOResp, f.unmountISOErr
}

func (f *fakeBMCClient) VirtualMediaStatus(ctx context.Context, in *platformv1.BMCVirtualMediaStatusRequest, opts ...grpc.CallOption) (*platformv1.BMCVirtualMediaStatusResponse, error) {
	f.lastVMediaStatus = in
	return f.vmediaStatusResp, f.vmediaStatusErr
}

func (f *fakeBMCClient) GetSensors(ctx context.Context, in *platformv1.BMCGetSensorsRequest, opts ...grpc.CallOption) (*platformv1.BMCGetSensorsResponse, error) {
	f.lastSensors = in
	return f.sensorsResp, f.sensorsErr
}

func (f *fakeBMCClient) GetSystemInfo(ctx context.Context, in *platformv1.BMCGetSystemInfoRequest, opts ...grpc.CallOption) (*platformv1.BMCGetSystemInfoResponse, error) {
	f.lastSystemInfo = in
	return f.systemInfoResp, f.systemInfoErr
}

func (f *fakeBMCClient) Provision(ctx context.Context, in *platformv1.BMCProvisionRequest, opts ...grpc.CallOption) (*platformv1.BMCProvisionResponse, error) {
	f.lastProvision = in
	return f.provisionResp, f.provisionErr
}

func (f *fakeBMCClient) ProvisionStatus(ctx context.Context, in *platformv1.BMCProvisionStatusRequest, opts ...grpc.CallOption) (*platformv1.BMCProvisionStatusResponse, error) {
	f.lastProvisionStat = in
	return f.provisionStatResp, f.provisionStatErr
}

func (f *fakeBMCClient) GetWebCertificate(ctx context.Context, in *platformv1.BMCGetWebCertificateRequest, opts ...grpc.CallOption) (*platformv1.BMCGetWebCertificateResponse, error) {
	f.lastCert = in
	return f.certResp, f.certErr
}

func (f *fakeBMCClient) ReplaceWebCertificate(ctx context.Context, in *platformv1.BMCReplaceWebCertificateRequest, opts ...grpc.CallOption) (*platformv1.BMCReplaceWebCertificateResponse, error) {
	f.lastReplaceCert = in
	return f.replaceCertResp, f.replaceCertErr
}

func (f *fakeBMCClient) ListUsers(ctx context.Context, in *platformv1.BMCListUsersRequest, opts ...grpc.CallOption) (*platformv1.BMCListUsersResponse, error) {
	f.lastListUsers = in
	return f.listUsersResp, f.listUsersErr
}

func (f *fakeBMCClient) CreateUser(ctx context.Context, in *platformv1.BMCCreateUserRequest, opts ...grpc.CallOption) (*platformv1.BMCCreateUserResponse, error) {
	f.lastCreateUser = in
	return f.createResp, f.createErr
}

func (f *fakeBMCClient) DeleteUser(ctx context.Context, in *platformv1.BMCDeleteUserRequest, opts ...grpc.CallOption) (*platformv1.BMCDeleteUserResponse, error) {
	f.lastDeleteUser = in
	return f.deleteResp, f.deleteErr
}

func (f *fakeBMCClient) SetUserPassword(ctx context.Context, in *platformv1.BMCSetUserPasswordRequest, opts ...grpc.CallOption) (*platformv1.BMCSetUserPasswordResponse, error) {
	f.lastSetPassword = in
	return f.setPwResp, f.setPwErr
}

func (f *fakeBMCClient) SetUserPrivilege(ctx context.Context, in *platformv1.BMCSetUserPrivilegeRequest, opts ...grpc.CallOption) (*platformv1.BMCSetUserPrivilegeResponse, error) {
	f.lastSetPriv = in
	return f.setPrivResp, f.setPrivErr
}

// =============================================================================
// Constructor tests
// =============================================================================

func TestBMCNewClient_NilAdapterReturnsError(t *testing.T) {
	_, err := NewClient(nil)
	if !errors.Is(err, common.ErrNilConnection) {
		t.Fatalf("err = %v, want common.ErrNilConnection", err)
	}
}

// nilConnAdapter is a transport adapter whose Connection() is nil.
type nilConnAdapter struct{}

func (nilConnAdapter) Connection() grpc.ClientConnInterface { return nil }
func (nilConnAdapter) Close() error                         { return nil }
func (nilConnAdapter) IsConnected() bool                     { return false }
func (nilConnAdapter) Target() string                        { return "" }

func TestBMCNewClient_NilConnectionReturnsError(t *testing.T) {
	_, err := NewClient(nilConnAdapter{})
	if !errors.Is(err, common.ErrNilConnection) {
		t.Fatalf("err = %v, want common.ErrNilConnection", err)
	}
}

// stubClientConn is a minimal grpc.ClientConnInterface used to exercise
// the happy path of NewClient — we only need Connection() to return
// non-nil.
type stubClientConn struct{}

func (stubClientConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	return errors.New("unexpected invoke")
}

func (stubClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected stream")
}

type stubConnAdapter struct{}

func (stubConnAdapter) Connection() grpc.ClientConnInterface { return stubClientConn{} }
func (stubConnAdapter) Close() error                         { return nil }
func (stubConnAdapter) IsConnected() bool                     { return true }
func (stubConnAdapter) Target() string                        { return "stub" }

func TestBMCNewClient_HappyPathBuildsPowerActions(t *testing.T) {
	c, err := NewClient(stubConnAdapter{})
	if err != nil {
		t.Fatalf("NewClient: unexpected error: %v", err)
	}
	for _, action := range []string{"on", "off", "reset", "cycle"} {
		if _, ok := c.powerActions[action]; !ok {
			t.Errorf("power action %q missing from dispatch map", action)
		}
	}
}

func TestBMCNewClientFromGRPC_InitializesPowerActions(t *testing.T) {
	c := NewClientFromGRPC(&fakeBMCClient{})
	if c == nil {
		t.Fatal("NewClientFromGRPC returned nil")
	}
	if len(c.powerActions) != 4 {
		t.Errorf("powerActions size = %d, want 4", len(c.powerActions))
	}
}

// =============================================================================
// Power operations
// =============================================================================

func TestBMCClientPowerOn_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{powerOnResp: &platformv1.BMCPowerResponse{
		PreviousState: platformv1.BMCPowerState_BMC_POWER_STATE_OFF,
		CurrentState:  platformv1.BMCPowerState_BMC_POWER_STATE_ON,
	}}
	c := NewClientFromGRPC(fc)
	resp, err := c.PowerOn(context.Background(), 42)
	if err != nil {
		t.Fatalf("PowerOn: %v", err)
	}
	if resp.PreviousState != PowerStateOff || resp.CurrentState != PowerStateOn {
		t.Errorf("resp = %+v", resp)
	}
	if fc.lastPowerOn == nil || fc.lastPowerOn.ProfileId != 42 {
		t.Errorf("fake received req = %+v", fc.lastPowerOn)
	}
}

func TestBMCClientPowerOn_ErrorWrapped(t *testing.T) {
	cause := errors.New("rpc failed")
	fc := &fakeBMCClient{powerOnErr: cause}
	c := NewClientFromGRPC(fc)
	_, err := c.PowerOn(context.Background(), 1)
	var typed *ErrPowerFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *ErrPowerFailed", err)
	}
	if typed.Action != "on" || typed.ProfileID != 1 {
		t.Errorf("typed = %+v", typed)
	}
	if !errors.Is(err, cause) {
		t.Errorf("cause not wrapped")
	}
}

func TestBMCClientPowerOff_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{powerOffResp: &platformv1.BMCPowerResponse{
		PreviousState: platformv1.BMCPowerState_BMC_POWER_STATE_ON,
		CurrentState:  platformv1.BMCPowerState_BMC_POWER_STATE_OFF,
	}}
	c := NewClientFromGRPC(fc)
	resp, err := c.PowerOff(context.Background(), 7)
	if err != nil {
		t.Fatalf("PowerOff: %v", err)
	}
	if resp.CurrentState != PowerStateOff {
		t.Errorf("state = %v", resp.CurrentState)
	}
	if fc.lastPowerOff.ProfileId != 7 {
		t.Errorf("profile id = %d", fc.lastPowerOff.ProfileId)
	}
}

func TestBMCClientPowerOff_Error(t *testing.T) {
	fc := &fakeBMCClient{powerOffErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.PowerOff(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBMCClientPowerReset_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{powerResetResp: &platformv1.BMCPowerResponse{
		CurrentState: platformv1.BMCPowerState_BMC_POWER_STATE_ON,
	}}
	c := NewClientFromGRPC(fc)
	resp, err := c.PowerReset(context.Background(), 3)
	if err != nil {
		t.Fatalf("PowerReset: %v", err)
	}
	if resp.CurrentState != PowerStateOn {
		t.Errorf("state = %v", resp.CurrentState)
	}
}

func TestBMCClientPowerReset_Error(t *testing.T) {
	fc := &fakeBMCClient{powerResetErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.PowerReset(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBMCClientPowerCycle_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{powerCycleResp: &platformv1.BMCPowerResponse{}}
	c := NewClientFromGRPC(fc)
	_, err := c.PowerCycle(context.Background(), 2)
	if err != nil {
		t.Fatalf("PowerCycle: %v", err)
	}
	if fc.lastPowerCycle == nil {
		t.Error("fake.lastPowerCycle is nil")
	}
}

func TestBMCClientPowerCycle_Error(t *testing.T) {
	fc := &fakeBMCClient{powerCycleErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.PowerCycle(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestBMCClientPowerOp_UnknownAction(t *testing.T) {
	// Directly invoke the internal dispatch with an unknown action.
	c := NewClientFromGRPC(&fakeBMCClient{})
	_, err := c.powerOp(context.Background(), 1, "bogus")
	var typed *ErrPowerFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *ErrPowerFailed", err)
	}
	if !errors.Is(err, common.ErrInvalidArgument) {
		t.Errorf("cause should be ErrInvalidArgument, got %v", typed.Cause)
	}
}

func TestBMCClientPowerStatus_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{powerStatResp: &platformv1.BMCPowerStatusResponse{
		State: platformv1.BMCPowerState_BMC_POWER_STATE_ON,
	}}
	c := NewClientFromGRPC(fc)
	state, err := c.PowerStatus(context.Background(), 1)
	if err != nil {
		t.Fatalf("PowerStatus: %v", err)
	}
	if state != PowerStateOn {
		t.Errorf("state = %v", state)
	}
}

func TestBMCClientPowerStatus_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{powerStatErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	state, err := c.PowerStatus(context.Background(), 1)
	if state != PowerStateUnspecified {
		t.Errorf("state = %v, want unspecified on error", state)
	}
	var typed *ErrPowerFailed
	if !errors.As(err, &typed) || typed.Action != "status" {
		t.Fatalf("err = %v", err)
	}
}

// =============================================================================
// Boot device
// =============================================================================

func TestBMCClientSetBootDevice_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{setBootResp: &platformv1.BMCSetBootDeviceResponse{}}
	c := NewClientFromGRPC(fc)
	if err := c.SetBootDevice(context.Background(), 1, BootDevicePXE, true); err != nil {
		t.Fatalf("SetBootDevice: %v", err)
	}
	if fc.lastSetBoot == nil || fc.lastSetBoot.Device != platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE ||
		!fc.lastSetBoot.Persistent {
		t.Errorf("req = %+v", fc.lastSetBoot)
	}
}

func TestBMCClientSetBootDevice_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{setBootErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	err := c.SetBootDevice(context.Background(), 1, BootDevicePXE, false)
	var typed *ErrBootDeviceFailed
	if !errors.As(err, &typed) || typed.ProfileID != 1 {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientGetBootDevice_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{getBootResp: &platformv1.BMCGetBootDeviceResponse{
		Device: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_DISK,
	}}
	c := NewClientFromGRPC(fc)
	d, err := c.GetBootDevice(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetBootDevice: %v", err)
	}
	if d != BootDeviceDisk {
		t.Errorf("device = %v, want DISK", d)
	}
}

func TestBMCClientGetBootDevice_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{getBootErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	d, err := c.GetBootDevice(context.Background(), 5)
	if d != BootDeviceUnspecified {
		t.Errorf("device = %v, want UNSPECIFIED on error", d)
	}
	var typed *ErrBootDeviceFailed
	if !errors.As(err, &typed) || typed.ProfileID != 5 {
		t.Fatalf("err = %v", err)
	}
}

// =============================================================================
// Virtual media
// =============================================================================

func TestBMCClientMountISO_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{mountISOResp: &platformv1.BMCMountISOResponse{Mounted: true}}
	c := NewClientFromGRPC(fc)
	if err := c.MountISO(context.Background(), 1, "http://x/y.iso"); err != nil {
		t.Fatalf("MountISO: %v", err)
	}
	if fc.lastMountISO.IsoUrl != "http://x/y.iso" {
		t.Errorf("iso url = %q", fc.lastMountISO.IsoUrl)
	}
}

func TestBMCClientMountISO_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{mountISOErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	err := c.MountISO(context.Background(), 1, "x")
	var typed *ErrVirtualMediaFailed
	if !errors.As(err, &typed) || typed.Action != "mount" {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientUnmountISO_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{unmountISOResp: &platformv1.BMCUnmountISOResponse{}}
	c := NewClientFromGRPC(fc)
	if err := c.UnmountISO(context.Background(), 4); err != nil {
		t.Fatalf("UnmountISO: %v", err)
	}
}

func TestBMCClientUnmountISO_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{unmountISOErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	err := c.UnmountISO(context.Background(), 1)
	var typed *ErrVirtualMediaFailed
	if !errors.As(err, &typed) || typed.Action != "unmount" {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientVirtualMediaStatus_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{vmediaStatusResp: &platformv1.BMCVirtualMediaStatusResponse{
		Mounted: true, ImageUrl: "http://x/y", MediaType: "iso",
	}}
	c := NewClientFromGRPC(fc)
	info, err := c.VirtualMediaStatus(context.Background(), 1)
	if err != nil {
		t.Fatalf("VirtualMediaStatus: %v", err)
	}
	if !info.Mounted || info.ImageURL != "http://x/y" || info.MediaType != "iso" {
		t.Errorf("info = %+v", info)
	}
}

func TestBMCClientVirtualMediaStatus_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{vmediaStatusErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	info, err := c.VirtualMediaStatus(context.Background(), 1)
	if info != nil {
		t.Errorf("info should be nil, got %+v", info)
	}
	var typed *ErrVirtualMediaFailed
	if !errors.As(err, &typed) || typed.Action != "status" {
		t.Fatalf("err = %v", err)
	}
}

// =============================================================================
// Monitoring
// =============================================================================

func TestBMCClientGetSensors_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{sensorsResp: &platformv1.BMCGetSensorsResponse{
		Sensors: []*platformv1.BMCSensorReading{
			{Name: "cpu", Value: 42, Units: "C", Status: "OK"},
		},
	}}
	c := NewClientFromGRPC(fc)
	sensors, err := c.GetSensors(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	if len(sensors) != 1 || sensors[0].Name != "cpu" || sensors[0].Status != SensorStatusOK {
		t.Errorf("sensors = %+v", sensors)
	}
}

func TestBMCClientGetSensors_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{sensorsErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.GetSensors(context.Background(), 1)
	var typed *ErrSensorsFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientGetSystemInfo_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{systemInfoResp: &platformv1.BMCGetSystemInfoResponse{
		Manufacturer:    "Supermicro",
		Product:         "X10",
		SerialNumber:    "ABC",
		FirmwareVersion: "1.0",
		BiosVersion:     "2.0",
		PowerState:      platformv1.BMCPowerState_BMC_POWER_STATE_ON,
	}}
	c := NewClientFromGRPC(fc)
	info, err := c.GetSystemInfo(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if info.Manufacturer != "Supermicro" || info.Product != "X10" || info.PowerState != PowerStateOn {
		t.Errorf("info = %+v", info)
	}
}

func TestBMCClientGetSystemInfo_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{systemInfoErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.GetSystemInfo(context.Background(), 1)
	var typed *ErrSystemInfoFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v", err)
	}
}

// =============================================================================
// Provisioning
// =============================================================================

func TestBMCClientProvision_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{provisionResp: &platformv1.BMCProvisionResponse{
		ProvisionId: "p-1",
		Status:      platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_PENDING,
	}}
	c := NewClientFromGRPC(fc)
	result, err := c.Provision(context.Background(), 11, "http://x/y.iso")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.ProvisionID != "p-1" || result.State != ProvisioningStatePending {
		t.Errorf("result = %+v", result)
	}
	if fc.lastProvision.ProfileId != 11 || fc.lastProvision.IsoUrl != "http://x/y.iso" {
		t.Errorf("req = %+v", fc.lastProvision)
	}
}

func TestBMCClientProvision_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{provisionErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.Provision(context.Background(), 1, "x")
	var typed *ErrProvisionFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientProvisionStatus_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fc := &fakeBMCClient{provisionStatResp: &platformv1.BMCProvisionStatusResponse{
		Status:    platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_INSTALLING,
		Message:   "hi",
		StartedAt: timestamppb.New(now),
		UpdatedAt: timestamppb.New(now),
	}}
	c := NewClientFromGRPC(fc)
	s, err := c.ProvisionStatus(context.Background(), 1)
	if err != nil {
		t.Fatalf("ProvisionStatus: %v", err)
	}
	if s.State != ProvisioningStateInstalling || s.Message != "hi" ||
		!s.StartedAt.Equal(now) || !s.UpdatedAt.Equal(now) {
		t.Errorf("status = %+v", s)
	}
}

func TestBMCClientProvisionStatus_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{provisionStatErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.ProvisionStatus(context.Background(), 1)
	var typed *ErrProvisionFailed
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v", err)
	}
}

// =============================================================================
// Certificate management
// =============================================================================

func TestBMCClientGetWebCertificate_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fc := &fakeBMCClient{certResp: &platformv1.BMCGetWebCertificateResponse{
		Subject:                 "CN=x",
		Issuer:                  "CN=issuer",
		SerialNumber:            "DEAD",
		NotBefore:               timestamppb.New(now),
		NotAfter:                timestamppb.New(now.Add(time.Hour)),
		DaysRemaining:           30,
		SubjectAlternativeNames: []string{"s1", "s2"},
		Fingerprint:             "fp",
	}}
	c := NewClientFromGRPC(fc)
	info, err := c.GetWebCertificate(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	if info.Subject != "CN=x" || info.Issuer != "CN=issuer" ||
		info.SerialNumber != "DEAD" || info.DaysRemaining != 30 ||
		info.Fingerprint != "fp" || len(info.SubjectAlternativeNames) != 2 ||
		!info.NotBefore.Equal(now) {
		t.Errorf("info = %+v", info)
	}
}

func TestBMCClientGetWebCertificate_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{certErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.GetWebCertificate(context.Background(), 1)
	var typed *ErrCertificateFailed
	if !errors.As(err, &typed) || typed.Action != "get" {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientReplaceWebCertificate_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{replaceCertResp: &platformv1.BMCReplaceWebCertificateResponse{
		Message: "replaced",
	}}
	c := NewClientFromGRPC(fc)
	msg, err := c.ReplaceWebCertificate(context.Background(), 1, []byte("cert"), []byte("key"))
	if err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
	if msg != "replaced" {
		t.Errorf("msg = %q", msg)
	}
	if string(fc.lastReplaceCert.CertPem) != "cert" || string(fc.lastReplaceCert.KeyPem) != "key" {
		t.Errorf("req = %+v", fc.lastReplaceCert)
	}
}

func TestBMCClientReplaceWebCertificate_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{replaceCertErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	msg, err := c.ReplaceWebCertificate(context.Background(), 1, []byte("c"), []byte("k"))
	if msg != "" {
		t.Errorf("msg = %q, want empty on error", msg)
	}
	var typed *ErrCertificateFailed
	if !errors.As(err, &typed) || typed.Action != "replace" {
		t.Fatalf("err = %v", err)
	}
}

// =============================================================================
// User management
// =============================================================================

func TestBMCClientListUsers_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{listUsersResp: &platformv1.BMCListUsersResponse{
		Users: []*platformv1.BMCUser{
			{Slot: 1, Username: "admin", Enabled: true,
				Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR, Channel: 1},
		},
	}}
	c := NewClientFromGRPC(fc)
	users, err := c.ListUsers(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Username != "admin" || users[0].Privilege != PrivilegeAdministrator {
		t.Errorf("users = %+v", users)
	}
}

func TestBMCClientListUsers_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{listUsersErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	_, err := c.ListUsers(context.Background(), 1)
	var typed *ErrUserFailed
	if !errors.As(err, &typed) || typed.Action != "list" {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientCreateUser_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{createResp: &platformv1.BMCCreateUserResponse{Slot: 3}}
	c := NewClientFromGRPC(fc)
	u := &User{Slot: 3, Username: "new", Enabled: true, Privilege: PrivilegeOperator, Channel: 2}
	slot, err := c.CreateUser(context.Background(), 1, u, "pw")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if slot != 3 {
		t.Errorf("slot = %d", slot)
	}
	if fc.lastCreateUser.User.Username != "new" ||
		fc.lastCreateUser.User.Privilege != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR ||
		fc.lastCreateUser.Password != "pw" {
		t.Errorf("req = %+v", fc.lastCreateUser)
	}
}

func TestBMCClientCreateUser_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{createErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	slot, err := c.CreateUser(context.Background(), 1, &User{Slot: 2}, "pw")
	if slot != 0 {
		t.Errorf("slot = %d, want 0 on error", slot)
	}
	var typed *ErrUserFailed
	if !errors.As(err, &typed) || typed.Action != "create" {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientDeleteUser_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{deleteResp: &platformv1.BMCDeleteUserResponse{}}
	c := NewClientFromGRPC(fc)
	if err := c.DeleteUser(context.Background(), 1, 5); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if fc.lastDeleteUser.Slot != 5 {
		t.Errorf("slot = %d", fc.lastDeleteUser.Slot)
	}
}

func TestBMCClientDeleteUser_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{deleteErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	err := c.DeleteUser(context.Background(), 1, 1)
	var typed *ErrUserFailed
	if !errors.As(err, &typed) || typed.Action != "delete" {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientSetUserPassword_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{setPwResp: &platformv1.BMCSetUserPasswordResponse{}}
	c := NewClientFromGRPC(fc)
	if err := c.SetUserPassword(context.Background(), 1, 2, "pw"); err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if fc.lastSetPassword.Slot != 2 || fc.lastSetPassword.Password != "pw" {
		t.Errorf("req = %+v", fc.lastSetPassword)
	}
}

func TestBMCClientSetUserPassword_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{setPwErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	err := c.SetUserPassword(context.Background(), 1, 2, "pw")
	var typed *ErrUserFailed
	if !errors.As(err, &typed) || typed.Action != "set-password" {
		t.Fatalf("err = %v", err)
	}
}

func TestBMCClientSetUserPrivilege_HappyPath(t *testing.T) {
	fc := &fakeBMCClient{setPrivResp: &platformv1.BMCSetUserPrivilegeResponse{}}
	c := NewClientFromGRPC(fc)
	if err := c.SetUserPrivilege(context.Background(), 1, 2, 1, PrivilegeOperator); err != nil {
		t.Fatalf("SetUserPrivilege: %v", err)
	}
	if fc.lastSetPriv.Slot != 2 || fc.lastSetPriv.Channel != 1 ||
		fc.lastSetPriv.Privilege != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR {
		t.Errorf("req = %+v", fc.lastSetPriv)
	}
}

func TestBMCClientSetUserPrivilege_ErrorWrapped(t *testing.T) {
	fc := &fakeBMCClient{setPrivErr: errors.New("x")}
	c := NewClientFromGRPC(fc)
	err := c.SetUserPrivilege(context.Background(), 1, 2, 1, PrivilegeOperator)
	var typed *ErrUserFailed
	if !errors.As(err, &typed) || typed.Action != "set-privilege" {
		t.Fatalf("err = %v", err)
	}
}
