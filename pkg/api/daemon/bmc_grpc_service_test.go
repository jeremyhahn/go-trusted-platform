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
	"io"
	"log/slog"
	"math"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Fakes
// =============================================================================

// fakeBMCService records call arguments and returns configured responses.
// Zero values for responses and errors are the defaults; tests override
// individual fields per case.
type fakeBMCService struct {
	// mu guards bmcCalls and powerStatusSequence: a transport's server
	// goroutine records a call while the test reads it, and a reply over a
	// socket gives the race detector no happens-before edge.
	mu sync.Mutex
	bmcCalls

	powerOnErr     error
	powerOffErr    error
	powerResetErr  error
	powerCycleErr  error
	powerStatus    bmc.PowerState
	powerStatusErr error
	// powerStatusSequence allows the test to return different values from
	// consecutive PowerStatus calls. When non-nil, the slice is consumed
	// one entry at a time; powerStatus/powerStatusErr are used once the
	// slice is exhausted.
	powerStatusSequence []powerStatusStep

	setBootErr       error
	getBootDevice    bmc.BootDevice
	getBootDeviceErr error

	mountISOErr error
	unmountErr  error
	vmedia      *bmc.VirtualMediaInfo
	vmediaErr   error

	sensors        []bmc.SensorReading
	sensorsErr     error
	systemInfo     *bmc.SystemInfo
	systemInfoErr  error
	getCertInfo    *bmc.CertificateInfo
	getCertInfoErr error
	replaceCertErr error

	listUsers      []bmc.User
	listUsersErr   error
	createUserErr  error
	deleteUserErr  error
	setPasswordErr error
	setPrivErr     error
}

// bmcCalls is what fakeBMCService records of the calls it serves.
type bmcCalls struct {
	lastProfileID    uint64
	powerStatusCalls int

	setBootDevice  bmc.BootDevice
	setBootPersist bool
	mountISOURL    string
	replaceCert    []byte
	replaceKey     []byte

	lastCreatedUser  bmc.User
	lastPassword     string
	lastDeletedSlot  uint8
	lastPasswordSlot uint8
	lastPrivilege    bmc.Privilege
	lastPrivSlot     uint8
	lastPrivChannel  uint8
}

// calls returns a copy of the recorded calls, taken under the lock.
func (f *fakeBMCService) calls() bmcCalls {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bmcCalls
}

// record runs one call's bookkeeping under the lock.
func (f *fakeBMCService) record(profileID uint64, note func(*bmcCalls)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastProfileID = profileID
	if note != nil {
		note(&f.bmcCalls)
	}
}

type powerStatusStep struct {
	state bmc.PowerState
	err   error
}

func (f *fakeBMCService) PowerOn(ctx context.Context, profileID uint64) error {
	f.record(profileID, nil)
	return f.powerOnErr
}

func (f *fakeBMCService) PowerOff(ctx context.Context, profileID uint64) error {
	f.record(profileID, nil)
	return f.powerOffErr
}

func (f *fakeBMCService) PowerReset(ctx context.Context, profileID uint64) error {
	f.record(profileID, nil)
	return f.powerResetErr
}

func (f *fakeBMCService) PowerCycle(ctx context.Context, profileID uint64) error {
	f.record(profileID, nil)
	return f.powerCycleErr
}

func (f *fakeBMCService) PowerStatus(ctx context.Context, profileID uint64) (bmc.PowerState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastProfileID = profileID
	if f.powerStatusSequence != nil && f.powerStatusCalls < len(f.powerStatusSequence) {
		step := f.powerStatusSequence[f.powerStatusCalls]
		f.powerStatusCalls++
		return step.state, step.err
	}
	f.powerStatusCalls++
	return f.powerStatus, f.powerStatusErr
}

func (f *fakeBMCService) SetBootDevice(ctx context.Context, profileID uint64, device bmc.BootDevice, persistent bool) error {
	f.record(profileID, func(c *bmcCalls) {
		c.setBootDevice = device
		c.setBootPersist = persistent
	})
	return f.setBootErr
}

func (f *fakeBMCService) GetBootDevice(ctx context.Context, profileID uint64) (bmc.BootDevice, error) {
	f.record(profileID, nil)
	return f.getBootDevice, f.getBootDeviceErr
}

func (f *fakeBMCService) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	f.record(profileID, func(c *bmcCalls) { c.mountISOURL = isoURL })
	return f.mountISOErr
}

func (f *fakeBMCService) UnmountISO(ctx context.Context, profileID uint64) error {
	f.record(profileID, nil)
	return f.unmountErr
}

func (f *fakeBMCService) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmc.VirtualMediaInfo, error) {
	f.record(profileID, nil)
	return f.vmedia, f.vmediaErr
}

func (f *fakeBMCService) GetSensors(ctx context.Context, profileID uint64) ([]bmc.SensorReading, error) {
	f.record(profileID, nil)
	return f.sensors, f.sensorsErr
}

func (f *fakeBMCService) GetSystemInfo(ctx context.Context, profileID uint64) (*bmc.SystemInfo, error) {
	f.record(profileID, nil)
	return f.systemInfo, f.systemInfoErr
}

func (f *fakeBMCService) GetWebCertificate(ctx context.Context, profileID uint64) (*bmc.CertificateInfo, error) {
	f.record(profileID, nil)
	return f.getCertInfo, f.getCertInfoErr
}

func (f *fakeBMCService) ReplaceWebCertificate(ctx context.Context, profileID uint64, certPEM, keyPEM []byte) error {
	f.record(profileID, func(c *bmcCalls) {
		c.replaceCert = certPEM
		c.replaceKey = keyPEM
	})
	return f.replaceCertErr
}

func (f *fakeBMCService) ListUsers(ctx context.Context, profileID uint64) ([]bmc.User, error) {
	f.record(profileID, nil)
	return f.listUsers, f.listUsersErr
}

func (f *fakeBMCService) CreateUser(ctx context.Context, profileID uint64, user bmc.User, password string) error {
	f.record(profileID, func(c *bmcCalls) {
		c.lastCreatedUser = user
		c.lastPassword = password
	})
	return f.createUserErr
}

func (f *fakeBMCService) DeleteUser(ctx context.Context, profileID uint64, slot uint8) error {
	f.record(profileID, func(c *bmcCalls) { c.lastDeletedSlot = slot })
	return f.deleteUserErr
}

func (f *fakeBMCService) SetUserPassword(ctx context.Context, profileID uint64, slot uint8, password string) error {
	f.record(profileID, func(c *bmcCalls) {
		c.lastPasswordSlot = slot
		c.lastPassword = password
	})
	return f.setPasswordErr
}

func (f *fakeBMCService) SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint8, privilege bmc.Privilege) error {
	f.record(profileID, func(c *bmcCalls) {
		c.lastPrivSlot = slot
		c.lastPrivChannel = channel
		c.lastPrivilege = privilege
	})
	return f.setPrivErr
}

// fakeBaremetalService records call args and returns configured responses.
type fakeBaremetalService struct {
	// mu guards baremetalCalls; see fakeBMCService.mu.
	mu sync.Mutex
	baremetalCalls

	provisionResult *baremetal.ProvisionResult
	provisionErr    error
	statusResult    *baremetal.ProvisionResult
	statusErr       error
}

// baremetalCalls is what fakeBaremetalService records of the calls it serves.
type baremetalCalls struct {
	lastProvisionReq *baremetal.ProvisionRequest
	lastStatusID     uint64
}

// calls returns a copy of the recorded calls, taken under the lock.
func (f *fakeBaremetalService) calls() baremetalCalls {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.baremetalCalls
}

func (f *fakeBaremetalService) Provision(ctx context.Context, req *baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastProvisionReq = req
	return f.provisionResult, f.provisionErr
}

func (f *fakeBaremetalService) StatusForProfile(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastStatusID = profileID
	return f.statusResult, f.statusErr
}

// newTestService builds a BMCGRPCService wired to the provided fakes.
// A discard logger keeps test output clean.
func newTestService(svc BMCServicer, bm BaremetalServicer) *BMCGRPCService {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewBMCGRPCService(svc, bm, logger)
}

// statusCode extracts the gRPC status code from an error. Returns
// codes.Unknown when err is not a gRPC status error.
func statusCode(err error) codes.Code {
	s, ok := status.FromError(err)
	if !ok {
		return codes.Unknown
	}
	return s.Code()
}

// =============================================================================
// Constructor
// =============================================================================

func TestBMCNewBMCGRPCService_WithNilLoggerUsesDefault(t *testing.T) {
	svc := NewBMCGRPCService(&fakeBMCService{}, &fakeBaremetalService{}, nil)
	if svc.logger == nil {
		t.Fatal("logger should default to slog.Default when nil is passed")
	}
	if svc.powerActions == nil {
		t.Fatal("power actions map should be initialized when service is non-nil")
	}
	for _, action := range []string{"on", "off", "reset", "cycle"} {
		if _, ok := svc.powerActions[action]; !ok {
			t.Errorf("power action %q missing from dispatch map", action)
		}
	}
}

func TestBMCNewBMCGRPCService_WithNilServiceSkipsActions(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	if svc.powerActions != nil {
		t.Error("power actions map should be nil when service is nil")
	}
}

func TestBMCSetBaremetalService_Injects(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	bm := &fakeBaremetalService{}
	svc.SetBaremetalService(bm)
	if svc.baremetal != bm {
		t.Error("baremetal service was not injected")
	}
}

// =============================================================================
// Power operations
// =============================================================================

func TestBMCPowerOn_HappyPath(t *testing.T) {
	fake := &fakeBMCService{
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOff},
			{state: bmc.PowerStateOn},
		},
	}
	svc := newTestService(fake, nil)

	resp, err := svc.PowerOn(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 42})
	if err != nil {
		t.Fatalf("PowerOn: unexpected error: %v", err)
	}
	if resp.GetPreviousState() != platformv1.BMCPowerState_BMC_POWER_STATE_OFF {
		t.Errorf("previous state = %v, want OFF", resp.GetPreviousState())
	}
	if resp.GetCurrentState() != platformv1.BMCPowerState_BMC_POWER_STATE_ON {
		t.Errorf("current state = %v, want ON", resp.GetCurrentState())
	}
	if fake.lastProfileID != 42 {
		t.Errorf("profile id = %d, want 42", fake.lastProfileID)
	}
}

func TestBMCPowerOn_NilServiceReturnsUnavailable(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.PowerOn(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCPowerOn_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.PowerOn(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 0})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCPowerOn_PreStatusError(t *testing.T) {
	fake := &fakeBMCService{
		powerStatusSequence: []powerStatusStep{
			{err: bmc.ErrConnectionFailed{Address: "10.0.0.1", Cause: errors.New("boom")}},
		},
	}
	svc := newTestService(fake, nil)
	_, err := svc.PowerOn(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 5})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCPowerOn_ActionError(t *testing.T) {
	fake := &fakeBMCService{
		powerOnErr: bmc.ErrUnsupportedOperation{Operation: "poweron"},
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOff},
		},
	}
	svc := newTestService(fake, nil)
	_, err := svc.PowerOn(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 5})
	if got := statusCode(err); got != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", got)
	}
}

func TestBMCPowerOn_PostStatusErrorReturnsUnknownState(t *testing.T) {
	fake := &fakeBMCService{
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOff},                      // pre
			{state: bmc.PowerStateOn, err: errors.New("x")}, // post fails
		},
	}
	svc := newTestService(fake, nil)
	resp, err := svc.PowerOn(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetCurrentState() != platformv1.BMCPowerState_BMC_POWER_STATE_UNKNOWN {
		t.Errorf("current state = %v, want UNKNOWN", resp.GetCurrentState())
	}
}

func TestBMCPowerOff_HappyPath(t *testing.T) {
	fake := &fakeBMCService{
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOn},
			{state: bmc.PowerStateOff},
		},
	}
	svc := newTestService(fake, nil)
	resp, err := svc.PowerOff(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 7})
	if err != nil {
		t.Fatalf("PowerOff: %v", err)
	}
	if resp.GetPreviousState() != platformv1.BMCPowerState_BMC_POWER_STATE_ON {
		t.Errorf("previous = %v, want ON", resp.GetPreviousState())
	}
	if resp.GetCurrentState() != platformv1.BMCPowerState_BMC_POWER_STATE_OFF {
		t.Errorf("current = %v, want OFF", resp.GetCurrentState())
	}
}

func TestBMCPowerOff_ActionError(t *testing.T) {
	fake := &fakeBMCService{
		powerOffErr: bmc.ErrProfileNotFound{ProfileID: 9},
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOn},
		},
	}
	svc := newTestService(fake, nil)
	_, err := svc.PowerOff(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 9})
	if got := statusCode(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", got)
	}
}

func TestBMCPowerReset_HappyPath(t *testing.T) {
	fake := &fakeBMCService{
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOn},
			{state: bmc.PowerStateOn},
		},
	}
	svc := newTestService(fake, nil)
	resp, err := svc.PowerReset(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 3})
	if err != nil {
		t.Fatalf("PowerReset: %v", err)
	}
	if resp.GetCurrentState() != platformv1.BMCPowerState_BMC_POWER_STATE_ON {
		t.Errorf("current = %v, want ON", resp.GetCurrentState())
	}
}

func TestBMCPowerReset_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.PowerReset(context.Background(), &platformv1.BMCPowerRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCPowerCycle_HappyPath(t *testing.T) {
	fake := &fakeBMCService{
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOn},
			{state: bmc.PowerStateOn},
		},
	}
	svc := newTestService(fake, nil)
	resp, err := svc.PowerCycle(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 3})
	if err != nil {
		t.Fatalf("PowerCycle: %v", err)
	}
	if resp == nil {
		t.Fatal("response is nil")
	}
}

func TestBMCPowerCycle_ActionError(t *testing.T) {
	fake := &fakeBMCService{
		powerCycleErr: errors.New("hardware fault"),
		powerStatusSequence: []powerStatusStep{
			{state: bmc.PowerStateOn},
		},
	}
	svc := newTestService(fake, nil)
	_, err := svc.PowerCycle(context.Background(), &platformv1.BMCPowerRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCPowerStatus_HappyPath(t *testing.T) {
	fake := &fakeBMCService{powerStatus: bmc.PowerStateOn}
	svc := newTestService(fake, nil)

	resp, err := svc.PowerStatus(context.Background(), &platformv1.BMCPowerStatusRequest{ProfileId: 8})
	if err != nil {
		t.Fatalf("PowerStatus: %v", err)
	}
	if resp.GetState() != platformv1.BMCPowerState_BMC_POWER_STATE_ON {
		t.Errorf("state = %v, want ON", resp.GetState())
	}
}

func TestBMCPowerStatus_ServiceError(t *testing.T) {
	fake := &fakeBMCService{powerStatusErr: bmc.ErrNilConfig{}}
	svc := newTestService(fake, nil)
	_, err := svc.PowerStatus(context.Background(), &platformv1.BMCPowerStatusRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCPowerStatus_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.PowerStatus(context.Background(), &platformv1.BMCPowerStatusRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCPowerStatus_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.PowerStatus(context.Background(), &platformv1.BMCPowerStatusRequest{ProfileId: 0})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

// =============================================================================
// Boot device
// =============================================================================

func TestBMCSetBootDevice_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)

	resp, err := svc.SetBootDevice(context.Background(), &platformv1.BMCSetBootDeviceRequest{
		ProfileId:  10,
		Device:     platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE,
		Persistent: true,
	})
	if err != nil {
		t.Fatalf("SetBootDevice: %v", err)
	}
	if resp.GetDevice() != platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE {
		t.Errorf("device = %v, want PXE", resp.GetDevice())
	}
	if fake.setBootDevice != bmc.BootDevicePXE {
		t.Errorf("fake received device = %v, want PXE", fake.setBootDevice)
	}
	if !fake.setBootPersist {
		t.Error("fake received persistent = false, want true")
	}
}

func TestBMCSetBootDevice_InvalidDevice(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetBootDevice(context.Background(), &platformv1.BMCSetBootDeviceRequest{
		ProfileId: 1,
		Device:    platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED,
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetBootDevice_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.SetBootDevice(context.Background(), &platformv1.BMCSetBootDeviceRequest{ProfileId: 1, Device: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCSetBootDevice_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetBootDevice(context.Background(), &platformv1.BMCSetBootDeviceRequest{Device: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetBootDevice_ServiceError(t *testing.T) {
	fake := &fakeBMCService{setBootErr: bmc.ErrInvalidConfig{Field: "x", Reason: "y"}}
	svc := newTestService(fake, nil)
	_, err := svc.SetBootDevice(context.Background(), &platformv1.BMCSetBootDeviceRequest{
		ProfileId: 1, Device: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE,
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCGetBootDevice_HappyPath(t *testing.T) {
	fake := &fakeBMCService{getBootDevice: bmc.BootDeviceVirtualMedia}
	svc := newTestService(fake, nil)
	resp, err := svc.GetBootDevice(context.Background(), &platformv1.BMCGetBootDeviceRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("GetBootDevice: %v", err)
	}
	if resp.GetDevice() != platformv1.BMCBootDevice_BMC_BOOT_DEVICE_VIRTUAL_MEDIA {
		t.Errorf("device = %v, want VIRTUAL_MEDIA", resp.GetDevice())
	}
}

func TestBMCGetBootDevice_ServiceError(t *testing.T) {
	fake := &fakeBMCService{getBootDeviceErr: errors.New("dial timeout")}
	svc := newTestService(fake, nil)
	_, err := svc.GetBootDevice(context.Background(), &platformv1.BMCGetBootDeviceRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCGetBootDevice_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.GetBootDevice(context.Background(), &platformv1.BMCGetBootDeviceRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCGetBootDevice_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.GetBootDevice(context.Background(), &platformv1.BMCGetBootDeviceRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

// =============================================================================
// Virtual media
// =============================================================================

func TestBMCMountISO_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)
	resp, err := svc.MountISO(context.Background(), &platformv1.BMCMountISORequest{
		ProfileId: 1, IsoUrl: "https://example.test/install.iso",
	})
	if err != nil {
		t.Fatalf("MountISO: %v", err)
	}
	if !resp.GetMounted() {
		t.Error("mounted = false, want true")
	}
	if fake.mountISOURL != "https://example.test/install.iso" {
		t.Errorf("iso url = %q, want https://example.test/install.iso", fake.mountISOURL)
	}
}

func TestBMCMountISO_MissingURL(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.MountISO(context.Background(), &platformv1.BMCMountISORequest{ProfileId: 1})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCMountISO_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.MountISO(context.Background(), &platformv1.BMCMountISORequest{ProfileId: 1, IsoUrl: "x"})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCMountISO_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.MountISO(context.Background(), &platformv1.BMCMountISORequest{IsoUrl: "x"})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCMountISO_ServiceError(t *testing.T) {
	fake := &fakeBMCService{mountISOErr: errors.New("mount failed")}
	svc := newTestService(fake, nil)
	_, err := svc.MountISO(context.Background(), &platformv1.BMCMountISORequest{ProfileId: 1, IsoUrl: "x"})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCUnmountISO_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)
	_, err := svc.UnmountISO(context.Background(), &platformv1.BMCUnmountISORequest{ProfileId: 4})
	if err != nil {
		t.Fatalf("UnmountISO: %v", err)
	}
	if fake.lastProfileID != 4 {
		t.Errorf("profile id = %d, want 4", fake.lastProfileID)
	}
}

func TestBMCUnmountISO_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.UnmountISO(context.Background(), &platformv1.BMCUnmountISORequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCUnmountISO_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.UnmountISO(context.Background(), &platformv1.BMCUnmountISORequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCUnmountISO_ServiceError(t *testing.T) {
	fake := &fakeBMCService{unmountErr: bmc.ErrConnectionFailed{}}
	svc := newTestService(fake, nil)
	_, err := svc.UnmountISO(context.Background(), &platformv1.BMCUnmountISORequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCVirtualMediaStatus_HappyPath(t *testing.T) {
	fake := &fakeBMCService{vmedia: &bmc.VirtualMediaInfo{
		Mounted:   true,
		ImageURL:  "http://x/y.iso",
		MediaType: "iso",
	}}
	svc := newTestService(fake, nil)
	resp, err := svc.VirtualMediaStatus(context.Background(), &platformv1.BMCVirtualMediaStatusRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("VirtualMediaStatus: %v", err)
	}
	if !resp.GetMounted() || resp.GetImageUrl() != "http://x/y.iso" || resp.GetMediaType() != "iso" {
		t.Errorf("got %+v, want mounted/url/type populated", resp)
	}
}

func TestBMCVirtualMediaStatus_NilInfoReturnsEmpty(t *testing.T) {
	fake := &fakeBMCService{vmedia: nil}
	svc := newTestService(fake, nil)
	resp, err := svc.VirtualMediaStatus(context.Background(), &platformv1.BMCVirtualMediaStatusRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("VirtualMediaStatus: %v", err)
	}
	if resp.GetMounted() || resp.GetImageUrl() != "" || resp.GetMediaType() != "" {
		t.Errorf("expected empty response, got %+v", resp)
	}
}

func TestBMCVirtualMediaStatus_ServiceError(t *testing.T) {
	fake := &fakeBMCService{vmediaErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.VirtualMediaStatus(context.Background(), &platformv1.BMCVirtualMediaStatusRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCVirtualMediaStatus_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.VirtualMediaStatus(context.Background(), &platformv1.BMCVirtualMediaStatusRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCVirtualMediaStatus_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.VirtualMediaStatus(context.Background(), &platformv1.BMCVirtualMediaStatusRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

// =============================================================================
// Monitoring
// =============================================================================

func TestBMCGetSensors_HappyPath(t *testing.T) {
	fake := &fakeBMCService{sensors: []bmc.SensorReading{
		{Name: "cpu", Value: 42.5, Units: "C", Status: "ok"},
		{Name: "fan", Value: 1200, Units: "RPM", Status: "ok"},
	}}
	svc := newTestService(fake, nil)
	resp, err := svc.GetSensors(context.Background(), &platformv1.BMCGetSensorsRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("GetSensors: %v", err)
	}
	if len(resp.GetSensors()) != 2 {
		t.Fatalf("sensor count = %d, want 2", len(resp.GetSensors()))
	}
	if resp.Sensors[0].GetName() != "cpu" || resp.Sensors[0].GetValue() != 42.5 {
		t.Errorf("sensor[0] = %+v, want cpu=42.5", resp.Sensors[0])
	}
}

func TestBMCGetSensors_ServiceError(t *testing.T) {
	fake := &fakeBMCService{sensorsErr: bmc.ErrUnsupportedOperation{Operation: "sensors"}}
	svc := newTestService(fake, nil)
	_, err := svc.GetSensors(context.Background(), &platformv1.BMCGetSensorsRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", got)
	}
}

func TestBMCGetSensors_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.GetSensors(context.Background(), &platformv1.BMCGetSensorsRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCGetSensors_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.GetSensors(context.Background(), &platformv1.BMCGetSensorsRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCGetSystemInfo_HappyPath(t *testing.T) {
	fake := &fakeBMCService{systemInfo: &bmc.SystemInfo{
		Manufacturer:    "Supermicro",
		Product:         "X10",
		SerialNumber:    "ABC",
		FirmwareVersion: "1.0",
		BIOSVersion:     "2.0",
		PowerState:      bmc.PowerStateOn,
	}}
	svc := newTestService(fake, nil)
	resp, err := svc.GetSystemInfo(context.Background(), &platformv1.BMCGetSystemInfoRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if resp.GetManufacturer() != "Supermicro" || resp.GetProduct() != "X10" ||
		resp.GetSerialNumber() != "ABC" || resp.GetFirmwareVersion() != "1.0" ||
		resp.GetBiosVersion() != "2.0" {
		t.Errorf("system info mismatch: %+v", resp)
	}
	if resp.GetPowerState() != platformv1.BMCPowerState_BMC_POWER_STATE_ON {
		t.Errorf("power state = %v, want ON", resp.GetPowerState())
	}
}

func TestBMCGetSystemInfo_NilInfoReturnsEmpty(t *testing.T) {
	fake := &fakeBMCService{systemInfo: nil}
	svc := newTestService(fake, nil)
	resp, err := svc.GetSystemInfo(context.Background(), &platformv1.BMCGetSystemInfoRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("GetSystemInfo: %v", err)
	}
	if resp.GetManufacturer() != "" {
		t.Errorf("expected empty manufacturer, got %q", resp.GetManufacturer())
	}
}

func TestBMCGetSystemInfo_ServiceError(t *testing.T) {
	fake := &fakeBMCService{systemInfoErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.GetSystemInfo(context.Background(), &platformv1.BMCGetSystemInfoRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCGetSystemInfo_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.GetSystemInfo(context.Background(), &platformv1.BMCGetSystemInfoRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCGetSystemInfo_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.GetSystemInfo(context.Background(), &platformv1.BMCGetSystemInfoRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

// =============================================================================
// Provisioning
// =============================================================================

func TestBMCProvision_HappyPath(t *testing.T) {
	bm := &fakeBaremetalService{provisionResult: &baremetal.ProvisionResult{
		ProvisionID: "p-1",
		Status:      baremetal.StatusPending,
	}}
	svc := newTestService(&fakeBMCService{}, bm)

	resp, err := svc.Provision(context.Background(), &platformv1.BMCProvisionRequest{
		ProfileId: 11, IsoUrl: "http://x/y.iso",
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if resp.GetProvisionId() != "p-1" {
		t.Errorf("provision id = %q, want p-1", resp.GetProvisionId())
	}
	if resp.GetStatus() != platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_PENDING {
		t.Errorf("status = %v, want PENDING", resp.GetStatus())
	}
	if bm.lastProvisionReq == nil || bm.lastProvisionReq.ProfileID != 11 {
		t.Errorf("baremetal not called with expected request: %+v", bm.lastProvisionReq)
	}
}

func TestBMCProvision_NilBaremetal(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.Provision(context.Background(), &platformv1.BMCProvisionRequest{ProfileId: 1, IsoUrl: "x"})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCProvision_InvalidProfileID(t *testing.T) {
	bm := &fakeBaremetalService{}
	svc := newTestService(&fakeBMCService{}, bm)
	_, err := svc.Provision(context.Background(), &platformv1.BMCProvisionRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCProvision_InProgress(t *testing.T) {
	bm := &fakeBaremetalService{provisionErr: baremetal.ErrProvisionInProgress{ProfileID: 1}}
	svc := newTestService(&fakeBMCService{}, bm)
	_, err := svc.Provision(context.Background(), &platformv1.BMCProvisionRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", got)
	}
}

func TestBMCProvision_InvalidRequest(t *testing.T) {
	bm := &fakeBaremetalService{provisionErr: baremetal.ErrInvalidProvisionRequest{Reason: "x"}}
	svc := newTestService(&fakeBMCService{}, bm)
	_, err := svc.Provision(context.Background(), &platformv1.BMCProvisionRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCProvision_ProfileNoBMC(t *testing.T) {
	bm := &fakeBaremetalService{provisionErr: baremetal.ErrProfileNoBMC{ProfileID: 1}}
	svc := newTestService(&fakeBMCService{}, bm)
	_, err := svc.Provision(context.Background(), &platformv1.BMCProvisionRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", got)
	}
}

func TestBMCProvisionStatus_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	bm := &fakeBaremetalService{statusResult: &baremetal.ProvisionResult{
		ProvisionID: "p-1",
		Status:      baremetal.StatusInstalling,
		Message:     "installing",
		StartedAt:   now,
		UpdatedAt:   now,
	}}
	svc := newTestService(&fakeBMCService{}, bm)
	resp, err := svc.ProvisionStatus(context.Background(), &platformv1.BMCProvisionStatusRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("ProvisionStatus: %v", err)
	}
	if resp.GetStatus() != platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_INSTALLING {
		t.Errorf("status = %v, want INSTALLING", resp.GetStatus())
	}
	if resp.GetMessage() != "installing" {
		t.Errorf("message = %q, want installing", resp.GetMessage())
	}
	if resp.GetStartedAt() == nil || resp.GetUpdatedAt() == nil {
		t.Error("timestamps should be populated")
	}
}

func TestBMCProvisionStatus_NotFound(t *testing.T) {
	bm := &fakeBaremetalService{statusErr: baremetal.ErrProvisionNotFound{ProvisionID: "x"}}
	svc := newTestService(&fakeBMCService{}, bm)
	_, err := svc.ProvisionStatus(context.Background(), &platformv1.BMCProvisionStatusRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", got)
	}
}

func TestBMCProvisionStatus_NilBaremetal(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.ProvisionStatus(context.Background(), &platformv1.BMCProvisionStatusRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCProvisionStatus_InvalidProfileID(t *testing.T) {
	bm := &fakeBaremetalService{}
	svc := newTestService(&fakeBMCService{}, bm)
	_, err := svc.ProvisionStatus(context.Background(), &platformv1.BMCProvisionStatusRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

// =============================================================================
// Certificate management
// =============================================================================

func TestBMCGetWebCertificate_HappyPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	fake := &fakeBMCService{getCertInfo: &bmc.CertificateInfo{
		Subject:                 "CN=x",
		Issuer:                  "CN=issuer",
		SerialNumber:            "ABCD",
		NotBefore:               now,
		NotAfter:                now.Add(time.Hour),
		DaysRemaining:           7,
		SubjectAlternativeNames: []string{"x.example"},
		Fingerprint:             "aabb",
	}}
	svc := newTestService(fake, nil)

	resp, err := svc.GetWebCertificate(context.Background(), &platformv1.BMCGetWebCertificateRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	if resp.GetSubject() != "CN=x" || resp.GetIssuer() != "CN=issuer" ||
		resp.GetSerialNumber() != "ABCD" || resp.GetDaysRemaining() != 7 ||
		resp.GetFingerprint() != "aabb" {
		t.Errorf("cert info mismatch: %+v", resp)
	}
	if len(resp.GetSubjectAlternativeNames()) != 1 {
		t.Errorf("sans = %v, want one entry", resp.GetSubjectAlternativeNames())
	}
}

func TestBMCGetWebCertificate_NilInfoReturnsEmpty(t *testing.T) {
	fake := &fakeBMCService{getCertInfo: nil}
	svc := newTestService(fake, nil)
	resp, err := svc.GetWebCertificate(context.Background(), &platformv1.BMCGetWebCertificateRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("GetWebCertificate: %v", err)
	}
	if resp.GetSubject() != "" {
		t.Errorf("expected empty subject, got %q", resp.GetSubject())
	}
}

func TestBMCGetWebCertificate_ServiceError(t *testing.T) {
	fake := &fakeBMCService{getCertInfoErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.GetWebCertificate(context.Background(), &platformv1.BMCGetWebCertificateRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCGetWebCertificate_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.GetWebCertificate(context.Background(), &platformv1.BMCGetWebCertificateRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCGetWebCertificate_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.GetWebCertificate(context.Background(), &platformv1.BMCGetWebCertificateRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCReplaceWebCertificate_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)
	resp, err := svc.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 1,
		CertPem:   []byte("cert"),
		KeyPem:    []byte("key"),
	})
	if err != nil {
		t.Fatalf("ReplaceWebCertificate: %v", err)
	}
	if resp.GetMessage() == "" {
		t.Error("message should be populated")
	}
	if string(fake.replaceCert) != "cert" || string(fake.replaceKey) != "key" {
		t.Errorf("fake received wrong PEM bytes: cert=%q key=%q", fake.replaceCert, fake.replaceKey)
	}
}

func TestBMCReplaceWebCertificate_MissingCertPEM(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 1, KeyPem: []byte("key"),
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCReplaceWebCertificate_MissingKeyPEM(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 1, CertPem: []byte("cert"),
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCReplaceWebCertificate_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 1, CertPem: []byte("x"), KeyPem: []byte("y"),
	})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCReplaceWebCertificate_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		CertPem: []byte("x"), KeyPem: []byte("y"),
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCReplaceWebCertificate_ServiceError(t *testing.T) {
	fake := &fakeBMCService{replaceCertErr: errors.New("apply failed")}
	svc := newTestService(fake, nil)
	_, err := svc.ReplaceWebCertificate(context.Background(), &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: 1, CertPem: []byte("x"), KeyPem: []byte("y"),
	})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

// =============================================================================
// User management
// =============================================================================

func TestBMCListUsers_HappyPath(t *testing.T) {
	fake := &fakeBMCService{listUsers: []bmc.User{
		{Slot: 1, Username: "admin", Enabled: true, Privilege: bmc.PrivilegeAdministrator, Channel: 1},
		{Slot: 2, Username: "ops", Enabled: false, Privilege: bmc.PrivilegeOperator, Channel: 1},
	}}
	svc := newTestService(fake, nil)
	resp, err := svc.ListUsers(context.Background(), &platformv1.BMCListUsersRequest{ProfileId: 1})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(resp.GetUsers()) != 2 {
		t.Fatalf("user count = %d, want 2", len(resp.GetUsers()))
	}
	if resp.Users[0].GetUsername() != "admin" ||
		resp.Users[0].GetPrivilege() != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR {
		t.Errorf("user[0] = %+v", resp.Users[0])
	}
}

func TestBMCListUsers_ServiceError(t *testing.T) {
	fake := &fakeBMCService{listUsersErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.ListUsers(context.Background(), &platformv1.BMCListUsersRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCListUsers_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.ListUsers(context.Background(), &platformv1.BMCListUsersRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCListUsers_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.ListUsers(context.Background(), &platformv1.BMCListUsersRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCCreateUser_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)
	resp, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 1,
		User: &platformv1.BMCUser{
			Slot:      3,
			Username:  "new",
			Enabled:   true,
			Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
			Channel:   2,
		},
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if resp.GetSlot() != 3 {
		t.Errorf("slot = %d, want 3", resp.GetSlot())
	}
	if fake.lastCreatedUser.Username != "new" ||
		fake.lastCreatedUser.Privilege != bmc.PrivilegeOperator ||
		fake.lastCreatedUser.Slot != 3 || fake.lastCreatedUser.Channel != 2 {
		t.Errorf("fake received user = %+v", fake.lastCreatedUser)
	}
	if fake.lastPassword != "secret" {
		t.Errorf("password = %q, want secret", fake.lastPassword)
	}
}

func TestBMCCreateUser_MissingUser(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCCreateUser_SlotOverflow(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 1,
		User:      &platformv1.BMCUser{Slot: math.MaxUint8 + 1},
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCCreateUser_ChannelOverflow(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 1,
		User:      &platformv1.BMCUser{Slot: 2, Channel: math.MaxUint8 + 1},
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCCreateUser_InvalidPrivilege(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 1,
		User: &platformv1.BMCUser{
			Slot:      2,
			Privilege: platformv1.BMCUserPrivilege(999),
		},
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCCreateUser_ServiceError(t *testing.T) {
	fake := &fakeBMCService{createUserErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 1,
		User: &platformv1.BMCUser{
			Slot: 2, Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR,
		},
	})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCCreateUser_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		ProfileId: 1, User: &platformv1.BMCUser{Slot: 1},
	})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCCreateUser_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.CreateUser(context.Background(), &platformv1.BMCCreateUserRequest{
		User: &platformv1.BMCUser{Slot: 2},
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCDeleteUser_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)
	_, err := svc.DeleteUser(context.Background(), &platformv1.BMCDeleteUserRequest{ProfileId: 1, Slot: 5})
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if fake.lastDeletedSlot != 5 {
		t.Errorf("slot = %d, want 5", fake.lastDeletedSlot)
	}
}

func TestBMCDeleteUser_SlotOverflow(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.DeleteUser(context.Background(), &platformv1.BMCDeleteUserRequest{
		ProfileId: 1, Slot: math.MaxUint8 + 1,
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCDeleteUser_ServiceError(t *testing.T) {
	fake := &fakeBMCService{deleteUserErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.DeleteUser(context.Background(), &platformv1.BMCDeleteUserRequest{ProfileId: 1, Slot: 2})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCDeleteUser_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.DeleteUser(context.Background(), &platformv1.BMCDeleteUserRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCDeleteUser_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.DeleteUser(context.Background(), &platformv1.BMCDeleteUserRequest{Slot: 1})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetUserPassword_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)
	_, err := svc.SetUserPassword(context.Background(), &platformv1.BMCSetUserPasswordRequest{
		ProfileId: 1, Slot: 2, Password: "p",
	})
	if err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if fake.lastPasswordSlot != 2 || fake.lastPassword != "p" {
		t.Errorf("fake received slot=%d password=%q", fake.lastPasswordSlot, fake.lastPassword)
	}
}

func TestBMCSetUserPassword_SlotOverflow(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetUserPassword(context.Background(), &platformv1.BMCSetUserPasswordRequest{
		ProfileId: 1, Slot: math.MaxUint8 + 1, Password: "p",
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetUserPassword_ServiceError(t *testing.T) {
	fake := &fakeBMCService{setPasswordErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.SetUserPassword(context.Background(), &platformv1.BMCSetUserPasswordRequest{
		ProfileId: 1, Slot: 2, Password: "p",
	})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCSetUserPassword_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.SetUserPassword(context.Background(), &platformv1.BMCSetUserPasswordRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCSetUserPassword_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetUserPassword(context.Background(), &platformv1.BMCSetUserPasswordRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetUserPrivilege_HappyPath(t *testing.T) {
	fake := &fakeBMCService{}
	svc := newTestService(fake, nil)
	_, err := svc.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: 1, Slot: 2, Channel: 1,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
	})
	if err != nil {
		t.Fatalf("SetUserPrivilege: %v", err)
	}
	if fake.lastPrivilege != bmc.PrivilegeOperator || fake.lastPrivSlot != 2 || fake.lastPrivChannel != 1 {
		t.Errorf("fake received priv=%v slot=%d channel=%d",
			fake.lastPrivilege, fake.lastPrivSlot, fake.lastPrivChannel)
	}
}

func TestBMCSetUserPrivilege_SlotOverflow(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: 1, Slot: math.MaxUint8 + 1,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetUserPrivilege_ChannelOverflow(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: 1, Slot: 2, Channel: math.MaxUint8 + 1,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetUserPrivilege_InvalidPrivilege(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: 1, Slot: 2, Channel: 1,
		Privilege: platformv1.BMCUserPrivilege(999),
	})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

func TestBMCSetUserPrivilege_ServiceError(t *testing.T) {
	fake := &fakeBMCService{setPrivErr: errors.New("x")}
	svc := newTestService(fake, nil)
	_, err := svc.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: 1, Slot: 2, Channel: 1,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
	})
	if got := statusCode(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal", got)
	}
}

func TestBMCSetUserPrivilege_NilService(t *testing.T) {
	svc := NewBMCGRPCService(nil, nil, slog.Default())
	_, err := svc.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{ProfileId: 1})
	if got := statusCode(err); got != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", got)
	}
}

func TestBMCSetUserPrivilege_InvalidProfileID(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	_, err := svc.SetUserPrivilege(context.Background(), &platformv1.BMCSetUserPrivilegeRequest{})
	if got := statusCode(err); got != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", got)
	}
}

// =============================================================================
// toGRPCError error translation
// =============================================================================

func TestBMCToGRPCError_NilPassThrough(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	if err := svc.toGRPCError("op", nil); err != nil {
		t.Fatalf("toGRPCError(nil) = %v, want nil", err)
	}
}

func TestBMCToGRPCError_Translations(t *testing.T) {
	svc := newTestService(&fakeBMCService{}, nil)
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"ProfileNotFound", bmc.ErrProfileNotFound{ProfileID: 1}, codes.NotFound},
		{"NilConfig", bmc.ErrNilConfig{}, codes.InvalidArgument},
		{"InvalidConfig", bmc.ErrInvalidConfig{Field: "x", Reason: "y"}, codes.InvalidArgument},
		{"Unsupported", bmc.ErrUnsupportedOperation{Operation: "op"}, codes.Unimplemented},
		{"ConnectionFailed", bmc.ErrConnectionFailed{Address: "x"}, codes.Unavailable},
		{"ProvisionNotFound", baremetal.ErrProvisionNotFound{ProvisionID: "x"}, codes.NotFound},
		{"ProvisionInProgress", baremetal.ErrProvisionInProgress{ProfileID: 1}, codes.AlreadyExists},
		{"InvalidProvReq", baremetal.ErrInvalidProvisionRequest{Reason: "x"}, codes.InvalidArgument},
		{"ProfileNoBMC", baremetal.ErrProfileNoBMC{ProfileID: 1}, codes.FailedPrecondition},
		{"UnknownBecomesInternal", errors.New("random"), codes.Internal},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := statusCode(svc.toGRPCError("op", tc.err))
			if got != tc.want {
				t.Errorf("code = %v, want %v", got, tc.want)
			}
		})
	}
}

// =============================================================================
// Helpers
// =============================================================================

func TestBMCPowerStateProto_AllMappings(t *testing.T) {
	cases := []struct {
		in   bmc.PowerState
		want platformv1.BMCPowerState
	}{
		{bmc.PowerStateOn, platformv1.BMCPowerState_BMC_POWER_STATE_ON},
		{bmc.PowerStateOff, platformv1.BMCPowerState_BMC_POWER_STATE_OFF},
		{bmc.PowerStateUnknown, platformv1.BMCPowerState_BMC_POWER_STATE_UNKNOWN},
		{bmc.PowerState("garbage"), platformv1.BMCPowerState_BMC_POWER_STATE_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := powerStateProto(tc.in); got != tc.want {
			t.Errorf("powerStateProto(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestBMCBootDeviceProto_AllMappings(t *testing.T) {
	cases := []struct {
		in   bmc.BootDevice
		want platformv1.BMCBootDevice
	}{
		{bmc.BootDevicePXE, platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE},
		{bmc.BootDeviceDisk, platformv1.BMCBootDevice_BMC_BOOT_DEVICE_DISK},
		{bmc.BootDeviceCDROM, platformv1.BMCBootDevice_BMC_BOOT_DEVICE_CDROM},
		{bmc.BootDeviceVirtualMedia, platformv1.BMCBootDevice_BMC_BOOT_DEVICE_VIRTUAL_MEDIA},
		{bmc.BootDeviceNone, platformv1.BMCBootDevice_BMC_BOOT_DEVICE_NONE},
		{bmc.BootDevice("garbage"), platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := bootDeviceProto(tc.in); got != tc.want {
			t.Errorf("bootDeviceProto(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestBMCProvisioningStatusProto_AllMappings(t *testing.T) {
	cases := []struct {
		in   baremetal.ProvisioningStatus
		want platformv1.BMCProvisioningStatus
	}{
		{baremetal.StatusPending, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_PENDING},
		{baremetal.StatusConnecting, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_CONNECTING},
		{baremetal.StatusSettingBoot, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_SETTING_BOOT},
		{baremetal.StatusMountingISO, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_MOUNTING_ISO},
		{baremetal.StatusPoweringOn, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_POWERING_ON},
		{baremetal.StatusInstalling, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_INSTALLING},
		{baremetal.StatusFinalizing, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FINALIZING},
		{baremetal.StatusComplete, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_COMPLETE},
		{baremetal.StatusFailed, platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FAILED},
		{baremetal.ProvisioningStatus("garbage"), platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := provisioningStatusProto(tc.in); got != tc.want {
			t.Errorf("provisioningStatusProto(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestBMCUserToProto_UnknownPrivilegeIsUnspecified(t *testing.T) {
	u := bmc.User{Slot: 1, Username: "x", Privilege: bmc.Privilege(0xEE), Channel: 2, Enabled: true}
	out := userToProto(u)
	if out.GetPrivilege() != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED {
		t.Errorf("privilege = %v, want UNSPECIFIED", out.GetPrivilege())
	}
	if out.GetSlot() != 1 || out.GetUsername() != "x" || out.GetChannel() != 2 || !out.GetEnabled() {
		t.Errorf("user mismatch: %+v", out)
	}
}

func TestBMCUserFromProto_UnspecifiedPrivilegeIsAllowed(t *testing.T) {
	u, err := userFromProto(&platformv1.BMCUser{
		Slot: 2, Username: "admin", Channel: 1, Enabled: true,
		Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED,
	})
	if err != nil {
		t.Fatalf("userFromProto: unexpected error: %v", err)
	}
	if u.Slot != 2 || u.Username != "admin" || u.Channel != 1 || !u.Enabled {
		t.Errorf("user mismatch: %+v", u)
	}
	// Privilege defaults to zero value for unspecified.
	if u.Privilege != 0 {
		t.Errorf("privilege = %v, want zero", u.Privilege)
	}
}

func TestBMCUserFromProto_InvalidPrivilege(t *testing.T) {
	_, err := userFromProto(&platformv1.BMCUser{
		Slot: 2, Privilege: platformv1.BMCUserPrivilege(999),
	})
	var invalid ErrInvalidPrivilege
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrInvalidPrivilege", err)
	}
}

func TestBMCUserFromProto_SlotOverflow(t *testing.T) {
	_, err := userFromProto(&platformv1.BMCUser{Slot: math.MaxUint8 + 1})
	var invalid ErrInvalidSlot
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrInvalidSlot", err)
	}
}

func TestBMCUserFromProto_ChannelOverflow(t *testing.T) {
	_, err := userFromProto(&platformv1.BMCUser{Slot: 1, Channel: math.MaxUint8 + 1})
	var invalid ErrInvalidChannel
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrInvalidChannel", err)
	}
}

func TestBMCSlotFromProto(t *testing.T) {
	s, err := slotFromProto(7)
	if err != nil || s != 7 {
		t.Fatalf("slotFromProto(7) = (%d, %v), want (7, nil)", s, err)
	}
	if _, err := slotFromProto(math.MaxUint8 + 1); err == nil {
		t.Error("expected overflow error")
	}
}

func TestBMCChannelFromProto(t *testing.T) {
	c, err := channelFromProto(3)
	if err != nil || c != 3 {
		t.Fatalf("channelFromProto(3) = (%d, %v), want (3, nil)", c, err)
	}
	if _, err := channelFromProto(math.MaxUint8 + 1); err == nil {
		t.Error("expected overflow error")
	}
}

func TestBMCTimeToProto(t *testing.T) {
	if got := timeToProto(time.Time{}); got != nil {
		t.Errorf("zero time should return nil, got %v", got)
	}
	now := time.Now().UTC().Truncate(time.Second)
	if got := timeToProto(now); got == nil || !got.AsTime().Equal(now) {
		t.Errorf("non-zero time not preserved: got %v", got)
	}
}

func TestBMCCertInfoToProto_Nil(t *testing.T) {
	out := certInfoToProto(nil)
	if out == nil {
		t.Fatal("certInfoToProto(nil) should not return nil response")
	}
	if out.GetSubject() != "" {
		t.Errorf("subject = %q, want empty", out.GetSubject())
	}
}

// =============================================================================
// Error message coverage
// =============================================================================

func TestBMCErrors_MessagesNonEmpty(t *testing.T) {
	cases := []error{
		ErrBMCServiceNotConfigured{},
		ErrBaremetalServiceNotConfigured{},
		ErrInvalidProfileID{},
		ErrMissingISOURL{},
		ErrInvalidBootDevice{Device: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED},
		ErrInvalidPrivilege{Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED},
		ErrMissingUser{},
		ErrMissingCertPEM{},
		ErrMissingKeyPEM{},
		ErrInvalidSlot{Slot: 999},
		ErrInvalidChannel{Channel: 999},
	}
	for _, e := range cases {
		if e.Error() == "" {
			t.Errorf("%T returned empty error message", e)
		}
	}
}
