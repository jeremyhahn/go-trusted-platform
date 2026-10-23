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

package baremetal

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// mockBMC implements BMCOperator for testing.
type mockBMC struct {
	power          atomic.Value // bmc.PowerState
	bootDevice     atomic.Value // bmc.BootDevice
	bootPersistent atomic.Value // bool
	mounted        atomic.Value // bool
	mountedURL     atomic.Value // string

	powerOnErr     error
	powerOffErr    error
	powerCycleErr  error
	powerStatusErr error
	setBootErr     error
	mountErr       error
	unmountErr     error

	powerOnCalls    atomic.Int64
	powerOffCalls   atomic.Int64
	powerCycleCalls atomic.Int64
	setBootCalls    atomic.Int64
	mountCalls      atomic.Int64
	unmountCalls    atomic.Int64
}

func newMockBMC() *mockBMC {
	m := &mockBMC{}
	m.power.Store(bmc.PowerStateOff)
	m.bootDevice.Store(bmc.BootDeviceDisk)
	m.bootPersistent.Store(false)
	m.mounted.Store(false)
	m.mountedURL.Store("")
	return m
}

func (m *mockBMC) PowerOn(_ context.Context, _ uint64) error {
	m.powerOnCalls.Add(1)
	if m.powerOnErr != nil {
		return m.powerOnErr
	}
	m.power.Store(bmc.PowerStateOn)
	return nil
}

func (m *mockBMC) PowerOff(_ context.Context, _ uint64) error {
	m.powerOffCalls.Add(1)
	if m.powerOffErr != nil {
		return m.powerOffErr
	}
	m.power.Store(bmc.PowerStateOff)
	return nil
}

func (m *mockBMC) PowerCycle(_ context.Context, _ uint64) error {
	m.powerCycleCalls.Add(1)
	if m.powerCycleErr != nil {
		return m.powerCycleErr
	}
	m.power.Store(bmc.PowerStateOn)
	return nil
}

func (m *mockBMC) PowerStatus(_ context.Context, _ uint64) (bmc.PowerState, error) {
	if m.powerStatusErr != nil {
		return bmc.PowerStateUnknown, m.powerStatusErr
	}
	return m.power.Load().(bmc.PowerState), nil
}

func (m *mockBMC) SetBootDevice(_ context.Context, _ uint64, device bmc.BootDevice, persistent bool) error {
	m.setBootCalls.Add(1)
	if m.setBootErr != nil {
		return m.setBootErr
	}
	m.bootDevice.Store(device)
	m.bootPersistent.Store(persistent)
	return nil
}

func (m *mockBMC) MountISO(_ context.Context, _ uint64, isoURL string) error {
	m.mountCalls.Add(1)
	if m.mountErr != nil {
		return m.mountErr
	}
	m.mounted.Store(true)
	m.mountedURL.Store(isoURL)
	return nil
}

func (m *mockBMC) UnmountISO(_ context.Context, _ uint64) error {
	m.unmountCalls.Add(1)
	if m.unmountErr != nil {
		return m.unmountErr
	}
	m.mounted.Store(false)
	m.mountedURL.Store("")
	return nil
}

// mockProfiles implements ProfileChecker for testing.
type mockProfiles struct {
	configs map[uint64]*bmc.Config
	err     error
}

func (m *mockProfiles) Get(_ context.Context, id uint64) (*bmc.Config, error) {
	if m.err != nil {
		return nil, m.err
	}
	cfg, ok := m.configs[id]
	if !ok {
		return nil, bmc.ErrProfileNotFound{ProfileID: id}
	}
	return cfg, nil
}

// testConfig returns a fast config for testing.
func testConfig() *Config {
	return &Config{
		InstallTimeout: 5 * time.Second,
		PowerOnDelay:   10 * time.Millisecond,
	}
}

// testProfiles returns a mock profile store with a single profile.
func testProfiles() *mockProfiles {
	return &mockProfiles{
		configs: map[uint64]*bmc.Config{
			1: {Address: "10.0.0.1", Port: 623, Protocol: bmc.ProtocolIPMI},
		},
	}
}

// waitForStatus polls the provision status until it matches or the context expires.
func waitForStatus(ctx context.Context, svc *Service, provisionID string, statuses ...ProvisioningStatus) (*ProvisionResult, error) {
	want := make(map[ProvisioningStatus]struct{}, len(statuses))
	for _, s := range statuses {
		want[s] = struct{}{}
	}
	for {
		result, err := svc.Status(provisionID)
		if err != nil {
			return nil, err
		}
		if _, ok := want[result.Status]; ok {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
	}
}

func TestNewService_Success(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
}

func TestNewService_NilBMC(t *testing.T) {
	_, err := NewService(ServiceParams{
		Profiles: testProfiles(),
	})
	if err == nil {
		t.Fatal("expected error for nil BMC")
	}
	var target ErrInvalidProvisionRequest
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidProvisionRequest, got: %T", err)
	}
}

func TestNewService_NilProfiles(t *testing.T) {
	_, err := NewService(ServiceParams{
		BMC: newMockBMC(),
	})
	if err == nil {
		t.Fatal("expected error for nil profiles")
	}
	var target ErrInvalidProvisionRequest
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidProvisionRequest, got: %T", err)
	}
}

func TestNewService_DefaultConfig(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if svc.config.InstallTimeout != 30*time.Minute {
		t.Errorf("expected default install timeout 30m, got %v", svc.config.InstallTimeout)
	}
}

func TestService_Provision_Success(t *testing.T) {
	bmcMock := newMockBMC()
	svc, err := NewService(ServiceParams{
		BMC:      bmcMock,
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{
		ProfileID: 1,
		ISOURL:    "http://example.com/install.iso",
	})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}
	if result.ProvisionID == "" {
		t.Fatal("expected non-empty provision ID")
	}
	if result.ProfileID != 1 {
		t.Errorf("ProfileID = %d, want 1", result.ProfileID)
	}

	// Wait for installing state, then complete.
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing state: %v", err)
	}

	if err := svc.CompleteInstall(result.ProvisionID); err != nil {
		t.Fatalf("CompleteInstall() error = %v", err)
	}

	// Wait for completion.
	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusComplete, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach terminal state: %v", err)
	}
	if final.Status != StatusComplete {
		t.Errorf("Status = %s, want complete, message: %s", final.Status, final.Message)
	}

	// Verify BMC interactions.
	if bmcMock.powerOnCalls.Load() < 1 {
		t.Error("expected at least one PowerOn call")
	}
	if bmcMock.mountCalls.Load() < 1 {
		t.Error("expected at least one MountISO call")
	}
	if bmcMock.unmountCalls.Load() < 1 {
		t.Error("expected at least one UnmountISO call")
	}
	if bmcMock.powerCycleCalls.Load() < 1 {
		t.Error("expected at least one PowerCycle call")
	}
}

func TestService_Provision_InvalidRequest_NilRequest(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	_, err = svc.Provision(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil request")
	}
	var target ErrInvalidProvisionRequest
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidProvisionRequest, got: %T", err)
	}
}

func TestService_Provision_InvalidRequest_ZeroProfile(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	_, err = svc.Provision(context.Background(), &ProvisionRequest{ProfileID: 0})
	if err == nil {
		t.Fatal("expected error for zero profile ID")
	}
	var target ErrInvalidProvisionRequest
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidProvisionRequest, got: %T", err)
	}
}

func TestService_Provision_AlreadyInProgress(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1, ISOURL: "http://example.com/install.iso"})
	if err != nil {
		t.Fatalf("first Provision() error = %v", err)
	}

	// Wait for installing to ensure it is in flight.
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}

	// Second provision for the same profile should fail.
	_, err = svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err == nil {
		t.Fatal("expected error for duplicate provision")
	}
	var target ErrProvisionInProgress
	if !errors.As(err, &target) {
		t.Errorf("expected ErrProvisionInProgress, got: %T", err)
	}

	// Clean up: complete the first provision.
	if completeErr := svc.CompleteInstall(result.ProvisionID); completeErr != nil {
		t.Logf("CompleteInstall cleanup error: %v", completeErr)
	}
}

func TestService_Provision_BMCError(t *testing.T) {
	bmcMock := newMockBMC()
	bmcMock.powerStatusErr = errors.New("connection refused")

	svc, err := NewService(ServiceParams{
		BMC:      bmcMock,
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	// Wait for the failure.
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach failed state: %v", err)
	}
	if final.Status != StatusFailed {
		t.Errorf("Status = %s, want failed", final.Status)
	}
	if final.Message == "" {
		t.Error("expected error message in failed result")
	}
}

func TestService_Provision_ProfileNotFound(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	_, err = svc.Provision(context.Background(), &ProvisionRequest{ProfileID: 999})
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
	var target ErrProfileNoBMC
	if !errors.As(err, &target) {
		t.Errorf("expected ErrProfileNoBMC, got: %T", err)
	}
}

func TestService_Status_NotFound(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	_, err = svc.Status("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for missing provision ID")
	}
	var target ErrProvisionNotFound
	if !errors.As(err, &target) {
		t.Errorf("expected ErrProvisionNotFound, got: %T", err)
	}
}

func TestService_Status_InProgress(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1, ISOURL: "http://example.com/test.iso"})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	current, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}
	if current.Status != StatusInstalling {
		t.Errorf("Status = %s, want installing", current.Status)
	}

	// Clean up.
	if completeErr := svc.CompleteInstall(result.ProvisionID); completeErr != nil {
		t.Logf("CompleteInstall cleanup error: %v", completeErr)
	}
}

func TestService_CompleteInstall_Success(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1, ISOURL: "http://example.com/test.iso"})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}

	if err := svc.CompleteInstall(result.ProvisionID); err != nil {
		t.Fatalf("CompleteInstall() error = %v", err)
	}

	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusComplete, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach terminal: %v", err)
	}
	if final.Status != StatusComplete {
		t.Errorf("Status = %s, want complete, message: %s", final.Status, final.Message)
	}
}

func TestService_CompleteInstall_NotFound(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	err = svc.CompleteInstall("does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing provision ID")
	}
	var target ErrProvisionNotFound
	if !errors.As(err, &target) {
		t.Errorf("expected ErrProvisionNotFound, got: %T", err)
	}
}

func TestService_CompleteInstall_WrongState(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1, ISOURL: "http://example.com/test.iso"})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	// Wait for installing, complete, then try again.
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}

	if err := svc.CompleteInstall(result.ProvisionID); err != nil {
		t.Fatalf("first CompleteInstall() error = %v", err)
	}

	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusComplete, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach terminal: %v", err)
	}

	// Second call should fail because status is no longer installing.
	err = svc.CompleteInstall(result.ProvisionID)
	if err == nil {
		t.Fatal("expected error for wrong state")
	}
	var target ErrProvisionFailed
	if !errors.As(err, &target) {
		t.Errorf("expected ErrProvisionFailed, got: %T", err)
	}
}

func TestService_List(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	// Initially empty.
	results := svc.List()
	if len(results) != 0 {
		t.Errorf("List() returned %d results, want 0", len(results))
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1, ISOURL: "http://example.com/test.iso"})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	results = svc.List()
	if len(results) != 1 {
		t.Fatalf("List() returned %d results, want 1", len(results))
	}
	if results[0].ProvisionID != result.ProvisionID {
		t.Errorf("List()[0].ProvisionID = %s, want %s", results[0].ProvisionID, result.ProvisionID)
	}

	// Clean up.
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)
	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}
	if completeErr := svc.CompleteInstall(result.ProvisionID); completeErr != nil {
		t.Logf("CompleteInstall cleanup error: %v", completeErr)
	}
}

func TestService_List_Empty(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	results := svc.List()
	if len(results) != 0 {
		t.Errorf("List() returned %d results, want empty", len(results))
	}
}

func TestService_Provision_NoISO(t *testing.T) {
	bmcMock := newMockBMC()
	svc, err := NewService(ServiceParams{
		BMC:      bmcMock,
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}

	if err := svc.CompleteInstall(result.ProvisionID); err != nil {
		t.Fatalf("CompleteInstall() error = %v", err)
	}

	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusComplete, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach terminal: %v", err)
	}
	if final.Status != StatusComplete {
		t.Errorf("Status = %s, want complete, message: %s", final.Status, final.Message)
	}

	// Without ISO: mount and unmount should not be called.
	if bmcMock.mountCalls.Load() != 0 {
		t.Errorf("MountISO called %d times, want 0", bmcMock.mountCalls.Load())
	}
	if bmcMock.unmountCalls.Load() != 0 {
		t.Errorf("UnmountISO called %d times, want 0", bmcMock.unmountCalls.Load())
	}

	// PXE is used instead of virtual media, and finalization leaves the
	// machine pointed at its own disk for the next boot.
	if got := bmcMock.bootDevice.Load().(bmc.BootDevice); got != bmc.BootDeviceDisk {
		t.Errorf("final boot device = %v, want %v", got, bmc.BootDeviceDisk)
	}
}

func TestService_Provision_PowerOffError(t *testing.T) {
	bmcMock := newMockBMC()
	bmcMock.power.Store(bmc.PowerStateOn)
	bmcMock.powerOffErr = errors.New("BMC timeout")

	svc, err := NewService(ServiceParams{
		BMC:      bmcMock,
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach failed state: %v", err)
	}
	if final.Status != StatusFailed {
		t.Errorf("Status = %s, want failed", final.Status)
	}
	if final.Message == "" {
		t.Error("expected error message")
	}
}

func TestService_Provision_MountError(t *testing.T) {
	bmcMock := newMockBMC()
	bmcMock.mountErr = errors.New("virtual media not supported")

	svc, err := NewService(ServiceParams{
		BMC:      bmcMock,
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{
		ProfileID: 1,
		ISOURL:    "http://example.com/install.iso",
	})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach failed state: %v", err)
	}
	if final.Status != StatusFailed {
		t.Errorf("Status = %s, want failed", final.Status)
	}
}

func TestService_Provision_InstallTimeout(t *testing.T) {
	// The install timeout runs on synctest time, so the test waits it out
	// without spending it (#284).
	synctest.Test(t, func(t *testing.T) {
		const installTimeout = 200 * time.Millisecond
		svc, err := NewService(ServiceParams{
			BMC:      newMockBMC(),
			Profiles: testProfiles(),
			Config: &Config{
				InstallTimeout: installTimeout,
				PowerOnDelay:   10 * time.Millisecond,
			},
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}

		result, err := svc.Provision(t.Context(), &ProvisionRequest{ProfileID: 1})
		if err != nil {
			t.Fatalf("Provision() error = %v", err)
		}

		// Do NOT call CompleteInstall; let it time out, then let the
		// provisioning goroutine record the failure and exit.
		<-time.After(installTimeout)
		synctest.Wait()

		final, err := svc.Status(result.ProvisionID)
		if err != nil {
			t.Fatalf("Status() error = %v", err)
		}
		if final.Status != StatusFailed {
			t.Errorf("Status = %s, want failed", final.Status)
		}
	})
}

func TestService_Provision_SetBootError(t *testing.T) {
	bmcMock := newMockBMC()
	bmcMock.setBootErr = errors.New("boot device error")

	svc, err := NewService(ServiceParams{
		BMC:      bmcMock,
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusFailed)
	if err != nil {
		t.Fatalf("failed to reach failed state: %v", err)
	}
	if final.Status != StatusFailed {
		t.Errorf("Status = %s, want failed", final.Status)
	}
}

func TestService_Provision_PowerCycleError(t *testing.T) {
	bmcMock := newMockBMC()
	bmcMock.powerCycleErr = errors.New("power cycle failed")

	svc, err := NewService(ServiceParams{
		BMC:      bmcMock,
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()
	result, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	_, err = waitForStatus(waitCtx, svc, result.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}

	if err := svc.CompleteInstall(result.ProvisionID); err != nil {
		t.Fatalf("CompleteInstall() error = %v", err)
	}

	final, err := waitForStatus(waitCtx, svc, result.ProvisionID, StatusFailed, StatusComplete)
	if err != nil {
		t.Fatalf("failed to reach terminal: %v", err)
	}
	if final.Status != StatusFailed {
		t.Errorf("Status = %s, want failed", final.Status)
	}
}

func TestService_Provision_CanReprovisionAfterComplete(t *testing.T) {
	svc, err := NewService(ServiceParams{
		BMC:      newMockBMC(),
		Profiles: testProfiles(),
		Config:   testConfig(),
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	ctx := context.Background()

	// First provision.
	result1, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("first Provision() error = %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel)

	_, err = waitForStatus(waitCtx, svc, result1.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}
	if err := svc.CompleteInstall(result1.ProvisionID); err != nil {
		t.Fatalf("CompleteInstall() error = %v", err)
	}
	_, err = waitForStatus(waitCtx, svc, result1.ProvisionID, StatusComplete)
	if err != nil {
		t.Fatalf("failed to reach complete: %v", err)
	}

	// Second provision for the same profile should succeed since first completed.
	result2, err := svc.Provision(ctx, &ProvisionRequest{ProfileID: 1})
	if err != nil {
		t.Fatalf("second Provision() error = %v", err)
	}
	if result2.ProvisionID == result1.ProvisionID {
		t.Error("expected different provision IDs")
	}

	// Clean up.
	waitCtx2, cancel2 := context.WithTimeout(ctx, 3*time.Second)
	t.Cleanup(cancel2)
	_, err = waitForStatus(waitCtx2, svc, result2.ProvisionID, StatusInstalling)
	if err != nil {
		t.Fatalf("failed to reach installing: %v", err)
	}
	if completeErr := svc.CompleteInstall(result2.ProvisionID); completeErr != nil {
		t.Logf("CompleteInstall cleanup error: %v", completeErr)
	}
}
