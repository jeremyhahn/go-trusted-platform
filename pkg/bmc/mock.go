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
	"sync/atomic"
)

// MockClient implements Client for testing.
type MockClient struct {
	// State
	Power          PowerState
	Boot           BootDevice
	BootPersistent bool
	Media          *VirtualMediaInfo
	SensorData     []SensorReading
	System         *SystemInfo

	// Error injection
	PowerOnErr          error
	PowerOffErr         error
	PowerResetErr       error
	PowerCycleErr       error
	PowerStatusErr      error
	SetBootDeviceErr    error
	GetBootDeviceErr    error
	MountISOErr         error
	UnmountISOErr       error
	VirtualMediaStatErr error
	GetSensorsErr       error
	GetSystemInfoErr        error
	CloseErr                error
	ConsoleErr              error
	ClearUEFIBootEntriesErr error

	// Call counters (atomic for lock-free access)
	powerOnCalls          atomic.Int64
	powerOffCalls         atomic.Int64
	powerResetCalls       atomic.Int64
	powerCycleCalls       atomic.Int64
	powerStatusCalls      atomic.Int64
	setBootDeviceCalls    atomic.Int64
	getBootDeviceCalls    atomic.Int64
	mountISOCalls         atomic.Int64
	unmountISOCalls       atomic.Int64
	virtualMediaStatCalls atomic.Int64
	getSensorsCalls       atomic.Int64
	getSystemInfoCalls    atomic.Int64
	closeCalls                atomic.Int64
	consoleCalls              atomic.Int64
	clearUEFIBootEntriesCalls atomic.Int64
}

// Compile-time interface check.
var _ Client = (*MockClient)(nil)

// NewMockClient returns a MockClient with sensible defaults.
func NewMockClient() *MockClient {
	return &MockClient{
		Power: PowerStateOff,
		Boot:  BootDeviceDisk,
		Media: &VirtualMediaInfo{},
	}
}

// PowerOn records the call and returns the configured error.
func (m *MockClient) PowerOn(_ context.Context) error {
	m.powerOnCalls.Add(1)
	if m.PowerOnErr != nil {
		return m.PowerOnErr
	}
	m.Power = PowerStateOn
	return nil
}

// PowerOff records the call and returns the configured error.
func (m *MockClient) PowerOff(_ context.Context) error {
	m.powerOffCalls.Add(1)
	if m.PowerOffErr != nil {
		return m.PowerOffErr
	}
	m.Power = PowerStateOff
	return nil
}

// PowerReset records the call and returns the configured error.
func (m *MockClient) PowerReset(_ context.Context) error {
	m.powerResetCalls.Add(1)
	if m.PowerResetErr != nil {
		return m.PowerResetErr
	}
	m.Power = PowerStateOn
	return nil
}

// PowerCycle records the call and returns the configured error.
func (m *MockClient) PowerCycle(_ context.Context) error {
	m.powerCycleCalls.Add(1)
	if m.PowerCycleErr != nil {
		return m.PowerCycleErr
	}
	m.Power = PowerStateOn
	return nil
}

// PowerStatus records the call and returns the configured power state.
func (m *MockClient) PowerStatus(_ context.Context) (PowerState, error) {
	m.powerStatusCalls.Add(1)
	if m.PowerStatusErr != nil {
		return PowerStateUnknown, m.PowerStatusErr
	}
	return m.Power, nil
}

// SetBootDevice records the call and the device/persistent settings.
func (m *MockClient) SetBootDevice(_ context.Context, device BootDevice, persistent bool) error {
	m.setBootDeviceCalls.Add(1)
	if m.SetBootDeviceErr != nil {
		return m.SetBootDeviceErr
	}
	m.Boot = device
	m.BootPersistent = persistent
	return nil
}

// GetBootDevice records the call and returns the configured boot device.
func (m *MockClient) GetBootDevice(_ context.Context) (BootDevice, error) {
	m.getBootDeviceCalls.Add(1)
	if m.GetBootDeviceErr != nil {
		return BootDeviceNone, m.GetBootDeviceErr
	}
	return m.Boot, nil
}

// MountISO records the call and simulates mounting.
func (m *MockClient) MountISO(_ context.Context, isoURL string) error {
	m.mountISOCalls.Add(1)
	if m.MountISOErr != nil {
		return m.MountISOErr
	}
	m.Media = &VirtualMediaInfo{
		Mounted:   true,
		ImageURL:  isoURL,
		MediaType: "iso",
	}
	return nil
}

// UnmountISO records the call and simulates unmounting.
func (m *MockClient) UnmountISO(_ context.Context) error {
	m.unmountISOCalls.Add(1)
	if m.UnmountISOErr != nil {
		return m.UnmountISOErr
	}
	m.Media = &VirtualMediaInfo{Mounted: false}
	return nil
}

// MountVirtualMedia delegates to MountISO using spec.URL after validating spec.
func (m *MockClient) MountVirtualMedia(ctx context.Context, spec *MediaSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	return m.MountISO(ctx, spec.URL)
}

// UnmountVirtualMedia delegates to UnmountISO.
func (m *MockClient) UnmountVirtualMedia(ctx context.Context) error {
	return m.UnmountISO(ctx)
}

// VirtualMediaStatus records the call and returns the configured media state.
func (m *MockClient) VirtualMediaStatus(_ context.Context) (*VirtualMediaInfo, error) {
	m.virtualMediaStatCalls.Add(1)
	if m.VirtualMediaStatErr != nil {
		return nil, m.VirtualMediaStatErr
	}
	return m.Media, nil
}

// GetSensors records the call and returns the configured sensor data.
func (m *MockClient) GetSensors(_ context.Context) ([]SensorReading, error) {
	m.getSensorsCalls.Add(1)
	if m.GetSensorsErr != nil {
		return nil, m.GetSensorsErr
	}
	return m.SensorData, nil
}

// GetSystemInfo records the call and returns the configured system info.
func (m *MockClient) GetSystemInfo(_ context.Context) (*SystemInfo, error) {
	m.getSystemInfoCalls.Add(1)
	if m.GetSystemInfoErr != nil {
		return nil, m.GetSystemInfoErr
	}
	return m.System, nil
}

// Close records the call and returns the configured error.

// Console records the call and returns the configured error.
// MockClient returns ErrUnsupportedOperation since there is no real RMCP session.
func (m *MockClient) Console(_ context.Context) (*SOLSession, error) {
	m.consoleCalls.Add(1)
	if m.ConsoleErr != nil {
		return nil, m.ConsoleErr
	}
	return nil, ErrUnsupportedOperation{Operation: "console"}
}

// ConsoleCalls returns the number of times Console was called.
func (m *MockClient) ConsoleCalls() int64 {
	return m.consoleCalls.Load()
}

// ClearUEFIBootEntries records the call and returns the configured
// error. The mock has no notion of UEFI NVRAM state to mutate; tests
// either set ClearUEFIBootEntriesErr to assert the error path or leave
// it nil to assert the no-op success path.
func (m *MockClient) ClearUEFIBootEntries(_ context.Context) error {
	m.clearUEFIBootEntriesCalls.Add(1)
	return m.ClearUEFIBootEntriesErr
}

// ClearUEFIBootEntriesCalls returns the number of times the method was
// called.
func (m *MockClient) ClearUEFIBootEntriesCalls() int64 {
	return m.clearUEFIBootEntriesCalls.Load()
}
func (m *MockClient) Close() error {
	m.closeCalls.Add(1)
	return m.CloseErr
}

// PowerOnCalls returns the number of times PowerOn was called.
func (m *MockClient) PowerOnCalls() int64 {
	return m.powerOnCalls.Load()
}

// PowerOffCalls returns the number of times PowerOff was called.
func (m *MockClient) PowerOffCalls() int64 {
	return m.powerOffCalls.Load()
}

// PowerResetCalls returns the number of times PowerReset was called.
func (m *MockClient) PowerResetCalls() int64 {
	return m.powerResetCalls.Load()
}

// PowerCycleCalls returns the number of times PowerCycle was called.
func (m *MockClient) PowerCycleCalls() int64 {
	return m.powerCycleCalls.Load()
}

// PowerStatusCalls returns the number of times PowerStatus was called.
func (m *MockClient) PowerStatusCalls() int64 {
	return m.powerStatusCalls.Load()
}

// SetBootDeviceCalls returns the number of times SetBootDevice was called.
func (m *MockClient) SetBootDeviceCalls() int64 {
	return m.setBootDeviceCalls.Load()
}

// GetBootDeviceCalls returns the number of times GetBootDevice was called.
func (m *MockClient) GetBootDeviceCalls() int64 {
	return m.getBootDeviceCalls.Load()
}

// MountISOCalls returns the number of times MountISO was called.
func (m *MockClient) MountISOCalls() int64 {
	return m.mountISOCalls.Load()
}

// UnmountISOCalls returns the number of times UnmountISO was called.
func (m *MockClient) UnmountISOCalls() int64 {
	return m.unmountISOCalls.Load()
}

// VirtualMediaStatusCalls returns the number of times VirtualMediaStatus was called.
func (m *MockClient) VirtualMediaStatusCalls() int64 {
	return m.virtualMediaStatCalls.Load()
}

// GetSensorsCalls returns the number of times GetSensors was called.
func (m *MockClient) GetSensorsCalls() int64 {
	return m.getSensorsCalls.Load()
}

// GetSystemInfoCalls returns the number of times GetSystemInfo was called.
func (m *MockClient) GetSystemInfoCalls() int64 {
	return m.getSystemInfoCalls.Load()
}

// CloseCalls returns the number of times Close was called.
func (m *MockClient) CloseCalls() int64 {
	return m.closeCalls.Load()
}

// MockClientFactory implements ClientFactory using MockClient for testing.
type MockClientFactory struct {
	Client   *MockClient
	ClientFn func(config *Config) (Client, error)
	Err      error
}

// Compile-time interface check.
var _ ClientFactory = (*MockClientFactory)(nil)

// NewClient returns the configured mock client or error.
func (f *MockClientFactory) NewClient(config *Config) (Client, error) {
	if f.ClientFn != nil {
		return f.ClientFn(config)
	}
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Client, nil
}
