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
	"log/slog"
	"testing"
)

// mockProfileStore implements ProfileStore for testing.
type mockProfileStore struct {
	configs map[uint64]*Config
	err     error
}

func (m *mockProfileStore) Get(_ context.Context, id uint64) (*Config, error) {
	if m.err != nil {
		return nil, m.err
	}
	cfg, ok := m.configs[id]
	if !ok {
		return nil, ErrProfileNotFound{ProfileID: id}
	}
	return cfg, nil
}

func newTestService(t *testing.T, mock *MockClient, profiles map[uint64]*Config) *Service {
	t.Helper()
	factory := &MockClientFactory{Client: mock}
	store := &mockProfileStore{configs: profiles}
	svc, err := NewService(ServiceParams{
		Factory:  factory,
		Profiles: store,
		Logger:   slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	return svc
}

func TestNewService_ValidParams(t *testing.T) {
	factory := &MockClientFactory{Client: NewMockClient()}
	store := &mockProfileStore{configs: map[uint64]*Config{}}
	svc, err := NewService(ServiceParams{
		Factory:  factory,
		Profiles: store,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNewService_MissingFactory(t *testing.T) {
	store := &mockProfileStore{configs: map[uint64]*Config{}}
	_, err := NewService(ServiceParams{
		Profiles: store,
	})
	if err == nil {
		t.Fatal("expected error for missing factory")
	}
	var target ErrInvalidConfig
	if !errors.As(err, &target) {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}
}

func TestNewService_OptionalProfileStore(t *testing.T) {
	factory := &MockClientFactory{Client: NewMockClient()}
	svc, err := NewService(ServiceParams{
		Factory: factory,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Service should be created — profiles are optional.
	// Methods that need profiles will fail at call time, not at creation time.
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestService_PowerOn(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	if err := svc.PowerOn(ctx, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.PowerOnCalls() != 1 {
		t.Errorf("PowerOnCalls() = %d, want 1", mock.PowerOnCalls())
	}
	if mock.Power != PowerStateOn {
		t.Errorf("Power = %q, want %q", mock.Power, PowerStateOn)
	}
}

func TestService_PowerOn_ProfileNotFound(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	profiles := map[uint64]*Config{} // empty
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	err := svc.PowerOn(ctx, 999)
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
	var target ErrProfileNotFound
	if !errors.As(err, &target) {
		t.Errorf("expected ErrProfileNotFound, got %T: %v", err, err)
	}
}

func TestService_PowerStatus(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Power = PowerStateOn
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	state, err := svc.PowerStatus(ctx, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != PowerStateOn {
		t.Errorf("PowerStatus() = %q, want %q", state, PowerStateOn)
	}
}

func TestService_PowerOff(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Power = PowerStateOn
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	if err := svc.PowerOff(ctx, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.Power != PowerStateOff {
		t.Errorf("Power = %q, want %q", mock.Power, PowerStateOff)
	}
}

func TestService_PowerReset(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	if err := svc.PowerReset(ctx, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.PowerResetCalls() != 1 {
		t.Errorf("PowerResetCalls() = %d, want 1", mock.PowerResetCalls())
	}
}

func TestService_PowerCycle(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	if err := svc.PowerCycle(ctx, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.PowerCycleCalls() != 1 {
		t.Errorf("PowerCycleCalls() = %d, want 1", mock.PowerCycleCalls())
	}
}

func TestService_SetBootDevice(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	if err := svc.SetBootDevice(ctx, 1, BootDevicePXE, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.Boot != BootDevicePXE {
		t.Errorf("Boot = %q, want %q", mock.Boot, BootDevicePXE)
	}
	if !mock.BootPersistent {
		t.Error("BootPersistent = false, want true")
	}
}

func TestService_SetBootDevice_Error(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.SetBootDeviceErr = errors.New("device not supported")
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	err := svc.SetBootDevice(ctx, 1, BootDevicePXE, false)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestService_GetBootDevice(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Boot = BootDeviceCDROM
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	device, err := svc.GetBootDevice(ctx, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if device != BootDeviceCDROM {
		t.Errorf("GetBootDevice() = %q, want %q", device, BootDeviceCDROM)
	}
}

func TestService_MountISO(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	isoURL := "http://example.com/install.iso"
	if err := svc.MountISO(ctx, 1, isoURL); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.Media.Mounted {
		t.Error("Media.Mounted = false, want true")
	}
	if mock.Media.ImageURL != isoURL {
		t.Errorf("Media.ImageURL = %q, want %q", mock.Media.ImageURL, isoURL)
	}
}

func TestService_MountISO_Error(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.MountISOErr = errors.New("mount failed")
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	err := svc.MountISO(ctx, 1, "http://example.com/test.iso")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestService_UnmountISO(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Media = &VirtualMediaInfo{Mounted: true}
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	if err := svc.UnmountISO(ctx, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.Media.Mounted {
		t.Error("Media.Mounted = true, want false after unmount")
	}
}

func TestService_VirtualMediaStatus(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Media = &VirtualMediaInfo{Mounted: true, ImageURL: "http://example.com/test.iso", MediaType: "iso"}
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	info, err := svc.VirtualMediaStatus(ctx, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.Mounted {
		t.Error("expected mounted virtual media")
	}
}

func TestService_GetSensors(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.SensorData = []SensorReading{
		{Name: "Fan1", Value: 3000, Units: "rpm", Status: "ok"},
	}
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	sensors, err := svc.GetSensors(ctx, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sensors) != 1 {
		t.Fatalf("expected 1 sensor, got %d", len(sensors))
	}
	if sensors[0].Name != "Fan1" {
		t.Errorf("sensor name = %q, want %q", sensors[0].Name, "Fan1")
	}
}

func TestService_GetSystemInfo(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.System = &SystemInfo{
		Manufacturer: "Supermicro",
		Product:      "X12SPL-F",
	}
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)
	t.Cleanup(func() { svc.Close() })

	info, err := svc.GetSystemInfo(ctx, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Manufacturer != "Supermicro" {
		t.Errorf("Manufacturer = %q, want %q", info.Manufacturer, "Supermicro")
	}
}

func TestService_ClientCaching(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	callCount := 0
	factory := &MockClientFactory{
		ClientFn: func(config *Config) (Client, error) {
			callCount++
			return mock, nil
		},
	}
	store := &mockProfileStore{configs: map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}}
	svc, err := NewService(ServiceParams{
		Factory:  factory,
		Profiles: store,
		Logger:   slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	t.Cleanup(func() { svc.Close() })

	// Call twice with the same profile ID.
	if err := svc.PowerOn(ctx, 1); err != nil {
		t.Fatalf("first PowerOn() error: %v", err)
	}
	if err := svc.PowerOff(ctx, 1); err != nil {
		t.Fatalf("second PowerOff() error: %v", err)
	}

	// Factory should have been called only once.
	if callCount != 1 {
		t.Errorf("factory called %d times, want 1 (caching should reuse client)", callCount)
	}
}

func TestService_Close(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
		2: {Address: "10.0.0.2", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)

	// Access both profiles to cache them.
	if err := svc.PowerOn(ctx, 1); err != nil {
		t.Fatalf("PowerOn(1) error: %v", err)
	}
	if err := svc.PowerOn(ctx, 2); err != nil {
		t.Fatalf("PowerOn(2) error: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	// Both profile IDs used the same mock, so Close was called at least twice.
	if mock.CloseCalls() < 2 {
		t.Errorf("CloseCalls() = %d, want >= 2", mock.CloseCalls())
	}
}

func TestService_Close_WithError(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.CloseErr = errors.New("close failed")
	profiles := map[uint64]*Config{
		1: {Address: "10.0.0.1", Port: 623, Protocol: ProtocolIPMI},
	}
	svc := newTestService(t, mock, profiles)

	// Access profile to cache it.
	if err := svc.PowerOn(ctx, 1); err != nil {
		t.Fatalf("PowerOn() error: %v", err)
	}

	err := svc.Close()
	if err == nil {
		t.Fatal("expected error from Close()")
	}
}
