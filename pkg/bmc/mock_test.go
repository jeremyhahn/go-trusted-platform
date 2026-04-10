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
)

func TestMockClient_PowerOn(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()

	if err := mock.PowerOn(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.Power != PowerStateOn {
		t.Errorf("Power = %q, want %q", mock.Power, PowerStateOn)
	}
	if mock.PowerOnCalls() != 1 {
		t.Errorf("PowerOnCalls() = %d, want 1", mock.PowerOnCalls())
	}
}

func TestMockClient_PowerOff(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Power = PowerStateOn

	if err := mock.PowerOff(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.Power != PowerStateOff {
		t.Errorf("Power = %q, want %q", mock.Power, PowerStateOff)
	}
	if mock.PowerOffCalls() != 1 {
		t.Errorf("PowerOffCalls() = %d, want 1", mock.PowerOffCalls())
	}
}

func TestMockClient_ErrorInjection(t *testing.T) {
	ctx := context.Background()
	injectedErr := errors.New("injected power error")

	t.Run("PowerOn error", func(t *testing.T) {
		mock := NewMockClient()
		mock.PowerOnErr = injectedErr
		err := mock.PowerOn(ctx)
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
		if mock.PowerOnCalls() != 1 {
			t.Errorf("PowerOnCalls() = %d, want 1", mock.PowerOnCalls())
		}
	})

	t.Run("PowerStatus error", func(t *testing.T) {
		mock := NewMockClient()
		mock.PowerStatusErr = injectedErr
		state, err := mock.PowerStatus(ctx)
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
		if state != PowerStateUnknown {
			t.Errorf("state = %q, want %q", state, PowerStateUnknown)
		}
	})

	t.Run("SetBootDevice error", func(t *testing.T) {
		mock := NewMockClient()
		mock.SetBootDeviceErr = injectedErr
		err := mock.SetBootDevice(ctx, BootDevicePXE, true)
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
	})

	t.Run("MountISO error", func(t *testing.T) {
		mock := NewMockClient()
		mock.MountISOErr = injectedErr
		err := mock.MountISO(ctx, "http://example.com/boot.iso")
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
	})

	t.Run("GetSensors error", func(t *testing.T) {
		mock := NewMockClient()
		mock.GetSensorsErr = injectedErr
		sensors, err := mock.GetSensors(ctx)
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
		if sensors != nil {
			t.Errorf("expected nil sensors on error")
		}
	})

	t.Run("GetSystemInfo error", func(t *testing.T) {
		mock := NewMockClient()
		mock.GetSystemInfoErr = injectedErr
		info, err := mock.GetSystemInfo(ctx)
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
		if info != nil {
			t.Errorf("expected nil system info on error")
		}
	})

	t.Run("Close error", func(t *testing.T) {
		mock := NewMockClient()
		mock.CloseErr = injectedErr
		err := mock.Close()
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
		if mock.CloseCalls() != 1 {
			t.Errorf("CloseCalls() = %d, want 1", mock.CloseCalls())
		}
	})
}

func TestMockClient_SetBootDevice(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()

	if err := mock.SetBootDevice(ctx, BootDevicePXE, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.Boot != BootDevicePXE {
		t.Errorf("Boot = %q, want %q", mock.Boot, BootDevicePXE)
	}
	if !mock.BootPersistent {
		t.Error("BootPersistent = false, want true")
	}
	if mock.SetBootDeviceCalls() != 1 {
		t.Errorf("SetBootDeviceCalls() = %d, want 1", mock.SetBootDeviceCalls())
	}
}

func TestMockClient_MountISO(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	isoURL := "http://example.com/install.iso"

	if err := mock.MountISO(ctx, isoURL); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.Media.Mounted {
		t.Error("Media.Mounted = false, want true")
	}
	if mock.Media.ImageURL != isoURL {
		t.Errorf("Media.ImageURL = %q, want %q", mock.Media.ImageURL, isoURL)
	}
	if mock.MountISOCalls() != 1 {
		t.Errorf("MountISOCalls() = %d, want 1", mock.MountISOCalls())
	}
}

func TestMockClient_UnmountISO(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Media = &VirtualMediaInfo{Mounted: true, ImageURL: "http://example.com/test.iso"}

	if err := mock.UnmountISO(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mock.Media.Mounted {
		t.Error("Media.Mounted = true, want false")
	}
	if mock.UnmountISOCalls() != 1 {
		t.Errorf("UnmountISOCalls() = %d, want 1", mock.UnmountISOCalls())
	}
}

func TestMockClient_GetSensors(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	expected := []SensorReading{
		{Name: "CPU Temp", Value: 45.0, Units: "celsius", Status: "ok"},
	}
	mock.SensorData = expected

	sensors, err := mock.GetSensors(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sensors) != 1 || sensors[0].Name != "CPU Temp" {
		t.Errorf("unexpected sensors: %v", sensors)
	}
}

func TestMockClient_GetSystemInfo(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	expected := &SystemInfo{
		Manufacturer: "Dell",
		Product:      "PowerEdge R750",
		SerialNumber: "SN12345",
	}
	mock.System = expected

	info, err := mock.GetSystemInfo(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Manufacturer != "Dell" {
		t.Errorf("Manufacturer = %q, want %q", info.Manufacturer, "Dell")
	}
}

func TestMockClientFactory_NewClient(t *testing.T) {
	t.Run("returns configured client", func(t *testing.T) {
		mock := NewMockClient()
		factory := &MockClientFactory{Client: mock}
		client, err := factory.NewClient(&Config{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if client != mock {
			t.Error("factory did not return the configured mock client")
		}
	})

	t.Run("returns configured error", func(t *testing.T) {
		injectedErr := errors.New("factory error")
		factory := &MockClientFactory{Err: injectedErr}
		client, err := factory.NewClient(&Config{})
		if !errors.Is(err, injectedErr) {
			t.Errorf("expected injected error, got: %v", err)
		}
		if client != nil {
			t.Error("expected nil client on error")
		}
	})

	t.Run("uses ClientFn when set", func(t *testing.T) {
		called := false
		factory := &MockClientFactory{
			ClientFn: func(config *Config) (Client, error) {
				called = true
				return NewMockClient(), nil
			},
		}
		client, err := factory.NewClient(&Config{Address: "test"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !called {
			t.Error("ClientFn was not called")
		}
		if client == nil {
			t.Error("expected non-nil client")
		}
	})
}
