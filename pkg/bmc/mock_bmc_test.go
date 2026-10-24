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
	"reflect"
	"testing"
)

func TestMockClient_MountVirtualMedia(t *testing.T) {
	ctx := context.Background()

	t.Run("valid spec mounts the URL", func(t *testing.T) {
		mock := NewMockClient()
		spec := &MediaSpec{URL: "https://images.example/boot.iso"}
		if err := mock.MountVirtualMedia(ctx, spec); err != nil {
			t.Fatalf("MountVirtualMedia: %v", err)
		}
		want := &VirtualMediaInfo{Mounted: true, ImageURL: spec.URL, MediaType: "iso"}
		if !reflect.DeepEqual(mock.Media, want) {
			t.Errorf("Media = %+v, want %+v", mock.Media, want)
		}
		if spec.Protocol != MediaProtocolHTTPS {
			t.Errorf("Protocol = %q, want the inferred %q", spec.Protocol, MediaProtocolHTTPS)
		}
		if mock.MountISOCalls() != 1 {
			t.Errorf("MountISOCalls() = %d, want 1", mock.MountISOCalls())
		}
	})

	t.Run("invalid spec never reaches the BMC", func(t *testing.T) {
		mock := NewMockClient()
		before := mock.Media
		err := mock.MountVirtualMedia(ctx, &MediaSpec{URL: "ftp://images.example/boot.iso"})
		var invalid ErrVirtualMediaInvalidSpec
		if !errors.As(err, &invalid) || invalid.Field != "URL" {
			t.Fatalf("err = %v, want ErrVirtualMediaInvalidSpec on URL", err)
		}
		if mock.MountISOCalls() != 0 || mock.Media != before {
			t.Errorf("MountISOCalls() = %d, Media = %+v, want no mount", mock.MountISOCalls(), mock.Media)
		}
	})
}

func TestMockClient_UnmountVirtualMedia(t *testing.T) {
	ctx := context.Background()
	injected := ErrConnectionFailed{Address: "10.0.0.5"}

	mock := NewMockClient()
	mock.Media = &VirtualMediaInfo{Mounted: true, ImageURL: "https://images.example/boot.iso"}
	if err := mock.UnmountVirtualMedia(ctx); err != nil {
		t.Fatalf("UnmountVirtualMedia: %v", err)
	}
	if mock.Media == nil || mock.Media.Mounted {
		t.Errorf("Media = %+v, want unmounted", mock.Media)
	}

	mock.UnmountISOErr = injected
	if err := mock.UnmountVirtualMedia(ctx); !errors.Is(err, injected) {
		t.Errorf("err = %v, want %v", err, injected)
	}
	if mock.UnmountISOCalls() != 2 {
		t.Errorf("UnmountISOCalls() = %d, want 2", mock.UnmountISOCalls())
	}
}

func TestMockClient_Console(t *testing.T) {
	ctx := context.Background()

	mock := NewMockClient()
	sess, err := mock.Console(ctx)
	var unsupported ErrUnsupportedOperation
	if !errors.As(err, &unsupported) || unsupported.Operation != "console" || sess != nil {
		t.Errorf("Console() = %v, %v, want nil and ErrUnsupportedOperation{console}", sess, err)
	}

	injected := ErrConnectionFailed{Address: "10.0.0.5"}
	mock.ConsoleErr = injected
	if _, err := mock.Console(ctx); !errors.Is(err, injected) {
		t.Errorf("err = %v, want %v", err, injected)
	}
	if mock.ConsoleCalls() != 2 {
		t.Errorf("ConsoleCalls() = %d, want 2", mock.ConsoleCalls())
	}
}

func TestMockClient_ClearUEFIBootEntries(t *testing.T) {
	ctx := context.Background()

	mock := NewMockClient()
	if err := mock.ClearUEFIBootEntries(ctx); err != nil {
		t.Fatalf("ClearUEFIBootEntries: %v", err)
	}

	injected := ErrUEFIBootClearUnsupported{Manufacturer: "Supermicro"}
	mock.ClearUEFIBootEntriesErr = injected
	if err := mock.ClearUEFIBootEntries(ctx); !errors.Is(err, injected) {
		t.Errorf("err = %v, want %v", err, injected)
	}
	if mock.ClearUEFIBootEntriesCalls() != 2 {
		t.Errorf("ClearUEFIBootEntriesCalls() = %d, want 2", mock.ClearUEFIBootEntriesCalls())
	}
}

// TestMockClient_InjectedErrors checks that every injectable method returns
// its injected error, leaves state untouched, and still counts the call.
func TestMockClient_InjectedErrors(t *testing.T) {
	ctx := context.Background()
	injected := ErrConnectionFailed{Address: "10.0.0.5"}

	tests := []struct {
		name   string
		inject func(*MockClient)
		call   func(*MockClient) error
		calls  func(*MockClient) int64
	}{
		{
			name:   "PowerOff",
			inject: func(m *MockClient) { m.PowerOffErr = injected },
			call:   func(m *MockClient) error { return m.PowerOff(ctx) },
			calls:  (*MockClient).PowerOffCalls,
		},
		{
			name:   "PowerReset",
			inject: func(m *MockClient) { m.PowerResetErr = injected },
			call:   func(m *MockClient) error { return m.PowerReset(ctx) },
			calls:  (*MockClient).PowerResetCalls,
		},
		{
			name:   "PowerCycle",
			inject: func(m *MockClient) { m.PowerCycleErr = injected },
			call:   func(m *MockClient) error { return m.PowerCycle(ctx) },
			calls:  (*MockClient).PowerCycleCalls,
		},
		{
			name:   "PowerStatus",
			inject: func(m *MockClient) { m.PowerStatusErr = injected },
			call: func(m *MockClient) error {
				_, err := m.PowerStatus(ctx)
				return err
			},
			calls: (*MockClient).PowerStatusCalls,
		},
		{
			name:   "GetBootDevice",
			inject: func(m *MockClient) { m.GetBootDeviceErr = injected },
			call: func(m *MockClient) error {
				dev, err := m.GetBootDevice(ctx)
				if dev != BootDeviceNone {
					t.Errorf("GetBootDevice() device = %q on error, want %q", dev, BootDeviceNone)
				}
				return err
			},
			calls: (*MockClient).GetBootDeviceCalls,
		},
		{
			name:   "UnmountISO",
			inject: func(m *MockClient) { m.UnmountISOErr = injected },
			call:   func(m *MockClient) error { return m.UnmountISO(ctx) },
			calls:  (*MockClient).UnmountISOCalls,
		},
		{
			name:   "VirtualMediaStatus",
			inject: func(m *MockClient) { m.VirtualMediaStatErr = injected },
			call: func(m *MockClient) error {
				info, err := m.VirtualMediaStatus(ctx)
				if info != nil {
					t.Errorf("VirtualMediaStatus() info = %+v on error, want nil", info)
				}
				return err
			},
			calls: (*MockClient).VirtualMediaStatusCalls,
		},
		{
			name:   "GetSensors",
			inject: func(m *MockClient) { m.GetSensorsErr = injected },
			call: func(m *MockClient) error {
				_, err := m.GetSensors(ctx)
				return err
			},
			calls: (*MockClient).GetSensorsCalls,
		},
		{
			name:   "GetSystemInfo",
			inject: func(m *MockClient) { m.GetSystemInfoErr = injected },
			call: func(m *MockClient) error {
				_, err := m.GetSystemInfo(ctx)
				return err
			},
			calls: (*MockClient).GetSystemInfoCalls,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMockClient()
			mock.Power = PowerStateOn
			media := &VirtualMediaInfo{Mounted: true, ImageURL: "https://images.example/boot.iso"}
			mock.Media = media
			tc.inject(mock)

			if err := tc.call(mock); !errors.Is(err, injected) {
				t.Errorf("err = %v, want %v", err, injected)
			}
			if got := tc.calls(mock); got != 1 {
				t.Errorf("call count = %d, want 1", got)
			}
			if mock.Power != PowerStateOn || mock.Media != media {
				t.Errorf("state changed on error: Power = %q, Media = %+v", mock.Power, mock.Media)
			}
		})
	}
}

func TestMockClient_ReadsReportStateAndCount(t *testing.T) {
	ctx := context.Background()
	mock := NewMockClient()
	mock.Boot = BootDevicePXE
	mock.Media = &VirtualMediaInfo{Mounted: true, ImageURL: "nfs://store/boot.iso"}

	dev, err := mock.GetBootDevice(ctx)
	if err != nil || dev != BootDevicePXE {
		t.Errorf("GetBootDevice() = %q, %v, want %q", dev, err, BootDevicePXE)
	}
	info, err := mock.VirtualMediaStatus(ctx)
	if err != nil || info != mock.Media {
		t.Errorf("VirtualMediaStatus() = %+v, %v, want %+v", info, err, mock.Media)
	}
	if mock.GetBootDeviceCalls() != 1 || mock.VirtualMediaStatusCalls() != 1 {
		t.Errorf("GetBootDeviceCalls() = %d, VirtualMediaStatusCalls() = %d, want 1 each",
			mock.GetBootDeviceCalls(), mock.VirtualMediaStatusCalls())
	}
}
