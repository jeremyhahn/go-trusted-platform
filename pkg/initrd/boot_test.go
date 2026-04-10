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

package initrd

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestBuildVolumeConfig_Basic(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	tests := []struct {
		name         string
		rootDevice   string
		expectError  bool
		expectedPath string
	}{
		{
			name:         "valid root device",
			rootDevice:   "/dev/sda2",
			expectError:  false,
			expectedPath: "/dev/sda2",
		},
		{
			name:        "empty root device",
			rootDevice:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impl.platform.Config.RootDevice = tt.rootDevice

			volume, err := impl.buildVolumeConfig()

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if volume == nil {
				t.Fatal("buildVolumeConfig returned nil volume")
			}

			if volume.DevicePath != tt.expectedPath {
				t.Errorf("expected device path %s, got %s", tt.expectedPath, volume.DevicePath)
			}

			if volume.MappingName != "cryptroot" {
				t.Errorf("expected mapping name cryptroot, got %s", volume.MappingName)
			}

			if volume.LUKSVersion != luks.LUKS2 {
				t.Errorf("expected LUKS version LUKS2, got %v", volume.LUKSVersion)
			}
		})
	}
}

func TestBuildVolumeConfigPCRBanks(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.PCRBanks = []string{"sha256", "sha384"}

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	volume, err := impl.buildVolumeConfig()
	if err != nil {
		t.Fatalf("buildVolumeConfig failed: %v", err)
	}

	if len(volume.PCRBanks) != 2 {
		t.Errorf("expected 2 PCR banks, got %d", len(volume.PCRBanks))
	}

	if volume.PCRBanks[0] != "sha256" || volume.PCRBanks[1] != "sha384" {
		t.Errorf("expected PCR banks [sha256 sha384], got %v", volume.PCRBanks)
	}
}

func TestBuildVolumeConfigPCRSelection(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.PCRSelection = []uint{0, 1, 2, 3, 7}

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	volume, err := impl.buildVolumeConfig()
	if err != nil {
		t.Fatalf("buildVolumeConfig failed: %v", err)
	}

	if len(volume.PCRSelection) != 5 {
		t.Errorf("expected 5 PCR selections, got %d", len(volume.PCRSelection))
	}

	expected := []uint{0, 1, 2, 3, 7}
	for i, pcr := range expected {
		if volume.PCRSelection[i] != pcr {
			t.Errorf("expected PCR[%d] = %d, got %d", i, pcr, volume.PCRSelection[i])
		}
	}
}

func TestBuildVolumeConfigXKMS(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.XKMSPath = "/var/lib/test/xkms"

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	volume, err := impl.buildVolumeConfig()
	if err != nil {
		t.Fatalf("buildVolumeConfig failed: %v", err)
	}

	if volume.XKMSPath != "/var/lib/test/xkms" {
		t.Errorf("expected xkms path /var/lib/test/xkms, got %s", volume.XKMSPath)
	}
}
