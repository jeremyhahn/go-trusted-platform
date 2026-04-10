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
)

func TestNewDiskPreparer(t *testing.T) {
	logger := logging.DefaultLogger()
	dp := NewDiskPreparer("/dev/sda", "/mnt", logger)

	if dp == nil {
		t.Fatal("NewDiskPreparer returned nil")
	}

	if dp.scheme == nil {
		t.Fatal("scheme is nil")
	}

	if dp.logger != logger {
		t.Error("logger not set correctly")
	}
}

func TestNewDiskPreparerScheme(t *testing.T) {
	logger := logging.DefaultLogger()

	tests := []struct {
		name          string
		device        string
		mountPoint    string
		expectedEFI   string
		expectedRoot  string
		expectedEFISz string
		expectedMount string
	}{
		{
			name:          "sda",
			device:        "/dev/sda",
			mountPoint:    "/mnt",
			expectedEFI:   "/dev/sda1",
			expectedRoot:  "/dev/sda2",
			expectedEFISz: "512M",
			expectedMount: "/mnt",
		},
		{
			name:          "nvme",
			device:        "/dev/nvme0n1",
			mountPoint:    "/target",
			expectedEFI:   "/dev/nvme0n11",
			expectedRoot:  "/dev/nvme0n12",
			expectedEFISz: "512M",
			expectedMount: "/target",
		},
		{
			name:          "vda",
			device:        "/dev/vda",
			mountPoint:    "/mnt/root",
			expectedEFI:   "/dev/vda1",
			expectedRoot:  "/dev/vda2",
			expectedEFISz: "512M",
			expectedMount: "/mnt/root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dp := NewDiskPreparer(tt.device, tt.mountPoint, logger)
			scheme := dp.GetScheme()

			if scheme == nil {
				t.Fatal("GetScheme returned nil")
			}

			if scheme.Device != tt.device {
				t.Errorf("expected device %s, got %s", tt.device, scheme.Device)
			}

			if scheme.EFIPartition != tt.expectedEFI {
				t.Errorf("expected EFI partition %s, got %s", tt.expectedEFI, scheme.EFIPartition)
			}

			if scheme.RootPartition != tt.expectedRoot {
				t.Errorf("expected root partition %s, got %s", tt.expectedRoot, scheme.RootPartition)
			}

			if scheme.EFISize != tt.expectedEFISz {
				t.Errorf("expected EFI size %s, got %s", tt.expectedEFISz, scheme.EFISize)
			}

			if scheme.MountPoint != tt.expectedMount {
				t.Errorf("expected mount point %s, got %s", tt.expectedMount, scheme.MountPoint)
			}
		})
	}
}

func TestGetScheme(t *testing.T) {
	logger := logging.DefaultLogger()
	dp := NewDiskPreparer("/dev/sda", "/mnt", logger)

	scheme := dp.GetScheme()
	if scheme == nil {
		t.Fatal("GetScheme returned nil")
	}

	// Verify it returns the same pointer
	scheme2 := dp.GetScheme()
	if scheme != scheme2 {
		t.Error("GetScheme should return the same scheme instance")
	}
}
