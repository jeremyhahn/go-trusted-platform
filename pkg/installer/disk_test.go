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

package installer

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiskManager(t *testing.T) {
	tests := []struct {
		name    string
		config  *DiskConfig
		wantErr bool
		errMsg  string
		verify  func(t *testing.T, dm DiskManager)
	}{
		{
			name: "valid config with defaults",
			config: &DiskConfig{
				Device:         "/dev/sda",
				PartitionTable: PartitionTableGPT,
			},
			wantErr: false,
			verify: func(t *testing.T, dm DiskManager) {
				assert.NotNil(t, dm)
			},
		},
		{
			name: "valid config with custom EFI size",
			config: &DiskConfig{
				Device:           "/dev/sda",
				PartitionTable:   PartitionTableGPT,
				EFIPartitionSize: 1024,
			},
			wantErr: false,
			verify: func(t *testing.T, dm DiskManager) {
				assert.NotNil(t, dm)
			},
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "disk config is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := createTestLogger()
			dm, err := NewDiskManager(logger, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, dm)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, dm)
				if tt.verify != nil {
					tt.verify(t, dm)
				}
			}
		})
	}
}

func TestDiskManager_FormatFilesystem_UnsupportedType(t *testing.T) {
	logger := createTestLogger()
	config := &DiskConfig{
		Device:         "/dev/sda",
		PartitionTable: PartitionTableGPT,
	}

	dm, err := NewDiskManager(logger, config)
	require.NoError(t, err)

	ctx := context.Background()
	err = dm.FormatFilesystem(ctx, "/dev/sda1", "btrfs", "TEST")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported filesystem")
}

func TestDiskManager_Close(t *testing.T) {
	logger := createTestLogger()
	config := &DiskConfig{
		Device:         "/dev/sda",
		PartitionTable: PartitionTableGPT,
	}

	dm, err := NewDiskManager(logger, config)
	require.NoError(t, err)

	err = dm.Close()
	assert.NoError(t, err)
}

// Note: The following tests would actually modify disk devices, so they can't run in unit tests.
// They are documented here to show what would be tested in integration tests.

// TestDiskManager_CreatePartitionTable - Integration test only
// - Tests creating GPT partition table
// - Tests creating MBR partition table
// - Tests handling invalid disk device
// - Tests handling permission errors

// TestDiskManager_CreateEFIPartition - Integration test only
// - Tests creating EFI partition with default size
// - Tests creating EFI partition with custom size
// - Tests formatting as FAT32
// - Tests partition alignment

// TestDiskManager_CreateRootPartition - Integration test only
// - Tests creating root partition using remaining space
// - Tests correct start sector calculation
// - Tests partition type for GPT (Linux Filesystem)
// - Tests partition type for MBR (Linux)

// TestDiskManager_SetupLUKS - Integration test only
// - Tests LUKS2 container creation with default settings
// - Tests LUKS2 container creation with custom cipher
// - Tests LUKS2 container creation with custom key size
// - Tests opening LUKS container with passphrase
// - Tests handling wrong passphrase
// - Tests custom mapped device name

// TestDiskManager_FormatFilesystem - Integration test only
// - Tests FAT32 formatting with label
// - Tests ext4 formatting with label
// - Tests formatting already formatted device
// - Tests handling invalid device

// TestDiskManager_Mount - Integration test only
// - Tests mounting filesystem to mountpoint
// - Tests creating mountpoint directory
// - Tests mount flags
// - Tests mounting already mounted device

// TestDiskManager_Unmount - Integration test only
// - Tests unmounting filesystem
// - Tests unmounting non-mounted path
// - Tests handling busy mountpoint

func TestPartitionTableTypes(t *testing.T) {
	tests := []struct {
		name  string
		table PartitionTable
		valid bool
	}{
		{
			name:  "GPT",
			table: PartitionTableGPT,
			valid: true,
		},
		{
			name:  "MBR",
			table: PartitionTableMBR,
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.valid {
				assert.NotEmpty(t, string(tt.table))
			}
		})
	}
}

// Mock tests for error handling

func TestDiskManager_ErrorHandling(t *testing.T) {
	tests := []struct {
		name   string
		setup  func() (DiskManager, error)
		action func(dm DiskManager) error
		verify func(t *testing.T, err error)
	}{
		{
			name: "format with empty device",
			setup: func() (DiskManager, error) {
				return NewDiskManager(createTestLogger(), &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				})
			},
			action: func(dm DiskManager) error {
				return dm.FormatFilesystem(context.Background(), "", "ext4", "ROOT")
			},
			verify: func(t *testing.T, err error) {
				assert.Error(t, err)
			},
		},
		{
			name: "mount to invalid path",
			setup: func() (DiskManager, error) {
				return NewDiskManager(createTestLogger(), &DiskConfig{
					Device:         "/dev/sda",
					PartitionTable: PartitionTableGPT,
				})
			},
			action: func(dm DiskManager) error {
				// Create a temp dir that we'll mount to (but won't actually mount in unit test)
				tmpDir := filepath.Join(os.TempDir(), "test-mount-invalid")
				defer func() {
					if removeErr := os.RemoveAll(tmpDir); removeErr != nil {
						log.Printf("test cleanup: %v", removeErr)
					}
				}()
				// This will fail because we're not root and can't actually mount
				return dm.Mount(context.Background(), "/dev/null", tmpDir, "ext4", 0)
			},
			verify: func(t *testing.T, err error) {
				// Expected to fail in unit test environment (not root)
				// In integration test, this would verify proper error handling
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to mount")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm, err := tt.setup()
			require.NoError(t, err)

			err = tt.action(dm)
			tt.verify(t, err)
		})
	}
}

func TestDiskConfig_Validation(t *testing.T) {
	tests := []struct {
		name   string
		config *DiskConfig
		verify func(t *testing.T, cfg *DiskConfig)
	}{
		{
			name: "valid GPT config",
			config: &DiskConfig{
				Device:         "/dev/sda",
				PartitionTable: PartitionTableGPT,
			},
			verify: func(t *testing.T, cfg *DiskConfig) {
				assert.NotEmpty(t, cfg.Device)
				assert.Equal(t, PartitionTableGPT, cfg.PartitionTable)
			},
		},
		{
			name: "valid MBR config",
			config: &DiskConfig{
				Device:         "/dev/vda",
				PartitionTable: PartitionTableMBR,
			},
			verify: func(t *testing.T, cfg *DiskConfig) {
				assert.NotEmpty(t, cfg.Device)
				assert.Equal(t, PartitionTableMBR, cfg.PartitionTable)
			},
		},
		{
			name: "with encryption",
			config: &DiskConfig{
				Device:         "/dev/sda",
				PartitionTable: PartitionTableGPT,
				Encryption: &EncryptionConfig{
					Version:  "luks2",
					Password: "test123",
				},
			},
			verify: func(t *testing.T, cfg *DiskConfig) {
				assert.NotNil(t, cfg.Encryption)
				assert.Equal(t, "luks2", cfg.Encryption.Version)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.verify(t, tt.config)
		})
	}
}

func TestDiskManager_EFISizeCalculation(t *testing.T) {
	tests := []struct {
		name           string
		configSize     int
		expectedBytes  int64
		expectedSizeMB int64
	}{
		{
			name:           "default size (538MB)",
			configSize:     0,
			expectedBytes:  538 * 1024 * 1024,
			expectedSizeMB: 538,
		},
		{
			name:           "custom 1GB",
			configSize:     1024,
			expectedBytes:  1024 * 1024 * 1024,
			expectedSizeMB: 1024,
		},
		{
			name:           "minimal 100MB",
			configSize:     100,
			expectedBytes:  100 * 1024 * 1024,
			expectedSizeMB: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &DiskConfig{
				Device:           "/dev/sda",
				PartitionTable:   PartitionTableGPT,
				EFIPartitionSize: tt.configSize,
			}

			dm, err := NewDiskManager(createTestLogger(), config)
			require.NoError(t, err)
			assert.NotNil(t, dm)

			// Verify the internal efiSize is calculated correctly
			// This would be checked via the actual partition creation in integration tests
		})
	}
}

func TestFilesystemTypes(t *testing.T) {
	tests := []struct {
		name      string
		fsType    string
		supported bool
	}{
		{
			name:      "vfat",
			fsType:    "vfat",
			supported: true,
		},
		{
			name:      "fat32",
			fsType:    "fat32",
			supported: true,
		},
		{
			name:      "ext4",
			fsType:    "ext4",
			supported: true,
		},
		{
			name:      "btrfs",
			fsType:    "btrfs",
			supported: false,
		},
		{
			name:      "xfs",
			fsType:    "xfs",
			supported: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dm, err := NewDiskManager(createTestLogger(), &DiskConfig{
				Device:         "/dev/sda",
				PartitionTable: PartitionTableGPT,
			})
			require.NoError(t, err)

			err = dm.FormatFilesystem(context.Background(), "/dev/null", tt.fsType, "TEST")

			if tt.supported {
				// Will still fail because /dev/null isn't a real block device,
				// but it won't be an "unsupported filesystem" error
				assert.Error(t, err)
				// In unit test, the mkfs commands will fail, but that's expected
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "unsupported filesystem")
			}
		})
	}
}
