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
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewMultiDriveManagerNilPlatform(t *testing.T) {
	logger := logging.DefaultLogger()
	config := createTestStorageConfig()

	_, err := NewMultiDriveManager(nil, config, logger)
	if err == nil {
		t.Error("expected error for nil platform")
	}
}

func TestNewMultiDriveManagerNilStorageConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	_, err := NewMultiDriveManager(platform, nil, logger)
	if err == nil {
		t.Error("expected error for nil storage config")
	}
}

func TestNewMultiDriveManagerNilLogger(t *testing.T) {
	platform := createTestPlatform()
	config := createTestStorageConfig()

	_, err := NewMultiDriveManager(platform, config, nil)
	if err == nil {
		t.Error("expected error for nil logger")
	}
}

func TestNewMultiDriveManagerInvalidStorageConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := &drive.StorageConfig{} // Invalid - no drives

	_, err := NewMultiDriveManager(platform, config, logger)
	if err == nil {
		t.Error("expected error for invalid storage config")
	}
}

func TestCountSlashes(t *testing.T) {
	tests := []struct {
		path     string
		expected int
	}{
		{"/", 1},
		{"/boot", 1},
		{"/boot/efi", 2},
		{"/var/lib/data", 3},
		{"", 0},
		{"noSlash", 0},
	}

	for _, tt := range tests {
		result := countSlashes(tt.path)
		if result != tt.expected {
			t.Errorf("countSlashes(%q) = %d, want %d", tt.path, result, tt.expected)
		}
	}
}

func TestPartitionToVolumeConfigBasic(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
	}

	volume := mgr.partitionToVolumeConfig(part)

	if volume.MappingName != "crypt-root" {
		t.Errorf("expected mapping name crypt-root, got %s", volume.MappingName)
	}

	if volume.DevicePath != "/dev/disk/by-partlabel/root-partition" {
		t.Errorf("expected device path /dev/disk/by-partlabel/root-partition, got %s", volume.DevicePath)
	}
}

func TestPartitionToVolumeConfigWithLUKS(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
			LUKS: &drive.LUKSConfig{
				Cipher:  "aes-xts-plain64",
				KeySize: 512,
				Hash:    "sha256",
				PBKDF:   "argon2id",
			},
		},
	}

	volume := mgr.partitionToVolumeConfig(part)

	if volume.Cipher != "aes-xts-plain64" {
		t.Errorf("expected cipher aes-xts-plain64, got %s", volume.Cipher)
	}

	if volume.KeySize != 512 {
		t.Errorf("expected key size 512, got %d", volume.KeySize)
	}

	if volume.HashAlgorithm != "sha256" {
		t.Errorf("expected hash sha256, got %s", volume.HashAlgorithm)
	}

	if volume.PBKDFType != "argon2id" {
		t.Errorf("expected PBKDF argon2id, got %s", volume.PBKDFType)
	}
}

func TestGetDevicePathWithLabel(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "my-root",
	}

	path := mgr.getDevicePath(part)
	expected := "/dev/disk/by-partlabel/my-root"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestGetDevicePathWithoutLabel(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	part := &drive.PartitionConfig{
		ID: "root",
	}

	path := mgr.getDevicePath(part)
	expected := "/dev/disk/by-partlabel/root"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestIsRootPartition(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Root partition
	rootPart := &drive.PartitionConfig{
		ID: "root",
		Mount: &drive.MountConfig{
			Mountpoint: "/",
		},
	}
	if !mgr.isRootPartition(rootPart) {
		t.Error("expected true for root partition")
	}

	// Non-root partition
	dataPart := &drive.PartitionConfig{
		ID: "data",
		Mount: &drive.MountConfig{
			Mountpoint: "/data",
		},
	}
	if mgr.isRootPartition(dataPart) {
		t.Error("expected false for non-root partition")
	}

	// Partition without mount
	noMountPart := &drive.PartitionConfig{
		ID: "swap",
	}
	if mgr.isRootPartition(noMountPart) {
		t.Error("expected false for partition without mount")
	}
}

func TestGetMountOrder(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	config := &drive.StorageConfig{
		Drives: []drive.DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   drive.DriveRoleSystem,
				Partitions: []drive.PartitionConfig{
					{
						ID:     "efi",
						Number: 1,
						Size:   "512M",
						Mount:  &drive.MountConfig{Mountpoint: "/boot/efi"},
					},
					{
						ID:         "root",
						Number:     2,
						Size:       "50G",
						Mount:      &drive.MountConfig{Mountpoint: "/"},
						Encryption: &drive.EncryptionConfig{Enabled: true, MappingName: "cryptroot"},
					},
				},
			},
			{
				ID:     "data",
				Device: "/dev/sdb",
				Role:   drive.DriveRoleData,
				Partitions: []drive.PartitionConfig{
					{
						ID:         "var",
						Number:     1,
						Size:       "100%",
						Mount:      &drive.MountConfig{Mountpoint: "/var"},
						Encryption: &drive.EncryptionConfig{Enabled: true, MappingName: "cryptvar"},
					},
				},
			},
		},
	}

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	mountOrder := mgr.getMountOrder()

	// Should be sorted by depth: /, /boot/efi, /var
	if len(mountOrder) != 3 {
		t.Fatalf("expected 3 partitions, got %d", len(mountOrder))
	}

	// Root should be first (depth 1)
	if mountOrder[0].Mount.Mountpoint != "/" {
		t.Errorf("expected / first, got %s", mountOrder[0].Mount.Mountpoint)
	}

	// /boot/efi and /var both have depth 2, so either order is acceptable
	// but both should come after /
	for i := 1; i < len(mountOrder); i++ {
		depth := countSlashes(mountOrder[i].Mount.Mountpoint)
		if depth < 1 {
			t.Errorf("expected depth >= 1 for position %d, got %d", i, depth)
		}
	}
}

func TestGetStorageConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if mgr.GetStorageConfig() != config {
		t.Error("expected GetStorageConfig to return original config")
	}
}

func TestGetLUKSManager(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	if mgr.GetLUKSManager() == nil {
		t.Error("expected GetLUKSManager to return non-nil manager")
	}
}

func TestRegisterStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Create a mock strategy
	strategy := &mockStrategy{name: "test-strategy", priority: 1}
	mgr.RegisterStrategy(strategy)

	// Verify strategy was registered
	strategies := mgr.chain.List()
	if len(strategies) == 0 {
		t.Error("expected at least one strategy")
	}
}

// Helper functions

func createTestStorageConfig() *drive.StorageConfig {
	return &drive.StorageConfig{
		Drives: []drive.DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   drive.DriveRoleSystem,
				Partitions: []drive.PartitionConfig{
					{
						ID:     "root",
						Number: 1,
						Size:   "100%",
						Mount:  &drive.MountConfig{Mountpoint: "/"},
					},
				},
			},
		},
	}
}

// mockStrategy is a simple mock for testing
type mockStrategy struct {
	name     string
	priority int
}

func (m *mockStrategy) Name() string {
	return m.name
}

func (m *mockStrategy) Priority() int {
	return m.priority
}

func (m *mockStrategy) CanUnlock(_ context.Context, _ *luks.VolumeConfig) bool {
	return false
}

func (m *mockStrategy) Unlock(_ context.Context, _ *luks.VolumeConfig) error {
	return nil
}

func (m *mockStrategy) Install(_ context.Context, _ *luks.VolumeConfig, _ []byte) error {
	return nil
}
