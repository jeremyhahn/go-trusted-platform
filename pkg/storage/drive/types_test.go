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

package drive

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestDefaultStorageConfig(t *testing.T) {
	config := DefaultStorageConfig()

	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if config.DefaultFilesystem != FilesystemExt4 {
		t.Errorf("expected default filesystem ext4, got %s", config.DefaultFilesystem)
	}

	if !config.RequireRootEncryption {
		t.Error("expected RequireRootEncryption to be true")
	}

	if config.DefaultLUKS == nil {
		t.Fatal("expected non-nil DefaultLUKS")
	}

	if config.DefaultLUKS.Cipher != "aes-xts-plain64" {
		t.Errorf("expected cipher aes-xts-plain64, got %s", config.DefaultLUKS.Cipher)
	}

	if config.DefaultLUKS.KeySize != 512 {
		t.Errorf("expected key size 512, got %d", config.DefaultLUKS.KeySize)
	}

	if config.DefaultLUKS.PBKDF != "argon2id" {
		t.Errorf("expected PBKDF argon2id, got %s", config.DefaultLUKS.PBKDF)
	}
}

func TestDefaultTPMSealingConfig(t *testing.T) {
	config := DefaultTPMSealingConfig()

	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if !config.Enabled {
		t.Error("expected Enabled to be true")
	}

	if config.KeySlot != 1 {
		t.Errorf("expected KeySlot 1, got %d", config.KeySlot)
	}

	if !config.PCRPolicy {
		t.Error("expected PCRPolicy to be true")
	}

	if len(config.PCRSelection) != 6 {
		t.Errorf("expected 6 PCRs, got %d", len(config.PCRSelection))
	}

	expectedPCRs := []uint{0, 1, 2, 3, 7, 9}
	for i, pcr := range expectedPCRs {
		if config.PCRSelection[i] != pcr {
			t.Errorf("expected PCR %d at index %d, got %d", pcr, i, config.PCRSelection[i])
		}
	}
}

func TestDefaultRecoveryKeyConfig(t *testing.T) {
	config := DefaultRecoveryKeyConfig()

	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if !config.Generate {
		t.Error("expected Generate to be true")
	}

	if config.KeySlot != 2 {
		t.Errorf("expected KeySlot 2, got %d", config.KeySlot)
	}

	if config.Format != RecoveryKeyFormatDashed {
		t.Errorf("expected format dashed, got %s", config.Format)
	}

	if config.Length != 32 {
		t.Errorf("expected length 32, got %d", config.Length)
	}
}

func TestStorageConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *StorageConfig
		expectError error
	}{
		{
			name:        "no drives",
			config:      &StorageConfig{},
			expectError: ErrNoDrivesConfigured,
		},
		{
			name: "no system drive",
			config: &StorageConfig{
				Drives: []DriveConfig{
					{
						ID:     "data",
						Device: "/dev/sdb",
						Role:   DriveRoleData,
						Partitions: []PartitionConfig{
							{ID: "data", Number: 1, Size: "100%"},
						},
					},
				},
			},
			expectError: ErrNoSystemDrive,
		},
		{
			name: "valid config",
			config: &StorageConfig{
				Drives: []DriveConfig{
					{
						ID:     "system",
						Device: "/dev/sda",
						Role:   DriveRoleSystem,
						Partitions: []PartitionConfig{
							{ID: "root", Number: 1, Size: "100%"},
						},
					},
				},
			},
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError != nil {
				if err != tt.expectError {
					t.Errorf("expected error %v, got %v", tt.expectError, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestStorageConfigValidate_InvalidDrive(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "", Number: 1, Size: "100%"}, // Invalid partition
				},
			},
		},
	}

	err := config.Validate()
	if err != ErrPartitionIDRequired {
		t.Errorf("expected error %v, got %v", ErrPartitionIDRequired, err)
	}
}

func TestDriveConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		drive       *DriveConfig
		expectError error
	}{
		{
			name:        "missing ID",
			drive:       &DriveConfig{Device: "/dev/sda"},
			expectError: ErrDriveIDRequired,
		},
		{
			name:        "missing device",
			drive:       &DriveConfig{ID: "system"},
			expectError: ErrDevicePathRequired,
		},
		{
			name:        "no partitions",
			drive:       &DriveConfig{ID: "system", Device: "/dev/sda"},
			expectError: ErrNoPartitions,
		},
		{
			name: "valid drive",
			drive: &DriveConfig{
				ID:     "system",
				Device: "/dev/sda",
				Partitions: []PartitionConfig{
					{ID: "root", Number: 1, Size: "100%"},
				},
			},
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.drive.Validate()

			if tt.expectError != nil {
				if err != tt.expectError {
					t.Errorf("expected error %v, got %v", tt.expectError, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestDriveConfigValidate_InvalidPartition(t *testing.T) {
	drive := &DriveConfig{
		ID:     "system",
		Device: "/dev/sda",
		Partitions: []PartitionConfig{
			{ID: "root", Number: 0, Size: "100%"}, // Invalid partition number
		},
	}

	err := drive.Validate()
	if err != ErrInvalidPartitionNumber {
		t.Errorf("expected error %v, got %v", ErrInvalidPartitionNumber, err)
	}
}

func TestPartitionConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		partition   *PartitionConfig
		expectError error
	}{
		{
			name:        "missing ID",
			partition:   &PartitionConfig{Number: 1, Size: "100%"},
			expectError: ErrPartitionIDRequired,
		},
		{
			name:        "invalid number",
			partition:   &PartitionConfig{ID: "root", Number: 0, Size: "100%"},
			expectError: ErrInvalidPartitionNumber,
		},
		{
			name:        "missing size",
			partition:   &PartitionConfig{ID: "root", Number: 1},
			expectError: ErrPartitionSizeRequired,
		},
		{
			name:        "valid partition",
			partition:   &PartitionConfig{ID: "root", Number: 1, Size: "100%"},
			expectError: nil,
		},
		{
			name: "encrypted partition without a mapping name",
			partition: &PartitionConfig{ID: "data", Number: 2, Size: "100%",
				Encryption: &EncryptionConfig{Enabled: true}},
			expectError: ErrEncryptionMappingNameRequired,
		},
		{
			name: "encrypted partition with a valid mapping name",
			partition: &PartitionConfig{ID: "data", Number: 2, Size: "100%",
				Encryption: &EncryptionConfig{Enabled: true, MappingName: "cryptdata"}},
			expectError: nil,
		},
		{
			name: "disabled encryption needs no mapping name",
			partition: &PartitionConfig{ID: "data", Number: 2, Size: "100%",
				Encryption: &EncryptionConfig{Enabled: false}},
			expectError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.partition.Validate()

			if tt.expectError != nil {
				if err != tt.expectError {
					t.Errorf("expected error %v, got %v", tt.expectError, err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// go-luks2 v0.1.10 made Unlock refuse names device-mapper would mangle. The
// initrd formats an encrypted partition before it unlocks it under this name,
// so the name must be refused here, before the drive is wiped.
func TestPartitionConfigValidate_RejectsMappingNamesUnlockWouldRefuse(t *testing.T) {
	for _, name := range []string{"-data", "crypt/data", "crypt data", "../cryptdata"} {
		part := &PartitionConfig{ID: "data", Number: 2, Size: "100%",
			Encryption: &EncryptionConfig{Enabled: true, MappingName: name}}

		err := part.Validate()

		var invalid *InvalidMappingNameError
		if !errors.As(err, &invalid) || invalid.PartitionID != "data" || invalid.Name != name {
			t.Errorf("Validate() error for mapping-name %q = %v, want an InvalidMappingNameError naming partition data", name, err)
			continue
		}
		if !errors.Is(err, luks2.ErrInvalidMappingName) {
			t.Errorf("Validate() error for mapping-name %q = %v, want it to wrap luks2.ErrInvalidMappingName", name, err)
		}
	}
}

func TestInvalidMappingNameError(t *testing.T) {
	cause := errors.New("bad name")
	err := &InvalidMappingNameError{PartitionID: "data", Name: "crypt/data", Err: cause}

	if !errors.Is(err, cause) {
		t.Fatalf("InvalidMappingNameError does not unwrap to its cause")
	}
	if want := `partition data: invalid encryption mapping-name "crypt/data": bad name`; err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
}

func TestGetSystemDrive(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{ID: "data", Device: "/dev/sdb", Role: DriveRoleData},
			{ID: "system", Device: "/dev/sda", Role: DriveRoleSystem},
		},
	}

	drive := config.GetSystemDrive()
	if drive == nil {
		t.Fatal("expected system drive")
	}

	if drive.ID != "system" {
		t.Errorf("expected drive ID 'system', got %s", drive.ID)
	}
}

func TestGetSystemDriveNone(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{ID: "data", Device: "/dev/sdb", Role: DriveRoleData},
		},
	}

	drive := config.GetSystemDrive()
	if drive != nil {
		t.Error("expected nil for missing system drive")
	}
}

func TestGetRootPartition(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "efi", Number: 1, Size: "512M", Mount: &MountConfig{Mountpoint: "/boot/efi"}},
					{ID: "root", Number: 2, Size: "100%", Mount: &MountConfig{Mountpoint: "/"}},
				},
			},
		},
	}

	root := config.GetRootPartition()
	if root == nil {
		t.Fatal("expected root partition")
	}

	if root.ID != "root" {
		t.Errorf("expected partition ID 'root', got %s", root.ID)
	}
}

func TestGetRootPartition_NoSystemDrive(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "data",
				Device: "/dev/sdb",
				Role:   DriveRoleData,
				Partitions: []PartitionConfig{
					{ID: "data1", Number: 1, Size: "100%"},
				},
			},
		},
	}

	root := config.GetRootPartition()
	if root != nil {
		t.Error("expected nil when no system drive exists")
	}
}

func TestGetRootPartition_NoRootMount(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "efi", Number: 1, Size: "512M", Mount: &MountConfig{Mountpoint: "/boot/efi"}},
					{ID: "data", Number: 2, Size: "100%", Mount: &MountConfig{Mountpoint: "/data"}},
				},
			},
		},
	}

	root := config.GetRootPartition()
	if root != nil {
		t.Error("expected nil when no root partition exists")
	}
}

func TestGetEFIPartition(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "efi", Number: 1, Size: "512M", Flags: []string{"esp"}, Mount: &MountConfig{Mountpoint: "/boot/efi"}},
					{ID: "root", Number: 2, Size: "100%", Mount: &MountConfig{Mountpoint: "/"}},
				},
			},
		},
	}

	efi := config.GetEFIPartition()
	if efi == nil {
		t.Fatal("expected EFI partition")
	}

	if efi.ID != "efi" {
		t.Errorf("expected partition ID 'efi', got %s", efi.ID)
	}
}

func TestGetEFIPartition_BootFlag(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "boot", Number: 1, Size: "512M", Flags: []string{"boot"}},
					{ID: "root", Number: 2, Size: "100%", Mount: &MountConfig{Mountpoint: "/"}},
				},
			},
		},
	}

	efi := config.GetEFIPartition()
	if efi == nil {
		t.Fatal("expected EFI partition with boot flag")
	}

	if efi.ID != "boot" {
		t.Errorf("expected partition ID 'boot', got %s", efi.ID)
	}
}

func TestGetEFIPartition_BootMountpoint(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "boot", Number: 1, Size: "512M", Mount: &MountConfig{Mountpoint: "/boot"}},
					{ID: "root", Number: 2, Size: "100%", Mount: &MountConfig{Mountpoint: "/"}},
				},
			},
		},
	}

	efi := config.GetEFIPartition()
	if efi == nil {
		t.Fatal("expected EFI partition with /boot mountpoint")
	}

	if efi.ID != "boot" {
		t.Errorf("expected partition ID 'boot', got %s", efi.ID)
	}
}

func TestGetEFIPartition_NoSystemDrive(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "data",
				Device: "/dev/sdb",
				Role:   DriveRoleData,
				Partitions: []PartitionConfig{
					{ID: "data1", Number: 1, Size: "100%"},
				},
			},
		},
	}

	efi := config.GetEFIPartition()
	if efi != nil {
		t.Error("expected nil when no system drive exists")
	}
}

func TestGetEFIPartition_NoEFIPartition(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "root", Number: 1, Size: "100%", Mount: &MountConfig{Mountpoint: "/"}},
				},
			},
		},
	}

	efi := config.GetEFIPartition()
	if efi != nil {
		t.Error("expected nil when no EFI partition exists")
	}
}

func TestGetEncryptedPartitions(t *testing.T) {
	config := &StorageConfig{
		Drives: []DriveConfig{
			{
				ID:     "system",
				Device: "/dev/sda",
				Role:   DriveRoleSystem,
				Partitions: []PartitionConfig{
					{ID: "efi", Number: 1, Size: "512M"},
					{ID: "root", Number: 2, Size: "100%", Encryption: &EncryptionConfig{Enabled: true}},
				},
			},
			{
				ID:     "data",
				Device: "/dev/sdb",
				Role:   DriveRoleData,
				Partitions: []PartitionConfig{
					{ID: "data1", Number: 1, Size: "50%", Encryption: &EncryptionConfig{Enabled: true}},
					{ID: "data2", Number: 2, Size: "50%"},
				},
			},
		},
	}

	encrypted := config.GetEncryptedPartitions()
	if len(encrypted) != 2 {
		t.Errorf("expected 2 encrypted partitions, got %d", len(encrypted))
	}
}

func TestFilesystemTypeConstants(t *testing.T) {
	if FilesystemExt4 != "ext4" {
		t.Errorf("expected 'ext4', got %s", FilesystemExt4)
	}
	if FilesystemXFS != "xfs" {
		t.Errorf("expected 'xfs', got %s", FilesystemXFS)
	}
	if FilesystemZFS != "zfs" {
		t.Errorf("expected 'zfs', got %s", FilesystemZFS)
	}
	if FilesystemFAT32 != "vfat" {
		t.Errorf("expected 'vfat', got %s", FilesystemFAT32)
	}
}

func TestDriveRoleConstants(t *testing.T) {
	if DriveRoleSystem != "system" {
		t.Errorf("expected 'system', got %s", DriveRoleSystem)
	}
	if DriveRoleData != "data" {
		t.Errorf("expected 'data', got %s", DriveRoleData)
	}
	if DriveRoleBackup != "backup" {
		t.Errorf("expected 'backup', got %s", DriveRoleBackup)
	}
	if DriveRoleSwap != "swap" {
		t.Errorf("expected 'swap', got %s", DriveRoleSwap)
	}
}

func TestUnlockMethodConstants(t *testing.T) {
	if UnlockTPMPCR != "tpm-pcr" {
		t.Errorf("expected 'tpm-pcr', got %s", UnlockTPMPCR)
	}
	if UnlockTPMNoPCR != "tpm-nopcr" {
		t.Errorf("expected 'tpm-nopcr', got %s", UnlockTPMNoPCR)
	}
	if UnlockFIDO2 != "fido2" {
		t.Errorf("expected 'fido2', got %s", UnlockFIDO2)
	}
	if UnlockPassword != "password" {
		t.Errorf("expected 'password', got %s", UnlockPassword)
	}
	if UnlockKeyfile != "keyfile" {
		t.Errorf("expected 'keyfile', got %s", UnlockKeyfile)
	}
	if UnlockRecovery != "recovery" {
		t.Errorf("expected 'recovery', got %s", UnlockRecovery)
	}
}

func TestRecoveryKeyFormatConstants(t *testing.T) {
	if RecoveryKeyFormatHex != "hex" {
		t.Errorf("expected 'hex', got %s", RecoveryKeyFormatHex)
	}
	if RecoveryKeyFormatBase64 != "base64" {
		t.Errorf("expected 'base64', got %s", RecoveryKeyFormatBase64)
	}
	if RecoveryKeyFormatDashed != "dashed" {
		t.Errorf("expected 'dashed', got %s", RecoveryKeyFormatDashed)
	}
}
