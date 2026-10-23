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

package luks

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"
)

func TestAddRecoveryKeyHex(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			RecoveryKey: &drive.RecoveryKeyConfig{
				Generate:   true,
				KeySlot:    2,
				Format:     drive.RecoveryKeyFormatHex,
				Length:     32,
				OutputPath: "/tmp/recovery-key-test.hex",
			},
		},
	}

	// Will fail because device doesn't exist, but tests the code paths
	err := m.AddRecoveryKey(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestAddRecoveryKeyBase64(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			RecoveryKey: &drive.RecoveryKeyConfig{
				Generate: true,
				KeySlot:  2,
				Format:   drive.RecoveryKeyFormatBase64,
			},
		},
	}

	err := m.AddRecoveryKey(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestAddRecoveryKeyDashed(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			RecoveryKey: &drive.RecoveryKeyConfig{
				Generate: true,
				KeySlot:  2,
				Format:   drive.RecoveryKeyFormatDashed,
			},
		},
	}

	err := m.AddRecoveryKey(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestAddRecoveryKeyDefaultLength(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			RecoveryKey: &drive.RecoveryKeyConfig{
				Generate: true,
				KeySlot:  2,
				Length:   0, // Should default to 32
			},
		},
	}

	err := m.AddRecoveryKey(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestAddRecoveryKeyWithOutputPath(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			RecoveryKey: &drive.RecoveryKeyConfig{
				Generate:   true,
				KeySlot:    2,
				OutputPath: "/tmp/test-recovery.key",
			},
		},
	}

	err := m.AddRecoveryKey(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestUnlockWithPassphrase(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
	}

	err := m.UnlockWithPassphrase(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestUnlockWithRecoveryKey(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
	}

	// Test with hex format
	err := m.UnlockWithRecoveryKey(ctx, part, "0123456789abcdef0123456789abcdef")
	if err == nil {
		t.Error("expected error for invalid recovery key or non-existent device")
	}

	// Test with dashed format
	err = m.UnlockWithRecoveryKey(ctx, part, "0123-4567-89ab-cdef")
	if err == nil {
		t.Error("expected error for invalid recovery key or non-existent device")
	}

	// Test with base64 format
	err = m.UnlockWithRecoveryKey(ctx, part, "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=")
	if err == nil {
		t.Error("expected error for invalid recovery key or non-existent device")
	}
}

func TestLock(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
	}

	err := m.Lock(ctx, part)
	if err == nil {
		t.Error("expected error for non-existent mapping")
	}
}

func TestLockUpdatesState(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
	}

	// Add volume state - this tests the state update path when volume exists
	m.volumes[part.ID] = &VolumeState{
		Config:      part,
		DevicePath:  "/dev/disk/by-partlabel/root-partition",
		MappingName: "crypt-root",
		IsUnlocked:  true,
	}

	err := m.Lock(ctx, part)
	if err == nil {
		t.Error("expected error for non-existent mapping")
	}

	// The state should NOT be updated on error - only on success
	// This is the current behavior based on the code
	if state, ok := m.volumes[part.ID]; ok {
		if !state.IsUnlocked {
			t.Error("IsUnlocked should remain true since Lock failed")
		}
	}
}

func TestGetVolumeInfo(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
	}

	info, err := m.GetVolumeInfo(part)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
	if info != nil {
		t.Error("expected nil info on error")
	}
}

func TestListKeyslots(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
	}

	keyslots, err := m.ListKeyslots(part)
	if err == nil {
		t.Error("expected error for non-existent device")
	}
	if keyslots != nil {
		t.Error("expected nil keyslots on error")
	}
}

func TestMakeFilesystemExt4(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
		Filesystem: &drive.FilesystemConfig{
			Type:  drive.FilesystemExt4,
			Label: "rootfs",
		},
	}

	err := m.MakeFilesystem(ctx, part)
	if err == nil {
		t.Error("expected error for non-existent mapping")
	}
}

func TestMakeFilesystemXFS(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "data",
		Label: "data-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-data",
		},
		Filesystem: &drive.FilesystemConfig{
			Type:  drive.FilesystemXFS,
			Label: "datafs",
		},
	}

	err := m.MakeFilesystem(ctx, part)
	if err == nil {
		t.Error("expected error for non-existent mapping")
	}
}

func TestMountWithFilesystemType(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
		Filesystem: &drive.FilesystemConfig{
			Type:  drive.FilesystemExt4,
			Label: "rootfs",
		},
		Mount: &drive.MountConfig{
			Mountpoint: "/mnt/root",
		},
	}

	// Add volume state
	m.volumes[part.ID] = &VolumeState{
		Config:      part,
		DevicePath:  "/dev/disk/by-partlabel/root-partition",
		MappingName: "crypt-root",
		IsUnlocked:  true,
		IsMounted:   false,
	}

	err := m.Mount(ctx, part)
	if err == nil {
		t.Error("expected error for non-existent mapping")
	}
}

func TestMountWithoutFilesystemType(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
		Mount: &drive.MountConfig{
			Mountpoint: "/mnt/root",
		},
	}

	err := m.Mount(ctx, part)
	if err == nil {
		t.Error("expected error for non-existent mapping")
	}
}

func TestUnmountUpdatesState(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
		},
		Mount: &drive.MountConfig{
			Mountpoint: "/mnt/root",
		},
	}

	// Add mounted volume state
	m.volumes[part.ID] = &VolumeState{
		Config:      part,
		DevicePath:  "/dev/disk/by-partlabel/root-partition",
		MappingName: "crypt-root",
		IsUnlocked:  true,
		IsMounted:   true,
		MountPoint:  "/mnt/root",
	}

	err := m.Unmount(ctx, part)
	if err == nil {
		t.Error("expected error for non-existent mount point")
	}

	// The state should NOT be updated on error - only on success
	// This is the current behavior based on the code
	if state, ok := m.volumes[part.ID]; ok {
		if !state.IsMounted {
			t.Error("IsMounted should remain true since Unmount failed")
		}
		if state.MountPoint == "" {
			t.Error("MountPoint should remain set since Unmount failed")
		}
	}
}

func TestFormatVolumeWithTPMSealing(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				Cipher:         "aes-xts-plain64",
				KeySize:        512,
				Hash:           "sha256",
				PBKDF:          "argon2id",
				Argon2Memory:   1048576,
				Argon2Time:     4,
				Argon2Parallel: 4,
			},
			TPMSealing: &drive.TPMSealingConfig{
				Enabled:   true,
				KeySlot:   1,
				KeyName:   "test-key",
				PCRPolicy: true,
			},
		},
	}

	// Will fail because TPM is not available, but tests the code path
	err := m.FormatVolume(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device or missing TPM")
	}
}

func TestFormatVolumeWithRecoveryKey(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				Cipher:  "aes-xts-plain64",
				KeySize: 512,
			},
			RecoveryKey: &drive.RecoveryKeyConfig{
				Generate: true,
				KeySlot:  2,
			},
		},
	}

	// Will fail because device doesn't exist
	err := m.FormatVolume(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestBuildFormatOptionsAllFields(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				Cipher:         "aes-xts-plain64",
				KeySize:        512,
				Hash:           "sha256",
				PBKDF:          "argon2id",
				Argon2Memory:   1048576,
				Argon2Time:     4,
				Argon2Parallel: 4,
			},
		},
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	if opts.Cipher != "aes" {
		t.Errorf("expected cipher aes, got %s", opts.Cipher)
	}
	if opts.CipherMode != "xts-plain64" {
		t.Errorf("expected mode xts-plain64, got %s", opts.CipherMode)
	}
	if opts.Argon2Memory != 1048576 {
		t.Errorf("expected Argon2Memory 1048576, got %d", opts.Argon2Memory)
	}
	if opts.Argon2Time != 4 {
		t.Errorf("expected Argon2Time 4, got %d", opts.Argon2Time)
	}
	if opts.Argon2Parallel != 4 {
		t.Errorf("expected Argon2Parallel 4, got %d", opts.Argon2Parallel)
	}
}

func TestUnlockWithTPMNoSealedData(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
			TPMSealing: &drive.TPMSealingConfig{
				Enabled:    true,
				KeySlot:    1,
				SealedData: nil, // No sealed data
			},
		},
	}

	err := m.UnlockWithTPM(ctx, part)
	// Will fail with "TPM not available" before checking sealed data
	if err == nil {
		t.Error("expected error when TPM is not available")
	}
}
