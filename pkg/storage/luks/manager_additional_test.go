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

func TestAddRecoveryKeyFormats(t *testing.T) {
	tests := []struct {
		name   string
		format drive.RecoveryKeyFormat
		length int
	}{
		{name: "hex with explicit length", format: drive.RecoveryKeyFormatHex, length: 32},
		{name: "base64", format: drive.RecoveryKeyFormatBase64},
		{name: "unknown format defaults to dashed and default length", format: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := NewManager(nil, nil, nil, nil)

			part := &drive.PartitionConfig{
				ID:    "root",
				Label: "root-partition",
				Encryption: &drive.EncryptionConfig{
					Enabled: true,
					RecoveryKey: &drive.RecoveryKeyConfig{
						Generate: true,
						KeySlot:  2,
						Format:   tt.format,
						Length:   tt.length,
					},
				},
			}

			err := m.AddRecoveryKey(context.Background(), part, []byte("test-password"))
			if err == nil {
				t.Error("expected error for non-existent device")
			}
		})
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
	if _, ok := m.volumes[part.ID]; ok {
		t.Error("expected no volume state on unlock failure")
	}
}

func TestUnlockWithRecoveryKey(t *testing.T) {
	keys := map[string]string{
		"hex":       "0123456789abcdef0123456789abcdef",
		"dashed":    "0123-4567-89ab-cdef",
		"base64":    "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
		"malformed": "test-recovery-key",
	}

	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			m, _ := NewManager(nil, nil, nil, nil)

			part := &drive.PartitionConfig{
				ID:    "root",
				Label: "root-partition",
				Encryption: &drive.EncryptionConfig{
					Enabled:     true,
					MappingName: "crypt-root",
				},
			}

			err := m.UnlockWithRecoveryKey(context.Background(), part, key)
			if err == nil {
				t.Error("expected error for invalid recovery key or non-existent device")
			}
			if _, ok := m.volumes[part.ID]; ok {
				t.Error("expected no volume state on unlock failure")
			}
		})
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
	if state := m.volumes[part.ID]; state.IsMounted {
		t.Error("expected IsMounted to remain false on error")
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
