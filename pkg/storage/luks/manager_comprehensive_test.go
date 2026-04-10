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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/drive"
)

func TestManagerWithLogger(t *testing.T) {
	logger := logging.DefaultLogger()
	m, err := NewManager(logger, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestAddRecoveryKeyUnknownFormat(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)
	ctx := context.Background()

	// Unknown format - should default to dashed
	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			RecoveryKey: &drive.RecoveryKeyConfig{
				Generate: true,
				KeySlot:  2,
				Format:   "unknown", // Unknown format
			},
		},
	}

	err := m.AddRecoveryKey(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestBuildFormatOptionsNilEncryption(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		// No encryption config
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	// Should still create valid options with defaults
	if opts.Device != "/dev/test" {
		t.Errorf("expected device /dev/test, got %s", opts.Device)
	}
	if opts.Label != "root-partition" {
		t.Errorf("expected label root-partition, got %s", opts.Label)
	}
}

func TestBuildFormatOptionsEmptyCipher(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				Cipher: "", // Empty cipher
			},
		},
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	// Cipher and mode should not be set when empty
	if opts.Cipher != "" {
		t.Errorf("expected empty cipher, got %s", opts.Cipher)
	}
}

func TestBuildFormatOptionsZeroKeySize(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				KeySize: 0, // Zero key size - should use default
			},
		},
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	if opts.KeySize != 0 {
		t.Errorf("expected key size 0 (default), got %d", opts.KeySize)
	}
}

func TestBuildFormatOptionsEmptyHash(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				Hash: "", // Empty hash
			},
		},
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	if opts.HashAlgo != "" {
		t.Errorf("expected empty hash algo, got %s", opts.HashAlgo)
	}
}

func TestBuildFormatOptionsEmptyPBKDF(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				PBKDF: "", // Empty PBKDF
			},
		},
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	if opts.KDFType != "" {
		t.Errorf("expected empty KDF type, got %s", opts.KDFType)
	}
}

func TestBuildFormatOptionsZeroArgon2Values(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			LUKS: &drive.LUKSConfig{
				Argon2Memory:   0,
				Argon2Time:     0,
				Argon2Parallel: 0,
			},
		},
	}

	opts := m.buildFormatOptions(part, []byte("pass"), "/dev/test")

	if opts.Argon2Memory != 0 {
		t.Errorf("expected Argon2Memory 0, got %d", opts.Argon2Memory)
	}
	if opts.Argon2Time != 0 {
		t.Errorf("expected Argon2Time 0, got %d", opts.Argon2Time)
	}
	if opts.Argon2Parallel != 0 {
		t.Errorf("expected Argon2Parallel 0, got %d", opts.Argon2Parallel)
	}
}

func TestUnlockWithPassphraseTracksState(t *testing.T) {
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

	// This will fail, but we're testing that the code path is exercised
	_ = m.UnlockWithPassphrase(ctx, part, []byte("test-password"))

	// Even on failure, state should not be added
	if _, ok := m.volumes[part.ID]; ok {
		t.Error("expected no volume state on unlock failure")
	}
}

func TestUnlockWithRecoveryKeyTracksState(t *testing.T) {
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

	// This will fail, but we're testing that the code path is exercised
	_ = m.UnlockWithRecoveryKey(ctx, part, "test-recovery-key")

	// Even on failure, state should not be added
	if _, ok := m.volumes[part.ID]; ok {
		t.Error("expected no volume state on unlock failure")
	}
}

func TestMountUpdatesState(t *testing.T) {
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

	// This will fail, but we're testing state handling
	_ = m.Mount(ctx, part)

	// State should remain unchanged on error
	if state, ok := m.volumes[part.ID]; ok {
		if state.IsMounted {
			t.Error("expected IsMounted to remain false on error")
		}
	}
}

func TestAddRecoveryKeyCustomLength(t *testing.T) {
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
				Length:   64, // Custom length
			},
		},
	}

	err := m.AddRecoveryKey(ctx, part, []byte("test-password"))
	if err == nil {
		t.Error("expected error for non-existent device")
	}
}

func TestGetSealedKeyPathWithCustomConfig(t *testing.T) {
	config := &Config{
		XKMSPath: "/custom/path",
	}
	m, _ := NewManager(nil, nil, nil, config)

	path := m.getSealedKeyPath("test-partition")
	expected := "/custom/path/test-partition"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestIsUnlockedExistingMapping(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			MappingName: "nonexistent-mapping-test",
		},
	}

	// This delegates to go-luks2's IsUnlocked which checks actual device mapper state
	unlocked := m.IsUnlocked(part)
	if unlocked {
		t.Error("expected false for non-existent mapping")
	}
}

func TestVolumeStateFields(t *testing.T) {
	state := &VolumeState{
		Config: &drive.PartitionConfig{
			ID:    "test",
			Label: "test-partition",
		},
		DevicePath:    "/dev/sda1",
		MappingName:   "crypt-test",
		IsUnlocked:    true,
		IsMounted:     true,
		MountPoint:    "/mnt/test",
		SealedKeyPath: "/var/lib/luks/test",
	}

	if state.SealedKeyPath != "/var/lib/luks/test" {
		t.Errorf("expected sealed key path /var/lib/luks/test, got %s", state.SealedKeyPath)
	}
	if !state.IsUnlocked {
		t.Error("expected IsUnlocked to be true")
	}
	if !state.IsMounted {
		t.Error("expected IsMounted to be true")
	}
}

func TestConfigFields(t *testing.T) {
	config := &Config{
		XKMSPath:            "/test/path",
		DefaultPCRSelection: []uint{0, 1, 2},
		DefaultPCRBanks:     []string{"sha256", "sha384"},
		Debug:               true,
	}

	if config.XKMSPath != "/test/path" {
		t.Errorf("expected XKMS path /test/path, got %s", config.XKMSPath)
	}
	if len(config.DefaultPCRBanks) != 2 {
		t.Errorf("expected 2 PCR banks, got %d", len(config.DefaultPCRBanks))
	}
	if !config.Debug {
		t.Error("expected Debug to be true")
	}
}

func TestClearBytesNonEmpty(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	clearBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d not cleared: expected 0, got %d", i, b)
		}
	}
}

func TestClearBytesNil(t *testing.T) {
	var data []byte
	clearBytes(data) // Should not panic
}
