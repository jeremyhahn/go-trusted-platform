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

func TestNewManager(t *testing.T) {
	// Test with nil config - should use defaults
	m, err := NewManager(nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
	if m.config == nil {
		t.Fatal("expected default config")
	}
}

func TestNewManagerWithConfig(t *testing.T) {
	config := &Config{
		XKMSPath:            "/custom/path",
		DefaultPCRSelection: []uint{0, 7},
		DefaultPCRBanks:     []string{"sha384"},
		Debug:               true,
	}

	m, err := NewManager(nil, nil, nil, config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if m.config.XKMSPath != "/custom/path" {
		t.Errorf("expected XKMS path /custom/path, got %s", m.config.XKMSPath)
	}
	if len(m.config.DefaultPCRSelection) != 2 {
		t.Errorf("expected 2 PCRs, got %d", len(m.config.DefaultPCRSelection))
	}
	if !m.config.Debug {
		t.Error("expected debug to be true")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("expected non-nil config")
	}

	if config.XKMSPath != "/var/lib/trusted-platform/luks" {
		t.Errorf("expected default XKMS path, got %s", config.XKMSPath)
	}

	if len(config.DefaultPCRSelection) != 6 {
		t.Errorf("expected 6 default PCRs, got %d", len(config.DefaultPCRSelection))
	}

	expectedPCRs := []uint{0, 1, 2, 3, 7, 9}
	for i, pcr := range expectedPCRs {
		if config.DefaultPCRSelection[i] != pcr {
			t.Errorf("expected PCR %d at index %d, got %d", pcr, i, config.DefaultPCRSelection[i])
		}
	}

	if len(config.DefaultPCRBanks) != 1 || config.DefaultPCRBanks[0] != "sha256" {
		t.Errorf("expected sha256 PCR bank, got %v", config.DefaultPCRBanks)
	}

	if config.Debug {
		t.Error("expected debug to be false by default")
	}
}

func TestGetDevicePath(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
	}

	path := m.getDevicePath(part)
	expected := "/dev/disk/by-partlabel/root-partition"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestGetSealedKeyPath(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	path := m.getSealedKeyPath("root")
	expected := "/var/lib/trusted-platform/luks/root"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestGetSealedKeyPathCustomConfig(t *testing.T) {
	config := &Config{
		XKMSPath: "/custom/luks",
	}
	m, _ := NewManager(nil, nil, nil, config)

	path := m.getSealedKeyPath("data")
	expected := "/custom/luks/data"
	if path != expected {
		t.Errorf("expected %s, got %s", expected, path)
	}
}

func TestBuildFormatOptions(t *testing.T) {
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

	passphrase := []byte("test-passphrase")
	devicePath := "/dev/sda2"

	opts := m.buildFormatOptions(part, passphrase, devicePath)

	if opts.Device != devicePath {
		t.Errorf("expected device %s, got %s", devicePath, opts.Device)
	}

	if string(opts.Passphrase) != string(passphrase) {
		t.Error("expected passphrase to match")
	}

	if opts.Label != "root-partition" {
		t.Errorf("expected label root-partition, got %s", opts.Label)
	}

	if opts.KeySize != 512 {
		t.Errorf("expected key size 512, got %d", opts.KeySize)
	}

	if opts.HashAlgo != "sha256" {
		t.Errorf("expected hash sha256, got %s", opts.HashAlgo)
	}

	if opts.KDFType != "argon2id" {
		t.Errorf("expected KDF argon2id, got %s", opts.KDFType)
	}

	if opts.Cipher != "aes" {
		t.Errorf("expected cipher aes, got %s", opts.Cipher)
	}

	if opts.CipherMode != "xts-plain64" {
		t.Errorf("expected mode xts-plain64, got %s", opts.CipherMode)
	}

	if opts.Argon2Memory != 1048576 || opts.Argon2Time != 4 || opts.Argon2Parallel != 4 {
		t.Errorf("expected argon2 1048576/4/4, got %d/%d/%d", opts.Argon2Memory, opts.Argon2Time, opts.Argon2Parallel)
	}
}

func TestBuildFormatOptionsMinimal(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID:    "root",
		Label: "root-partition",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
		},
	}

	passphrase := []byte("test-passphrase")
	devicePath := "/dev/sda2"

	opts := m.buildFormatOptions(part, passphrase, devicePath)

	if opts.Device != devicePath {
		t.Errorf("expected device %s, got %s", devicePath, opts.Device)
	}

	// With no LUKS config, cipher defaults should be used
	if opts.KeySize != 0 {
		t.Errorf("expected key size 0 (use default), got %d", opts.KeySize)
	}
}

func TestFormatVolumeNoEncryption(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "data",
		// No encryption config
	}

	err := m.FormatVolume(context.TODO(), part, []byte("test"))
	if err == nil {
		t.Error("expected error for partition without encryption")
	}
}

func TestFormatVolumeEncryptionDisabled(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "data",
		Encryption: &drive.EncryptionConfig{
			Enabled: false,
		},
	}

	err := m.FormatVolume(context.TODO(), part, []byte("test"))
	if err == nil {
		t.Error("expected error for partition with encryption disabled")
	}
}

func TestAddTPMSealedKeyNoTPM(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			Enabled: true,
			TPMSealing: &drive.TPMSealingConfig{
				Enabled: true,
				KeySlot: 1,
			},
		},
	}

	err := m.AddTPMSealedKey(context.TODO(), part, []byte("test"))
	if err == nil {
		t.Error("expected error when TPM is not available")
	}
}

func TestUnlockWithTPMNoTPM(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
			TPMSealing: &drive.TPMSealingConfig{
				Enabled: true,
				KeySlot: 1,
			},
		},
	}

	err := m.UnlockWithTPM(context.TODO(), part)
	if err == nil {
		t.Error("expected error when TPM is not available")
	}
}

func TestUnlockWithTPMNotConfigured(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
			// No TPM sealing config
		},
	}

	err := m.UnlockWithTPM(context.TODO(), part)
	if err == nil {
		t.Error("expected error when TPM sealing not configured")
	}
}

func TestUnlockWithTPMDisabled(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			Enabled:     true,
			MappingName: "crypt-root",
			TPMSealing: &drive.TPMSealingConfig{
				Enabled: false, // TPM sealing disabled
			},
		},
	}

	err := m.UnlockWithTPM(context.TODO(), part)
	if err == nil {
		t.Error("expected error when TPM sealing disabled")
	}
}

func TestClearBytes(t *testing.T) {
	data := []byte("sensitive-data")
	original := make([]byte, len(data))
	copy(original, data)

	clearBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d not cleared: expected 0, got %d", i, b)
		}
	}
}

func TestClearBytesEmpty(t *testing.T) {
	data := []byte{}
	clearBytes(data) // Should not panic
}

func TestIsUnlockedNoState(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			MappingName: "nonexistent-mapping",
		},
	}

	// This will check the actual device mapper state, not our internal tracking
	// Since the mapping doesn't exist, it should return false
	if m.IsUnlocked(part) {
		t.Error("expected IsUnlocked to return false for nonexistent mapping")
	}
}

func TestMakeFilesystemNoConfig(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			MappingName: "crypt-root",
		},
		// No filesystem config
	}

	err := m.MakeFilesystem(context.TODO(), part)
	if err == nil {
		t.Error("expected error for partition without filesystem config")
	}
}

func TestMountNoConfig(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			MappingName: "crypt-root",
		},
		// No mount config
	}

	err := m.Mount(context.TODO(), part)
	if err == nil {
		t.Error("expected error for partition without mount config")
	}
}

func TestUnmountNoConfig(t *testing.T) {
	m, _ := NewManager(nil, nil, nil, nil)

	part := &drive.PartitionConfig{
		ID: "root",
		Encryption: &drive.EncryptionConfig{
			MappingName: "crypt-root",
		},
		// No mount config
	}

	err := m.Unmount(context.TODO(), part)
	if err == nil {
		t.Error("expected error for partition without mount config")
	}
}
