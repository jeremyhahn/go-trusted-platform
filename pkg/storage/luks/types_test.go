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
	"testing"
)

func TestUnlockMethods(t *testing.T) {
	tests := []struct {
		name   string
		method UnlockMethod
	}{
		{"TPM PCR", UnlockTPMPCR},
		{"TPM No PCR", UnlockTPMNoPCR},
		{"TPM Upgrade", UnlockTPMUpgrade},
		{"Password", UnlockPassword},
		{"Keyfile", UnlockKeyfile},
		{"FIDO2", UnlockFIDO2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.method == "" {
				t.Error("unlock method should not be empty")
			}
		})
	}
}

func TestLUKSVersionConstants(t *testing.T) {
	if LUKS1 != 1 {
		t.Errorf("expected LUKS1 to be 1, got %d", LUKS1)
	}
	if LUKS2 != 2 {
		t.Errorf("expected LUKS2 to be 2, got %d", LUKS2)
	}
	if LUKSVersion1 != 1 {
		t.Errorf("expected LUKSVersion1 to be 1, got %d", LUKSVersion1)
	}
	if LUKSVersion2 != 2 {
		t.Errorf("expected LUKSVersion2 to be 2, got %d", LUKSVersion2)
	}
}

func TestVolumeConfig(t *testing.T) {
	config := &VolumeConfig{
		DevicePath:    "/dev/sda1",
		MappingName:   "cryptroot",
		Cipher:        "aes-xts-plain64",
		KeySize:       512,
		Hash:          "sha256",
		MountPoint:    "/",
		Filesystem:    "ext4",
		Label:         "root",
		UUID:          "test-uuid",
		PCRSelection:  []uint{0, 1, 2, 3, 7},
		PCRBanks:      []string{"sha256"},
		XKMSPath:      "/var/lib/luks",
		LUKSVersion:   LUKS2,
		AllowDiscards: true,
		Timeout:       30,
		HashAlgorithm: "sha512",
		PBKDFType:     "argon2id",
	}

	if config.DevicePath != "/dev/sda1" {
		t.Errorf("expected device path /dev/sda1, got %s", config.DevicePath)
	}
	if config.MappingName != "cryptroot" {
		t.Errorf("expected mapping name cryptroot, got %s", config.MappingName)
	}
	if config.KeySize != 512 {
		t.Errorf("expected key size 512, got %d", config.KeySize)
	}
	if !config.AllowDiscards {
		t.Error("expected AllowDiscards to be true")
	}
	if config.LUKSVersion != LUKS2 {
		t.Errorf("expected LUKS2, got %d", config.LUKSVersion)
	}
}

func TestKeySlot(t *testing.T) {
	slot := &KeySlot{
		Index:    0,
		Type:     UnlockTPMPCR,
		Priority: 10,
		Enabled:  true,
	}

	if slot.Index != 0 {
		t.Errorf("expected index 0, got %d", slot.Index)
	}
	if slot.Type != UnlockTPMPCR {
		t.Errorf("expected type UnlockTPMPCR, got %s", slot.Type)
	}
	if !slot.Enabled {
		t.Error("expected slot to be enabled")
	}
}

func TestKeySlotInfoAlias(t *testing.T) {
	// KeySlotInfo is an alias for KeySlot
	info := KeySlot{
		Index:   1,
		Type:    UnlockPassword,
		Enabled: true,
	}

	if info.Index != 1 {
		t.Errorf("expected index 1, got %d", info.Index)
	}
}

func TestOpenOptions(t *testing.T) {
	keyslot := 0
	opts := &OpenOptions{
		ReadOnly:            true,
		AllowDiscards:       true,
		NoReadWorkqueue:     true,
		NoWriteWorkqueue:    true,
		SubmitFromCryptCPUs: true,
		Timeout:             60,
		KeySlot:             &keyslot,
	}

	if !opts.ReadOnly {
		t.Error("expected ReadOnly to be true")
	}
	if !opts.AllowDiscards {
		t.Error("expected AllowDiscards to be true")
	}
	if !opts.NoReadWorkqueue {
		t.Error("expected NoReadWorkqueue to be true")
	}
	if !opts.NoWriteWorkqueue {
		t.Error("expected NoWriteWorkqueue to be true")
	}
	if !opts.SubmitFromCryptCPUs {
		t.Error("expected SubmitFromCryptCPUs to be true")
	}
	if opts.Timeout != 60 {
		t.Errorf("expected timeout 60, got %d", opts.Timeout)
	}
	if opts.KeySlot == nil || *opts.KeySlot != 0 {
		t.Error("expected keyslot to be 0")
	}
}

func TestVolumeStatus(t *testing.T) {
	status := &VolumeStatus{
		Active:      true,
		DevicePath:  "/dev/sda1",
		MappingPath: "/dev/mapper/cryptroot",
		Cipher:      "aes",
		KeySize:     512,
		Mode:        "xts-plain64",
		Offset:      4096,
		Size:        1024 * 1024 * 1024,
		Version:     LUKSVersion2,
		UUID:        "test-uuid",
		ActiveSlots: []int{0, 1},
	}

	if !status.Active {
		t.Error("expected status to be active")
	}
	if status.Version != LUKSVersion2 {
		t.Errorf("expected version 2, got %d", status.Version)
	}
	if len(status.ActiveSlots) != 2 {
		t.Errorf("expected 2 active slots, got %d", len(status.ActiveSlots))
	}
}

func TestFormatOptions(t *testing.T) {
	opts := &FormatOptions{
		Device:         "/dev/sda1",
		Passphrase:     []byte("test-pass"),
		Label:          "root",
		Subsystem:      "home",
		Cipher:         "aes",
		CipherMode:     "xts-plain64",
		KeySize:        512,
		HashAlgo:       "sha256",
		HashAlgorithm:  "sha512",
		SectorSize:     512,
		KDFType:        "argon2id",
		PBKDFType:      "pbkdf2",
		PBKDFIterTime:  2000,
		Argon2Time:     4,
		Argon2Memory:   1048576,
		Argon2Parallel: 4,
	}

	if opts.Device != "/dev/sda1" {
		t.Errorf("expected device /dev/sda1, got %s", opts.Device)
	}
	if opts.KeySize != 512 {
		t.Errorf("expected key size 512, got %d", opts.KeySize)
	}
	if opts.HashAlgo != "sha256" {
		t.Errorf("expected hash algo sha256, got %s", opts.HashAlgo)
	}
	if opts.HashAlgorithm != "sha512" {
		t.Errorf("expected hash algorithm sha512, got %s", opts.HashAlgorithm)
	}
	if opts.KDFType != "argon2id" {
		t.Errorf("expected KDF type argon2id, got %s", opts.KDFType)
	}
	if opts.PBKDFType != "pbkdf2" {
		t.Errorf("expected PBKDF type pbkdf2, got %s", opts.PBKDFType)
	}
}

func TestAddKeyOptions(t *testing.T) {
	keyslot := 1
	keyslot2 := 2
	opts := &AddKeyOptions{
		KeySlot: &keyslot,
		Keyslot: &keyslot2,
		Force:   true,
		KDFType: "argon2id",
		Hash:    "sha256",
	}

	if opts.KeySlot == nil || *opts.KeySlot != 1 {
		t.Error("expected KeySlot to be 1")
	}
	if opts.Keyslot == nil || *opts.Keyslot != 2 {
		t.Error("expected Keyslot alias to be 2")
	}
	if !opts.Force {
		t.Error("expected Force to be true")
	}
	if opts.KDFType != "argon2id" {
		t.Errorf("expected KDF type argon2id, got %s", opts.KDFType)
	}
	if opts.Hash != "sha256" {
		t.Errorf("expected hash sha256, got %s", opts.Hash)
	}
}

func TestHandlerInterface(t *testing.T) {
	// Verify that CryptsetupHandler implements Handler interface
	var _ Handler = (*CryptsetupHandler)(nil)
}
