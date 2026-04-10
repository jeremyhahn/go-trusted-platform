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

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if config.Mode != ModeInstall {
		t.Errorf("expected mode ModeInstall, got %v", config.Mode)
	}

	if config.RootDevice != "/dev/sda2" {
		t.Errorf("expected root device /dev/sda2, got %s", config.RootDevice)
	}

	if config.BootDevice != "/dev/sda1" {
		t.Errorf("expected boot device /dev/sda1, got %s", config.BootDevice)
	}

	if config.XKMSPath != "/var/lib/trusted-platform/xkms" {
		t.Errorf("expected xkms path /var/lib/trusted-platform/xkms, got %s", config.XKMSPath)
	}

	if len(config.PCRBanks) != 1 || config.PCRBanks[0] != "sha256" {
		t.Errorf("expected PCRBanks [sha256], got %v", config.PCRBanks)
	}

	if config.PCRSelection != nil {
		t.Errorf("expected PCRSelection to be nil (must be set from installer), got %v", config.PCRSelection)
	}

	if config.UnlockTimeout != 30 {
		t.Errorf("expected unlock timeout 30, got %d", config.UnlockTimeout)
	}

	if config.RetryCount != 3 {
		t.Errorf("expected retry count 3, got %d", config.RetryCount)
	}

	if !config.EnableAuditLog {
		t.Error("expected audit log to be enabled")
	}

	if len(config.FallbackMethods) != 4 {
		t.Errorf("expected 4 fallback methods, got %d", len(config.FallbackMethods))
	}

	expectedMethods := []luks.UnlockMethod{
		luks.UnlockTPMPCR,
		luks.UnlockTPMUpgrade,
		luks.UnlockFIDO2,
		luks.UnlockPassword,
	}

	for i, method := range expectedMethods {
		if config.FallbackMethods[i] != method {
			t.Errorf("expected fallback method %d to be %v, got %v", i, method, config.FallbackMethods[i])
		}
	}
}

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("/some/path/config.yaml")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config == nil {
		t.Fatal("LoadConfig returned nil config")
	}

	// Current implementation returns default config
	if config.Mode != ModeInstall {
		t.Errorf("expected mode ModeInstall, got %v", config.Mode)
	}
}

func TestSaveConfig(t *testing.T) {
	config := &Config{
		Mode:            ModeBoot,
		RootDevice:      "/dev/sda2",
		BootDevice:      "/dev/sda1",
		XKMSPath:        "/var/lib/trusted-platform/xkms",
		PCRBanks:        []string{"sha256"},
		PCRSelection:    []uint{0, 1, 2, 3, 7},
		UnlockTimeout:   30,
		FallbackMethods: []luks.UnlockMethod{luks.UnlockTPMPCR},
		RetryCount:      3,
		EnableAuditLog:  true,
		AuditLogPath:    "/var/log/initrd-unlock.log",
	}

	err := SaveConfig(config, "/tmp/test-config.yaml")
	if err != nil {
		t.Errorf("SaveConfig failed: %v", err)
	}
}

func TestSaveConfigInvalid(t *testing.T) {
	// Invalid config with empty RootDevice
	config := &Config{
		Mode:         ModeBoot,
		RootDevice:   "", // Invalid
		XKMSPath:     "/var/lib/trusted-platform/xkms",
		PCRSelection: []uint{0, 1, 2},
	}

	err := SaveConfig(config, "/tmp/test-config.yaml")
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestMergeConfig(t *testing.T) {
	base := &Config{
		Mode:            ModeBoot,
		RootDevice:      "/dev/sda2",
		BootDevice:      "/dev/sda1",
		XKMSPath:        "/var/lib/trusted-platform/xkms",
		PCRBanks:        []string{"sha256"},
		PCRSelection:    []uint{0, 1, 2},
		UnlockTimeout:   30,
		FallbackMethods: []luks.UnlockMethod{luks.UnlockTPMPCR},
		RetryCount:      3,
		AuditLogPath:    "/var/log/initrd.log",
	}

	override := &Config{
		Mode:            ModeRecovery,
		RootDevice:      "/dev/nvme0n1p2",
		PCRSelection:    []uint{0, 1, 2, 3, 7},
		UnlockTimeout:   60,
		FallbackMethods: []luks.UnlockMethod{luks.UnlockPassword},
	}

	result := MergeConfig(base, override)

	// Check overridden values
	if result.Mode != ModeRecovery {
		t.Errorf("expected mode ModeRecovery, got %v", result.Mode)
	}

	if result.RootDevice != "/dev/nvme0n1p2" {
		t.Errorf("expected root device /dev/nvme0n1p2, got %s", result.RootDevice)
	}

	if len(result.PCRSelection) != 5 {
		t.Errorf("expected 5 PCR selections, got %d", len(result.PCRSelection))
	}

	if result.UnlockTimeout != 60 {
		t.Errorf("expected unlock timeout 60, got %d", result.UnlockTimeout)
	}

	if len(result.FallbackMethods) != 1 || result.FallbackMethods[0] != luks.UnlockPassword {
		t.Errorf("expected fallback methods [Password], got %v", result.FallbackMethods)
	}

	// Check preserved values from base
	if result.BootDevice != "/dev/sda1" {
		t.Errorf("expected boot device /dev/sda1, got %s", result.BootDevice)
	}

	if result.XKMSPath != "/var/lib/trusted-platform/xkms" {
		t.Errorf("expected xkms path /var/lib/trusted-platform/xkms, got %s", result.XKMSPath)
	}

	if result.RetryCount != 3 {
		t.Errorf("expected retry count 3, got %d", result.RetryCount)
	}
}

func TestMergeConfigEmptyOverride(t *testing.T) {
	base := &Config{
		Mode:         ModeBoot,
		RootDevice:   "/dev/sda2",
		BootDevice:   "/dev/sda1",
		XKMSPath:     "/var/lib/trusted-platform/xkms",
		PCRBanks:     []string{"sha256"},
		PCRSelection: []uint{0, 1, 2},
	}

	override := &Config{}

	result := MergeConfig(base, override)

	// All values should be from base
	if result.Mode != ModeBoot {
		t.Errorf("expected mode ModeBoot, got %v", result.Mode)
	}

	if result.RootDevice != "/dev/sda2" {
		t.Errorf("expected root device /dev/sda2, got %s", result.RootDevice)
	}

	if result.BootDevice != "/dev/sda1" {
		t.Errorf("expected boot device /dev/sda1, got %s", result.BootDevice)
	}
}

func TestMergeConfigPCRBanks(t *testing.T) {
	base := &Config{
		RootDevice:   "/dev/sda2",
		XKMSPath:     "/var/lib/trusted-platform/xkms",
		PCRBanks:     []string{"sha256"},
		PCRSelection: []uint{0, 1, 2},
	}

	override := &Config{
		PCRBanks: []string{"sha256", "sha384"},
	}

	result := MergeConfig(base, override)

	if len(result.PCRBanks) != 2 {
		t.Errorf("expected 2 PCR banks, got %d", len(result.PCRBanks))
	}

	if result.PCRBanks[0] != "sha256" || result.PCRBanks[1] != "sha384" {
		t.Errorf("expected PCR banks [sha256 sha384], got %v", result.PCRBanks)
	}
}

func TestMergeConfigUpgradePCRSelection(t *testing.T) {
	base := &Config{
		RootDevice:          "/dev/sda2",
		XKMSPath:            "/var/lib/trusted-platform/xkms",
		PCRSelection:        []uint{0, 1, 2},
		UpgradePCRSelection: []uint{7},
	}

	override := &Config{
		UpgradePCRSelection: []uint{7, 14},
	}

	result := MergeConfig(base, override)

	if len(result.UpgradePCRSelection) != 2 {
		t.Errorf("expected 2 upgrade PCR selections, got %d", len(result.UpgradePCRSelection))
	}

	if result.UpgradePCRSelection[0] != 7 || result.UpgradePCRSelection[1] != 14 {
		t.Errorf("expected upgrade PCR selection [7 14], got %v", result.UpgradePCRSelection)
	}
}
