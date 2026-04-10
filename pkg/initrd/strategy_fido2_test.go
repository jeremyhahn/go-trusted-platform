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
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewFIDO2Strategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	if strategy == nil {
		t.Fatal("NewFIDO2Strategy returned nil")
	}

	if strategy.Name() != "FIDO2" {
		t.Errorf("expected name FIDO2, got %s", strategy.Name())
	}

	if strategy.Priority() != 3 {
		t.Errorf("expected priority 3, got %d", strategy.Priority())
	}
}

func TestFIDO2StrategyCanUnlockNoHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.FIDO2 = nil

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockFIDO2},
		},
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false when FIDO2 handler is nil")
	}
}

func TestFIDO2StrategyCanUnlockNoFIDO2Slot(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	// FIDO2 is nil by default in createTestPlatform

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockTPMPCR},
			{Index: 1, Type: luks.UnlockPassword},
		},
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false without FIDO2 key slot")
	}
}

func TestFIDO2StrategyCanUnlockEmptySlots(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.FIDO2 = nil

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots:    []luks.KeySlot{},
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false with empty slots")
	}
}

func TestFIDO2StrategyUnlockNoFIDO2Slots(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error when no FIDO2 slots")
	}
}

func TestFIDO2StrategyUnlockContextCanceled(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockFIDO2},
		},
	}

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestFIDO2StrategyInstallNoHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.FIDO2 = nil

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockFIDO2},
		},
	}

	err := strategy.Install(ctx, volume, []byte("password"))
	if err == nil {
		t.Error("expected error when FIDO2 handler is nil")
	}
}

func TestFIDO2StrategyInstallNoFIDO2Slot(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Install(ctx, volume, []byte("password"))
	if err == nil {
		t.Error("expected error when no FIDO2 key slot configured")
	}
}

func TestFIDO2StrategyLoadAuthConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	slot := luks.KeySlot{
		Index: 0,
		Type:  luks.UnlockFIDO2,
	}

	config, err := strategy.loadAuthConfig(slot)
	if err != nil {
		t.Fatalf("loadAuthConfig failed: %v", err)
	}

	if config == nil {
		t.Fatal("loadAuthConfig returned nil config")
	}

	if config.RelyingPartyID != "luks-root" {
		t.Errorf("expected relying party ID luks-root, got %s", config.RelyingPartyID)
	}

	if config.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
}

func TestFIDO2StrategyLoadAuthConfigDifferentSlots(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	// Test with different slot indexes
	for _, idx := range []int{0, 1, 5, 10} {
		slot := luks.KeySlot{
			Index: idx,
			Type:  luks.UnlockFIDO2,
		}

		config, err := strategy.loadAuthConfig(slot)
		if err != nil {
			t.Errorf("loadAuthConfig failed for slot %d: %v", idx, err)
			continue
		}

		if config == nil {
			t.Errorf("loadAuthConfig returned nil for slot %d", idx)
		}
	}
}

func TestFIDO2StrategyStoreEnrollmentMetadata(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewFIDO2Strategy(platform, logger)

	slot := &luks.KeySlot{
		Index: 0,
		Type:  luks.UnlockFIDO2,
	}

	// Should not panic - it's a no-op currently
	strategy.storeEnrollmentMetadata(slot, nil)
}
