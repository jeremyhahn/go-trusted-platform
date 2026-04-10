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

func TestNewTPMNoPCRStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewTPMNoPCRStrategy(platform, logger)

	if strategy == nil {
		t.Fatal("NewTPMNoPCRStrategy returned nil")
	}

	if strategy.Name() != "TPM-NoPCR" {
		t.Errorf("expected name TPM-NoPCR, got %s", strategy.Name())
	}

	if strategy.Priority() != 5 {
		t.Errorf("expected priority 5, got %d", strategy.Priority())
	}
}

func TestTPMNoPCRStrategyCanUnlockNoTPM(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMNoPCRStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false when TPM is nil")
	}
}

func TestTPMNoPCRStrategyCanUnlockNoSealFiles(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	tmpDir := t.TempDir()
	platform.Config.XKMSPath = tmpDir

	strategy := NewTPMNoPCRStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false (no TPM)")
	}
}

func TestTPMNoPCRStrategyGetPlatformKeystoreSRKHandleDefault(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMNoPCRStrategy(platform, logger)

	handle := strategy.getPlatformKeystoreSRKHandle()
	if handle != 0x81000002 {
		t.Errorf("expected default handle 0x81000002, got 0x%08x", handle)
	}
}

func TestTPMNoPCRStrategyGetPlatformPolicyDefault(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMNoPCRStrategy(platform, logger)

	policy := strategy.getPlatformPolicy()
	if !policy {
		t.Error("expected default platform policy to be true")
	}
}
