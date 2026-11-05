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

func TestNewTPMUpgradeStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewTPMUpgradeStrategy(platform, logger)

	if strategy == nil {
		t.Fatal("NewTPMUpgradeStrategy returned nil")
	}

	if strategy.Name() != "TPM-Upgrade" {
		t.Errorf("expected name TPM-Upgrade, got %s", strategy.Name())
	}

	if strategy.Priority() != 2 {
		t.Errorf("expected priority 2, got %d", strategy.Priority())
	}
}

func TestTPMUpgradeStrategyCanUnlockNoTPM(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMUpgradeStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false when TPM is nil")
	}
}

func TestTPMUpgradeStrategyGetEFIPath(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewTPMUpgradeStrategy(platform, logger)

	path := strategy.getEFIPath()
	if path != efiMountPoint {
		t.Errorf("expected EFI path %s, got %s", efiMountPoint, path)
	}
}

func TestTPMUpgradeStrategyGetSSRKHandleDefault(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.TPM = nil

	strategy := NewTPMUpgradeStrategy(platform, logger)

	handle := strategy.getSSRKHandle()
	if handle != 0x81000001 {
		t.Errorf("expected default SSRK handle 0x81000001, got 0x%08x", handle)
	}
}
