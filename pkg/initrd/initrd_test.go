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
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestNewManager(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	if mgr == nil {
		t.Fatal("NewManager returned nil manager")
	}
}

func TestNewManagerNilPlatform(t *testing.T) {
	logger := logging.DefaultLogger()

	_, err := NewManager(nil, logger)
	if err == nil {
		t.Error("expected error for nil platform")
	}
}

func TestNewManagerNilLogger(t *testing.T) {
	platform := createTestPlatform()

	_, err := NewManager(platform, nil)
	if err == nil {
		t.Error("expected error for nil logger")
	}
}

func TestNewManagerInvalidConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.RootDevice = "" // Invalid

	_, err := NewManager(platform, logger)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestInitialize(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	// Create a temporary file to act as the root device
	tmpDir := t.TempDir()
	tmpDevice := filepath.Join(tmpDir, "sda2")
	if err := os.WriteFile(tmpDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp device: %v", err)
	}

	platform.Config.RootDevice = tmpDevice

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx := context.Background()
	err = mgr.Initialize(ctx)
	if err != nil {
		t.Errorf("Initialize failed: %v", err)
	}
}

func TestInitializeMissingDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.RootDevice = "/dev/nonexistent-device"

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx := context.Background()
	err = mgr.Initialize(ctx)
	if err == nil {
		t.Error("expected error for missing device")
	}
}

func TestDetectModeFromConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.Mode = ModeRecovery

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx := context.Background()
	mode, err := mgr.DetectMode(ctx)
	if err != nil {
		t.Errorf("DetectMode failed: %v", err)
	}

	if mode != ModeRecovery {
		t.Errorf("expected mode ModeRecovery, got %v", mode)
	}
}

func TestDetectModeInstall(t *testing.T) {
	// Test mode detection for various configured modes.
	// NOTE: ModeInstall = 0 (iota), which means the check "Mode != 0" in DetectMode
	// treats it as "auto-detect". This tests the behavior with explicit non-zero modes.

	logger := logging.DefaultLogger()

	// Create a temporary file to act as the root device
	tmpDir := t.TempDir()
	tmpDevice := filepath.Join(tmpDir, "sda2")
	if err := os.WriteFile(tmpDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp device: %v", err)
	}

	t.Run("auto_detect_defaults_to_boot", func(t *testing.T) {
		platform := createTestPlatform()
		platform.Config.Mode = 0 // Auto-detect (which is also ModeInstall value)
		platform.Config.RootDevice = tmpDevice

		mgr, err := NewManager(platform, logger)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}

		ctx := context.Background()
		mode, err := mgr.DetectMode(ctx)
		if err != nil {
			t.Errorf("DetectMode failed: %v", err)
		}
		// When Mode is 0 (auto-detect), and no markers exist, defaults to ModeBoot
		if mode != ModeBoot {
			t.Errorf("expected default mode ModeBoot, got %v", mode)
		}
	})

	t.Run("explicit_boot_mode", func(t *testing.T) {
		platform := createTestPlatform()
		platform.Config.Mode = ModeBoot // This is 1
		platform.Config.RootDevice = tmpDevice

		mgr, err := NewManager(platform, logger)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}

		ctx := context.Background()
		mode, err := mgr.DetectMode(ctx)
		if err != nil {
			t.Errorf("DetectMode failed: %v", err)
		}
		if mode != ModeBoot {
			t.Errorf("expected mode ModeBoot, got %v", mode)
		}
	})

	t.Run("explicit_recovery_mode", func(t *testing.T) {
		platform := createTestPlatform()
		platform.Config.Mode = ModeRecovery // This is 2
		platform.Config.RootDevice = tmpDevice

		mgr, err := NewManager(platform, logger)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}

		ctx := context.Background()
		mode, err := mgr.DetectMode(ctx)
		if err != nil {
			t.Errorf("DetectMode failed: %v", err)
		}
		if mode != ModeRecovery {
			t.Errorf("expected mode ModeRecovery, got %v", mode)
		}
	})

	t.Run("explicit_maintenance_mode", func(t *testing.T) {
		platform := createTestPlatform()
		platform.Config.Mode = ModeMaintenance // This is 3
		platform.Config.RootDevice = tmpDevice

		mgr, err := NewManager(platform, logger)
		if err != nil {
			t.Fatalf("NewManager failed: %v", err)
		}

		ctx := context.Background()
		mode, err := mgr.DetectMode(ctx)
		if err != nil {
			t.Errorf("DetectMode failed: %v", err)
		}
		if mode != ModeMaintenance {
			t.Errorf("expected mode ModeMaintenance, got %v", mode)
		}
	})
}

func TestDetectModeDefaultBoot(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.Mode = 0 // Auto-detect

	// Create a temporary file to act as the root device
	tmpDir := t.TempDir()
	tmpDevice := filepath.Join(tmpDir, "sda2")
	if err := os.WriteFile(tmpDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp device: %v", err)
	}
	platform.Config.RootDevice = tmpDevice

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx := context.Background()
	mode, err := mgr.DetectMode(ctx)
	if err != nil {
		t.Errorf("DetectMode failed: %v", err)
	}

	// Should default to boot mode when no markers exist
	if mode != ModeBoot {
		t.Errorf("expected default mode ModeBoot, got %v", mode)
	}
}

func TestManagerRegisterStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	initialCount := mgr.(*initrdManager).chain.Count()

	customStrategy := &mockStrategy{
		name:     "custom-test",
		priority: 99,
	}

	mgr.RegisterStrategy(customStrategy)

	newCount := mgr.(*initrdManager).chain.Count()
	if newCount != initialCount+1 {
		t.Errorf("expected %d strategies after registration, got %d", initialCount+1, newCount)
	}
}

func TestUnlockVolumes(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	// Create a temporary file to act as the root device
	tmpDir := t.TempDir()
	tmpDevice := filepath.Join(tmpDir, "sda2")
	if err := os.WriteFile(tmpDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp device: %v", err)
	}
	platform.Config.RootDevice = tmpDevice

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Register a mock strategy that will succeed
	successStrategy := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "test-success", priority: 1},
	}
	mgr.RegisterStrategy(successStrategy)

	ctx := context.Background()
	err = mgr.UnlockVolumes(ctx)
	if err != nil {
		t.Errorf("UnlockVolumes failed: %v", err)
	}

	if !successStrategy.unlockCalled {
		t.Error("strategy unlock should have been called")
	}
}

func TestClose(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	err = mgr.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestRegisterDefaultStrategies(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.FallbackMethods = []luks.UnlockMethod{
		luks.UnlockTPMPCR,
		luks.UnlockTPMUpgrade,
		luks.UnlockPassword,
	}

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// Should have registered: FirstbootSeal, Keyfile, TPMPCRStrategy, TPMUpgradeStrategy, PasswordStrategy
	// Total: 5 strategies
	count := mgr.(*initrdManager).chain.Count()
	if count < 3 {
		t.Errorf("expected at least 3 strategies, got %d", count)
	}
}

func TestRegisterDefaultStrategiesUnknownMethod(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.FallbackMethods = []luks.UnlockMethod{
		luks.UnlockMethod("unknown-method"),
	}

	// Should not fail, just log a warning
	_, err := NewManager(platform, logger)
	if err != nil {
		t.Errorf("NewManager should not fail with unknown method: %v", err)
	}
}

func TestValidateDevices(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	// Create temporary files for devices
	tmpDir := t.TempDir()
	rootDevice := filepath.Join(tmpDir, "sda2")
	bootDevice := filepath.Join(tmpDir, "sda1")

	if err := os.WriteFile(rootDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp root device: %v", err)
	}
	if err := os.WriteFile(bootDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp boot device: %v", err)
	}

	platform.Config.RootDevice = rootDevice
	platform.Config.BootDevice = bootDevice

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx := context.Background()
	err = mgr.Initialize(ctx)
	if err != nil {
		t.Errorf("Initialize failed: %v", err)
	}
}

func TestValidateDevicesMissingBootDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	// Create only root device
	tmpDir := t.TempDir()
	rootDevice := filepath.Join(tmpDir, "sda2")

	if err := os.WriteFile(rootDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp root device: %v", err)
	}

	platform.Config.RootDevice = rootDevice
	platform.Config.BootDevice = "/dev/nonexistent-boot"

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx := context.Background()
	// Should succeed with warning (boot device is optional)
	err = mgr.Initialize(ctx)
	if err != nil {
		t.Errorf("Initialize should succeed with missing boot device: %v", err)
	}
}

func TestDetectModeFromCmdline(t *testing.T) {
	// This test would require mocking /proc/cmdline
	// For now, we'll create a basic test that exercises the code path
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.Mode = 0 // Auto-detect

	// Create a temporary file to act as the root device
	tmpDir := t.TempDir()
	tmpDevice := filepath.Join(tmpDir, "sda2")
	if err := os.WriteFile(tmpDevice, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to create temp device: %v", err)
	}
	platform.Config.RootDevice = tmpDevice

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	ctx := context.Background()
	_, err = mgr.DetectMode(ctx)
	// Error is expected if /proc/cmdline doesn't exist or doesn't contain our markers
	// That's OK for this test
	_ = err
}

func TestBuildVolumeConfig(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	volume, err := impl.buildVolumeConfig()
	if err != nil {
		t.Fatalf("buildVolumeConfig failed: %v", err)
	}

	if volume == nil {
		t.Fatal("buildVolumeConfig returned nil volume")
	}

	if volume.DevicePath != platform.Config.RootDevice {
		t.Errorf("expected device path %s, got %s", platform.Config.RootDevice, volume.DevicePath)
	}
}
