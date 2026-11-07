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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

func TestBuildVolumeConfigKeySlotsPriority(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.FallbackMethods = []luks.UnlockMethod{
		luks.UnlockTPMPCR,
		luks.UnlockTPMUpgrade,
		luks.UnlockFIDO2,
		luks.UnlockPassword,
	}

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	volume, err := impl.buildVolumeConfig()
	if err != nil {
		t.Fatalf("buildVolumeConfig failed: %v", err)
	}

	if len(volume.KeySlots) != 4 {
		t.Fatalf("expected 4 key slots, got %d", len(volume.KeySlots))
	}

	// Verify priorities
	expectedPriorities := map[luks.UnlockMethod]int{
		luks.UnlockTPMPCR:     1,
		luks.UnlockTPMUpgrade: 2,
		luks.UnlockFIDO2:      3,
		luks.UnlockPassword:   100,
	}

	for _, slot := range volume.KeySlots {
		expected, ok := expectedPriorities[slot.Type]
		if !ok {
			t.Errorf("unexpected slot type: %v", slot.Type)
			continue
		}
		if slot.Priority != expected {
			t.Errorf("slot %v: expected priority %d, got %d", slot.Type, expected, slot.Priority)
		}
	}
}

func TestBuildVolumeConfigKeySlotIndexes(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.FallbackMethods = []luks.UnlockMethod{
		luks.UnlockTPMPCR,
		luks.UnlockPassword,
	}

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	volume, err := impl.buildVolumeConfig()
	if err != nil {
		t.Fatalf("buildVolumeConfig failed: %v", err)
	}

	// Verify slot indexes are sequential
	for i, slot := range volume.KeySlots {
		if slot.Index != i {
			t.Errorf("expected slot index %d, got %d", i, slot.Index)
		}
	}
}

func TestBuildVolumeConfigEmptyRootDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	impl.platform.Config.RootDevice = ""

	_, err = impl.buildVolumeConfig()
	if err == nil {
		t.Error("expected error for empty root device")
	}

	if !errors.Is(err, ErrVolumeNotConfigured) {
		t.Errorf("expected ErrVolumeNotConfigured, got %v", err)
	}
}

func TestBuildVolumeConfigAllowDiscards(t *testing.T) {
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

	if !volume.AllowDiscards {
		t.Error("expected AllowDiscards to be true")
	}

	if volume.Timeout != platform.Config.UnlockTimeout {
		t.Errorf("expected timeout %d, got %d", platform.Config.UnlockTimeout, volume.Timeout)
	}
}

func TestBuildVolumeConfigNoFallbackMethods(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.FallbackMethods = nil

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	volume, err := impl.buildVolumeConfig()
	if err != nil {
		t.Fatalf("buildVolumeConfig failed: %v", err)
	}

	if len(volume.KeySlots) != 0 {
		t.Errorf("expected 0 key slots with no fallback methods, got %d", len(volume.KeySlots))
	}
}

func TestUnlockWithAuditSuccess(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	// Add a successful strategy
	successStrategy := &mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "test-success", priority: 1},
	}
	impl.chain.Add(successStrategy)

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	auditLog := &AuditLog{
		Attempts: make([]UnlockAttempt, 0),
	}

	err = impl.unlockWithAudit(context.Background(), volume, auditLog)
	if err != nil {
		t.Errorf("expected success: %v", err)
	}

	if len(auditLog.Attempts) != 1 {
		t.Errorf("expected 1 audit attempt, got %d", len(auditLog.Attempts))
	}

	if !auditLog.Attempts[0].Success {
		t.Error("expected first attempt to be successful")
	}

	if auditLog.Attempts[0].Strategy != "test-success" {
		t.Errorf("expected strategy name test-success, got %s", auditLog.Attempts[0].Strategy)
	}
}

func TestUnlockWithAuditFailure(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	// Clear default strategies and add only a failing one
	impl.chain = NewStrategyChain(logger)
	failStrategy := &mockFailStrategy{
		mockStrategy: mockStrategy{name: "test-fail", priority: 1},
	}
	impl.chain.Add(failStrategy)

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	auditLog := &AuditLog{
		Attempts: make([]UnlockAttempt, 0),
	}

	err = impl.unlockWithAudit(context.Background(), volume, auditLog)
	if err == nil {
		t.Error("expected error")
	}

	if len(auditLog.Attempts) != 1 {
		t.Errorf("expected 1 audit attempt, got %d", len(auditLog.Attempts))
	}

	if auditLog.Attempts[0].Success {
		t.Error("expected attempt to be marked as failed")
	}

	if auditLog.Attempts[0].Error == "" {
		t.Error("expected error message in audit attempt")
	}
}

func TestUnlockWithAuditCannotUnlock(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	// Clear default strategies and add one that can't unlock
	impl.chain = NewStrategyChain(logger)
	cannotUnlockStrategy := &mockCannotUnlockStrategy{
		mockStrategy: mockStrategy{name: "test-cannot", priority: 1},
	}
	impl.chain.Add(cannotUnlockStrategy)

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	auditLog := &AuditLog{
		Attempts: make([]UnlockAttempt, 0),
	}

	err = impl.unlockWithAudit(context.Background(), volume, auditLog)
	if err == nil {
		t.Error("expected error when no strategy can unlock")
	}

	if !errors.Is(err, ErrUnlockFailed) {
		t.Errorf("expected ErrUnlockFailed, got %v", err)
	}

	// No attempts should be recorded since CanUnlock returned false
	if len(auditLog.Attempts) != 0 {
		t.Errorf("expected 0 audit attempts (skipped), got %d", len(auditLog.Attempts))
	}
}

func TestUnlockWithAuditMultipleStrategies(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	impl.chain = NewStrategyChain(logger)

	// First strategy fails, second succeeds
	impl.chain.Add(&mockFailStrategy{
		mockStrategy: mockStrategy{name: "fail-first", priority: 1},
	})
	impl.chain.Add(&mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "succeed-second", priority: 2},
	})

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	auditLog := &AuditLog{
		Attempts: make([]UnlockAttempt, 0),
	}

	err = impl.unlockWithAudit(context.Background(), volume, auditLog)
	if err != nil {
		t.Errorf("expected success from fallback: %v", err)
	}

	if len(auditLog.Attempts) != 2 {
		t.Fatalf("expected 2 audit attempts, got %d", len(auditLog.Attempts))
	}

	if auditLog.Attempts[0].Success {
		t.Error("expected first attempt to fail")
	}
	if !auditLog.Attempts[1].Success {
		t.Error("expected second attempt to succeed")
	}
}

func TestSaveAuditLogDisabled(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.EnableAuditLog = false

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	auditLog := &AuditLog{
		Mode:        ModeBoot,
		FinalStatus: true,
	}

	// Should return immediately without panic
	impl.saveAuditLog(auditLog)
}

func TestSaveAuditLogEnabled(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.EnableAuditLog = true

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	auditLog := &AuditLog{
		Mode:          ModeBoot,
		FinalStatus:   true,
		TotalDuration: 100,
		Attempts: []UnlockAttempt{
			{
				Strategy: "test",
				Success:  true,
				Duration: 50,
			},
			{
				Strategy: "test2",
				Success:  false,
				Error:    "test error",
				Duration: 30,
			},
		},
	}

	// Should not panic, logs summary
	impl.saveAuditLog(auditLog)
}

func TestSaveAuditLogEmptyAttempts(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.EnableAuditLog = true

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	auditLog := &AuditLog{
		Mode:          ModeRecovery,
		FinalStatus:   false,
		TotalDuration: 0,
		Attempts:      []UnlockAttempt{},
	}

	// Should not panic
	impl.saveAuditLog(auditLog)
}

func TestRegisterNilStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	initialCount := mgr.(*initrdManager).chain.Count()

	// Registering nil strategy should be a no-op
	mgr.RegisterStrategy(nil)

	afterCount := mgr.(*initrdManager).chain.Count()
	if afterCount != initialCount {
		t.Errorf("expected count %d after nil register, got %d", initialCount, afterCount)
	}
}

func TestStrategyChainAddNil(t *testing.T) {
	logger := logging.DefaultLogger()
	chain := NewStrategyChain(logger)

	chain.Add(nil)

	if chain.Count() != 0 {
		t.Errorf("expected 0 strategies after adding nil, got %d", chain.Count())
	}
}

func TestMultiDriveRegisterNilStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	config := createTestStorageConfig()

	mgr, err := NewMultiDriveManager(platform, config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	initialCount := mgr.chain.Count()

	// Registering nil strategy should be a no-op
	mgr.RegisterStrategy(nil)

	if mgr.chain.Count() != initialCount {
		t.Errorf("expected count %d after nil register, got %d", initialCount, mgr.chain.Count())
	}
}

func TestRegisterDefaultStrategiesWithFIDO2(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.FallbackMethods = []luks.UnlockMethod{
		luks.UnlockFIDO2,
	}

	// With FIDO2 handler nil, FIDO2 strategy should be skipped with warning
	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	// FIDO2 should not be registered since handler is nil
	impl := mgr.(*initrdManager)
	for _, s := range impl.chain.List() {
		if s.Name() == "FIDO2" {
			t.Error("FIDO2 strategy should not be registered when handler is nil")
		}
	}
}

func TestRegisterDefaultStrategiesAllMethods(t *testing.T) {
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

	impl := mgr.(*initrdManager)
	// Should have Keyfile + TPM-PCR + TPM-Upgrade + Password = 4 minimum
	count := impl.chain.Count()
	if count < 4 {
		t.Errorf("expected at least 4 strategies, got %d", count)
	}

	// Verify specific strategies are registered
	names := make(map[string]bool)
	for _, s := range impl.chain.List() {
		names[s.Name()] = true
	}

	expectedNames := []string{"Keyfile", "TPM-PCR", "TPM-Upgrade", "Password"}
	for _, name := range expectedNames {
		if !names[name] {
			t.Errorf("expected strategy %s to be registered", name)
		}
	}
}

func TestMergeConfigAuditLogPath(t *testing.T) {
	base := &Config{
		RootDevice:   "/dev/sda2",
		XKMSPath:     "/var/lib/xkms",
		PCRSelection: []uint{0, 1},
		AuditLogPath: "/var/log/base.log",
	}

	override := &Config{
		AuditLogPath: "/var/log/override.log",
	}

	result := MergeConfig(base, override)
	if result.AuditLogPath != "/var/log/override.log" {
		t.Errorf("expected audit log path /var/log/override.log, got %s", result.AuditLogPath)
	}
}

func TestMergeConfigRetryCount(t *testing.T) {
	base := &Config{
		RootDevice:   "/dev/sda2",
		XKMSPath:     "/var/lib/xkms",
		PCRSelection: []uint{0, 1},
		RetryCount:   3,
	}

	override := &Config{
		RetryCount: 5,
	}

	result := MergeConfig(base, override)
	if result.RetryCount != 5 {
		t.Errorf("expected retry count 5, got %d", result.RetryCount)
	}
}

func TestMergeConfigBoolFieldsPreserved(t *testing.T) {
	base := &Config{
		RootDevice:     "/dev/sda2",
		XKMSPath:       "/var/lib/xkms",
		PCRSelection:   []uint{0, 1},
		EnableAuditLog: true,
		FIPS:           true,
	}

	override := &Config{}

	result := MergeConfig(base, override)
	if !result.EnableAuditLog {
		t.Error("expected EnableAuditLog to be preserved from base")
	}
	if !result.FIPS {
		t.Error("expected FIPS to be preserved from base")
	}
}

func TestMergeConfigDoesNotMutateBase(t *testing.T) {
	base := &Config{
		RootDevice:   "/dev/sda2",
		XKMSPath:     "/var/lib/xkms",
		PCRSelection: []uint{0, 1},
		RetryCount:   3,
	}

	override := &Config{
		RootDevice: "/dev/nvme0n1p2",
		RetryCount: 5,
	}

	_ = MergeConfig(base, override)

	// Base should not be mutated
	if base.RootDevice != "/dev/sda2" {
		t.Error("MergeConfig mutated base config")
	}
	if base.RetryCount != 3 {
		t.Error("MergeConfig mutated base config retry count")
	}
}

func TestDisplayRecoveryMenu(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	// Should not panic
	impl.displayRecoveryMenu()
}

func TestReorderForRecovery(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	// Should not panic
	impl.reorderForRecovery()
}

func TestUnlockVolumesWithFailingChain(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)

	// Replace chain with one containing only failing strategies
	impl.chain = NewStrategyChain(logger)
	impl.chain.Add(&mockFailStrategy{
		mockStrategy: mockStrategy{name: "fail", priority: 1},
	})

	ctx := context.Background()
	err = mgr.UnlockVolumes(ctx)
	if err == nil {
		t.Error("expected error when all strategies fail")
	}
}

func TestUnlockVolumesEmptyRootDevice(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	impl.platform.Config.RootDevice = ""

	ctx := context.Background()
	err = mgr.UnlockVolumes(ctx)
	if err == nil {
		t.Error("expected error for empty root device")
	}
}

func TestUnlockWithAuditFallbackSuccess(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	mgr, err := NewManager(platform, logger)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	impl := mgr.(*initrdManager)
	impl.chain = NewStrategyChain(logger)

	// First strategy fails, second succeeds
	impl.chain.Add(&mockFailStrategy{
		mockStrategy: mockStrategy{name: "fail-first", priority: 1},
	})
	impl.chain.Add(&mockSuccessStrategy{
		mockStrategy: mockStrategy{name: "succeed-second", priority: 2},
	})

	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	auditLog := &AuditLog{
		Attempts: make([]UnlockAttempt, 0),
	}

	err = impl.unlockWithAudit(context.Background(), volume, auditLog)
	if err != nil {
		t.Errorf("expected success from fallback: %v", err)
	}

	if len(auditLog.Attempts) != 2 {
		t.Fatalf("expected 2 audit attempts, got %d", len(auditLog.Attempts))
	}

	if auditLog.Attempts[0].Success {
		t.Error("expected first attempt to fail")
	}
	if !auditLog.Attempts[1].Success {
		t.Error("expected second attempt to succeed")
	}
}
