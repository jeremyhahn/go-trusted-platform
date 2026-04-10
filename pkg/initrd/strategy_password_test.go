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
	"bufio"
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
	"github.com/stretchr/testify/mock"
)

func TestNewPasswordStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewPasswordStrategy(platform, logger)

	if strategy == nil {
		t.Fatal("NewPasswordStrategy returned nil")
	}

	if strategy.Name() != "Password" {
		t.Errorf("expected name Password, got %s", strategy.Name())
	}

	if strategy.Priority() != 100 {
		t.Errorf("expected priority 100, got %d", strategy.Priority())
	}
}

func TestPasswordStrategyCanUnlockWithPasswordSlot(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockPassword},
		},
	}

	if !strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return true with password slot")
	}
}

func TestPasswordStrategyCanUnlockNoPasswordSlot(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockTPMPCR},
		},
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false without password slot")
	}
}

func TestPasswordStrategyCanUnlockEmptySlots(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots:    []luks.KeySlot{},
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false with empty key slots")
	}
}

func TestPasswordStrategyCanUnlockMultipleSlots(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockTPMPCR},
			{Index: 1, Type: luks.UnlockFIDO2},
			{Index: 2, Type: luks.UnlockPassword},
		},
	}

	if !strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return true when password slot is among others")
	}
}

func TestPasswordStrategyUnlockPromptsDisabled(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.DisablePasswordPrompt = true

	strategy := NewPasswordStrategy(platform, logger)

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
		t.Error("expected error when password prompts are disabled")
	}
}

func TestPasswordStrategyUnlockNoPasswordSlots(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.DisablePasswordPrompt = false

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockTPMPCR},
		},
	}

	// Provide a reader so it doesn't block on stdin
	strategy.SetReader(bufio.NewReader(strings.NewReader("testpassword\n")))

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error when no password slots configured")
	}
}

func TestPasswordStrategyUnlockSuccess(t *testing.T) {
	logger := logging.DefaultLogger()

	mockLUKS := &MockLUKSHandler{}
	slotIdx := 0
	mockLUKS.On("Open",
		mock.Anything,
		"/dev/sda2",
		"cryptroot",
		[]byte("test-password"),
		mock.AnythingOfType("*luks.OpenOptions"),
	).Return(nil)

	platform := &Platform{
		LUKS: mockLUKS,
		Config: &Config{
			RootDevice:            "/dev/sda2",
			XKMSPath:              "/var/lib/test/xkms",
			PCRBanks:              []string{"sha256"},
			PCRSelection:          []uint{0, 1, 2, 3, 7},
			DisablePasswordPrompt: false,
		},
	}

	strategy := NewPasswordStrategy(platform, logger)
	strategy.SetReader(bufio.NewReader(strings.NewReader("test-password\n")))

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:    "/dev/sda2",
		MappingName:   "cryptroot",
		AllowDiscards: true,
		Timeout:       30,
		KeySlots: []luks.KeySlot{
			{Index: slotIdx, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Unlock(ctx, volume)
	if err != nil {
		t.Errorf("expected success, got: %v", err)
	}
}

func TestPasswordStrategyUnlockFallbackToNoSlot(t *testing.T) {
	logger := logging.DefaultLogger()

	slotErr := &testError{msg: "wrong password for slot"}
	mockLUKS := &MockLUKSHandler{}

	// First call with specific slot fails
	slotIdx := 0
	mockLUKS.On("Open",
		mock.Anything, "/dev/sda2", "cryptroot",
		[]byte("test-password"),
		mock.MatchedBy(func(opts *luks.OpenOptions) bool {
			return opts != nil && opts.KeySlot != nil && *opts.KeySlot == slotIdx
		}),
	).Return(slotErr)

	// Fallback call without slot succeeds
	mockLUKS.On("Open",
		mock.Anything, "/dev/sda2", "cryptroot",
		[]byte("test-password"),
		mock.MatchedBy(func(opts *luks.OpenOptions) bool {
			return opts != nil && opts.KeySlot == nil
		}),
	).Return(nil)

	platform := &Platform{
		LUKS: mockLUKS,
		Config: &Config{
			RootDevice:            "/dev/sda2",
			XKMSPath:              "/var/lib/test/xkms",
			PCRBanks:              []string{"sha256"},
			PCRSelection:          []uint{0, 1, 2, 3, 7},
			DisablePasswordPrompt: false,
		},
	}

	strategy := NewPasswordStrategy(platform, logger)
	strategy.SetReader(bufio.NewReader(strings.NewReader("test-password\n")))

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:    "/dev/sda2",
		MappingName:   "cryptroot",
		AllowDiscards: true,
		Timeout:       30,
		KeySlots: []luks.KeySlot{
			{Index: slotIdx, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Unlock(ctx, volume)
	if err != nil {
		t.Errorf("expected success from fallback, got: %v", err)
	}
}

func TestPasswordStrategySetReader(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewPasswordStrategy(platform, logger)

	if strategy.reader != nil {
		t.Error("expected reader to be nil initially")
	}

	reader := bufio.NewReader(strings.NewReader("test"))
	strategy.SetReader(reader)

	if strategy.reader != reader {
		t.Error("expected reader to be set")
	}
}

func TestPasswordStrategyInstallSuccess(t *testing.T) {
	logger := logging.DefaultLogger()

	mockLUKS := &MockLUKSHandler{}
	slotIdx := 0
	mockLUKS.On("TestKey",
		mock.Anything,
		"/dev/sda2",
		[]byte("test-password"),
		&slotIdx,
	).Return(nil)

	platform := &Platform{
		LUKS: mockLUKS,
		Config: &Config{
			RootDevice:   "/dev/sda2",
			XKMSPath:     "/var/lib/test/xkms",
			PCRBanks:     []string{"sha256"},
			PCRSelection: []uint{0, 1, 2, 3, 7},
		},
	}

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: slotIdx, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Install(ctx, volume, []byte("test-password"))
	if err != nil {
		t.Errorf("expected success, got: %v", err)
	}
}

func TestPasswordStrategyInstallNoPasswordSlot(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: 0, Type: luks.UnlockTPMPCR},
		},
	}

	err := strategy.Install(ctx, volume, []byte("test-password"))
	if err == nil {
		t.Error("expected error when no password slot configured")
	}
}

func TestPasswordStrategyInstallTestKeyFails(t *testing.T) {
	logger := logging.DefaultLogger()

	testKeyErr := &testError{msg: "wrong password"}
	mockLUKS := &MockLUKSHandler{}
	slotIdx := 0
	mockLUKS.On("TestKey",
		mock.Anything,
		"/dev/sda2",
		[]byte("bad-password"),
		&slotIdx,
	).Return(testKeyErr)

	platform := &Platform{
		LUKS: mockLUKS,
		Config: &Config{
			RootDevice:   "/dev/sda2",
			XKMSPath:     "/var/lib/test/xkms",
			PCRBanks:     []string{"sha256"},
			PCRSelection: []uint{0, 1, 2, 3, 7},
		},
	}

	strategy := NewPasswordStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: slotIdx, Type: luks.UnlockPassword},
		},
	}

	err := strategy.Install(ctx, volume, []byte("bad-password"))
	if err == nil {
		t.Error("expected error when TestKey fails")
	}
}

func TestPasswordStrategyUnlockContextCanceled(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()
	platform.Config.DisablePasswordPrompt = false

	strategy := NewPasswordStrategy(platform, logger)
	strategy.SetReader(bufio.NewReader(strings.NewReader("password\n")))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	slotIdx := 0
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
		KeySlots: []luks.KeySlot{
			{Index: slotIdx, Type: luks.UnlockPassword},
		},
	}

	mockLUKS := platform.LUKS.(*MockLUKSHandler)
	mockLUKS.On("Open", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything).Return(context.Canceled)

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}
