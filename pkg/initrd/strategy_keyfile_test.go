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
	"github.com/stretchr/testify/mock"
)

func TestNewKeyfileStrategy(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	if strategy == nil {
		t.Fatal("NewKeyfileStrategy returned nil")
	}

	if strategy.Name() != "Keyfile" {
		t.Errorf("expected name Keyfile, got %s", strategy.Name())
	}

	if strategy.Priority() != 80 {
		t.Errorf("expected priority 80, got %d", strategy.Priority())
	}
}

func TestKeyfileStrategyGetKeyfilePaths(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	paths := strategy.GetKeyfilePaths()
	if len(paths) == 0 {
		t.Error("expected at least one keyfile path")
	}

	if paths[0] != "/mnt/installer/luks-key.bin" {
		t.Errorf("expected first path /mnt/installer/luks-key.bin, got %s", paths[0])
	}
}

func TestKeyfileStrategyGetKeyfilePathNoFile(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	path := strategy.GetKeyfilePath()
	if path != "" {
		t.Errorf("expected empty path when no keyfile exists, got %s", path)
	}
}

func TestKeyfileStrategyGetKeyfilePathExists(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	// Create a temporary keyfile
	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks-key.bin")
	if err := os.WriteFile(keyfilePath, []byte("test-key-data"), 0600); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}

	// Override the keyfile paths for testing
	strategy.keyfilePaths = []string{keyfilePath}

	path := strategy.GetKeyfilePath()
	if path != keyfilePath {
		t.Errorf("expected path %s, got %s", keyfilePath, path)
	}
}

func TestKeyfileStrategyCanUnlockNoFile(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false when no keyfile exists")
	}
}

func TestKeyfileStrategyCanUnlockWithFile(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	// Create a readable keyfile
	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks-key.bin")
	if err := os.WriteFile(keyfilePath, []byte("test-key-data"), 0600); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}
	strategy.keyfilePaths = []string{keyfilePath}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if !strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return true when keyfile exists")
	}
}

func TestKeyfileStrategyCanUnlockNotRegularFile(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	// Use a directory instead of a file
	tmpDir := t.TempDir()
	strategy.keyfilePaths = []string{tmpDir}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false for directory")
	}
}

func TestKeyfileStrategyCanUnlockUnreadableFile(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	// Create a file with no read permissions
	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks-key.bin")
	if err := os.WriteFile(keyfilePath, []byte("test-key-data"), 0200); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}
	strategy.keyfilePaths = []string{keyfilePath}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	// On root the file may still be readable, skip if running as root
	if os.Getuid() == 0 {
		t.Skip("skipping unreadable file test when running as root")
	}

	if strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return false for unreadable file")
	}
}

func TestKeyfileStrategyUnlockNoKeyfile(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)
	// Set to nonexistent paths
	strategy.keyfilePaths = []string{"/nonexistent/path/key.bin"}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error when no keyfile exists")
	}
}

func TestKeyfileStrategyUnlockEmptyKeyfile(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	// Create an empty keyfile
	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks-key.bin")
	if err := os.WriteFile(keyfilePath, []byte{}, 0600); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}
	strategy.keyfilePaths = []string{keyfilePath}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error for empty keyfile")
	}
}

func TestKeyfileStrategyUnlockSuccess(t *testing.T) {
	logger := logging.DefaultLogger()

	mockLUKS := &MockLUKSHandler{}
	mockLUKS.On("Open",
		mock.Anything,           // ctx
		"/dev/sda2",             // device
		"cryptroot",             // mapping
		[]byte("test-key-data"), // password
		mock.AnythingOfType("*luks.OpenOptions"),
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

	strategy := NewKeyfileStrategy(platform, logger)

	// Create a binary keyfile
	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks-key.bin")
	if err := os.WriteFile(keyfilePath, []byte("test-key-data"), 0600); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}
	strategy.keyfilePaths = []string{keyfilePath}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:    "/dev/sda2",
		MappingName:   "cryptroot",
		AllowDiscards: true,
		Timeout:       30,
	}

	err := strategy.Unlock(ctx, volume)
	if err != nil {
		t.Errorf("expected success, got: %v", err)
	}

	mockLUKS.AssertCalled(t, "Open",
		mock.Anything, "/dev/sda2", "cryptroot",
		[]byte("test-key-data"),
		mock.AnythingOfType("*luks.OpenOptions"))
}

func TestKeyfileStrategyUnlockTextKeyTrimming(t *testing.T) {
	logger := logging.DefaultLogger()

	mockLUKS := &MockLUKSHandler{}
	mockLUKS.On("Open",
		mock.Anything,
		"/dev/sda2",
		"cryptroot",
		[]byte("my-password"),
		mock.AnythingOfType("*luks.OpenOptions"),
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

	strategy := NewKeyfileStrategy(platform, logger)

	// Create a text keyfile with whitespace (uses .key extension)
	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks.key")
	if err := os.WriteFile(keyfilePath, []byte("  my-password  \n"), 0600); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}
	strategy.keyfilePaths = []string{keyfilePath}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:    "/dev/sda2",
		MappingName:   "cryptroot",
		AllowDiscards: true,
		Timeout:       30,
	}

	err := strategy.Unlock(ctx, volume)
	if err != nil {
		t.Errorf("expected success, got: %v", err)
	}

	// Verify trimmed password was used
	mockLUKS.AssertCalled(t, "Open",
		mock.Anything, "/dev/sda2", "cryptroot",
		[]byte("my-password"),
		mock.AnythingOfType("*luks.OpenOptions"))
}

func TestKeyfileStrategyUnlockLUKSError(t *testing.T) {
	logger := logging.DefaultLogger()

	luksErr := &testError{msg: "luks open failed"}
	mockLUKS := &MockLUKSHandler{}
	mockLUKS.On("Open",
		mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything,
	).Return(luksErr)

	platform := &Platform{
		LUKS: mockLUKS,
		Config: &Config{
			RootDevice:   "/dev/sda2",
			XKMSPath:     "/var/lib/test/xkms",
			PCRBanks:     []string{"sha256"},
			PCRSelection: []uint{0, 1, 2, 3, 7},
		},
	}

	strategy := NewKeyfileStrategy(platform, logger)

	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks-key.bin")
	if err := os.WriteFile(keyfilePath, []byte("test-key-data"), 0600); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}
	strategy.keyfilePaths = []string{keyfilePath}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:    "/dev/sda2",
		MappingName:   "cryptroot",
		AllowDiscards: true,
		Timeout:       30,
	}

	err := strategy.Unlock(ctx, volume)
	if err == nil {
		t.Error("expected error when LUKS open fails")
	}
}

func TestKeyfileStrategyCanUnlockMultiplePaths(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	// First path doesn't exist, second does
	tmpDir := t.TempDir()
	keyfilePath := filepath.Join(tmpDir, "luks-key.bin")
	if err := os.WriteFile(keyfilePath, []byte("test"), 0600); err != nil {
		t.Fatalf("failed to create keyfile: %v", err)
	}

	strategy.keyfilePaths = []string{"/nonexistent/path", keyfilePath}

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	if !strategy.CanUnlock(ctx, volume) {
		t.Error("expected CanUnlock to return true when second path exists")
	}
}

func TestKeyfileStrategyInstall(t *testing.T) {
	logger := logging.DefaultLogger()
	platform := createTestPlatform()

	strategy := NewKeyfileStrategy(platform, logger)

	ctx := context.Background()
	volume := &luks.VolumeConfig{
		DevicePath:  "/dev/sda2",
		MappingName: "cryptroot",
	}

	// Install is a no-op for keyfile strategy
	err := strategy.Install(ctx, volume, []byte("password"))
	if err != nil {
		t.Errorf("Install should succeed (no-op): %v", err)
	}
}

// testError is a typed error for testing
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
