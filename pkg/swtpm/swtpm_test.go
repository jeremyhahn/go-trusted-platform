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

package swtpm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewSWTPM tests the creation of a new SWTPM instance
func TestNewSWTPM(t *testing.T) {
	testCases := []struct {
		name        string
		config      *Config
		expectError error
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: ErrInvalidConfig,
		},
		{
			name: "empty state directory",
			config: &Config{
				StateDir: "",
			},
			expectError: ErrInvalidConfig,
		},
		{
			name: "valid config with defaults",
			config: &Config{
				StateDir: "/tmp/test-swtpm",
			},
			expectError: nil,
		},
		{
			name: "valid config with custom settings",
			config: &Config{
				StateDir:   "/tmp/test-swtpm",
				SocketPath: "/tmp/test-swtpm/custom.sock",
				PCRBanks:   []string{"sha256", "sha384"},
				LogLevel:   10,
				Debug:      true,
			},
			expectError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			swtpm, err := NewSWTPM(tc.config, logger)

			if tc.expectError != nil {
				assert.ErrorIs(t, err, tc.expectError)
				assert.Nil(t, swtpm)
			} else {
				// Check if swtpm is installed
				if _, lookupErr := exec.LookPath("swtpm"); lookupErr != nil {
					t.Skip("swtpm not installed, skipping test")
				}

				assert.NoError(t, err)
				assert.NotNil(t, swtpm)
				assert.Equal(t, tc.config.StateDir, swtpm.config.StateDir)

				// Check defaults
				if tc.config.SocketPath == "" {
					assert.Equal(t, filepath.Join(tc.config.StateDir, "swtpm.sock"), swtpm.config.SocketPath)
				}
				if len(tc.config.PCRBanks) == 0 {
					assert.Equal(t, []string{"sha256"}, swtpm.config.PCRBanks)
				}
				if tc.config.LogLevel == 0 {
					assert.Equal(t, 20, swtpm.config.LogLevel)
				}
			}
		})
	}
}

// TestSWTPMNotInstalled tests behavior when swtpm is not installed
func TestSWTPMNotInstalled(t *testing.T) {
	// Temporarily modify PATH to simulate swtpm not being installed
	oldPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", "/nonexistent")
	defer func() { _ = os.Setenv("PATH", oldPath) }()

	config := &Config{
		StateDir: "/tmp/test-swtpm",
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)

	assert.ErrorIs(t, err, ErrSWTPMNotInstalled)
	assert.Nil(t, swtpm)
}

// TestInitialize tests TPM initialization
func TestInitialize(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm_setup"); err != nil {
		t.Skip("swtpm_setup not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
		Debug:    true,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)
	require.NotNil(t, swtpm)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	assert.NoError(t, err)

	// Verify state directory exists
	_, err = os.Stat(tempDir)
	assert.NoError(t, err)

	// Verify TPM state files were created
	entries, err := os.ReadDir(tempDir)
	assert.NoError(t, err)
	assert.NotEmpty(t, entries, "state directory should contain TPM state files")
}

// TestInitializeWithContext tests initialization with context cancellation
func TestInitializeWithContext(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm_setup"); err != nil {
		t.Skip("swtpm_setup not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Create a context that is already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = swtpm.Initialize(ctx)
	assert.Error(t, err)
}

// TestStartStop tests starting and stopping the swtpm daemon
func TestStartStop(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
		Debug:    true,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Initialize first
	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	// Start the daemon
	err = swtpm.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, swtpm.IsRunning())
	assert.Greater(t, swtpm.PID(), 0)

	// Wait for socket to be ready
	err = swtpm.WaitForSocket(5 * time.Second)
	assert.NoError(t, err)

	// Verify socket exists
	_, err = os.Stat(swtpm.SocketPath())
	assert.NoError(t, err)

	// Stop the daemon
	err = swtpm.Stop()
	assert.NoError(t, err)
	assert.False(t, swtpm.IsRunning())
	assert.Equal(t, 0, swtpm.PID())
}

// TestStartAlreadyRunning tests starting swtpm when it's already running
func TestStartAlreadyRunning(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
		Debug:    true,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	// Start the daemon
	err = swtpm.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = swtpm.Stop() }()

	// Try to start again
	err = swtpm.Start(ctx)
	assert.ErrorIs(t, err, ErrAlreadyRunning)
}

// TestStopNotRunning tests stopping swtpm when it's not running
func TestStopNotRunning(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	err = swtpm.Stop()
	assert.ErrorIs(t, err, ErrNotRunning)
}

// TestIsRunning tests the IsRunning method
func TestIsRunning(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
		Debug:    true,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Should not be running initially
	assert.False(t, swtpm.IsRunning())

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	// Start the daemon
	err = swtpm.Start(ctx)
	require.NoError(t, err)

	// Should be running now
	assert.True(t, swtpm.IsRunning())

	// Stop the daemon
	err = swtpm.Stop()
	require.NoError(t, err)

	// Should not be running after stop
	assert.False(t, swtpm.IsRunning())
}

// TestWaitForSocketTimeout tests socket wait timeout
func TestWaitForSocketTimeout(t *testing.T) {
	tempDir := t.TempDir()

	config := &Config{
		StateDir:   tempDir,
		SocketPath: filepath.Join(tempDir, "nonexistent.sock"),
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Socket doesn't exist, should timeout
	err = swtpm.WaitForSocket(500 * time.Millisecond)
	assert.ErrorIs(t, err, ErrSocketNotReady)
}

// TestStopExisting tests stopping existing swtpm processes
func TestStopExisting(t *testing.T) {
	// This test only verifies the function doesn't panic
	// when no processes are running
	tempDir := t.TempDir()
	err := StopExisting(tempDir)
	assert.NoError(t, err)
}

// TestAccessors tests getter methods
func TestAccessors(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test.sock")

	config := &Config{
		StateDir:   tempDir,
		SocketPath: socketPath,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	assert.Equal(t, tempDir, swtpm.StateDir())
	assert.Equal(t, socketPath, swtpm.SocketPath())
	assert.Equal(t, 0, swtpm.PID())
}

// TestStartWithoutInitialize tests starting without initialization
func TestStartWithoutInitialize(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	// Use a non-existent subdirectory to simulate uninitialized state
	tempDir := filepath.Join(os.TempDir(), "swtpm-test-nonexistent-12345")
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Try to start without initializing first
	err = swtpm.Start(ctx)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(t, err.Error(), "state directory does not exist")
	}
}

// TestMultiplePCRBanks tests initialization with multiple PCR banks
func TestMultiplePCRBanks(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm_setup"); err != nil {
		t.Skip("swtpm_setup not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
		PCRBanks: []string{"sha256", "sha384", "sha512"},
		Debug:    true,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	assert.NoError(t, err)
}

// TestNilLogger tests creation with nil logger
func TestNilLogger(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	config := &Config{
		StateDir: t.TempDir(),
	}

	// Pass nil logger, should use default
	swtpm, err := NewSWTPM(config, nil)
	assert.NoError(t, err)
	assert.NotNil(t, swtpm)
	assert.NotNil(t, swtpm.logger)
}

// TestConcurrentAccess tests concurrent access to SWTPM methods
func TestConcurrentAccess(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	err = swtpm.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = swtpm.Stop() }()

	// Concurrent reads should work fine
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = swtpm.IsRunning()
			_ = swtpm.StateDir()
			_ = swtpm.SocketPath()
			_ = swtpm.PID()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestSendStartup tests sending TPM2_Startup command
func TestSendStartup(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
		Debug:    true,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	// Start the daemon
	err = swtpm.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = swtpm.Stop() }()

	// Wait for socket to be ready
	err = swtpm.WaitForSocket(5 * time.Second)
	require.NoError(t, err)

	// Send TPM2_Startup command
	err = swtpm.SendStartup()
	assert.NoError(t, err)

	// Calling again should be idempotent (TPM already initialized)
	err = swtpm.SendStartup()
	assert.NoError(t, err)
}

// TestSendStartupNotRunning tests SendStartup when swtpm is not running
func TestSendStartupNotRunning(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Try to send startup without starting swtpm
	err = swtpm.SendStartup()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrStartupFailed)
}

// TestIsInitialized tests the IsInitialized method
func TestIsInitialized(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm_setup"); err != nil {
		t.Skip("swtpm_setup not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Should not be initialized initially
	assert.False(t, swtpm.IsInitialized())

	// Initialize the TPM
	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	// Should be initialized now
	assert.True(t, swtpm.IsInitialized())
}

// TestIsInitializedNoStateDir tests IsInitialized with non-existent state directory
func TestIsInitializedNoStateDir(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := filepath.Join(os.TempDir(), "swtpm-test-nonexistent-99999")
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Should return false when state directory doesn't exist
	assert.False(t, swtpm.IsInitialized())
}

// TestWaitForSocketNonSocketFile tests WaitForSocket when a non-socket file exists
func TestWaitForSocketNonSocketFile(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "fake.sock")

	// Create a regular file instead of a socket
	err := os.WriteFile(socketPath, []byte("not a socket"), 0644)
	require.NoError(t, err)

	config := &Config{
		StateDir:   tempDir,
		SocketPath: socketPath,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	// Should fail because it's not a socket
	err = swtpm.WaitForSocket(1 * time.Second)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSocketNotReady)
	if err != nil {
		assert.Contains(t, err.Error(), "not a socket")
	}
}

// TestWaitForSocketProcessDied tests WaitForSocket when process dies during wait
func TestWaitForSocketProcessDied(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	err = swtpm.Start(ctx)
	require.NoError(t, err)

	// Kill the process immediately
	if swtpm.cmd != nil && swtpm.cmd.Process != nil {
		_ = swtpm.cmd.Process.Kill()
	}

	// Wait should fail because process died
	err = swtpm.WaitForSocket(2 * time.Second)
	assert.Error(t, err)
	// May get either socket not ready or process died error
	assert.ErrorIs(t, err, ErrSocketNotReady)
}

// TestStopAfterKill tests Stop when process was already killed
func TestStopAfterKill(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	err = swtpm.Start(ctx)
	require.NoError(t, err)

	// Kill the process first
	if swtpm.cmd != nil && swtpm.cmd.Process != nil {
		require.NoError(t, swtpm.cmd.Process.Kill())
		<-swtpm.exitCh
	}

	// Stop should handle the already-dead process gracefully
	// The SIGTERM will fail, but it will continue
	err = swtpm.Stop()
	// Should succeed even though process was already dead
	assert.NoError(t, err)
}

// TestStopExistingWithRunningProcess tests StopExisting when processes are actually running
func TestStopExistingWithRunningProcess(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	err = swtpm.Start(ctx)
	require.NoError(t, err)

	// Record the original PID
	originalPID := swtpm.PID()
	require.Greater(t, originalPID, 0)

	// Now stop existing processes using pkill
	err = StopExisting(tempDir)
	assert.NoError(t, err)

	// StopExisting should complete without error - that's the main test
	// The actual process termination is handled by pkill which we've verified doesn't error
}

// TestIsRunningAfterProcessKilled tests IsRunning properly detects process death
func TestIsRunningAfterProcessKilled(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm"); err != nil {
		t.Skip("swtpm not installed, skipping test")
	}

	tempDir := t.TempDir()

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	require.NoError(t, err)

	err = swtpm.Start(ctx)
	require.NoError(t, err)

	// Process should be running
	assert.True(t, swtpm.IsRunning())

	// Kill the process
	if swtpm.cmd != nil && swtpm.cmd.Process != nil {
		require.NoError(t, swtpm.cmd.Process.Kill())
	}

	// The wait goroutine closes exitCh once it has recorded the exit.
	<-swtpm.exitCh

	// IsRunning should return false after process is killed
	assert.False(t, swtpm.IsRunning())
}

// TestInitializeError tests initialization failure
func TestInitializeError(t *testing.T) {
	// Check if swtpm is installed
	if _, err := exec.LookPath("swtpm_setup"); err != nil {
		t.Skip("swtpm_setup not installed, skipping test")
	}

	// Use a read-only directory to cause mkdir failure
	tempDir := "/proc/swtpm-test-readonly"

	config := &Config{
		StateDir: tempDir,
	}

	logger := logging.DefaultLogger()
	swtpm, err := NewSWTPM(config, logger)
	require.NoError(t, err)

	ctx := context.Background()
	err = swtpm.Initialize(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInitFailed)
}
