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
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// unixSocketPathMax is the maximum length for Unix socket paths.
// Linux uses 108 bytes including null terminator, but we use 104 for safety margin.
const unixSocketPathMax = 104

// Config holds the configuration for a software TPM instance
type Config struct {
	StateDir   string   // TPM state directory
	SocketPath string   // Socket path for QEMU connection
	PCRBanks   []string // PCR banks (e.g., ["sha256"])
	LogLevel   int      // Log level (default: 20)
	Debug      bool     // Enable debug mode
	QEMUMode   bool     // Use --ctrl socket for QEMU (default: false uses --server for go-tpm)
}

// SWTPM represents a software TPM instance
type SWTPM struct {
	config       *Config
	logger       *logging.Logger
	tools        tools
	cmd          *exec.Cmd
	mu           sync.RWMutex
	pid          int
	tempStateDir string      // Temp directory for state files when using Docker volumes
	logFile      string      // Path to swtpm log file for error reporting
	exited       atomic.Bool // Set to true when process exits
	exitErr      error       // Error from process exit
	exitMu       sync.RWMutex
	exitCh       chan struct{} // Closed when the process exits
}

// tools reaches the swtpm host binaries.
// Overridable seam for tests; defaults to hostTools.
type tools struct {
	// lookPath reports where the named binary is installed.
	lookPath func(file string) (string, error)

	// runSetup runs swtpm_setup with args, writing its output to stdout
	// and stderr.
	runSetup func(ctx context.Context, args []string, stdout, stderr io.Writer) error
}

// hostTools finds and runs the swtpm binaries on PATH.
var hostTools = tools{
	lookPath: exec.LookPath,
	runSetup: runSWTPMSetup,
}

// runSWTPMSetup runs the swtpm_setup binary.
func runSWTPMSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "swtpm_setup", args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// stopGracePeriod is how long Stop waits after SIGTERM before it kills
// swtpm. A variable so tests can shorten it.
var stopGracePeriod = 5 * time.Second

// NewSWTPM creates a new software TPM instance
func NewSWTPM(config *Config, logger *logging.Logger) (*SWTPM, error) {
	return newSWTPM(config, logger, hostTools)
}

// newSWTPM builds an SWTPM that reaches the swtpm binaries through tools.
func newSWTPM(config *Config, logger *logging.Logger, tools tools) (*SWTPM, error) {
	if config == nil {
		return nil, ErrInvalidConfig
	}

	if config.StateDir == "" {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidConfig, Cause: &MessageError{Msg: "StateDir is required"}}
	}

	if config.SocketPath == "" {
		config.SocketPath = filepath.Join(config.StateDir, "swtpm.sock")
	}

	if len(config.PCRBanks) == 0 {
		config.PCRBanks = []string{"sha256"}
	}

	if config.LogLevel == 0 {
		config.LogLevel = 20
	}

	if logger == nil {
		logger = logging.DefaultLogger()
	}

	// Check if swtpm is installed
	if _, err := tools.lookPath("swtpm"); err != nil {
		return nil, ErrSWTPMNotInstalled
	}

	if _, err := tools.lookPath("swtpm_setup"); err != nil {
		return nil, ErrSWTPMNotInstalled
	}

	return &SWTPM{
		config: config,
		logger: logger,
		tools:  tools,
	}, nil
}

// Initialize initializes the TPM state using swtpm_setup
func (s *SWTPM) Initialize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Infof("Initializing swtpm state directory: %s", s.config.StateDir)

	// Create state directory if it doesn't exist
	if err := os.MkdirAll(s.config.StateDir, 0755); err != nil {
		return &SentinelCauseError{Sentinel: ErrInitFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to create state directory: %v", err)}}
	}

	// swtpm_setup internally starts swtpm which creates socket files.
	// Docker volume mounts may not support certain operations required for socket creation.
	// Workaround: run swtpm_setup in a temp directory and copy the state files.
	tempDir, err := os.MkdirTemp("", "swtpm-init-*")
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrInitFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to create temp directory: %v", err)}}
	}
	defer func() {
		if removeErr := os.RemoveAll(tempDir); removeErr != nil {
			s.logger.Warn("failed to remove temp directory", "error", removeErr)
		}
	}()

	// Build swtpm_setup command with temp directory
	args := []string{
		"--tpm2",
		"--tpmstate", tempDir,
		"--pcr-banks", strings.Join(s.config.PCRBanks, ","),
		"--overwrite",
	}

	// Capture stderr for error reporting
	var stderr bytes.Buffer
	var stdout io.Writer
	var stderrOut io.Writer = &stderr
	if s.config.Debug {
		stdout = os.Stdout
		stderrOut = io.MultiWriter(os.Stderr, &stderr)
	}

	s.logger.Debugf("Running: swtpm_setup %s", strings.Join(args, " "))

	if err := s.tools.runSetup(ctx, args, stdout, stderrOut); err != nil {
		return &SentinelCauseError{Sentinel: ErrInitFailed, Cause: &MessageError{Msg: fmt.Sprintf("swtpm_setup failed: %v (stderr: %s)", err, stderr.String())}}
	}

	// Copy state files from temp directory to final destination
	entries, err := os.ReadDir(tempDir)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrInitFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to read temp directory: %v", err)}}
	}

	for _, entry := range entries {
		srcPath := filepath.Join(tempDir, entry.Name())
		dstPath := filepath.Join(s.config.StateDir, entry.Name())

		// Read source file
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrInitFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to read state file %s: %v", entry.Name(), err)}}
		}

		// Get source file info for permissions
		info, err := os.Stat(srcPath)
		if err != nil {
			return &SentinelCauseError{Sentinel: ErrInitFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to stat state file %s: %v", entry.Name(), err)}}
		}

		// Write to destination
		if err := os.WriteFile(dstPath, data, info.Mode()); err != nil {
			return &SentinelCauseError{Sentinel: ErrInitFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to write state file %s: %v", entry.Name(), err)}}
		}

		s.logger.Debugf("Copied TPM state file: %s -> %s", srcPath, dstPath)
	}

	s.logger.Info("swtpm initialization completed successfully")
	return nil
}

// Start starts the swtpm daemon
func (s *SWTPM) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil && s.cmd.Process != nil {
		return ErrAlreadyRunning
	}

	s.logger.Info("Starting swtpm daemon")

	// Reset exit state
	s.exited.Store(false)
	s.exitMu.Lock()
	s.exitErr = nil
	s.exitMu.Unlock()

	// Verify state directory exists
	if _, err := os.Stat(s.config.StateDir); os.IsNotExist(err) {
		return &MessageError{Msg: fmt.Sprintf("state directory does not exist: %s", s.config.StateDir)}
	}

	// Determine if we need a temp directory for swtpm execution.
	// We need a temp directory if:
	// 1. StateDir is not in /tmp or /var/run (Docker volume compatibility)
	// 2. Socket path exceeds Unix socket path limit (~108 chars)
	stateDir := s.config.StateDir
	socketPath := s.config.SocketPath
	needsTempDir := false

	// Check for Docker volume compatibility
	if !strings.HasPrefix(s.config.StateDir, "/tmp/") && !strings.HasPrefix(s.config.StateDir, "/var/run/") {
		needsTempDir = true
		s.logger.Debug("Using temp directory for Docker compatibility")
	}

	// Check for socket path length - Unix sockets have a ~108 char limit
	if len(socketPath) >= unixSocketPathMax {
		needsTempDir = true
		s.logger.Debugf("Socket path too long (%d chars >= %d limit), using temp directory",
			len(socketPath), unixSocketPathMax)
	}

	if needsTempDir {
		// Create a unique temp directory for swtpm with a short name
		tmpDir, err := os.MkdirTemp("", "swtpm-*")
		if err != nil {
			return &WrappedError{Msg: "failed to create temp directory", Err: err}
		}
		s.tempStateDir = tmpDir
		stateDir = tmpDir
		socketPath = filepath.Join(tmpDir, "swtpm.sock")
		s.config.SocketPath = socketPath
		s.logger.Debugf("Using temp directory: %s (socket: %s)", tmpDir, socketPath)

		// Copy state files from configured StateDir to temp directory
		entries, err := os.ReadDir(s.config.StateDir)
		if err != nil {
			return &WrappedError{Msg: "failed to read state directory", Err: err}
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			srcPath := filepath.Join(s.config.StateDir, entry.Name())
			dstPath := filepath.Join(tmpDir, entry.Name())
			data, err := os.ReadFile(srcPath)
			if err != nil {
				return &WrappedError{Msg: fmt.Sprintf("failed to read state file %s", entry.Name()), Err: err}
			}
			info, err := os.Stat(srcPath)
			if err != nil {
				return &WrappedError{Msg: fmt.Sprintf("failed to stat state file %s", entry.Name()), Err: err}
			}
			if err := os.WriteFile(dstPath, data, info.Mode()); err != nil {
				return &WrappedError{Msg: fmt.Sprintf("failed to write state file %s", entry.Name()), Err: err}
			}
			s.logger.Debugf("Copied state file to temp: %s -> %s", srcPath, dstPath)
		}
	}

	// Build swtpm socket command
	// NOTE: We do NOT use --daemon flag because:
	// 1. With --daemon, swtpm forks and the parent exits, leaving a zombie process
	// 2. The child process gets a new PID that we don't track
	// 3. This causes "broken pipe" errors when QEMU tries to use the TPM
	// Instead, we run swtpm in foreground and let Go manage it as a background process
	//
	// Socket type selection:
	// - QEMUMode=true: Use --ctrl (control channel) which QEMU's tpmdev emulator expects
	// - QEMUMode=false: Use --server (data channel) for direct go-tpm communication
	//
	// NOTE: Do NOT use the "disconnect" option - it causes swtpm to close connections
	// before the client can read responses. linuxudstpm works correctly when the CLIENT
	// closes connections after each command (the server doesn't need to force disconnect).
	socketType := "--server"
	if s.config.QEMUMode {
		socketType = "--ctrl"
		s.logger.Debug("Using QEMU mode (--ctrl socket)")
	}
	args := []string{
		"socket",
		"--tpmstate", fmt.Sprintf("dir=%s", stateDir),
		socketType, fmt.Sprintf("type=unixio,path=%s", socketPath),
		"--tpm2",
		"--flags", "not-need-init",
		"--log", fmt.Sprintf("level=%d", s.config.LogLevel),
	}

	// Create log file in temp dir (not state dir) to avoid mounted volume issues
	logFile := filepath.Join(filepath.Dir(socketPath), "swtpm.log")
	args = append(args, "--log", fmt.Sprintf("file=%s", logFile))
	s.logFile = logFile

	cmd := exec.CommandContext(ctx, "swtpm", args...)

	// Set process group to allow clean shutdown
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if s.config.Debug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	s.logger.Debugf("Running: swtpm %s", strings.Join(args, " "))

	if err := cmd.Start(); err != nil {
		return &WrappedError{Msg: "failed to start swtpm", Err: err}
	}

	s.cmd = cmd
	s.pid = cmd.Process.Pid

	s.watchExit(cmd)

	s.logger.Infof("swtpm daemon started with PID %d", s.pid)

	return nil
}

// watchExit waits for cmd in a goroutine and records its exit status. The
// exited flag and exitCh report process death at once, without polling with
// signal 0 (which doesn't work well for zombies).
func (s *SWTPM) watchExit(cmd *exec.Cmd) {
	exitCh := make(chan struct{})
	s.exitCh = exitCh
	go func() {
		err := cmd.Wait()
		s.exitMu.Lock()
		s.exitErr = err
		s.exitMu.Unlock()
		s.exited.Store(true)
		close(exitCh)
	}()
}

// Stop stops the swtpm daemon
func (s *SWTPM) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd == nil || s.cmd.Process == nil {
		return ErrNotRunning
	}

	s.logger.Infof("Stopping swtpm daemon (PID %d)", s.pid)

	// Check if process already exited
	if s.exited.Load() {
		s.exitMu.RLock()
		exitErr := s.exitErr
		s.exitMu.RUnlock()
		if exitErr != nil {
			s.logger.Debugf("swtpm exited with error: %v", exitErr)
		}
	} else {
		// Send SIGTERM for graceful shutdown
		if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			s.logger.Warnf("Failed to send SIGTERM to swtpm: %v", err)
			// Try SIGKILL as fallback
			if killErr := s.cmd.Process.Kill(); killErr != nil {
				return &WrappedError{Msg: "failed to kill swtpm process", Err: killErr}
			}
		}

		// Wait for process to exit, killing it once the grace period ends
		timeout := time.NewTimer(stopGracePeriod)
		defer timeout.Stop()

		select {
		case <-s.exitCh:
			s.exitMu.RLock()
			exitErr := s.exitErr
			s.exitMu.RUnlock()
			if exitErr != nil {
				s.logger.Debugf("swtpm exited with error: %v", exitErr)
			}
		case <-timeout.C:
			s.logger.Warn("swtpm did not exit in time, forcing kill")
			if err := s.cmd.Process.Kill(); err != nil {
				return &WrappedError{Msg: "failed to force kill swtpm", Err: err}
			}
			<-s.exitCh
		}
	}

	// If we used a temp directory, copy state files back for persistence
	if s.tempStateDir != "" {
		s.logger.Debugf("Copying state files back from temp directory: %s -> %s", s.tempStateDir, s.config.StateDir)
		entries, err := os.ReadDir(s.tempStateDir)
		if err != nil {
			s.logger.Warnf("Failed to read temp state directory: %v", err)
		} else {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				// Only copy TPM state files, not sockets or logs
				name := entry.Name()
				if strings.HasPrefix(name, "tpm2-") || strings.HasPrefix(name, ".lock") {
					srcPath := filepath.Join(s.tempStateDir, name)
					dstPath := filepath.Join(s.config.StateDir, name)
					data, err := os.ReadFile(srcPath)
					if err != nil {
						s.logger.Warnf("Failed to read temp state file %s: %v", name, err)
						continue
					}
					if err := os.WriteFile(dstPath, data, 0640); err != nil {
						s.logger.Warnf("Failed to write state file %s: %v", name, err)
						continue
					}
					s.logger.Debugf("Copied state file back: %s -> %s", srcPath, dstPath)
				}
			}
		}
		// Clean up temp directory
		if err := os.RemoveAll(s.tempStateDir); err != nil {
			s.logger.Warnf("Failed to remove temp state directory: %v", err)
		}
		s.tempStateDir = ""
	}

	s.cmd = nil
	s.pid = 0

	s.logger.Info("swtpm daemon stopped successfully")
	return nil
}

// IsRunning checks if swtpm is running
func (s *SWTPM) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.cmd == nil || s.cmd.Process == nil {
		return false
	}

	// Use the exited flag which is set by the wait goroutine
	return !s.exited.Load()
}

// WaitForSocket waits for the socket to be ready using channel-based polling.
// NOTE: We intentionally do NOT connect to verify the socket is ready because:
// 1. swtpm in server mode may only accept one connection at a time
// 2. Connecting here would consume that single connection slot
// 3. When we close our test connection, swtpm might not be ready for a new client
// Instead, we just wait for the socket file to exist and verify the process is running.
func (s *SWTPM) WaitForSocket(timeout time.Duration) error {
	s.logger.Debugf("Waiting for swtpm socket to be ready: %s", s.config.SocketPath)

	// Use a ticker for polling with channel-based synchronization
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	// Create deadline timer
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case <-deadline.C:
			// On timeout, check if swtpm log file has useful error information
			errMsg := fmt.Sprintf("socket file not ready after %v", timeout)
			if s.logFile != "" {
				if logContent, err := os.ReadFile(s.logFile); err == nil && len(logContent) > 0 {
					// Truncate log to last 500 bytes for error message
					logStr := string(logContent)
					if len(logStr) > 500 {
						logStr = "..." + logStr[len(logStr)-500:]
					}
					errMsg = fmt.Sprintf("%s; swtpm log: %s", errMsg, strings.TrimSpace(logStr))
				}
			}
			return &SentinelCauseError{Sentinel: ErrSocketNotReady, Cause: &MessageError{Msg: errMsg}}

		case <-ticker.C:
			// Check if socket file exists
			fi, err := os.Stat(s.config.SocketPath)
			if err != nil {
				// Socket doesn't exist yet, check if process died early
				if !s.IsRunning() {
					// Process died, read log for error details
					errMsg := "swtpm process exited before socket was created"
					if s.logFile != "" {
						if logContent, err := os.ReadFile(s.logFile); err == nil && len(logContent) > 0 {
							logStr := string(logContent)
							if len(logStr) > 500 {
								logStr = "..." + logStr[len(logStr)-500:]
							}
							errMsg = fmt.Sprintf("%s; swtpm log: %s", errMsg, strings.TrimSpace(logStr))
						}
					}
					return &SentinelCauseError{Sentinel: ErrSocketNotReady, Cause: &MessageError{Msg: errMsg}}
				}
				// Process still running, continue polling
				continue
			}

			// Verify it's actually a socket
			if fi.Mode()&os.ModeSocket == 0 {
				return &SentinelCauseError{Sentinel: ErrSocketNotReady, Cause: &MessageError{Msg: fmt.Sprintf("%s is not a socket", s.config.SocketPath)}}
			}

			// Verify swtpm process is still running
			if !s.IsRunning() {
				return &SentinelCauseError{Sentinel: ErrSocketNotReady, Cause: &MessageError{Msg: "swtpm process died"}}
			}

			s.logger.Info("swtpm socket is ready")
			return nil
		}
	}
}

// SendStartup sends the TPM2_Startup command to initialize the TPM.
// This MUST be called after the swtpm daemon is started and before any
// other TPM commands are sent. Unlike physical TPMs which are started
// during system boot, swtpm requires an explicit Startup command.
func (s *SWTPM) SendStartup() error {
	s.logger.Debug("Sending TPM2_Startup command to swtpm")

	// Open connection to swtpm socket
	t, err := linuxudstpm.Open(s.config.SocketPath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrStartupFailed, Cause: &MessageError{Msg: fmt.Sprintf("failed to open swtpm socket: %v", err)}}
	}
	defer func() { _ = t.Close() }()

	// Send TPM2_Startup(TPM_SU_CLEAR)
	_, err = tpm2.Startup{
		StartupType: tpm2.TPMSUClear,
	}.Execute(t)
	if err != nil {
		// Check if TPM is already initialized (not an error)
		if tpmErr, ok := err.(tpm2.TPMRC); ok {
			if uint32(tpmErr) == 0x100 { // TPM_RC_INITIALIZE - already started
				s.logger.Debug("TPM already initialized")
				return nil
			}
		}
		return &SentinelCauseError{Sentinel: ErrStartupFailed, Cause: &MessageError{Msg: fmt.Sprintf("TPM2_Startup failed: %v", err)}}
	}

	s.logger.Info("TPM2_Startup completed successfully")

	return nil
}

// StopExisting stops any existing swtpm processes for the given state directory
func StopExisting(stateDir string) error {
	// Find processes using the state directory
	cmd := exec.Command("pkill", "-f", fmt.Sprintf("swtpm.*%s", stateDir))
	if err := cmd.Run(); err != nil {
		// pkill returns non-zero if no processes are found, which is not an error
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// No processes found, this is expected
				return nil
			}
		}
		return &WrappedError{Msg: "failed to stop existing swtpm processes", Err: err}
	}

	// Wait for processes to terminate using channel-based synchronization
	// instead of time.Sleep
	done := make(chan struct{})
	go func() {
		// Poll for process termination
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(500 * time.Millisecond)
		defer deadline.Stop()

		for {
			select {
			case <-deadline.C:
				close(done)
				return
			case <-ticker.C:
				// Check if any swtpm processes still exist
				checkCmd := exec.Command("pgrep", "-f", fmt.Sprintf("swtpm.*%s", stateDir))
				if err := checkCmd.Run(); err != nil {
					// pgrep returns non-zero when no processes found
					close(done)
					return
				}
			}
		}
	}()

	<-done
	return nil
}

// SocketPath returns the path to the swtpm socket
func (s *SWTPM) SocketPath() string {
	return s.config.SocketPath
}

// IsInitialized checks if the TPM state directory contains existing state.
// This can be used to skip initialization on subsequent boots to preserve
// PCR values and sealed data.
func (s *SWTPM) IsInitialized() bool {
	// Check for the presence of tpm2-00.permall which is created by swtpm_setup
	stateFile := filepath.Join(s.config.StateDir, "tpm2-00.permall")
	_, err := os.Stat(stateFile)
	return err == nil
}

// StateDir returns the state directory path
func (s *SWTPM) StateDir() string {
	return s.config.StateDir
}

// PID returns the process ID of the running swtpm daemon
func (s *SWTPM) PID() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pid
}
