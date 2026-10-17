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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errFakeSetup is the failure fakeTools reports for swtpm_setup.
var errFakeSetup = &MessageError{Msg: "fake swtpm_setup failure"}

// fakeTools stands in for the swtpm binaries. Its swtpm_setup writes the
// state file the real one leaves in --tpmstate.
type fakeTools struct {
	missing   map[string]bool
	setupErr  error
	setupArgs []string
	setupRuns int

	// daemonArgs records the arguments of every daemon Start ran.
	daemonArgs [][]string
}

func (f *fakeTools) tools() tools {
	return tools{lookPath: f.lookPath, runSetup: f.runSetup, daemon: f.daemon}
}

// daemon stands in for the swtpm daemon with a process that runs until
// Stop signals it.
func (f *fakeTools) daemon(ctx context.Context, args []string) *exec.Cmd {
	f.daemonArgs = append(f.daemonArgs, args)
	return exec.CommandContext(ctx, "sleep", "300")
}

// daemonSocket is the socket path the daemon run of index i was given.
func (f *fakeTools) daemonSocket(t *testing.T, i int) string {
	t.Helper()
	require.Greater(t, len(f.daemonArgs), i)
	args := f.daemonArgs[i]
	for j, arg := range args {
		if arg == "--ctrl" || arg == "--server" {
			return strings.TrimPrefix(args[j+1], "type=unixio,path=")
		}
	}
	t.Fatalf("daemon run %d has no socket argument: %v", i, args)
	return ""
}

func (f *fakeTools) lookPath(file string) (string, error) {
	if f.missing[file] {
		return "", exec.ErrNotFound
	}
	return "/usr/bin/" + file, nil
}

func (f *fakeTools) runSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	f.setupRuns++
	f.setupArgs = args
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.setupErr != nil {
		if _, err := io.WriteString(stderr, "fake setup stderr"); err != nil {
			return err
		}
		return f.setupErr
	}
	stateDir := args[slices.Index(args, "--tpmstate")+1]
	return os.WriteFile(filepath.Join(stateDir, "tpm2-00.permall"), []byte("tpm state"), 0600)
}

// newFakeSWTPM builds an SWTPM whose binaries are fake.
func newFakeSWTPM(t *testing.T, config *Config, fake *fakeTools) *SWTPM {
	t.Helper()
	s, err := newSWTPM(config, logging.DefaultLogger(), fake.tools())
	require.NoError(t, err)
	return s
}

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
			fake := &fakeTools{}
			swtpm, err := newSWTPM(tc.config, logging.DefaultLogger(), fake.tools())

			if tc.expectError != nil {
				assert.ErrorIs(t, err, tc.expectError)
				assert.Nil(t, swtpm)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, swtpm)
			assert.Equal(t, tc.config.StateDir, swtpm.config.StateDir)
			assert.Zero(t, fake.setupRuns, "construction must not run swtpm_setup")
		})
	}
}

// TestNewSWTPM_Defaults verifies the defaults applied to an empty config
// and that explicit settings are kept.
func TestNewSWTPM_Defaults(t *testing.T) {
	stateDir := t.TempDir()
	defaulted := newFakeSWTPM(t, &Config{StateDir: stateDir}, &fakeTools{})
	assert.Equal(t, filepath.Join(stateDir, "swtpm.sock"), defaulted.config.SocketPath)
	assert.Equal(t, []string{"sha256"}, defaulted.config.PCRBanks)
	assert.Equal(t, 20, defaulted.config.LogLevel)

	custom := newFakeSWTPM(t, &Config{
		StateDir:   "/tmp/test-swtpm",
		SocketPath: "/tmp/test-swtpm/custom.sock",
		PCRBanks:   []string{"sha256", "sha384"},
		LogLevel:   10,
	}, &fakeTools{})
	assert.Equal(t, "/tmp/test-swtpm/custom.sock", custom.config.SocketPath)
	assert.Equal(t, []string{"sha256", "sha384"}, custom.config.PCRBanks)
	assert.Equal(t, 10, custom.config.LogLevel)
}

// TestNewSWTPM_ToolMissing verifies that either missing binary is reported
// as not installed.
func TestNewSWTPM_ToolMissing(t *testing.T) {
	for _, binary := range []string{"swtpm", "swtpm_setup"} {
		t.Run(binary, func(t *testing.T) {
			fake := &fakeTools{missing: map[string]bool{binary: true}}
			swtpm, err := newSWTPM(&Config{StateDir: t.TempDir()}, nil, fake.tools())
			assert.ErrorIs(t, err, ErrSWTPMNotInstalled)
			assert.Nil(t, swtpm)
		})
	}
}

// TestSWTPMNotInstalled verifies that NewSWTPM looks the binaries up on PATH.
func TestSWTPMNotInstalled(t *testing.T) {
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty"))

	swtpm, err := NewSWTPM(&Config{StateDir: t.TempDir()}, logging.DefaultLogger())

	assert.ErrorIs(t, err, ErrSWTPMNotInstalled)
	assert.Nil(t, swtpm)
}

// TestInitialize verifies that swtpm_setup runs in a scratch directory and
// its state files are copied into StateDir.
func TestInitialize(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(map[bool]string{false: "quiet", true: "debug"}[debug], func(t *testing.T) {
			stateDir := filepath.Join(t.TempDir(), "state")
			fake := &fakeTools{}
			swtpm := newFakeSWTPM(t, &Config{
				StateDir: stateDir,
				PCRBanks: []string{"sha256", "sha384", "sha512"},
				Debug:    debug,
			}, fake)

			require.NoError(t, swtpm.Initialize(context.Background()))

			require.Equal(t, 1, fake.setupRuns)
			tpmState := fake.setupArgs[slices.Index(fake.setupArgs, "--tpmstate")+1]
			assert.NotEqual(t, stateDir, tpmState, "swtpm_setup must run in a scratch directory")
			assert.NoDirExists(t, tpmState, "the scratch directory must be removed")
			assert.Equal(t, []string{
				"--tpm2",
				"--tpmstate", tpmState,
				"--pcr-banks", "sha256,sha384,sha512",
				"--overwrite",
			}, fake.setupArgs)

			data, err := os.ReadFile(filepath.Join(stateDir, "tpm2-00.permall"))
			require.NoError(t, err)
			assert.Equal(t, "tpm state", string(data))
			info, err := os.Stat(filepath.Join(stateDir, "tpm2-00.permall"))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		})
	}
}

// TestInitializeSetupFails verifies that a failed swtpm_setup is reported
// with its stderr and leaves no state behind.
func TestInitializeSetupFails(t *testing.T) {
	stateDir := t.TempDir()
	swtpm := newFakeSWTPM(t, &Config{StateDir: stateDir}, &fakeTools{setupErr: errFakeSetup})

	err := swtpm.Initialize(context.Background())

	require.ErrorIs(t, err, ErrInitFailed)
	assert.Contains(t, err.Error(), errFakeSetup.Error())
	assert.Contains(t, err.Error(), "fake setup stderr")
	assert.False(t, swtpm.IsInitialized())
}

// TestInitializeWithContext verifies that the caller's context reaches
// swtpm_setup, so a cancelled context fails initialization.
func TestInitializeWithContext(t *testing.T) {
	swtpm := newFakeSWTPM(t, &Config{StateDir: t.TempDir()}, &fakeTools{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := swtpm.Initialize(ctx)
	assert.ErrorIs(t, err, ErrInitFailed)
	assert.False(t, swtpm.IsInitialized())
}

// TestInitializeError verifies that a state directory that cannot be
// created fails before swtpm_setup runs.
func TestInitializeError(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(parent, []byte("not a directory"), 0600))
	fake := &fakeTools{}
	swtpm := newFakeSWTPM(t, &Config{StateDir: filepath.Join(parent, "state")}, fake)

	err := swtpm.Initialize(context.Background())

	assert.ErrorIs(t, err, ErrInitFailed)
	assert.Zero(t, fake.setupRuns)
}

// TestIsInitialized verifies that the permanent state file marks the TPM
// as initialized.
func TestIsInitialized(t *testing.T) {
	swtpm := newFakeSWTPM(t, &Config{StateDir: t.TempDir()}, &fakeTools{})

	assert.False(t, swtpm.IsInitialized())
	require.NoError(t, swtpm.Initialize(context.Background()))
	assert.True(t, swtpm.IsInitialized())
}

// TestIsInitializedNoStateDir verifies a missing state directory reads as
// uninitialized.
func TestIsInitializedNoStateDir(t *testing.T) {
	swtpm := newFakeSWTPM(t, &Config{StateDir: filepath.Join(t.TempDir(), "missing")}, &fakeTools{})

	assert.False(t, swtpm.IsInitialized())
}

// TestAccessors tests the accessor methods
func TestAccessors(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test.sock")

	swtpm := newFakeSWTPM(t, &Config{
		StateDir:   tempDir,
		SocketPath: socketPath,
	}, &fakeTools{})

	assert.Equal(t, tempDir, swtpm.StateDir())
	assert.Equal(t, socketPath, swtpm.SocketPath())
	assert.Equal(t, 0, swtpm.PID())
	assert.False(t, swtpm.IsRunning())
}

// TestNilLogger verifies a nil logger falls back to the default logger.
func TestNilLogger(t *testing.T) {
	fake := &fakeTools{}
	swtpm, err := newSWTPM(&Config{StateDir: t.TempDir()}, nil, fake.tools())

	require.NoError(t, err)
	assert.NotNil(t, swtpm.logger)
}

// TestStopNotRunning tests stopping when not running
func TestStopNotRunning(t *testing.T) {
	swtpm := newFakeSWTPM(t, &Config{StateDir: t.TempDir()}, &fakeTools{})

	assert.ErrorIs(t, swtpm.Stop(), ErrNotRunning)
}

// TestStartWithoutInitialize verifies Start refuses a missing state
// directory before launching anything.
func TestStartWithoutInitialize(t *testing.T) {
	swtpm := newFakeSWTPM(t, &Config{StateDir: filepath.Join(t.TempDir(), "missing")}, &fakeTools{})

	err := swtpm.Start(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "state directory does not exist")
	assert.False(t, swtpm.IsRunning())
}

// TestSendStartupNotRunning verifies TPM2_Startup fails without a socket.
func TestSendStartupNotRunning(t *testing.T) {
	swtpm := newFakeSWTPM(t, &Config{StateDir: t.TempDir()}, &fakeTools{})

	assert.ErrorIs(t, swtpm.SendStartup(), ErrStartupFailed)
}

// TestWaitForSocketNoProcess verifies the wait ends as soon as it sees no
// swtpm process behind a missing socket.
func TestWaitForSocketNoProcess(t *testing.T) {
	tempDir := t.TempDir()
	swtpm := newFakeSWTPM(t, &Config{
		StateDir:   tempDir,
		SocketPath: filepath.Join(tempDir, "nonexistent.sock"),
	}, &fakeTools{})

	err := swtpm.WaitForSocket(time.Minute)

	require.ErrorIs(t, err, ErrSocketNotReady)
	assert.Contains(t, err.Error(), "exited before socket was created")
}

// TestWaitForSocketNonSocketFile verifies a regular file at the socket path
// is rejected.
func TestWaitForSocketNonSocketFile(t *testing.T) {
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "fake.sock")
	require.NoError(t, os.WriteFile(socketPath, []byte("not a socket"), 0644))

	swtpm := newFakeSWTPM(t, &Config{
		StateDir:   tempDir,
		SocketPath: socketPath,
	}, &fakeTools{})

	err := swtpm.WaitForSocket(time.Minute)
	require.ErrorIs(t, err, ErrSocketNotReady)
	assert.Contains(t, err.Error(), "not a socket")
}

// TestStopExisting verifies StopExisting succeeds when no swtpm uses the
// state directory.
func TestStopExisting(t *testing.T) {
	assert.NoError(t, StopExisting(t.TempDir()))
}
