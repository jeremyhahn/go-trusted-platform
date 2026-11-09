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
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// swtpmLogTail is a log longer than the 500 bytes WaitForSocket quotes:
// only the trailing "b" run may appear in an error.
var swtpmLogTail = strings.Repeat("a", 100) + strings.Repeat("b", 500)

// listenUnix opens a Unix socket at path for the length of the test.
func listenUnix(t *testing.T, path string) {
	t.Helper()
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
}

// writeSWTPMLog writes swtpmLogTail to a log file and points s at it.
func writeSWTPMLog(t *testing.T, s *SWTPM) {
	t.Helper()
	s.logFile = filepath.Join(t.TempDir(), "swtpm.log")
	require.NoError(t, os.WriteFile(s.logFile, []byte(swtpmLogTail), 0o600))
}

func TestRunSWTPMSetup_PassesArgsAndOutput(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\necho out-$1\necho err-$2 >&2\nexit 3\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "swtpm_setup"), []byte(script), 0o755))
	t.Setenv("PATH", binDir)

	var stdout, stderr bytes.Buffer
	err := runSWTPMSetup(context.Background(), []string{"--tpm2", "--overwrite"}, &stdout, &stderr)

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, 3, exitErr.ExitCode())
	assert.Equal(t, "out---tpm2\n", stdout.String())
	assert.Equal(t, "err---overwrite\n", stderr.String())
}

func TestRunSWTPMSetup_Errors(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name string
		ctx  context.Context
		want error
	}{
		{name: "binary missing", ctx: context.Background(), want: exec.ErrNotFound},
		{name: "context cancelled", ctx: cancelled, want: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binDir := t.TempDir()
			if tt.want != exec.ErrNotFound {
				require.NoError(t, os.WriteFile(filepath.Join(binDir, "swtpm_setup"), []byte("#!/bin/sh\nexit 0\n"), 0o755))
			}
			t.Setenv("PATH", binDir)

			err := runSWTPMSetup(tt.ctx, nil, nil, nil)
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestWrappedError_MessageAndCause(t *testing.T) {
	cause := &MessageError{Msg: "disk full"}
	err := &WrappedError{Msg: "failed to write", Err: cause}

	assert.Equal(t, "failed to write: disk full", err.Error())
	var got *MessageError
	require.ErrorAs(t, err, &got)
	assert.Same(t, cause, got)
}

func TestWaitForSocket_ReadyWhenSocketListensAndProcessRuns(t *testing.T) {
	s := startStandIn(t, "echo ready; exec cat")
	t.Cleanup(func() { require.NoError(t, s.Stop()) })
	s.config.SocketPath = filepath.Join(s.config.StateDir, "s.sock")
	listenUnix(t, s.config.SocketPath)

	assert.NoError(t, s.WaitForSocket(time.Minute))
}

func TestWaitForSocket_Failures(t *testing.T) {
	tests := []struct {
		name    string
		running bool
		socket  bool
		log     bool
		timeout bool
		want    string
	}{
		{name: "socket without process", socket: true, want: "swtpm process died"},
		{name: "process exited with log", log: true, want: "exited before socket was created; swtpm log: ..." + strings.Repeat("b", 500)},
		{name: "timeout with log", running: true, log: true, timeout: true, want: "socket file not ready after 1ns; swtpm log: ..." + strings.Repeat("b", 500)},
		{name: "timeout without log", running: true, timeout: true, want: "socket file not ready after 1ns"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &SWTPM{config: &Config{StateDir: t.TempDir()}, logger: logging.DefaultLogger()}
			if tt.running {
				s = startStandIn(t, "echo ready; exec cat")
				t.Cleanup(func() { require.NoError(t, s.Stop()) })
			}
			s.config.SocketPath = filepath.Join(s.config.StateDir, "s.sock")
			if tt.socket {
				listenUnix(t, s.config.SocketPath)
			}
			if tt.log {
				writeSWTPMLog(t, s)
			}
			timeout := time.Minute
			if tt.timeout {
				timeout = time.Nanosecond
			}

			err := s.WaitForSocket(timeout)

			require.ErrorIs(t, err, ErrSocketNotReady)
			assert.True(t, strings.HasSuffix(err.Error(), tt.want), "error %q must end with %q", err.Error(), tt.want)
			assert.NotContains(t, err.Error(), "ab", "the log is quoted from its last 500 bytes")
		})
	}
}

func TestStart_SocketTypeFollowsQEMUMode(t *testing.T) {
	tests := []struct {
		name       string
		qemuMode   bool
		longSocket bool
		want       string
	}{
		{name: "data channel", qemuMode: false, want: "--server type=unixio,path="},
		{name: "control channel", qemuMode: true, want: "--ctrl type=unixio,path="},
		{name: "control channel on a socket path that takes the temp-directory fallback", qemuMode: true, longSocket: true, want: "--ctrl type=unixio,path="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := filepath.Join(t.TempDir(), "args")
			fakeSWTPMScriptOnPath(t, "#!/bin/sh\necho \"$@\" > "+argsFile+"\n")
			stateDir := t.TempDir()
			socketName := "s.sock"
			if tt.longSocket {
				socketName = strings.Repeat("s", unixSocketPathMax) + ".sock"
			}
			socketPath := filepath.Join(t.TempDir(), socketName)
			s := &SWTPM{
				config: &Config{StateDir: stateDir, SocketPath: socketPath, QEMUMode: tt.qemuMode, Debug: true, LogLevel: 5},
				logger: logging.DefaultLogger(),
			}

			require.NoError(t, s.Start(context.Background()))
			// The path Start handed to swtpm: the configured one, or the
			// temp-directory fallback when the host's temp path is long.
			effective := s.SocketPath()
			<-s.exitCh
			require.NoError(t, s.Stop(), "Stop must accept a daemon that already exited")

			if tt.longSocket {
				assert.NotEqual(t, socketPath, effective)
				assert.Equal(t, os.TempDir(), filepath.Dir(filepath.Dir(effective)))
				assert.True(t, strings.HasPrefix(filepath.Base(filepath.Dir(effective)), "swtpm-"))
				assert.Equal(t, "swtpm.sock", filepath.Base(effective))
				assert.Equal(t, socketPath, s.SocketPath(), "Stop restores the configured socket path")
			}

			args, err := os.ReadFile(argsFile)
			require.NoError(t, err)
			assert.Contains(t, string(args), tt.want+effective)
			assert.Contains(t, string(args), "--tpmstate dir=")
			assert.Contains(t, string(args), "--log level=5")
			assert.Contains(t, string(args), "--log file="+filepath.Join(filepath.Dir(effective), "swtpm.log"))
		})
	}
}

func TestStart_StateRoundTripsThroughTempDir(t *testing.T) {
	fakeSWTPMOnPath(t)
	stateDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "tpm2-00.permall"), []byte("initial"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(stateDir, "nested"), 0o700))
	configured := filepath.Join(t.TempDir(), strings.Repeat("s", unixSocketPathMax), "swtpm.sock")
	s := &SWTPM{config: &Config{StateDir: stateDir, SocketPath: configured}, logger: logging.DefaultLogger()}

	require.NoError(t, s.Start(context.Background()))
	tempDir := filepath.Dir(s.SocketPath())

	copied := filepath.Join(tempDir, "tpm2-00.permall")
	data, err := os.ReadFile(copied)
	require.NoError(t, err)
	assert.Equal(t, "initial", string(data))
	info, err := os.Stat(copied)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "Start must keep the state file mode")
	assert.NoDirExists(t, filepath.Join(tempDir, "nested"), "Start copies files, not directories")

	// The daemon writes new state and a log beside it while it runs.
	require.NoError(t, os.WriteFile(copied, []byte("updated"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "swtpm.log"), []byte("log"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(tempDir, "tpm2-dir"), 0o700))

	require.NoError(t, s.Stop())

	data, err = os.ReadFile(filepath.Join(stateDir, "tpm2-00.permall"))
	require.NoError(t, err)
	assert.Equal(t, "updated", string(data), "Stop must copy TPM state back")
	assert.NoFileExists(t, filepath.Join(stateDir, "swtpm.log"), "Stop must not copy the log back")
	assert.NoDirExists(t, filepath.Join(stateDir, "tpm2-dir"))
	assert.NoDirExists(t, tempDir)
}

func TestStart_Errors(t *testing.T) {
	t.Run("state directory missing", func(t *testing.T) {
		fakeSWTPMOnPath(t)
		missing := filepath.Join(t.TempDir(), "missing")
		s := &SWTPM{config: &Config{StateDir: missing, SocketPath: filepath.Join(t.TempDir(), "s.sock")}, logger: logging.DefaultLogger()}

		err := s.Start(context.Background())

		var msgErr *MessageError
		require.ErrorAs(t, err, &msgErr)
		assert.Equal(t, "state directory does not exist: "+missing, msgErr.Msg)
		assert.False(t, s.IsRunning())
	})

	t.Run("swtpm binary missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		s := &SWTPM{config: &Config{StateDir: t.TempDir(), SocketPath: filepath.Join(t.TempDir(), "s.sock")}, logger: logging.DefaultLogger()}

		err := s.Start(context.Background())
		t.Cleanup(func() { require.NoError(t, os.RemoveAll(s.tempStateDir)) })

		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to start swtpm", wrapped.Msg)
		assert.True(t, errors.Is(err, exec.ErrNotFound))
		assert.Zero(t, s.PID())
		assert.False(t, s.IsRunning())
	})
}
