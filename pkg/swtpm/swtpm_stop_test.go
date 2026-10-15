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
	"bufio"
	"os/exec"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startStandIn starts script under sh as a stand-in for the swtpm daemon and
// waits until it prints "ready", so any signal disposition it sets is in
// place before the test signals it. stdin stays open until the test ends.
func startStandIn(t *testing.T, script string) *SWTPM {
	t.Helper()

	cmd := exec.Command("sh", "-c", script)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := stdin.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	require.Equal(t, "ready\n", line)

	s := &SWTPM{
		config: &Config{StateDir: t.TempDir()},
		logger: logging.DefaultLogger(),
		cmd:    cmd,
		pid:    cmd.Process.Pid,
	}
	s.watchExit(cmd)
	return s
}

func exitSignal(t *testing.T, err error) syscall.Signal {
	t.Helper()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled())
	return status.Signal()
}

func TestStop_ProcessExitsOnSIGTERM(t *testing.T) {
	s := startStandIn(t, "echo ready; exec cat")
	exitCh := s.exitCh

	require.NoError(t, s.Stop())

	<-exitCh
	assert.Equal(t, syscall.SIGTERM, exitSignal(t, s.exitErr))
	assert.False(t, s.IsRunning())
	assert.Nil(t, s.cmd)
}

func TestStop_KillsProcessThatIgnoresSIGTERM(t *testing.T) {
	restore := stopGracePeriod
	stopGracePeriod = 0
	t.Cleanup(func() { stopGracePeriod = restore })

	s := startStandIn(t, `trap "" TERM; echo ready; exec cat`)
	exitCh := s.exitCh

	require.NoError(t, s.Stop())

	<-exitCh
	assert.Equal(t, syscall.SIGKILL, exitSignal(t, s.exitErr))
	assert.False(t, s.IsRunning())
}

func TestStop_WithoutProcessReportsNotRunning(t *testing.T) {
	s := &SWTPM{
		config: &Config{StateDir: t.TempDir()},
		logger: logging.DefaultLogger(),
	}

	require.ErrorIs(t, s.Stop(), ErrNotRunning)
}
