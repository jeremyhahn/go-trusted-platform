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

package qemu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForPath_ReturnsOnceThePathExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qmp.sock")

	// The path appears while the wait is underway.
	found := make(chan bool, 1)
	go func() { found <- waitForPath(context.Background(), path, time.Hour) }()
	require.NoError(t, os.WriteFile(path, nil, 0o600))

	assert.True(t, <-found)
}

func TestWaitForPath_TimesOutOnMissingPath(t *testing.T) {
	assert.False(t, waitForPath(context.Background(), filepath.Join(t.TempDir(), "missing"), 0))
}

func TestWaitForPath_CancelEndsTheWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	assert.False(t, waitForPath(ctx, filepath.Join(t.TempDir(), "missing"), time.Hour))
}

func TestConnectMonitor_CancelEndsTheSocketWait(t *testing.T) {
	cfg := &Config{QMPSocketPath: filepath.Join(t.TempDir(), "qmp.sock")}
	vm := newSocketTestVM(cfg)
	vm.running.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := vm.ConnectMonitor(ctx)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Contains(t, wrapped.Msg, cfg.QMPSocketPath)
}

func TestConnectMonitor_MissingSocketAfterDeadline(t *testing.T) {
	cfg := &Config{QMPSocketPath: filepath.Join(t.TempDir(), "qmp.sock")}
	vm := newSocketTestVM(cfg)
	vm.running.Store(true)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()

	err := vm.ConnectMonitor(ctx)

	var notFound ErrMonitorSocketNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, cfg.QMPSocketPath, notFound.SocketPath)
}

// startTapHolder starts script under sh with a command line that matches the
// QEMU pgrep pattern for a TAP device unique to this test, and waits until the
// script prints "ready". It returns the TAP name and a channel that receives
// the process's exit error once it has been reaped.
func startTapHolder(t *testing.T, script string) (string, <-chan error) {
	t.Helper()

	tap := fmt.Sprintf("tgt%d", os.Getpid())
	cmd := exec.Command("sh", "-c", script, "qemu-ifname="+tap)
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

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	return tap, exited
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

func TestStopExistingByTap_TerminatesTheProcess(t *testing.T) {
	tap, exited := startTapHolder(t, "echo ready; read x")

	require.NoError(t, StopExistingByTap(tap))

	assert.Equal(t, syscall.SIGTERM, exitSignal(t, <-exited))
}

func TestStopExistingByTap_KillsProcessThatIgnoresSIGTERM(t *testing.T) {
	tap, exited := startTapHolder(t, `trap "" TERM; echo ready; read x`)

	require.NoError(t, StopExistingByTap(tap))

	assert.Equal(t, syscall.SIGKILL, exitSignal(t, <-exited))
}

func TestStopExistingByTap_NoMatchingProcess(t *testing.T) {
	require.NoError(t, StopExistingByTap(fmt.Sprintf("tgtnone%d", os.Getpid())))
}

func TestWaitForProcessesExit_TimesOutOnLiveProcess(t *testing.T) {
	assert.False(t, waitForProcessesExit([]int{os.Getpid()}, 0))
}

func TestSignalProcesses_SkipsExitedProcess(t *testing.T) {
	cmd := exec.Command("true")
	require.NoError(t, cmd.Run())

	assert.Empty(t, signalProcesses([]int{cmd.Process.Pid}, syscall.Signal(0)))
}
