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

package iso

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// expiredContext returns a context whose deadline has already passed.
func expiredContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	t.Cleanup(cancel)
	return ctx
}

// installedDisk writes a sparse disk file larger than the 100 MB install
// threshold.
func installedDisk(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "disk.qcow2")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(200*1024*1024))
	require.NoError(t, f.Close())
	return path
}

func TestTestVerbs_TimeoutFlag(t *testing.T) {
	cmd := newTestCommand(getTestFlags)
	for _, name := range []string{"install", "firstboot", "boot", "all"} {
		sub, _, err := cmd.Find([]string{name})
		require.NoError(t, err, name)
		flag := sub.Flags().Lookup("timeout")
		require.NotNil(t, flag, "%s should take --timeout", name)
		assert.Equal(t, "0s", flag.DefValue, "%s waits for power-off by default", name)
	}
}

func TestCreateTestContext_TimeoutSetsDeadline(t *testing.T) {
	ctx, cancel := createTestContext(time.Millisecond)
	defer cancel()

	_, ok := ctx.Deadline()
	assert.True(t, ok, "a positive timeout should bound the context")
	<-ctx.Done()
	assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
}

func TestCreateTestContext_ZeroTimeoutHasNoDeadline(t *testing.T) {
	ctx, cancel := createTestContext(0)
	defer cancel()

	_, ok := ctx.Deadline()
	assert.False(t, ok, "zero waits until the guest powers off")
}

func TestInstallWaitResult_DeadlineFailsEvenWithWrittenDisk(t *testing.T) {
	err := installWaitResult(expiredContext(t), errors.New("signal: killed"), installedDisk(t), logging.DefaultLogger())
	require.Error(t, err, "an install cut off at the deadline must not pass on disk size")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestInstallWaitResult_RebootWithInstalledDiskSucceeds(t *testing.T) {
	err := installWaitResult(context.Background(), errors.New("exit status 1"), installedDisk(t), logging.DefaultLogger())
	assert.NoError(t, err)
}

func TestInstallWaitResult_ExitWithoutInstalledDiskFails(t *testing.T) {
	waitErr := errors.New("exit status 1")
	err := installWaitResult(context.Background(), waitErr, filepath.Join(t.TempDir(), "missing.qcow2"), logging.DefaultLogger())
	require.Error(t, err)
	assert.ErrorIs(t, err, waitErr)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestInstallWaitResult_PowerOffSucceeds(t *testing.T) {
	err := installWaitResult(context.Background(), nil, filepath.Join(t.TempDir(), "missing.qcow2"), logging.DefaultLogger())
	assert.NoError(t, err)
}

func TestInstallWaitResult_InterruptKeepsDiskCheck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := installWaitResult(ctx, errors.New("signal: killed"), installedDisk(t), logging.DefaultLogger())
	assert.NoError(t, err, "Ctrl+C after the install is the interactive way to finish")
}

func TestVMDeadlineError(t *testing.T) {
	assert.NoError(t, vmDeadlineError(context.Background()))

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	assert.NoError(t, vmDeadlineError(canceled), "an interrupt is not a timeout")

	assert.ErrorIs(t, vmDeadlineError(expiredContext(t)), context.DeadlineExceeded)
}

func TestTestVMError_DeadlineNamesTimeout(t *testing.T) {
	err := testVMError(45*time.Minute, "QEMU installation failed", vmDeadlineError(expiredContext(t)))

	var timeoutErr ErrVMTimeout
	require.ErrorAs(t, err, &timeoutErr)
	assert.Equal(t, 45*time.Minute, timeoutErr.Timeout)
	assert.Contains(t, err.Error(), "--timeout 45m0s")
}

func TestTestVMError_OtherFailureIsWrapped(t *testing.T) {
	cause := errors.New("exit status 1")
	err := testVMError(45*time.Minute, "QEMU boot failed", cause)

	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "QEMU boot failed")
	var timeoutErr ErrVMTimeout
	assert.False(t, errors.As(err, &timeoutErr))
}

// consoleLog writes a fake guest console log of n CRLF-terminated lines.
func consoleLog(t *testing.T, n int) string {
	t.Helper()
	var sb strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&sb, "console line %d\r\n", i)
	}
	path := filepath.Join(t.TempDir(), bootConsoleLogName)
	require.NoError(t, os.WriteFile(path, []byte(sb.String()), 0o600))
	return path
}

func TestBootError_TimeoutCarriesConsoleTail(t *testing.T) {
	path := consoleLog(t, 100)
	deadline := &WrappedError{Msg: "the VM was still running at the deadline", Err: context.DeadlineExceeded}

	err := bootError(45*time.Minute, 45*time.Minute+3*time.Second, path, deadline)

	var bootErr ErrBootTimeout
	require.ErrorAs(t, err, &bootErr)
	lines := strings.Split(bootErr.ConsoleTail, "\n")
	require.Len(t, lines, bootConsoleTailLines)
	assert.Equal(t, "console line 41", lines[0])
	assert.Equal(t, "console line 100", lines[len(lines)-1])
	assert.NotContains(t, bootErr.ConsoleTail, "\r")
	assert.Contains(t, err.Error(), "--timeout 45m0s (ran 45m3s)")
	assert.Contains(t, err.Error(), "last console lines from "+path+":\nconsole line 41\n")
	assert.NotContains(t, err.Error(), "console line 40\n")

	var timeoutErr ErrVMTimeout
	require.ErrorAs(t, err, &timeoutErr, "a boot timeout is still a VM timeout")
	assert.Equal(t, 45*time.Minute, timeoutErr.Timeout)
}

func TestBootError_MissingConsoleLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), bootConsoleLogName)

	err := bootError(time.Minute, time.Minute, path, context.DeadlineExceeded)

	var bootErr ErrBootTimeout
	require.ErrorAs(t, err, &bootErr)
	assert.Empty(t, bootErr.ConsoleTail)
	assert.Contains(t, err.Error(), "the console log "+path+" is missing or empty")
}

func TestBootError_EmptyConsoleLog(t *testing.T) {
	path := consoleLog(t, 0)

	err := bootError(time.Minute, time.Minute, path, context.DeadlineExceeded)

	var bootErr ErrBootTimeout
	require.ErrorAs(t, err, &bootErr)
	assert.Empty(t, bootErr.ConsoleTail)
	assert.Contains(t, err.Error(), "is missing or empty")
}

func TestBootError_QEMUFailureCarriesConsoleTail(t *testing.T) {
	path := consoleLog(t, 3)
	cause := errors.New("exit status 1")

	err := bootError(0, time.Second, path, cause)

	var failed *ErrBootFailed
	require.ErrorAs(t, err, &failed)
	assert.ErrorIs(t, err, cause)
	assert.Equal(t, "console line 1\nconsole line 2\nconsole line 3", failed.ConsoleTail)
	var timeoutErr ErrVMTimeout
	assert.False(t, errors.As(err, &timeoutErr))
}

func TestBootError_InteractiveRunHasNoConsoleLog(t *testing.T) {
	err := bootError(0, time.Second, "", errors.New("exit status 1"))

	assert.Contains(t, err.Error(), "the guest console was on the terminal")
}
