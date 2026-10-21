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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeBootVM is a VM that has started; Wait returns waitErr at once, as
// if the guest had powered off.
type fakeBootVM struct {
	waitErr error
	waited  bool
	stopped bool
}

func (f *fakeBootVM) Wait() error {
	f.waited = true
	return f.waitErr
}

func (f *fakeBootVM) Stop() error {
	f.stopped = true
	return nil
}

func TestTestBoot_ExpectFlag(t *testing.T) {
	cmd := newTestCommand(getTestFlags)
	for _, name := range []string{"firstboot", "boot"} {
		sub, _, err := cmd.Find([]string{name})
		require.NoError(t, err, name)
		flag := sub.Flags().Lookup("expect")
		require.NotNil(t, flag, "%s should take --expect", name)
		assert.Empty(t, flag.DefValue, "%s waits for power-off by default", name)
	}

	install, _, err := cmd.Find([]string{"install"})
	require.NoError(t, err)
	assert.Nil(t, install.Flags().Lookup("expect"), "an install ends at power-off, not a milestone")
}

func TestRunTestBoot_ExpectNeedsTimeout(t *testing.T) {
	err := runTestBoot(nil, &testFlags{expect: "login:"}, "Normal Boot Test")

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Contains(t, err.Error(), "--expect needs --timeout")
}

// The installed node never powers off: the milestone, not QEMU's exit,
// ends the boot test, and the VM is then stopped (#973 run 59851).
func TestWaitForBoot_MilestoneSeenSucceedsAndStopsVM(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := filepath.Join(t.TempDir(), bootConsoleLogName)
		require.NoError(t, os.WriteFile(path, []byte("OpenRC is starting up\r\n\r\nnode-01 login: "), 0o600))
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		vm := &fakeBootVM{}

		err := waitForBoot(ctx, logging.DefaultLogger(), vm, path, "login:")

		assert.NoError(t, err)
		assert.True(t, vm.stopped, "a node that reached its milestone is stopped")
		assert.False(t, vm.waited, "the milestone ends the test, not a power-off")
	})
}

func TestWaitForBoot_MilestoneNeverSeenIsBootTimeoutWithTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := consoleLog(t, 100)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		vm := &fakeBootVM{}

		err := waitForBoot(ctx, logging.DefaultLogger(), vm, path, "login:")
		require.ErrorIs(t, err, context.DeadlineExceeded)
		assert.True(t, vm.stopped, "the VM is stopped at the deadline")

		var bootErr ErrBootTimeout
		require.ErrorAs(t, bootError(20*time.Minute, 20*time.Minute, path, err), &bootErr)
		lines := strings.Split(bootErr.ConsoleTail, "\n")
		require.Len(t, lines, bootConsoleTailLines)
		assert.Equal(t, "console line 100", lines[len(lines)-1])
	})
}

func TestWaitForBoot_InterruptBeforeMilestoneFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		path := consoleLog(t, 3)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		vm := &fakeBootVM{}

		err := waitForBoot(ctx, logging.DefaultLogger(), vm, path, "login:")

		require.Error(t, err, "Ctrl+C before the milestone is not a pass")
		assert.NotErrorIs(t, err, context.DeadlineExceeded, "an interrupt is not a timeout")
		assert.Contains(t, err.Error(), `waiting for "login:"`)
		assert.True(t, vm.stopped)
	})
}

// A second boot in the same work dir must not pass on the first boot's
// milestone, read before QEMU truncates the log.
func TestResetConsoleLog_RemovesThePreviousBootsLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), bootConsoleLogName)
	require.NoError(t, os.WriteFile(path, []byte("node-01 login: "), 0o600))

	require.NoError(t, resetConsoleLog(path))
	assert.NoFileExists(t, path)
	assert.NoError(t, resetConsoleLog(path), "a first boot has no log to remove")
}

func TestResetConsoleLog_UnremovableLogFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), bootConsoleLogName)
	require.NoError(t, os.MkdirAll(filepath.Join(path, "child"), 0o700))

	err := resetConsoleLog(path)

	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Contains(t, err.Error(), path)
}

func TestWaitForBoot_NoExpectEndsAtPowerOff(t *testing.T) {
	vm := &fakeBootVM{}

	assert.NoError(t, waitForBoot(context.Background(), logging.DefaultLogger(), vm, "", ""))
	assert.True(t, vm.waited)
	assert.False(t, vm.stopped, "a guest that powered off is not stopped again")
}

func TestWaitForBoot_NoExpectQEMUFailureIsWrapped(t *testing.T) {
	cause := errors.New("exit status 1")
	vm := &fakeBootVM{waitErr: cause}

	err := waitForBoot(context.Background(), logging.DefaultLogger(), vm, "", "")

	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "VM execution failed")
}
