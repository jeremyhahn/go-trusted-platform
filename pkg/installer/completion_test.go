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

package installer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// completionFixture builds the minimum installer these helpers need: a logger.
func completionFixture() *installer {
	return &installer{logger: createTestLogger()}
}

// espWithUKI lays out an ESP tree in a temp dir and writes BOOTX64.EFI with
// the given contents. Passing nil omits the file entirely.
func espWithUKI(t *testing.T, contents []byte) string {
	t.Helper()
	root := t.TempDir()
	bootDir := filepath.Join(root, espBootDir)
	require.NoError(t, os.MkdirAll(bootDir, 0o755))
	if contents != nil {
		require.NoError(t, os.WriteFile(filepath.Join(bootDir, espUKIName), contents, 0o644))
	}
	return root
}

func requireCompletionError(t *testing.T, err error) *InstallerError {
	t.Helper()
	require.Error(t, err)
	var instErr *InstallerError
	require.True(t, errors.As(err, &instErr), "want *InstallerError, got %T", err)
	require.Equal(t, ErrorTypeCompletion, instErr.Type)
	return instErr
}

// TestSyncUKIOnESP_SucceedsWhenTheImageIsPresent is the control: a real,
// non-empty UKI must not fail the install. Without it, a change that failed
// unconditionally would satisfy every negative case below.
func TestSyncUKIOnESP_SucceedsWhenTheImageIsPresent(t *testing.T) {
	root := espWithUKI(t, []byte("MZ\x00\x00 a unified kernel image"))

	require.NoError(t, completionFixture().syncUKIOnESPAt(root))
}

// TestSyncUKIOnESP_MissingImageFailsTheInstall is the defect this change
// exists for. The old code logged "UKI file MISSING from EFI partition" as a
// warning and carried on to unmount and reboot.
func TestSyncUKIOnESP_MissingImageFailsTheInstall(t *testing.T) {
	root := espWithUKI(t, nil)

	err := completionFixture().syncUKIOnESPAt(root)

	instErr := requireCompletionError(t, err)
	assert.Contains(t, instErr.Message, "would not boot",
		"the message must say what happens at the next boot, not just name a syscall")
}

// TestSyncUKIOnESP_EmptyImageFailsTheInstall covers the case an existence
// check cannot see. A zero-length BOOTX64.EFI stats successfully and is
// exactly as unbootable as an absent one; the old code logged its size.
func TestSyncUKIOnESP_EmptyImageFailsTheInstall(t *testing.T) {
	root := espWithUKI(t, []byte{})

	instErr := requireCompletionError(t, completionFixture().syncUKIOnESPAt(root))
	assert.Contains(t, instErr.Message, "empty")
}

// TestSyncUKIOnESP_MissingBootDirectoryFailsTheInstall covers an ESP that was
// never populated at all, rather than one missing just the image.
func TestSyncUKIOnESP_MissingBootDirectoryFailsTheInstall(t *testing.T) {
	requireCompletionError(t, completionFixture().syncUKIOnESPAt(t.TempDir()))
}

// TestUnmountOrFail_RegularUnmountSucceeds asserts the ordinary path does not
// reach for the lazy fallback.
func TestUnmountOrFail_RegularUnmountSucceeds(t *testing.T) {
	var flags []int
	unmount := func(target string, f int) error {
		flags = append(flags, f)
		return nil
	}

	require.NoError(t, completionFixture().unmountOrFail("/mnt", unmount))
	assert.Equal(t, []int{0}, flags, "a successful unmount must not also be attempted lazily")
}

// TestUnmountOrFail_LazyFallbackStillSucceeds is the guard against making this
// too strict. A lazy unmount is a legitimate outcome: it detaches the tree and
// completes teardown when the last reference goes. Failing here would turn a
// working install into a failed one, which is the more expensive mistake.
func TestUnmountOrFail_LazyFallbackStillSucceeds(t *testing.T) {
	var flags []int
	unmount := func(target string, f int) error {
		flags = append(flags, f)
		if f == 0 {
			return errors.New("device or resource busy")
		}
		return nil
	}

	require.NoError(t, completionFixture().unmountOrFail("/mnt/boot/efi", unmount))
	assert.Equal(t, []int{0, unix.MNT_DETACH}, flags)
}

// TestUnmountOrFail_BothAttemptsFailTheInstall covers the case the old code
// logged twice and stepped over: the filesystem is still attached and still
// dirty when the machine reboots.
func TestUnmountOrFail_BothAttemptsFailTheInstall(t *testing.T) {
	unmount := func(target string, f int) error { return errors.New("device or resource busy") }

	instErr := requireCompletionError(t,
		completionFixture().unmountOrFail("/mnt/boot/efi", unmount))
	assert.Contains(t, instErr.Message, "/mnt/boot/efi")
}

// TestFlushBuffers_SucceedsWhenTheDeviceFlushes is the control.
func TestFlushBuffers_SucceedsWhenTheDeviceFlushes(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, nil
	}

	require.NoError(t, completionFixture().flushBuffers(context.Background(), "/dev/sda2", run))
}

// TestFlushBuffers_RefusedFlushFailsTheInstall: the device ran the command and
// rejected it, so pending writes may not have reached the disk.
func TestFlushBuffers_RefusedFlushFailsTheInstall(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return []byte("BLKFLSBUF failed: Input/output error"), &exec.ExitError{}
	}

	instErr := requireCompletionError(t,
		completionFixture().flushBuffers(context.Background(), "/dev/sda2", run))
	assert.Contains(t, instErr.Message, "/dev/sda2")
}

// TestFlushBuffers_MissingBlockdevDoesNotFailTheInstall is the other half of
// the "too strict is an outage" pair. These calls sit after a unix.Sync() that
// already blocked until writeback completed, so an absent optional tool must
// not fail an install that actually worked.
func TestFlushBuffers_MissingBlockdevDoesNotFailTheInstall(t *testing.T) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return nil, &exec.Error{Name: "blockdev", Err: exec.ErrNotFound}
	}

	require.NoError(t, completionFixture().flushBuffers(context.Background(), "/dev/sda2", run))
}

// TestFlushFailureIsFatal_ClassifiesByWhetherTheCommandRan pins the
// distinction the two tests above depend on.
func TestFlushFailureIsFatal_ClassifiesByWhetherTheCommandRan(t *testing.T) {
	cases := map[string]struct {
		err   error
		fatal bool
	}{
		"no failure":               {nil, false},
		"blockdev not installed":   {&exec.Error{Name: "blockdev", Err: exec.ErrNotFound}, false},
		"wrapped lookup failure":   {&InstallerError{Message: "x", Cause: &exec.Error{Name: "blockdev", Err: exec.ErrNotFound}}, false},
		"device refused the flush": {&exec.ExitError{}, true},
		"context cancelled":        {context.Canceled, true},
		"unclassifiable I/O error": {errors.New("input/output error"), true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.fatal, flushFailureIsFatal(tc.err))
		})
	}
}
