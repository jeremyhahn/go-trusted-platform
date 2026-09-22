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

package commands

import (
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closerRecorder is an installerCloser whose operations record and fail on
// demand.
type closerRecorder struct {
	unmountFlags []int
	unmountErrs  map[int]error // by flags
	lockErrs     []error       // one per attempt; nil past the end
	lockCalls    int
	detached     []string
	detachErr    error
	waits        int
}

func (r *closerRecorder) closer() installerCloser {
	return installerCloser{
		unmount: func(_ string, flags int) error {
			r.unmountFlags = append(r.unmountFlags, flags)
			return r.unmountErrs[flags]
		},
		lock: func(string) error {
			i := r.lockCalls
			r.lockCalls++
			if i < len(r.lockErrs) {
				return r.lockErrs[i]
			}
			return nil
		},
		detach: func(dev string) error { r.detached = append(r.detached, dev); return r.detachErr },
		wait:   func() { r.waits++ },
		sync:   func() {},
	}
}

func TestCloseInstaller_Closes(t *testing.T) {
	r := &closerRecorder{}

	require.NoError(t, closeInstaller("/dev/loop7", r.closer()))

	assert.Equal(t, []int{0}, r.unmountFlags, "a normal unmount that works needs no lazy one")
	assert.Equal(t, 1, r.lockCalls)
	assert.Equal(t, []string{"/dev/loop7"}, r.detached)
	assert.Zero(t, r.waits)
}

func TestCloseInstaller_LazyUnmountAndLockRetry(t *testing.T) {
	r := &closerRecorder{
		unmountErrs: map[int]error{0: errors.New("EBUSY")},
		lockErrs:    []error{errors.New("device busy"), errors.New("device busy")},
	}

	require.NoError(t, closeInstaller("/dev/loop7", r.closer()))

	assert.Equal(t, []int{0, syscall.MNT_DETACH}, r.unmountFlags, "a busy mount is detached lazily")
	assert.Equal(t, 3, r.lockCalls, "the mapping was busy twice, then closed")
	assert.Equal(t, 2, r.waits, "one wait between attempts, none after the last")
	assert.Equal(t, []string{"/dev/loop7"}, r.detached)
}

func TestCloseInstaller_ReportsWhatStaysOpen(t *testing.T) {
	t.Run("unmount fails both ways", func(t *testing.T) {
		r := &closerRecorder{unmountErrs: map[int]error{0: errors.New("EBUSY"), syscall.MNT_DETACH: errors.New("EINVAL")}}

		err := closeInstaller("/dev/loop7", r.closer())

		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Contains(t, err.Error(), "unmounting")
		assert.Zero(t, r.lockCalls, "a mapping under a live mount is not closed")
		assert.Empty(t, r.detached)
	})

	t.Run("the mapping never closes", func(t *testing.T) {
		busy := make([]error, installerLockAttempts)
		for i := range busy {
			busy[i] = errors.New("device busy")
		}
		r := &closerRecorder{lockErrs: busy}

		err := closeInstaller("/dev/loop7", r.closer())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "closing the installer LUKS mapping")
		assert.Equal(t, installerLockAttempts, r.lockCalls)
		assert.Equal(t, installerLockAttempts-1, r.waits)
		assert.Empty(t, r.detached, "the loop device under a live mapping is not detached")
	})

	t.Run("the loop device will not detach", func(t *testing.T) {
		r := &closerRecorder{detachErr: errors.New("EBUSY")}

		err := closeInstaller("/dev/loop7", r.closer())

		require.Error(t, err)
		assert.Contains(t, err.Error(), "detaching /dev/loop7")
	})

	t.Run("no loop device of our own means nothing to detach", func(t *testing.T) {
		r := &closerRecorder{}
		require.NoError(t, closeInstaller("", r.closer()))
		assert.Empty(t, r.detached)
	})
}

func TestDefaultInstallerCloser_IsComplete(t *testing.T) {
	c := defaultInstallerCloser()
	assert.NotNil(t, c.unmount)
	assert.NotNil(t, c.lock)
	assert.NotNil(t, c.detach)
	assert.NotNil(t, c.wait)
	assert.NotNil(t, c.sync)
}
