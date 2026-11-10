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

package securewipe

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cov964FillError is the error a failing fill returns, so a test can tell
// it apart from any error the filesystem raises.
type cov964FillError struct{}

func (cov964FillError) Error() string { return "fill failed" }

// cov964File is a small regular file under a temp dir.
func cov964File(t *testing.T, flag int) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wipe.bin")
	require.NoError(t, os.WriteFile(path, []byte("SECRET"), 0o600))
	f, err := os.OpenFile(path, flag, 0)
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	return f
}

func TestCov964ErrorMessagesAndUnwrap(t *testing.T) {
	cause := os.ErrPermission
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "a pass error names the pass, the count and the fill",
			err:  &PassError{Pass: 2, Passes: 3, What: "ones", Err: cause},
			want: "securewipe: pass 2/3 (ones): " + cause.Error(),
		},
		{
			name: "a remove error names the path",
			err:  &RemoveError{Path: "/tmp/x.luks", Err: cause},
			want: "securewipe: removing /tmp/x.luks: " + cause.Error(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
			assert.ErrorIs(t, tt.err, cause, "the cause is reachable through Unwrap")
		})
	}
}

func TestCov964WritePassErrors(t *testing.T) {
	failing := fill{what: "failing", fn: func([]byte) error { return cov964FillError{} }}

	t.Run("a fill that fails stops the pass with its error", func(t *testing.T) {
		f := cov964File(t, os.O_WRONLY)

		err := writePass(f, 6, failing, make([]byte, 4))

		assert.ErrorIs(t, err, cov964FillError{})
	})

	t.Run("a file not open for writing fails the write", func(t *testing.T) {
		f := cov964File(t, os.O_RDONLY)

		err := writePass(f, 6, fillZeros, make([]byte, 4))

		require.Error(t, err)
		assert.NotErrorIs(t, err, cov964FillError{})
		got, readErr := os.ReadFile(f.Name())
		require.NoError(t, readErr)
		assert.Equal(t, []byte("SECRET"), got, "nothing was written")
	})

	t.Run("a closed file fails the seek", func(t *testing.T) {
		f := cov964File(t, os.O_WRONLY)
		require.NoError(t, f.Close())

		err := writePass(f, 6, fillZeros, make([]byte, 4))

		assert.ErrorIs(t, err, os.ErrClosed)
	})

	t.Run("an empty file writes nothing and syncs", func(t *testing.T) {
		f := cov964File(t, os.O_WRONLY)

		assert.NoError(t, writePass(f, 0, failing, make([]byte, 4)), "no chunk, so the fill never runs")
	})
}

func TestCov964OverwriteReportsFailingPass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wipe.bin")
	require.NoError(t, os.WriteFile(path, []byte("SECRET"), 0o600))
	failing := fill{what: "failing", fn: func([]byte) error { return cov964FillError{} }}
	var lines []string

	err := overwrite(path, []fill{fillZeros, failing}, func(s string) { lines = append(lines, s) })

	var pass *PassError
	require.ErrorAs(t, err, &pass)
	assert.Equal(t, 2, pass.Pass)
	assert.Equal(t, 2, pass.Passes)
	assert.Equal(t, "failing", pass.What)
	assert.ErrorIs(t, err, cov964FillError{})
	assert.Equal(t, []string{"Pass 1/2: zeros", "Pass 2/2: failing"}, lines)
}

func TestCov964RemoveNonEmptyDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "k"), []byte("x"), 0o600))

	err := remove(dir)

	var rm *RemoveError
	require.ErrorAs(t, err, &rm)
	assert.Equal(t, dir, rm.Path)
	assert.DirExists(t, dir, "a failed unlink leaves the target in place")
}

func TestCov964IsTrimUnavailable(t *testing.T) {
	assert.False(t, IsTrimUnavailable(os.ErrNotExist), "a missing directory is a real error")
	assert.False(t, IsTrimUnavailable(cov964FillError{}))
}
