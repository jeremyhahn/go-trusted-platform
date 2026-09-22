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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasses(t *testing.T) {
	names := func(fs []fill) []string {
		out := make([]string, len(fs))
		for i, f := range fs {
			out[i] = f.what
		}
		return out
	}
	assert.Equal(t, []string{"random"}, names(passes(0)), "below one pass is one random pass")
	assert.Equal(t, []string{"random"}, names(passes(PassesNIST)))
	assert.Equal(t, []string{"random", "random"}, names(passes(2)))
	assert.Equal(t, []string{"zeros", "ones", "random"}, names(passes(PassesDoD)))
	assert.Equal(t, []string{"zeros", "ones", "random", "random", "random", "random", "random"}, names(passes(PassesDoDECE)))
}

// secretFile is a regular file of a recognisable pattern, larger than one
// chunk so the chunk loop is exercised.
func secretFile(t *testing.T) (string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "installer.luks")
	secret := bytes.Repeat([]byte("SECRET-KEY-MATERIAL-"), (chunkSize+4096)/20)
	require.NoError(t, os.WriteFile(path, secret, 0o600))
	return path, secret
}

func TestOverwrite(t *testing.T) {
	t.Run("a zeros pass leaves nothing of the original", func(t *testing.T) {
		path, secret := secretFile(t)

		require.NoError(t, overwrite(path, []fill{fillZeros}, func(string) {}))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Len(t, got, len(secret), "the size is unchanged: no truncate-and-reallocate")
		assert.Equal(t, bytes.Repeat([]byte{0}, len(secret)), got)
	})

	t.Run("a ones pass covers every byte across the chunk boundary", func(t *testing.T) {
		path, secret := secretFile(t)

		require.NoError(t, overwrite(path, []fill{fillOnes}, func(string) {}))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, bytes.Repeat([]byte{0xFF}, len(secret)), got)
	})

	t.Run("a random pass is not the original and not a pattern", func(t *testing.T) {
		path, secret := secretFile(t)

		require.NoError(t, overwrite(path, []fill{fillRandom}, func(string) {}))

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Len(t, got, len(secret))
		assert.NotEqual(t, secret, got)
		assert.False(t, bytes.Contains(got, []byte("SECRET-KEY-MATERIAL-")), "no fragment of the secret survives")
	})

	t.Run("a missing file fails on the first pass and says which", func(t *testing.T) {
		err := overwrite(filepath.Join(t.TempDir(), "absent"), passes(PassesDoD), func(string) {})

		var pass *PassError
		require.ErrorAs(t, err, &pass)
		assert.Equal(t, 1, pass.Pass)
		assert.Equal(t, PassesDoD, pass.Passes)
		assert.Equal(t, "zeros", pass.What)
	})
}

func TestFile(t *testing.T) {
	t.Run("a regular file is overwritten, removed and reported", func(t *testing.T) {
		path, _ := secretFile(t)
		var lines []string

		err := File(path, PassesDoD, func(s string) { lines = append(lines, s) })

		require.NoError(t, err)
		assert.NoFileExists(t, path)
		joined := strings.Join(lines, "\n")
		assert.Contains(t, joined, "Secure wipe: 3 passes")
		assert.Contains(t, joined, "Pass 1/3: zeros")
		assert.Contains(t, joined, "Pass 2/3: ones")
		assert.Contains(t, joined, "Pass 3/3: random")
		assert.Contains(t, joined, "Removed and synced")
		assert.True(t, strings.Contains(joined, "Filesystem trimmed") || strings.Contains(joined, "TRIM not available here"),
			"TRIM is reported either way; a filesystem that declines it is not a failure: %s", joined)
	})

	t.Run("a nil reporter and fewer than one pass are allowed", func(t *testing.T) {
		path, _ := secretFile(t)

		require.NoError(t, File(path, 0, nil))

		assert.NoFileExists(t, path)
	})

	t.Run("a missing file is a pass error, nothing is removed", func(t *testing.T) {
		err := File(filepath.Join(t.TempDir(), "absent"), PassesNIST, nil)
		assert.True(t, errors.As(err, new(*PassError)))
	})
}

func TestRemove(t *testing.T) {
	t.Run("unlinks and syncs the directory", func(t *testing.T) {
		path, _ := secretFile(t)
		require.NoError(t, remove(path))
		assert.NoFileExists(t, path)
	})

	t.Run("a missing file is a remove error", func(t *testing.T) {
		err := remove(filepath.Join(t.TempDir(), "absent"))
		var rm *RemoveError
		require.ErrorAs(t, err, &rm)
	})
}

func TestTrim(t *testing.T) {
	// A temp dir is tmpfs or a disk filesystem depending on the host, and
	// the test is not root: the ioctl succeeds, the filesystem declines it,
	// or the kernel refuses it for want of CAP_SYS_ADMIN. Anything else is
	// a real error.
	err := trim(t.TempDir())
	if err != nil {
		assert.True(t, IsTrimUnavailable(err), "unexpected FITRIM error: %v", err)
	}
	assert.Error(t, trim(filepath.Join(t.TempDir(), "absent")))
}
