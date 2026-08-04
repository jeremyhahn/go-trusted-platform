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

package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// ConsumeFirstbootHandoff tests
// =============================================================================

// TestConsumeFirstbootHandoff_FastPath verifies that when the handoff file does
// not exist, ConsumeFirstbootHandoff is a no-op returning (result, nil) with
// Present=false. This is the common case on every boot after the first.
func TestConsumeFirstbootHandoff_FastPath(t *testing.T) {
	app := &App{Logger: logging.DefaultLogger()}
	ctx := context.Background()

	result, err := app.ConsumeFirstbootHandoff(ctx)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Present)
	assert.Empty(t, result.Strategy)
	assert.Empty(t, result.SecretPath)
}

// =============================================================================
// shredAndUnlink tests
// =============================================================================

// TestShredAndUnlink_NonExistentPath verifies that shredAndUnlink is a no-op
// (returns nil) when the target file does not exist.
func TestShredAndUnlink_NonExistentPath(t *testing.T) {
	nonExistent := filepath.Join(t.TempDir(), "does-not-exist.key")
	err := shredAndUnlink(nonExistent, 0)
	require.NoError(t, err)
}

// TestShredAndUnlink_ExistingFile verifies that shredAndUnlink zeroes and
// removes an existing file.
func TestShredAndUnlink_ExistingFile(t *testing.T) {
	content := []byte("super-secret-recovery-passphrase")
	tmp, err := os.CreateTemp(t.TempDir(), "handoff-*.key")
	require.NoError(t, err)
	_, err = tmp.Write(content)
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	err = shredAndUnlink(tmp.Name(), len(content))
	require.NoError(t, err)

	// File must be gone.
	_, statErr := os.Stat(tmp.Name())
	require.Error(t, statErr)
	assert.True(t, os.IsNotExist(statErr))
}

// TestShredAndUnlink_EmptyFile verifies that an empty file (size=0) is handled
// without error.
func TestShredAndUnlink_EmptyFile(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "empty-*.key")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())

	err = shredAndUnlink(tmp.Name(), 0)
	require.NoError(t, err)

	_, statErr := os.Stat(tmp.Name())
	require.True(t, os.IsNotExist(statErr))
}

// TestShredAndUnlink_DirectoryPath verifies that opening a directory with
// O_WRONLY fails with a non-ErrNotExist error, covering the `return err` path
// in the OpenFile error handler.
func TestShredAndUnlink_DirectoryPath(t *testing.T) {
	dir := t.TempDir()
	// On Linux, opening a directory with O_WRONLY returns EISDIR,
	// which is not os.ErrNotExist, so shredAndUnlink must return that error.
	err := shredAndUnlink(dir, 0)
	require.Error(t, err)
	assert.False(t, os.IsNotExist(err))
}
