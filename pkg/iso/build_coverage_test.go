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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyFile(t *testing.T) {
	t.Run("copy valid file", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcPath := filepath.Join(tmpDir, "source.txt")
		dstPath := filepath.Join(tmpDir, "dest.txt")

		content := []byte("hello, world!")
		require.NoError(t, os.WriteFile(srcPath, content, 0644))

		err := copyFile(srcPath, dstPath)
		require.NoError(t, err)

		// Verify content was copied correctly
		data, err := os.ReadFile(dstPath)
		require.NoError(t, err)
		assert.Equal(t, content, data)
	})

	t.Run("copy nonexistent source", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := copyFile("/nonexistent/source.txt", filepath.Join(tmpDir, "dest.txt"))
		assert.Error(t, err)
	})

	t.Run("copy to invalid destination", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcPath := filepath.Join(tmpDir, "source.txt")
		require.NoError(t, os.WriteFile(srcPath, []byte("data"), 0644))

		err := copyFile(srcPath, "/nonexistent/dir/dest.txt")
		assert.Error(t, err)
	})

	t.Run("copy empty file", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcPath := filepath.Join(tmpDir, "empty.txt")
		dstPath := filepath.Join(tmpDir, "dest.txt")

		require.NoError(t, os.WriteFile(srcPath, []byte{}, 0644))

		err := copyFile(srcPath, dstPath)
		require.NoError(t, err)

		data, err := os.ReadFile(dstPath)
		require.NoError(t, err)
		assert.Empty(t, data)
	})
}

func TestCopyDir(t *testing.T) {
	t.Run("copy directory with files", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcDir := filepath.Join(tmpDir, "src")
		dstDir := filepath.Join(tmpDir, "dst")

		// Create source directory structure
		require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("file1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("file2"), 0644))

		err := copyDir(srcDir, dstDir)
		require.NoError(t, err)

		// Verify files were copied
		data1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
		require.NoError(t, err)
		assert.Equal(t, []byte("file1"), data1)

		data2, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file2.txt"))
		require.NoError(t, err)
		assert.Equal(t, []byte("file2"), data2)
	})

	t.Run("copy nonexistent source directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		err := copyDir("/nonexistent/src", filepath.Join(tmpDir, "dst"))
		assert.Error(t, err)
	})

	t.Run("copy empty directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcDir := filepath.Join(tmpDir, "empty-src")
		dstDir := filepath.Join(tmpDir, "empty-dst")

		require.NoError(t, os.MkdirAll(srcDir, 0755))

		err := copyDir(srcDir, dstDir)
		require.NoError(t, err)

		// Verify destination exists and is a directory
		info, err := os.Stat(dstDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("copy nested directories", func(t *testing.T) {
		tmpDir := t.TempDir()
		srcDir := filepath.Join(tmpDir, "src")
		dstDir := filepath.Join(tmpDir, "dst")

		// Create deeply nested structure
		require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "a", "b", "c"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a", "b", "c", "deep.txt"), []byte("deep"), 0644))

		err := copyDir(srcDir, dstDir)
		require.NoError(t, err)

		data, err := os.ReadFile(filepath.Join(dstDir, "a", "b", "c", "deep.txt"))
		require.NoError(t, err)
		assert.Equal(t, []byte("deep"), data)
	})
}
