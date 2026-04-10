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
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPostInstallExecutor(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &OSConfig{
		PostInstall:       "echo 'test'",
		PostInstallScript: "/path/to/script.sh",
	}

	executor := NewPostInstallExecutor(logger, config)
	assert.NotNil(t, executor)
	assert.Equal(t, logger, executor.logger)
	assert.Equal(t, config, executor.config)
}

func TestPostInstallExecutor_Execute(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("empty config - no scripts", func(t *testing.T) {
		config := &OSConfig{}
		executor := NewPostInstallExecutor(logger, config)

		tmpDir := t.TempDir()
		err := executor.Execute(context.Background(), tmpDir)
		require.NoError(t, err)
	})

	t.Run("execute inline script", func(t *testing.T) {
		config := &OSConfig{
			PostInstall: "#!/bin/sh\necho 'inline test'",
		}
		executor := NewPostInstallExecutor(logger, config)

		tmpDir := t.TempDir()
		// Create basic chroot structure
		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "bin"), 0755))
		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "tmp"), 0755))

		// This will fail in unit test without a full chroot, but tests the code path
		err := executor.Execute(context.Background(), tmpDir)
		// Expected to fail due to missing chroot environment
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "inline post-install script failed")
	})

	t.Run("execute script file - file not found", func(t *testing.T) {
		config := &OSConfig{
			PostInstallScript: "/nonexistent/script.sh",
		}
		executor := NewPostInstallExecutor(logger, config)

		tmpDir := t.TempDir()
		err := executor.Execute(context.Background(), tmpDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "post-install script file failed")
		assert.Contains(t, err.Error(), "local script file not found")
	})
}

func TestPostInstallExecutor_ExecuteScriptFile(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("local script file exists", func(t *testing.T) {
		tmpScript := filepath.Join(t.TempDir(), "test-script.sh")
		scriptContent := "#!/bin/sh\necho 'test'"
		err := os.WriteFile(tmpScript, []byte(scriptContent), 0700)
		require.NoError(t, err)

		config := &OSConfig{
			PostInstallScript: tmpScript,
		}
		executor := NewPostInstallExecutor(logger, config)

		tmpRoot := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(tmpRoot, "tmp"), 0755))

		// Will fail without full chroot, but tests file handling
		err = executor.executeScriptFile(context.Background(), tmpRoot, tmpScript)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "script execution failed")
	})

	t.Run("http script download - server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		config := &OSConfig{
			PostInstallScript: server.URL + "/script.sh",
		}
		executor := NewPostInstallExecutor(logger, config)

		tmpRoot := t.TempDir()
		err := executor.executeScriptFile(context.Background(), tmpRoot, config.PostInstallScript)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download HTTP script")
	})
}

func TestPostInstallExecutor_DownloadAndValidateHTTPScript(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &OSConfig{}
	executor := NewPostInstallExecutor(logger, config)

	t.Run("checksum file not found", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, err := executor.downloadAndValidateHTTPScript(context.Background(), server.URL+"/script.sh")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum file not found")
	})

	t.Run("valid script with checksum", func(t *testing.T) {
		scriptContent := "#!/bin/sh\necho 'test script'"
		// Calculate actual SHA256
		hash := sha256.Sum256([]byte(scriptContent))
		checksum := hex.EncodeToString(hash[:])

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/script.sh.sha256":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(checksum + "  script.sh\n"))
			case "/script.sh":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(scriptContent))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		tmpPath, err := executor.downloadAndValidateHTTPScript(context.Background(), server.URL+"/script.sh")
		require.NoError(t, err)
		assert.NotEmpty(t, tmpPath)
		defer os.Remove(tmpPath)

		// Verify file was downloaded
		data, err := os.ReadFile(tmpPath)
		require.NoError(t, err)
		assert.Equal(t, scriptContent, string(data))
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		scriptContent := "#!/bin/sh\necho 'test script'"
		wrongChecksum := "0000000000000000000000000000000000000000000000000000000000000000"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/script.sh.sha256":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(wrongChecksum + "  script.sh\n"))
			case "/script.sh":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(scriptContent))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		_, err := executor.downloadAndValidateHTTPScript(context.Background(), server.URL+"/script.sh")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
	})

	t.Run("script download fails", func(t *testing.T) {
		checksum := "abc123"

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/script.sh.sha256" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(checksum))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
		defer server.Close()

		_, err := executor.downloadAndValidateHTTPScript(context.Background(), server.URL+"/script.sh")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to download script")
	})
}
