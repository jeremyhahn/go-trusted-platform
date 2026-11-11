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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadCommand_Creation(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	require.NotNil(t, cmd, "newDownloadCommand returned nil")
	assert.Equal(t, "download", cmd.Use)
	assert.Equal(t, "Download Alpine Linux base ISO", cmd.Short)
	assert.Contains(t, cmd.Long, "Downloads Alpine Linux ISO")
}

func TestDownloadCommand_FlagsExist(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	// Verify all flags exist
	flags := []string{
		"url", "version", "mirror", "arch", "force", "verify", "resume",
		"work-dir", "debug",
	}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "expected flag '%s' to be defined", flagName)
	}

	for _, removed := range []string{"config", "verbose"} {
		assert.Nil(t, cmd.Flags().Lookup(removed), "flag '%s' should not be defined", removed)
	}
}

func TestDownloadCommand_DefaultValues(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)

	// Verify default flag values
	versionFlag := cmd.Flags().Lookup("version")
	assert.Equal(t, "3.22.2", versionFlag.DefValue)

	archFlag := cmd.Flags().Lookup("arch")
	assert.Equal(t, "x86_64", archFlag.DefValue)

	verifyFlag := cmd.Flags().Lookup("verify")
	assert.Equal(t, "true", verifyFlag.DefValue)

	resumeFlag := cmd.Flags().Lookup("resume")
	assert.Equal(t, "true", resumeFlag.DefValue)

	workDirFlag := cmd.Flags().Lookup("work-dir")
	assert.Equal(t, "work", workDirFlag.DefValue)

	forceFlag := cmd.Flags().Lookup("force")
	assert.Equal(t, "false", forceFlag.DefValue)

	debugFlag := cmd.Flags().Lookup("debug")
	assert.Equal(t, "false", debugFlag.DefValue)
}

// newISOServer serves an ISO image and its .sha256 file the way an Alpine
// mirror does. A wrong checksum makes the server publish a digest that does
// not match the image.
func newISOServer(t *testing.T, image []byte, wrongChecksum bool) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(image)
	digest := hex.EncodeToString(sum[:])
	if wrongChecksum {
		digest = strings.Repeat("0", len(digest))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/test.iso", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write(image); err != nil {
			t.Errorf("serving ISO: %v", err)
		}
	})
	mux.HandleFunc("/releases/test.iso.sha256", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(digest + "  test.iso\n")); err != nil {
			t.Errorf("serving checksum: %v", err)
		}
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func TestRunDownload_DownloadsAndVerifies(t *testing.T) {
	image := []byte("iso image bytes")
	server := newISOServer(t, image, false)
	workDir := t.TempDir()

	flags := &downloadFlags{
		url:          server.URL + "/releases/test.iso",
		version:      "3.22.2",
		mirror:       server.URL,
		arch:         "x86_64",
		verify:       true,
		resumeEnable: true,
		workDir:      workDir,
	}

	out := new(bytes.Buffer)
	require.NoError(t, runDownload(context.Background(), getJSONTestFlags(), flags, out))

	var result downloadResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &result), out.String())
	sum := sha256.Sum256(image)
	assert.True(t, result.Success)
	assert.True(t, result.Verified)
	assert.Equal(t, filepath.Join(workDir, "test.iso"), result.ISOPath)
	assert.Equal(t, hex.EncodeToString(sum[:]), result.SHA256)
	assert.Equal(t, int64(len(image)), result.SizeBytes)

	downloaded, err := os.ReadFile(result.ISOPath)
	require.NoError(t, err)
	assert.Equal(t, image, downloaded)
}

func TestRunDownload_ChecksumMismatch(t *testing.T) {
	server := newISOServer(t, []byte("iso image bytes"), true)
	workDir := t.TempDir()

	flags := &downloadFlags{
		url:     server.URL + "/releases/test.iso",
		version: "3.22.2",
		mirror:  server.URL,
		arch:    "x86_64",
		verify:  true,
		workDir: workDir,
	}

	out := new(bytes.Buffer)
	err := runDownload(context.Background(), getJSONTestFlags(), flags, out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum")
	assert.Empty(t, out.String(), "a failed download prints no result")
	assert.NoFileExists(t, filepath.Join(workDir, "test.iso"), "a mismatched ISO is removed")
}

func TestRunDownload_InvalidURL(t *testing.T) {
	flags := &downloadFlags{
		url:     "not-a-url",
		version: "3.22.2",
		mirror:  "https://mirror.example.com/alpine",
		arch:    "x86_64",
		workDir: t.TempDir(),
	}

	err := runDownload(context.Background(), getTestFlags(), flags, new(bytes.Buffer))

	var invalid ErrConfigValidationFailed
	require.ErrorAs(t, err, &invalid)
	assert.Contains(t, invalid.Reason, "--url")
}

func TestRunDownload_UnsupportedArchitecture(t *testing.T) {
	flags := &downloadFlags{
		version: "3.22.2",
		mirror:  "https://mirror.example.com/alpine",
		arch:    "sparc",
		workDir: t.TempDir(),
	}

	err := runDownload(context.Background(), getTestFlags(), flags, new(bytes.Buffer))

	var invalid ErrConfigValidationFailed
	require.ErrorAs(t, err, &invalid)
}

func TestDownloadCommand_HasRunE(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	assert.NotNil(t, cmd.RunE)
}

func TestDownloadCommand_LongDescription(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "SHA256")
	assert.Contains(t, cmd.Long, "checksum")
	assert.Contains(t, cmd.Long, "resuming")
}

func TestDownloadCommand_ExamplesExist(t *testing.T) {
	cmd := newDownloadCommand(getTestFlags)
	assert.Contains(t, cmd.Long, "Examples:")
	assert.Contains(t, cmd.Long, "platformctl iso download")
}
