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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadISO_Success(t *testing.T) {
	// Create test content
	testContent := []byte("This is test ISO content for Alpine Linux")
	testHash := sha256.Sum256(testContent)
	testHashStr := hex.EncodeToString(testHash[:])

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/alpine.iso":
			w.WriteHeader(http.StatusOK)
			w.Write(testContent)
		case "/alpine.iso.sha256":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(testHashStr + "  alpine.iso\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create temp directory
	tmpDir := t.TempDir()

	// Configure download
	config := &ISOConfig{
		Version:        "3.22.2",
		ISO:            "alpine.iso",
		URL:            server.URL + "/alpine.iso",
		MirrorURL:      server.URL,
		WorkDir:        tmpDir,
		VerifyChecksum: true,
		ResumeDownload: false,
	}

	// Execute download
	ctx := context.Background()
	err := DownloadISO(ctx, config)
	require.NoError(t, err)

	// Verify ISO file exists
	isoPath := filepath.Join(tmpDir, "alpine.iso")
	assert.FileExists(t, isoPath)

	// Verify content
	content, err := os.ReadFile(isoPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, content)

	// Verify checksum file exists
	checksumPath := filepath.Join(tmpDir, "alpine.iso.sha256")
	assert.FileExists(t, checksumPath)

	// Verify marker file exists
	markerPath := filepath.Join(tmpDir, "alpine.iso.verified")
	assert.FileExists(t, markerPath)
}

func TestDownloadISO_AlreadyVerified(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create pre-existing files
	isoPath := filepath.Join(tmpDir, "alpine.iso")
	markerPath := filepath.Join(tmpDir, "alpine.iso.verified")
	require.NoError(t, os.WriteFile(isoPath, []byte("existing content"), 0644))
	require.NoError(t, os.WriteFile(markerPath, []byte("verified"), 0644))

	// Configure download
	config := &ISOConfig{
		Version:        "3.22.2",
		ISO:            "alpine.iso",
		URL:            "http://should-not-be-called.example.com/alpine.iso",
		MirrorURL:      "http://should-not-be-called.example.com",
		WorkDir:        tmpDir,
		VerifyChecksum: true,
	}

	// Execute download - should skip
	ctx := context.Background()
	err := DownloadISO(ctx, config)
	require.NoError(t, err)

	// Verify original content unchanged
	content, err := os.ReadFile(isoPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("existing content"), content)
}

func TestDownloadISO_ChecksumMismatch(t *testing.T) {
	testContent := []byte("This is test ISO content")
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/alpine.iso":
			w.WriteHeader(http.StatusOK)
			w.Write(testContent)
		case "/alpine.iso.sha256":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(wrongHash + "  alpine.iso\n"))
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()

	config := &ISOConfig{
		Version:        "3.22.2",
		ISO:            "alpine.iso",
		URL:            server.URL + "/alpine.iso",
		MirrorURL:      server.URL,
		WorkDir:        tmpDir,
		VerifyChecksum: true,
		ResumeDownload: false,
	}

	ctx := context.Background()
	err := DownloadISO(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum verification failed")

	// Verify ISO file was cleaned up
	isoPath := filepath.Join(tmpDir, "alpine.iso")
	_, err = os.Stat(isoPath)
	assert.True(t, os.IsNotExist(err))
}

func TestDownloadISO_ContextCancellation(t *testing.T) {
	// Create slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep to simulate slow download
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("content"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()

	config := &ISOConfig{
		Version:        "3.22.2",
		ISO:            "alpine.iso",
		URL:            server.URL + "/alpine.iso",
		MirrorURL:      server.URL,
		WorkDir:        tmpDir,
		VerifyChecksum: false,
		ResumeDownload: false,
	}

	// Create context with quick timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := DownloadISO(ctx, config)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestDownloadISO_WithProgressCallback(t *testing.T) {
	testContent := make([]byte, 1024*100) // 100KB
	for i := range testContent {
		testContent[i] = byte(i % 256)
	}
	testHash := sha256.Sum256(testContent)
	testHashStr := hex.EncodeToString(testHash[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/alpine.iso":
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testContent)))
			w.WriteHeader(http.StatusOK)
			w.Write(testContent)
		case "/alpine.iso.sha256":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(testHashStr + "  alpine.iso\n"))
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()

	progressCalled := false
	config := &ISOConfig{
		Version:        "3.22.2",
		ISO:            "alpine.iso",
		URL:            server.URL + "/alpine.iso",
		MirrorURL:      server.URL,
		WorkDir:        tmpDir,
		VerifyChecksum: true,
		ResumeDownload: false,
		ProgressCallback: func(downloaded, total int64, percent float64) {
			progressCalled = true
			assert.Greater(t, downloaded, int64(0))
			assert.Greater(t, total, int64(0))
			assert.GreaterOrEqual(t, percent, 0.0)
			assert.LessOrEqual(t, percent, 100.0)
		},
	}

	ctx := context.Background()
	err := DownloadISO(ctx, config)
	require.NoError(t, err)
	assert.True(t, progressCalled, "Progress callback should have been called")
}

func TestCalculateSHA256(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := []byte("test content for hashing")

	require.NoError(t, os.WriteFile(testFile, testContent, 0644))

	hash, err := calculateSHA256(testFile)
	require.NoError(t, err)

	expectedHash := sha256.Sum256(testContent)
	expectedHashStr := hex.EncodeToString(expectedHash[:])

	assert.Equal(t, expectedHashStr, hash)
}

func TestCalculateSHA256_FileNotFound(t *testing.T) {
	_, err := calculateSHA256("/nonexistent/file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestVerifyChecksum_Success(t *testing.T) {
	tmpDir := t.TempDir()

	testContent := []byte("test content")
	testHash := sha256.Sum256(testContent)
	testHashStr := hex.EncodeToString(testHash[:])

	isoPath := filepath.Join(tmpDir, "test.iso")
	checksumPath := filepath.Join(tmpDir, "test.iso.sha256")

	require.NoError(t, os.WriteFile(isoPath, testContent, 0644))
	require.NoError(t, os.WriteFile(checksumPath, []byte(testHashStr+"  test.iso\n"), 0644))

	config := &ISOConfig{
		Version:   "3.22.2",
		ISO:       "test.iso",
		WorkDir:   tmpDir,
		MirrorURL: "http://example.com",
	}
	require.NoError(t, config.Validate())

	err := verifyChecksum(config)
	assert.NoError(t, err)
}

func TestVerifyChecksum_Mismatch(t *testing.T) {
	tmpDir := t.TempDir()

	testContent := []byte("test content")
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"

	isoPath := filepath.Join(tmpDir, "test.iso")
	checksumPath := filepath.Join(tmpDir, "test.iso.sha256")

	require.NoError(t, os.WriteFile(isoPath, testContent, 0644))
	require.NoError(t, os.WriteFile(checksumPath, []byte(wrongHash+"  test.iso\n"), 0644))

	config := &ISOConfig{
		Version:   "3.22.2",
		ISO:       "test.iso",
		WorkDir:   tmpDir,
		MirrorURL: "http://example.com",
	}
	require.NoError(t, config.Validate())

	err := verifyChecksum(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

func TestIsVerified(t *testing.T) {
	tmpDir := t.TempDir()

	config := &ISOConfig{
		Version:   "3.22.2",
		ISO:       "test.iso",
		WorkDir:   tmpDir,
		MirrorURL: "http://example.com",
	}
	require.NoError(t, config.Validate())

	// Should return false when files don't exist
	assert.False(t, isVerified(config))

	// Create ISO but not marker
	require.NoError(t, os.WriteFile(config.ISOPath(), []byte("content"), 0644))
	assert.False(t, isVerified(config))

	// Create marker
	require.NoError(t, os.WriteFile(config.VerifiedMarkerPath(), []byte("verified"), 0644))
	assert.True(t, isVerified(config))
}

func TestMarkAsVerified(t *testing.T) {
	tmpDir := t.TempDir()

	config := &ISOConfig{
		Version:   "3.22.2",
		ISO:       "test.iso",
		WorkDir:   tmpDir,
		MirrorURL: "http://example.com",
	}
	require.NoError(t, config.Validate())

	err := markAsVerified(config)
	require.NoError(t, err)

	// Verify marker file exists and contains timestamp
	content, err := os.ReadFile(config.VerifiedMarkerPath())
	require.NoError(t, err)
	assert.NotEmpty(t, content)

	// Verify timestamp is parseable
	_, err = time.Parse(time.RFC3339, string(content[:len(content)-1])) // Remove newline
	assert.NoError(t, err)
}

func TestCopyWithContext_Cancellation(t *testing.T) {
	// Create a reader with lots of data
	data := make([]byte, 1024*1024) // 1MB
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "output.bin")

	out, err := os.Create(outPath)
	require.NoError(t, err)
	defer out.Close()

	// Create cancelable context
	ctx, cancel := context.WithCancel(context.Background())

	// Start copy in goroutine
	errChan := make(chan error, 1)
	go func() {
		_, err := copyWithContext(ctx, out, &slowReader{data: data})
		errChan <- err
	}()

	// Cancel after a short delay
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Wait for copy to finish
	err = <-errChan
	assert.ErrorIs(t, err, context.Canceled)
}

// slowReader simulates a slow reader for testing
type slowReader struct {
	data []byte
	pos  int
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, nil
	}

	// Read slowly
	time.Sleep(5 * time.Millisecond)
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

// TestDownloadISO_Pinned covers a download whose digest the build pins:
// the mirror's checksum is never consulted, a cached copy is re-verified,
// and a file that does not match is refused and removed.
func TestDownloadISO_Pinned(t *testing.T) {
	good := []byte("alpine netboot tarball")
	sum := sha256.Sum256(good)
	pin := hex.EncodeToString(sum[:])

	serve := func(body []byte, requests *int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*requests++
			if r.URL.Path != "/netboot.tar.gz" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(body)
		}))
	}
	config := func(url, dir string) *ISOConfig {
		return &ISOConfig{Version: "3.22.2", ISO: "netboot.tar.gz", URL: url + "/netboot.tar.gz",
			MirrorURL: url, WorkDir: dir, VerifyChecksum: true, SHA256: pin}
	}

	t.Run("downloads, then serves the cache without a request", func(t *testing.T) {
		requests := 0
		server := serve(good, &requests)
		defer server.Close()
		dir := t.TempDir()

		require.NoError(t, DownloadISO(context.Background(), config(server.URL, dir)))
		require.NoError(t, DownloadISO(context.Background(), config(server.URL, dir)))
		assert.Equal(t, 1, requests, "no .sha256 fetch, and the second run is the cache")
		got, err := os.ReadFile(filepath.Join(dir, "netboot.tar.gz"))
		require.NoError(t, err)
		assert.Equal(t, good, got)
	})

	t.Run("a tampered cache is fetched again", func(t *testing.T) {
		requests := 0
		server := serve(good, &requests)
		defer server.Close()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "netboot.tar.gz"), []byte("stale"), 0o644))

		require.NoError(t, DownloadISO(context.Background(), config(server.URL, dir)))
		assert.Equal(t, 1, requests)
	})

	t.Run("a mismatch is refused and removed", func(t *testing.T) {
		requests := 0
		server := serve([]byte("not the pinned file"), &requests)
		defer server.Close()
		dir := t.TempDir()

		err := DownloadISO(context.Background(), config(server.URL, dir))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum mismatch")
		assert.NoFileExists(t, filepath.Join(dir, "netboot.tar.gz"))
	})

	t.Run("a pin that is not a digest is a configuration error", func(t *testing.T) {
		c := config("http://127.0.0.1:1", t.TempDir())
		c.SHA256 = "abc"
		err := DownloadISO(context.Background(), c)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a hex SHA-256 digest")
	})
}
