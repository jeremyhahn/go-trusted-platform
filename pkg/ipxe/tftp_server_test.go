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

package ipxe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/pin/tftp/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockReaderFrom implements io.ReaderFrom and tftp.OutgoingTransfer for testing
type mockReaderFrom struct {
	data       []byte
	size       int64
	remoteAddr net.UDPAddr
}

func (m *mockReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	buf := new(bytes.Buffer)
	n, err := buf.ReadFrom(r)
	if err != nil {
		return n, err
	}
	m.data = buf.Bytes()
	return n, nil
}

func (m *mockReaderFrom) RemoteAddr() net.UDPAddr {
	return m.remoteAddr
}

func (m *mockReaderFrom) SetSize(size int64) {
	m.size = size
}

func TestNewTFTPServer(t *testing.T) {
	tests := []struct {
		name     string
		config   *ServerConfig
		serverIP net.IP
	}{
		{
			name:     "create with default config",
			config:   DefaultServerConfig(),
			serverIP: net.ParseIP("192.168.1.1"),
		},
		{
			name: "create with custom config",
			config: &ServerConfig{
				TFTPPort: 6969,
			},
			serverIP: net.ParseIP("10.0.0.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()
			server := NewTFTPServer(tt.config, tt.serverIP, logger)

			assert.NotNil(t, server)
			assert.Equal(t, tt.config, server.config)
			assert.Equal(t, tt.serverIP, server.serverIP)
			assert.NotNil(t, server.logger)
			assert.NotNil(t, server.firmware)
			assert.Empty(t, server.firmware)
		})
	}
}

func TestTFTPServer_getCacheDir(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	cacheDir := server.getCacheDir()

	assert.NotEmpty(t, cacheDir)
	assert.Contains(t, cacheDir, cacheDirName)
	assert.Contains(t, cacheDir, firmwareSubDir)

	// Should return either user cache dir or /var/cache path
	userCache, err := os.UserCacheDir()
	if err == nil {
		expectedPath := filepath.Join(userCache, cacheDirName, firmwareSubDir)
		assert.Equal(t, expectedPath, cacheDir)
	} else {
		expectedPath := filepath.Join(systemCacheDir, cacheDirName, firmwareSubDir)
		assert.Equal(t, expectedPath, cacheDir)
	}
}

func TestTFTPServer_downloadFile(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	tests := []struct {
		name          string
		mockResponse  string
		mockStatus    int
		expectError   bool
		errorContains string
	}{
		{
			name:         "successful download",
			mockResponse: "test firmware data",
			mockStatus:   http.StatusOK,
			expectError:  false,
		},
		{
			name:          "404 not found",
			mockResponse:  "not found",
			mockStatus:    http.StatusNotFound,
			expectError:   true,
			errorContains: "HTTP error",
		},
		{
			name:          "500 internal error",
			mockResponse:  "server error",
			mockStatus:    http.StatusInternalServerError,
			expectError:   true,
			errorContains: "HTTP error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock HTTP server
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.mockStatus)
				w.Write([]byte(tt.mockResponse))
			}))
			defer mockServer.Close()

			data, err := server.downloadFile(mockServer.URL)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, []byte(tt.mockResponse), data)
			}
		})
	}
}

func TestTFTPServer_downloadFile_InvalidURL(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// A closed local port refuses instantly; a bogus hostname would wait
	// on the resolver instead.
	closed := httptest.NewServer(http.NotFoundHandler())
	url := closed.URL
	closed.Close()
	_, err := server.downloadFile(url + "/file")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP GET failed")
}

func TestTFTPServer_loadFirmwareFile(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Create temporary cache directory
	tmpDir := t.TempDir()

	tests := []struct {
		name          string
		filename      string
		setupCache    bool
		cacheData     []byte
		mockResponse  string
		mockStatus    int
		expectError   bool
		errorContains string
	}{
		{
			name:       "load from cache",
			filename:   "test.efi",
			setupCache: true,
			cacheData:  []byte("cached firmware"),
		},
		{
			name:         "download when not cached",
			filename:     "download.efi",
			setupCache:   false,
			mockResponse: "downloaded firmware",
			mockStatus:   http.StatusOK,
		},
		{
			name:          "download fails",
			filename:      "fail.efi",
			setupCache:    false,
			mockStatus:    http.StatusNotFound,
			expectError:   true,
			errorContains: "failed to download firmware",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup cache if needed
			cachePath := filepath.Join(tmpDir, tt.filename)
			if tt.setupCache {
				err := os.WriteFile(cachePath, tt.cacheData, 0644)
				require.NoError(t, err)
			}

			// Create mock HTTP server for download tests
			var mockURL string
			if !tt.setupCache {
				mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.mockStatus)
					w.Write([]byte(tt.mockResponse))
				}))
				defer mockServer.Close()
				mockURL = mockServer.URL
			}

			err := server.loadFirmwareFile(tt.filename, mockURL, tmpDir)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)

				// Verify firmware was loaded into memory
				server.firmwareMu.RLock()
				data, ok := server.firmware[tt.filename]
				server.firmwareMu.RUnlock()

				assert.True(t, ok, "firmware should be loaded into memory")
				if tt.setupCache {
					assert.Equal(t, tt.cacheData, data)
				} else {
					assert.Equal(t, []byte(tt.mockResponse), data)
				}
			}
		})
	}
}

func TestTFTPServer_readHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	tests := []struct {
		name          string
		filename      string
		setupFirmware bool
		firmwareData  []byte
		expectError   bool
		errorType     error
	}{
		{
			name:          "successful read",
			filename:      "ipxe.efi",
			setupFirmware: true,
			firmwareData:  []byte("test firmware content"),
			expectError:   false,
		},
		{
			name:          "file not found",
			filename:      "nonexistent.efi",
			setupFirmware: false,
			expectError:   true,
			errorType:     ErrFirmwareNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup firmware if needed
			if tt.setupFirmware {
				server.firmwareMu.Lock()
				server.firmware[tt.filename] = tt.firmwareData
				server.firmwareMu.Unlock()
			}

			// Create mock reader that properly implements the interface
			mockReader := &mockReaderFrom{
				remoteAddr: net.UDPAddr{
					IP:   net.ParseIP("192.168.1.100"),
					Port: 12345,
				},
			}

			err := server.readHandler(tt.filename, mockReader)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorType != nil {
					assert.True(t, errors.Is(err, tt.errorType))
				}
			} else {
				assert.NoError(t, err)
				// Verify data was transferred
				assert.Equal(t, tt.firmwareData, mockReader.data)
				// Verify size was set
				assert.Equal(t, int64(len(tt.firmwareData)), mockReader.size)
			}

			// Cleanup
			if tt.setupFirmware {
				server.firmwareMu.Lock()
				delete(server.firmware, tt.filename)
				server.firmwareMu.Unlock()
			}
		})
	}
}

func TestTFTPServer_loadFirmware_WithCache(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Create temporary cache directory and populate with firmware
	tmpDir := t.TempDir()
	efi64Data := []byte("64-bit EFI firmware")
	efi32Data := []byte("32-bit EFI firmware")

	err := os.WriteFile(filepath.Join(tmpDir, "ipxe.efi"), efi64Data, 0644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpDir, "ipxe32.efi"), efi32Data, 0644)
	require.NoError(t, err)

	// Manually call loadFirmwareFile with our temp directory
	err = server.loadFirmwareFile("ipxe.efi", server.firmwareURL(ipxeEFI64Path), tmpDir)
	assert.NoError(t, err)

	err = server.loadFirmwareFile("ipxe32.efi", server.firmwareURL(ipxeEFI32Path), tmpDir)
	assert.NoError(t, err)

	// Verify firmware was loaded
	server.firmwareMu.RLock()
	defer server.firmwareMu.RUnlock()

	data, ok := server.firmware["ipxe.efi"]
	assert.True(t, ok, "required firmware should be loaded")
	assert.Equal(t, efi64Data, data)

	data, ok = server.firmware["ipxe32.efi"]
	assert.True(t, ok, "optional firmware should be loaded")
	assert.Equal(t, efi32Data, data)
}

func TestTFTPServer_Start(t *testing.T) {
	// This test requires a real TFTP server, so we'll use a higher port
	// to avoid permission issues
	config := &ServerConfig{
		TFTPPort: 16969, // Use high port to avoid requiring root
	}

	logger := logging.DefaultLogger()
	server := NewTFTPServer(config, net.ParseIP("127.0.0.1"), logger)

	// Pre-load firmware to avoid download delays
	server.firmwareMu.Lock()
	server.firmware["ipxe.efi"] = []byte("test firmware")
	server.firmwareMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bound := newBoundSignal()
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx, bound)
	}()

	awaitBound(t, bound, "TFTP listener")

	// Test TFTP client connection
	client, err := tftp.NewClient("127.0.0.1:16969")
	if err == nil {
		// Try to read a file
		wt, err := client.Receive("ipxe.efi", "octet")
		if err == nil {
			buf := new(bytes.Buffer)
			_, _ = wt.WriteTo(buf)
			// If we got here, the server is working
		}
	}

	// Cancel rather than wait out a deadline: the shutdown path is the
	// same and the test does not sit on the clock (#284).
	cancel()
	select {
	case err := <-errChan:
		// Server should return nil on clean shutdown
		assert.NoError(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("server did not shut down in time")
	}
}

func TestTFTPServer_Start_LoadFirmwareError(t *testing.T) {
	// An empty firmware directory with downloads forbidden: Start must fail
	// on the required firmware before it binds anything, without touching
	// the network or the host's cache (#590).
	config := &ServerConfig{
		TFTPPort:        16970,
		FirmwareDir:     t.TempDir(),
		FirmwareOffline: true,
	}
	logger := logging.DefaultLogger()
	server := NewTFTPServer(config, net.ParseIP("127.0.0.1"), logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := server.Start(ctx, nil)
	require.Error(t, err)
	var unavailable *ErrFirmwareUnavailable
	assert.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "ipxe.efi", unavailable.Filename)
}

// TestTFTPServer_ThreadSafety tests concurrent access to firmware map
func TestTFTPServer_ThreadSafety(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	const numGoroutines = 10
	const numOperations = 100

	done := make(chan bool, numGoroutines)

	// Concurrent writes
	for i := 0; i < numGoroutines/2; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				server.firmwareMu.Lock()
				server.firmware["test.efi"] = []byte("data")
				server.firmwareMu.Unlock()
			}
			done <- true
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines/2; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				server.firmwareMu.RLock()
				_ = server.firmware["test.efi"]
				server.firmwareMu.RUnlock()
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestTFTPServer_readHandler_LargeFile tests handling of large firmware files
func TestTFTPServer_readHandler_LargeFile(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Create a large firmware file (1MB)
	largeFirmware := make([]byte, 1024*1024)
	for i := range largeFirmware {
		largeFirmware[i] = byte(i % 256)
	}

	server.firmwareMu.Lock()
	server.firmware["large.efi"] = largeFirmware
	server.firmwareMu.Unlock()

	mockReader := &mockReaderFrom{
		remoteAddr: net.UDPAddr{
			IP:   net.ParseIP("192.168.1.100"),
			Port: 12345,
		},
	}

	err := server.readHandler("large.efi", mockReader)
	assert.NoError(t, err)
	assert.Equal(t, largeFirmware, mockReader.data)
	assert.Equal(t, int64(len(largeFirmware)), mockReader.size)
}

// TestTFTPServer_readHandler_RemoteAddr tests logging of remote address
func TestTFTPServer_readHandler_RemoteAddr(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	testData := []byte("test data")
	server.firmwareMu.Lock()
	server.firmware["test.efi"] = testData
	server.firmwareMu.Unlock()

	mockReader := &mockReaderFrom{
		remoteAddr: net.UDPAddr{
			IP:   net.ParseIP("10.0.0.5"),
			Port: 54321,
		},
	}

	err := server.readHandler("test.efi", mockReader)
	assert.NoError(t, err)
	assert.Equal(t, testData, mockReader.data)
}

// TestTFTPServer_getCacheDir_FallbackPath tests cache dir fallback
func TestTFTPServer_getCacheDir_FallbackPath(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	cacheDir := server.getCacheDir()
	assert.NotEmpty(t, cacheDir)
	assert.Contains(t, cacheDir, cacheDirName)
	assert.Contains(t, cacheDir, firmwareSubDir)
}

// TestTFTPServer_downloadFile_Timeout tests error handling with timeout
func TestTFTPServer_downloadFile_Timeout(t *testing.T) {
	logger := logging.DefaultLogger()
	config := DefaultServerConfig()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)
	// A short client timeout: the test proves the timeout path, it does not
	// need to sit through the production 60 s.
	server.downloadTimeout = 50 * time.Millisecond

	// Create a server that returns immediately but with a delay signal
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Longer than the client's timeout, released by the client's cancel.
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()

		select {
		case <-timer.C:
			w.Write([]byte("too slow"))
		case <-r.Context().Done():
			// Context was cancelled, return immediately
			return
		}
	}))
	defer slowServer.Close()

	// Call with a very short timeout to fail quickly
	_, err := server.downloadFile(slowServer.URL)
	assert.Error(t, err)
}

// TestTFTPServer_FirmwareDirAndOffline pins #590: a configured firmware
// directory is the cache, downloads can be forbidden, and a required file
// missing offline is a typed error rather than a fetch from the internet.
func TestTFTPServer_FirmwareDirAndOffline(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultServerConfig()
	cfg.FirmwareDir = dir
	cfg.FirmwareOffline = true
	server := NewTFTPServer(cfg, net.ParseIP("192.168.1.1"), logging.DefaultLogger())

	assert.Equal(t, dir, server.getCacheDir())

	// Required firmware absent offline: typed error, no network.
	err := server.loadFirmware()
	var unavailable *ErrFirmwareUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, "ipxe.efi", unavailable.Filename)

	// With the files on disk, everything loads from the directory.
	for _, name := range []string{"ipxe.efi", "ipxe32.efi", "undionly.kpxe"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(name), 0o644))
	}
	require.NoError(t, server.loadFirmware())
	server.firmwareMu.RLock()
	defer server.firmwareMu.RUnlock()
	assert.Len(t, server.firmware, 3)
	assert.Equal(t, []byte("undionly.kpxe"), server.firmware["undionly.kpxe"])
}

func TestTFTPServer_FirmwareURL(t *testing.T) {
	cfg := DefaultServerConfig()
	server := NewTFTPServer(cfg, net.ParseIP("192.168.1.1"), logging.DefaultLogger())
	assert.Equal(t, "https://boot.ipxe.org/x86_64-efi/ipxe.efi", server.firmwareURL(ipxeEFI64Path))

	cfg.FirmwareUpstream = "https://mirror.example.internal/ipxe/"
	assert.Equal(t, "https://mirror.example.internal/ipxe/undionly.kpxe", server.firmwareURL(ipxeBIOSPath))
}
