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

//go:build standalone
// +build standalone

package ipxe

// This file contains standalone tests for the TFTP server that can be run
// independently without other package dependencies.
// Run with: go test -tags standalone -run Standalone

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockReaderFrom implements io.ReaderFrom for testing
type mockReaderFromStandalone struct {
	data       []byte
	size       int64
	remoteAddr net.Addr
}

func (m *mockReaderFromStandalone) ReadFrom(r io.Reader) (int64, error) {
	buf := new(bytes.Buffer)
	n, err := buf.ReadFrom(r)
	if err != nil {
		return n, err
	}
	m.data = buf.Bytes()
	return n, nil
}

func (m *mockReaderFromStandalone) RemoteAddr() net.Addr {
	return m.remoteAddr
}

func (m *mockReaderFromStandalone) SetSize(size int64) {
	m.size = size
}

func TestStandalone_NewTFTPServer(t *testing.T) {
	config := &ServerConfig{
		TFTPPort: 6969,
	}
	logger := logging.DefaultLogger()
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	assert.NotNil(t, server)
	assert.Equal(t, config, server.config)
	assert.NotNil(t, server.logger)
	assert.NotNil(t, server.firmware)
	assert.Empty(t, server.firmware)
}

func TestStandalone_getCacheDir(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{TFTPPort: 69}
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	cacheDir := server.getCacheDir()

	assert.NotEmpty(t, cacheDir)
	assert.Contains(t, cacheDir, cacheDirName)
	assert.Contains(t, cacheDir, firmwareSubDir)
}

func TestStandalone_downloadFile(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{TFTPPort: 69}
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test firmware data"))
	}))
	defer mockServer.Close()

	data, err := server.downloadFile(mockServer.URL)
	assert.NoError(t, err)
	assert.Equal(t, []byte("test firmware data"), data)
}

func TestStandalone_loadFirmwareFile(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{TFTPPort: 69}
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	tmpDir := t.TempDir()
	cacheData := []byte("cached firmware")
	cachePath := filepath.Join(tmpDir, "test.efi")
	err := os.WriteFile(cachePath, cacheData, 0644)
	require.NoError(t, err)

	err = server.loadFirmwareFile("test.efi", "", tmpDir)
	assert.NoError(t, err)

	server.firmwareMu.RLock()
	data, ok := server.firmware["test.efi"]
	server.firmwareMu.RUnlock()

	assert.True(t, ok, "firmware should be loaded into memory")
	assert.Equal(t, cacheData, data)
}

func TestStandalone_readHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{TFTPPort: 69}
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	firmwareData := []byte("test firmware content")
	server.firmwareMu.Lock()
	server.firmware["ipxe.efi"] = firmwareData
	server.firmwareMu.Unlock()

	mockReader := &mockReaderFromStandalone{
		remoteAddr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.100"),
			Port: 12345,
		},
	}

	err := server.readHandler("ipxe.efi", mockReader)
	assert.NoError(t, err)
	assert.Equal(t, firmwareData, mockReader.data)
	// Size is set via SetSize call
}

func TestStandalone_readHandler_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{TFTPPort: 69}
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	mockReader := &mockReaderFromStandalone{
		remoteAddr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.100"),
			Port: 12345,
		},
	}

	err := server.readHandler("nonexistent.efi", mockReader)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrFirmwareNotFound))
}

func TestStandalone_ThreadSafety(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{TFTPPort: 69}
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

func TestStandalone_LargeFile(t *testing.T) {
	logger := logging.DefaultLogger()
	config := &ServerConfig{TFTPPort: 69}
	server := NewTFTPServer(config, net.ParseIP("192.168.1.1"), logger)

	// Create a large firmware file (1MB)
	largeFirmware := make([]byte, 1024*1024)
	for i := range largeFirmware {
		largeFirmware[i] = byte(i % 256)
	}

	server.firmwareMu.Lock()
	server.firmware["large.efi"] = largeFirmware
	server.firmwareMu.Unlock()

	mockReader := &mockReaderFromStandalone{
		remoteAddr: &net.TCPAddr{
			IP:   net.ParseIP("192.168.1.100"),
			Port: 12345,
		},
	}

	err := server.readHandler("large.efi", mockReader)
	assert.NoError(t, err)
	assert.Equal(t, largeFirmware, mockReader.data)
	// Size is set via SetSize call
}
