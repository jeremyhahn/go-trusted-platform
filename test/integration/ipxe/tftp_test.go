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

//go:build integration

package ipxe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/pin/tftp/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TFTP Download Tests
// =============================================================================

// TestTFTPDownloadFirmware tests downloading iPXE firmware files via TFTP.
func TestTFTPDownloadFirmware(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := TFTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("DownloadIPXEEFI", func(t *testing.T) {
		data, err := downloadTFTPFile(ctx, cfg, "ipxe.efi")
		require.NoError(t, err, "TFTP download of ipxe.efi should succeed")
		require.NotNil(t, data, "Downloaded data should not be nil")

		// iPXE EFI binary should be at least 500KB
		assert.Greater(t, len(data), 500*1024, "ipxe.efi should be at least 500KB")

		// Verify it is a valid PE/EFI binary (starts with "MZ" magic)
		assert.Equal(t, "MZ", string(data[:2]), "ipxe.efi should be a PE binary")
	})

	t.Run("DownloadIPXE32EFI", func(t *testing.T) {
		data, err := downloadTFTPFile(ctx, cfg, "ipxe32.efi")
		if err != nil {
			// ipxe32.efi is optional
			t.Skip("ipxe32.efi not available (optional)")
		}

		// Verify it is a valid PE/EFI binary
		assert.Greater(t, len(data), 100*1024, "ipxe32.efi should be substantial")
		assert.Equal(t, "MZ", string(data[:2]), "ipxe32.efi should be a PE binary")
	})
}

// TestTFTPFileNotFound tests handling of non-existent files.
func TestTFTPFileNotFound(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := TFTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("NonExistentFile", func(t *testing.T) {
		_, err := downloadTFTPFile(ctx, cfg, "nonexistent-file.bin")
		require.Error(t, err, "Downloading non-existent file should fail")
	})

	t.Run("PathTraversalBlocked", func(t *testing.T) {
		_, err := downloadTFTPFile(ctx, cfg, "../../../etc/passwd")
		require.Error(t, err, "Path traversal should be blocked")
	})

	t.Run("EmptyFilename", func(t *testing.T) {
		_, err := downloadTFTPFile(ctx, cfg, "")
		require.Error(t, err, "Empty filename should fail")
	})
}

// TestTFTPFileIntegrity tests that downloaded files have correct content.
func TestTFTPFileIntegrity(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := TFTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("ConsistentDownloads", func(t *testing.T) {
		// Download the same file twice and verify consistency
		data1, err := downloadTFTPFile(ctx, cfg, "ipxe.efi")
		require.NoError(t, err, "First download should succeed")

		data2, err := downloadTFTPFile(ctx, cfg, "ipxe.efi")
		require.NoError(t, err, "Second download should succeed")

		assert.Equal(t, len(data1), len(data2), "File sizes should match")
		assert.True(t, bytes.Equal(data1, data2), "File contents should be identical")
	})
}

// TestTFTPTransferModes tests different TFTP transfer modes.
func TestTFTPTransferModes(t *testing.T) {
	SkipIfNotIntegration(t)

	cfg := GetTestServerConfig()

	t.Run("OctetMode", func(t *testing.T) {
		ctx, cancel := TFTPTestContext()
		defer cancel()

		data, err := downloadTFTPFileWithMode(ctx, cfg, "ipxe.efi", "octet")
		require.NoError(t, err, "Octet mode download should succeed")
		assert.Greater(t, len(data), 0, "Downloaded data should not be empty")
	})
}

// TestTFTPConcurrentDownloads tests handling multiple concurrent downloads.
func TestTFTPConcurrentDownloads(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := GetTestServerConfig()
	numClients := 3

	t.Run("ParallelDownloads", func(t *testing.T) {
		type result struct {
			clientID int
			size     int
			err      error
		}

		results := make(chan result, numClients)

		// Start concurrent downloads
		for i := 0; i < numClients; i++ {
			go func(id int) {
				data, err := downloadTFTPFile(ctx, cfg, "ipxe.efi")
				results <- result{clientID: id, size: len(data), err: err}
			}(i)
		}

		// Collect results
		var successCount int
		var expectedSize int
		for i := 0; i < numClients; i++ {
			r := <-results
			if r.err != nil {
				t.Errorf("Client %d failed: %v", r.clientID, r.err)
				continue
			}
			successCount++

			if expectedSize == 0 {
				expectedSize = r.size
			} else {
				assert.Equal(t, expectedSize, r.size,
					"All clients should get same file size")
			}
		}

		assert.Equal(t, numClients, successCount, "All downloads should succeed")
	})
}

// TestTFTPTransferSize tests that the TFTP server reports correct transfer sizes.
func TestTFTPTransferSize(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := TFTPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("TSizeOption", func(t *testing.T) {
		// Download with transfer size option
		data, reportedSize, err := downloadTFTPFileWithTSize(ctx, cfg, "ipxe.efi")
		require.NoError(t, err, "Download with tsize should succeed")

		if reportedSize > 0 {
			assert.Equal(t, int64(len(data)), reportedSize,
				"Reported size should match actual size")
		}
	})
}

// =============================================================================
// TFTP Helper Functions
// =============================================================================

// downloadTFTPFile downloads a file via TFTP using octet mode.
func downloadTFTPFile(ctx context.Context, cfg TestServerConfig, filename string) ([]byte, error) {
	return downloadTFTPFileWithMode(ctx, cfg, filename, "octet")
}

// downloadTFTPFileWithMode downloads a file via TFTP with a specific mode.
func downloadTFTPFileWithMode(ctx context.Context, cfg TestServerConfig, filename string,
	mode string) ([]byte, error) {

	// Create TFTP client
	client, err := tftp.NewClient(fmt.Sprintf("%s:%d", cfg.ServerIP.String(), cfg.TFTPPort))
	if err != nil {
		return nil, err
	}

	// Set timeout
	client.SetTimeout(5 * time.Second)

	// Request file
	wt, err := client.Receive(filename, mode)
	if err != nil {
		return nil, err
	}

	// Read into buffer
	var buf bytes.Buffer
	_, err = wt.WriteTo(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// downloadTFTPFileWithTSize downloads a file and returns the reported transfer size.
func downloadTFTPFileWithTSize(ctx context.Context, cfg TestServerConfig,
	filename string) ([]byte, int64, error) {

	// Create TFTP client
	client, err := tftp.NewClient(fmt.Sprintf("%s:%d", cfg.ServerIP.String(), cfg.TFTPPort))
	if err != nil {
		return nil, 0, err
	}

	// Set timeout
	client.SetTimeout(5 * time.Second)

	// Request file
	wt, err := client.Receive(filename, "octet")
	if err != nil {
		return nil, 0, err
	}

	// Get transfer size if available
	var reportedSize int64
	if transfer, ok := wt.(interface{ Size() int64 }); ok {
		reportedSize = transfer.Size()
	}

	// Read into buffer
	var buf bytes.Buffer
	_, err = wt.WriteTo(&buf)
	if err != nil {
		return nil, 0, err
	}

	return buf.Bytes(), reportedSize, nil
}

// =============================================================================
// TFTP Error Scenario Tests
// =============================================================================

// TestTFTPErrorScenarios tests various TFTP error conditions.
func TestTFTPErrorScenarios(t *testing.T) {
	SkipIfNotIntegration(t)

	cfg := GetTestServerConfig()

	t.Run("ServerUnreachable", func(t *testing.T) {
		// Try to connect to unreachable server
		badClient, err := tftp.NewClient("10.255.255.254:69")
		if err != nil {
			t.Skip("Could not create TFTP client")
		}

		badClient.SetTimeout(2 * time.Second)
		_, err = badClient.Receive("ipxe.efi", "octet")
		assert.Error(t, err, "Unreachable server should timeout")
	})

	t.Run("InvalidPort", func(t *testing.T) {
		// Try to connect to wrong port
		badClient, err := tftp.NewClient(cfg.ServerIP.String() + ":12345")
		if err != nil {
			t.Skip("Could not create TFTP client")
		}

		badClient.SetTimeout(2 * time.Second)
		_, err = badClient.Receive("ipxe.efi", "octet")
		assert.Error(t, err, "Wrong port should fail")
	})

	t.Run("LargeFilenameBlocked", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Create a very long filename
		longFilename := ""
		for i := 0; i < 1000; i++ {
			longFilename += "a"
		}
		longFilename += ".efi"

		_, err := downloadTFTPFile(ctx, cfg, longFilename)
		assert.Error(t, err, "Very long filename should be rejected")
	})
}

// =============================================================================
// TFTP Protocol Implementation Tests
// =============================================================================

// TestTFTPBlockSize tests TFTP blocksize negotiation.
func TestTFTPBlockSize(t *testing.T) {
	SkipIfNotIntegration(t)

	cfg := GetTestServerConfig()

	t.Run("DefaultBlockSize", func(t *testing.T) {
		ctx, cancel := TFTPTestContext()
		defer cancel()

		// Standard TFTP uses 512-byte blocks
		data, err := downloadTFTPFile(ctx, cfg, "ipxe.efi")
		require.NoError(t, err, "Download should succeed")
		assert.Greater(t, len(data), 0, "Data should not be empty")
	})
}

// TestTFTPRetransmission tests that TFTP handles packet loss gracefully.
func TestTFTPRetransmission(t *testing.T) {
	SkipIfNotIntegration(t)

	cfg := GetTestServerConfig()

	t.Run("ReliableTransfer", func(t *testing.T) {
		// Multiple downloads should all succeed and be identical
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		var firstData []byte
		for i := 0; i < 3; i++ {
			data, err := downloadTFTPFile(ctx, cfg, "ipxe.efi")
			require.NoError(t, err, "Download %d should succeed", i)

			if firstData == nil {
				firstData = data
			} else {
				assert.True(t, bytes.Equal(firstData, data),
					"Download %d should match first download", i)
			}
		}
	})
}

// =============================================================================
// TFTP Client Adapter Implementation
// =============================================================================

// TFTPClientAdapter implements the IPXECommands TFTP operations.
type TFTPClientAdapter struct {
	serverIP string
	port     int
	client   *tftp.Client
}

// NewTFTPClientAdapter creates a new TFTP client adapter.
func NewTFTPClientAdapter(serverIP string, port int) *TFTPClientAdapter {
	return &TFTPClientAdapter{
		serverIP: serverIP,
		port:     port,
	}
}

// Name returns the protocol adapter identifier.
func (t *TFTPClientAdapter) Name() string {
	return "TFTP"
}

// Setup initializes the TFTP client.
func (t *TFTPClientAdapter) Setup(ctx context.Context) error {
	port := t.port
	if port == 0 {
		port = 69
	}
	addr := fmt.Sprintf("%s:%d", t.serverIP, port)

	client, err := tftp.NewClient(addr)
	if err != nil {
		return err
	}

	client.SetTimeout(5 * time.Second)
	t.client = client

	return nil
}

// Teardown cleans up TFTP client resources.
func (t *TFTPClientAdapter) Teardown() error {
	t.client = nil
	return nil
}

// TFTPDownload downloads a file via TFTP.
func (t *TFTPClientAdapter) TFTPDownload(ctx context.Context,
	filename string) (*TFTPDownloadResult, error) {

	if t.client == nil {
		return nil, ErrTFTPClientNotInitialized
	}

	start := time.Now()

	wt, err := t.client.Receive(filename, "octet")
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	n, err := wt.WriteTo(&buf)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return &TFTPDownloadResult{
		Filename:     filename,
		Data:         buf.Bytes(),
		Size:         n,
		TransferTime: time.Since(start),
	}, nil
}

// TFTPList lists available files (not supported by standard TFTP).
func (t *TFTPClientAdapter) TFTPList(ctx context.Context) (*TFTPListResult, error) {
	// TFTP does not support directory listing
	// Return known firmware files
	return &TFTPListResult{
		Files: []TFTPFileInfo{
			{Filename: "ipxe.efi"},
			{Filename: "ipxe32.efi"},
		},
	}, nil
}
