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
	"time"

	"github.com/pin/tftp/v3"
)

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

// =============================================================================
// TFTP Client Adapter Implementation
// =============================================================================

// TFTPClientAdapter downloads firmware from the iPXE TFTP server.
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
