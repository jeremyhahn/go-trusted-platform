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

package authenticode

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// =============================================================================
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements AuthenticodeCommands using platformctl CLI commands.
type CLIAdapter struct {
	binaryPath string
}

// NewCLIAdapter creates a new CLI protocol adapter instance.
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup initializes the CLI adapter by locating the platformctl binary.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	binaryPath := os.Getenv(EnvPlatformCTL)
	if binaryPath == "" {
		binaryPath = GetServiceEndpoints().PlatformCTL
	}

	// Check if the binary exists and is executable
	_, err := exec.LookPath(binaryPath)
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	c.binaryPath = binaryPath

	// Verify connectivity by running a simple help command
	_, err = c.runCommand(ctx, "authenticode", "--help")
	if err != nil {
		return ErrConnectionFailed{Protocol: "CLI", Endpoint: binaryPath, Err: err}
	}

	return nil
}

// Teardown performs any cleanup needed by the CLI adapter.
func (c *CLIAdapter) Teardown() error {
	return nil
}

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("command failed: %s: %w", string(output), err)
	}
	return output, nil
}

// =============================================================================
// Sign Operations
// =============================================================================

// Sign signs a PE/COFF file using Authenticode via CLI.
func (c *CLIAdapter) Sign(ctx context.Context, opts SignOptions) (*SignResult, error) {
	args := []string{"authenticode", "sign", "-o", "json"}

	if opts.KeyPath != "" {
		args = append(args, "--key", opts.KeyPath)
	}
	if opts.CertPath != "" {
		args = append(args, "--cert", opts.CertPath)
	}
	if opts.Input != "" {
		args = append(args, "--input", opts.Input)
	}
	if opts.Output != "" {
		args = append(args, "--out", opts.Output)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "authenticode sign", Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Input   string `json:"input"`
		Output  string `json:"output"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "authenticode sign", Err: err}
	}

	return &SignResult{
		Success:  resp.Success,
		Message:  resp.Message,
		Input:    resp.Input,
		Output:   resp.Output,
		SignedAt: time.Now(),
	}, nil
}

// =============================================================================
// Verify Operations
// =============================================================================

// Verify verifies an Authenticode signature on a PE/COFF file via CLI.
func (c *CLIAdapter) Verify(ctx context.Context, opts VerifyOptions) (*VerifyResult, error) {
	args := []string{"authenticode", "verify", "-o", "json"}

	if opts.Input != "" {
		args = append(args, "--input", opts.Input)
	}
	if opts.CertPath != "" {
		args = append(args, "--cert", opts.CertPath)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "authenticode verify", Err: err}
	}

	var resp struct {
		Verified    bool   `json:"verified"`
		Message     string `json:"message"`
		Input       string `json:"input"`
		Certificate string `json:"certificate,omitempty"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "authenticode verify", Err: err}
	}

	return &VerifyResult{
		Verified:    resp.Verified,
		Message:     resp.Message,
		Input:       resp.Input,
		Certificate: resp.Certificate,
	}, nil
}

// Ensure CLIAdapter implements AuthenticodeCommands interface.
var _ AuthenticodeCommands = (*CLIAdapter)(nil)
