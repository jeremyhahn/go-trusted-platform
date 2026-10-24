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

// Package pxe provides integration test adapters for PXE provisioning services.
// This file implements the PXECommands interface using the platformctl CLI binary.

//go:build integration

package pxe

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// CLI Error Types
// =============================================================================

// ErrCLICommandFailed is returned when a CLI command fails to execute.
type ErrCLICommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLICommandFailed) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("CLI command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("CLI command %q failed: %v", e.Command, e.Err)
}

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
}

// ErrCLIPXENotImplemented is returned by every PXE verb of this adapter.
//
// docs/daemon/cli.md:223 documents that there is no `pxe` top-level group:
// "PXE device lifecycle is API-only". This adapter used to shell
// `platformctl pxe device ...` and `platformctl pxe state ...`, which do not
// exist, so the CLI leg of TestPXEMultiProtocol failed against the documented
// behaviour. It now refuses each verb with this typed error and the test
// (requireCLIPXEGap in pxe_test.go) asserts that refusal instead of a fake
// success. When a `platformctl pxe` group is added to the CLI, the adapter
// must drive it and this typed refusal goes away (docs/provisioning/
// engineering.md §7 records the hole and its flip).
type ErrCLIPXENotImplemented struct {
	Method string
}

func (e ErrCLIPXENotImplemented) Error() string {
	return fmt.Sprintf(
		"platformctl has no pxe command group (docs/daemon/cli.md:223; the PXE device lifecycle is API-only), so CLI %s is refused",
		e.Method)
}

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// CLIAdapter implements PXECommands using the platformctl CLI binary.
// This adapter executes CLI commands and parses JSON output to test
// the complete CLI workflow in integration tests.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	configDir      string
	configPath     string
	commandTimeout time.Duration
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv(EnvPlatformctlBinary)
	if binaryPath == "" {
		binaryPath = DefaultPlatformctlBinary
	}

	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}

	return &CLIAdapter{
		binaryPath:     binaryPath,
		socketPath:     socketPath,
		commandTimeout: DefaultCommandTimeout,
	}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary exists and is executable.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	dir, path, err := helpers.WriteTempLocalCLIConfig(c.socketPath, helpers.GetGRPCEndpoint())
	if err != nil {
		return err
	}
	c.configDir, c.configPath = dir, path

	_, err = c.runCommand(ctx, "version")
	if err != nil {
		return fmt.Errorf("CLI binary verification failed: %w", err)
	}

	return nil
}

// Teardown performs cleanup (no-op for CLI adapter).
func (c *CLIAdapter) Teardown() error {
	if c.configDir == "" {
		return nil
	}
	return os.RemoveAll(c.configDir)
}

// =============================================================================
// Command Execution
// =============================================================================

func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	fullArgs := []string{"--output", "json"}

	// platformctl has no --socket flag; the harness socket reaches it through
	// the config file Setup wrote (#540).
	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath)
	}

	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCLICommandFailed{
			Command: strings.Join(fullArgs, " "),
			Output:  output,
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Device Management Commands
//
// docs/daemon/cli.md:223: there is no `pxe` top-level group, the PXE
// device lifecycle is API-only. Every method below refuses with
// ErrCLIPXENotImplemented rather than shelling a command that does not exist
// or faking a success.
// =============================================================================

// RegisterDevice is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) RegisterDevice(_ context.Context, _ RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "RegisterDevice"}
}

// GetDevice is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) GetDevice(_ context.Context, _ string) (*GetDeviceResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "GetDevice"}
}

// GetDeviceByMAC is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) GetDeviceByMAC(_ context.Context, _ string) (*GetDeviceResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "GetDeviceByMAC"}
}

// ListDevices is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) ListDevices(_ context.Context, _ ListDevicesOptions) (*ListDevicesResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "ListDevices"}
}

// RemoveDevice is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) RemoveDevice(_ context.Context, _ string) (*RemoveDeviceResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "RemoveDevice"}
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) UpdateDeviceState(_ context.Context, _ UpdateStateOptions) (*UpdateStateResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "UpdateDeviceState"}
}

// SetDeviceEnrolled is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) SetDeviceEnrolled(_ context.Context, _, _ string) (*SetEnrolledResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "SetDeviceEnrolled"}
}

// AuthorizeDevice is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) AuthorizeDevice(_ context.Context, _ string, _ uint16) (*AuthorizeResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "AuthorizeDevice"}
}

// QuarantineDevice is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) QuarantineDevice(_ context.Context, _, _ string) (*QuarantineResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "QuarantineDevice"}
}

// RetryDevice is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) RetryDevice(_ context.Context, _ string) (*RetryResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "RetryDevice"}
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) GetEvents(_ context.Context, _ string) (*GetEventsResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "GetEvents"}
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus is refused: the PXE device lifecycle is API-only
// (docs/daemon/cli.md:223).
func (c *CLIAdapter) GetStatus(_ context.Context) (*GetStatusResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "GetStatus"}
}

// Ensure CLIAdapter implements PXECommands interface.
var _ PXECommands = (*CLIAdapter)(nil)
