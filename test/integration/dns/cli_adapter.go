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

// Package dns provides integration test adapters for DNS services.
// This file implements the DNSCommands interface using the platformctl CLI binary.

//go:build integration

package dns

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

// dnsCLIGroup is the platformctl command group the DNS operations would sit
// under. platformctl has none: docs/dns/cli.md §"No CLI surface".
const dnsCLIGroup = "dns"

// DNSCLIGapIssue records the missing platformctl dns group.
const DNSCLIGapIssue = "#954"

// =============================================================================
// Error Types
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

// =============================================================================
// CLI Adapter
// =============================================================================

// CLIAdapter is the DNS suite's CLI leg. platformctl has no dns command group
// (#954), so every DNS operation returns helpers.ErrCLINoCommandGroup without
// running a command. Setup fails with helpers.ErrCLICommandGroupPresent the
// day platformctl lists a dns group, so the declared gap cannot outlive the
// omission.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	configDir      string
	configPath     string
	commandTimeout time.Duration
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
// It reads the binary path from PLATFORMCTL_BINARY env var or uses the default.
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

// Name returns the protocol name for this adapter.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the binary runs and that its help still lists no dns group.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	dir, path, err := helpers.WriteTempLocalCLIConfig(c.socketPath, helpers.GetGRPCEndpoint())
	if err != nil {
		return err
	}
	c.configDir, c.configPath = dir, path

	help, err := c.runCommand(ctx, "--help")
	if err != nil {
		return err
	}
	if helpers.CLIHasCommandGroup(string(help), dnsCLIGroup) {
		return helpers.ErrCLICommandGroupPresent{Group: dnsCLIGroup, Issue: DNSCLIGapIssue}
	}
	return nil
}

// Teardown removes the config file Setup wrote.
func (c *CLIAdapter) Teardown() error {
	if c.configDir == "" {
		return nil
	}
	return os.RemoveAll(c.configDir)
}

// runCommand executes platformctl with the harness config and returns stdout.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	// platformctl has no --socket flag; the harness socket reaches it through
	// the config file Setup wrote (#540).
	fullArgs := append([]string{"--config", c.configPath}, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
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

// noDNSGroup is the refusal every DNS operation returns on the CLI leg.
func noDNSGroup(operation string) error {
	return helpers.ErrCLINoCommandGroup{Group: dnsCLIGroup, Operation: operation, Issue: DNSCLIGapIssue}
}

// CreateZone is refused: platformctl has no dns group.
func (c *CLIAdapter) CreateZone(context.Context, CreateZoneOptions) (*CreateZoneResult, error) {
	return nil, noDNSGroup("CreateZone")
}

// GetZone is refused: platformctl has no dns group.
func (c *CLIAdapter) GetZone(context.Context, string) (*GetZoneResult, error) {
	return nil, noDNSGroup("GetZone")
}

// UpdateZone is refused: platformctl has no dns group.
func (c *CLIAdapter) UpdateZone(context.Context, string, UpdateZoneOptions) (*UpdateZoneResult, error) {
	return nil, noDNSGroup("UpdateZone")
}

// DeleteZone is refused: platformctl has no dns group.
func (c *CLIAdapter) DeleteZone(context.Context, string) (*DeleteZoneResult, error) {
	return nil, noDNSGroup("DeleteZone")
}

// ListZones is refused: platformctl has no dns group.
func (c *CLIAdapter) ListZones(context.Context, ListZonesOptions) (*ListZonesResult, error) {
	return nil, noDNSGroup("ListZones")
}

// AddRecord is refused: platformctl has no dns group.
func (c *CLIAdapter) AddRecord(context.Context, AddRecordOptions) (*AddRecordResult, error) {
	return nil, noDNSGroup("AddRecord")
}

// GetRecord is refused: platformctl has no dns group.
func (c *CLIAdapter) GetRecord(context.Context, string, string) (*GetRecordResult, error) {
	return nil, noDNSGroup("GetRecord")
}

// UpdateRecord is refused: platformctl has no dns group.
func (c *CLIAdapter) UpdateRecord(context.Context, UpdateRecordOptions) (*UpdateRecordResult, error) {
	return nil, noDNSGroup("UpdateRecord")
}

// DeleteRecord is refused: platformctl has no dns group.
func (c *CLIAdapter) DeleteRecord(context.Context, string, string) (*DeleteRecordResult, error) {
	return nil, noDNSGroup("DeleteRecord")
}

// ListRecords is refused: platformctl has no dns group.
func (c *CLIAdapter) ListRecords(context.Context, string, ListRecordsOptions) (*ListRecordsResult, error) {
	return nil, noDNSGroup("ListRecords")
}

// Resolve is refused: platformctl has no dns group.
func (c *CLIAdapter) Resolve(context.Context, string, string) (*ResolveResult, error) {
	return nil, noDNSGroup("Resolve")
}

// AddTLSARecord is refused: platformctl has no dns group.
func (c *CLIAdapter) AddTLSARecord(context.Context, AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	return nil, noDNSGroup("AddTLSARecord")
}

// Compile-time check that CLIAdapter implements DNSCommands.
var _ DNSCommands = (*CLIAdapter)(nil)
