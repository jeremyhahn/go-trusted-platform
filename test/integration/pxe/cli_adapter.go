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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

// ErrCLIPXENotImplemented is returned by the PXE verbs platformctl does not
// have. The `platformctl pxe` group (docs/provisioning/cli.md §5) lists,
// inspects, authorizes, quarantines and retries devices and reads their
// events; this adapter drives those six through the binary. Registration,
// removal, lookup by MAC, raw state writes, set-enrolled and service status
// stay API-only (docs/provisioning/architecture.md), so those verbs refuse
// with this typed error and the CLI leg of TestPXEMultiProtocol asserts it.
type ErrCLIPXENotImplemented struct {
	Method string
}

func (e ErrCLIPXENotImplemented) Error() string {
	return fmt.Sprintf(
		"platformctl pxe has no verb for %s (it stays API-only, docs/provisioning/architecture.md), so CLI %s is refused",
		e.Method, e.Method)
}

// ErrCLIDecode is returned when platformctl's JSON reply does not decode.
type ErrCLIDecode struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLIDecode) Error() string {
	return fmt.Sprintf("decode platformctl %s reply: %v (output %q)", e.Command, e.Err, e.Output)
}

func (e ErrCLIDecode) Unwrap() error { return e.Err }

// runJSON runs `platformctl --output json pxe <args>` and decodes the reply.
// The CLI prints the gRPC reply with encoding/json, so it decodes back into
// the same platformv1 type.
func (c *CLIAdapter) runJSON(ctx context.Context, reply any, args ...string) error {
	out, err := c.runCommand(ctx, append([]string{"pxe"}, args...)...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(out, reply); err != nil {
		return ErrCLIDecode{Command: strings.Join(args, " "), Output: string(out), Err: err}
	}
	return nil
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
// Get, list, authorize, quarantine, retry and events drive `platformctl pxe`.
// The verbs the group does not have refuse with ErrCLIPXENotImplemented rather
// than shelling a command that does not exist or faking a success.
// =============================================================================

// RegisterDevice is refused: platformctl pxe has no such verb; it
// stays API-only (docs/provisioning/architecture.md).
func (c *CLIAdapter) RegisterDevice(_ context.Context, _ RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "RegisterDevice"}
}

// GetDevice runs `platformctl pxe get <device-id>`.
func (c *CLIAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	var reply platformv1.GetPXEDeviceResponse
	if err := c.runJSON(ctx, &reply, "get", deviceID); err != nil {
		return nil, err
	}
	return deviceResult(reply.GetDevice()), nil
}

// GetDeviceByMAC is refused: platformctl pxe has no such verb; it
// stays API-only (docs/provisioning/architecture.md).
func (c *CLIAdapter) GetDeviceByMAC(_ context.Context, _ string) (*GetDeviceResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "GetDeviceByMAC"}
}

// ListDevices runs `platformctl pxe list` with the options as flags; a zero
// option is left off, as the API treats it as "no filter".
func (c *CLIAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	args := []string{"list"}
	if opts.State != "" {
		args = append(args, "--state", opts.State)
	}
	if opts.MACAddress != "" {
		args = append(args, "--mac", opts.MACAddress)
	}
	if opts.VLAN != 0 {
		args = append(args, "--vlan", strconv.Itoa(int(opts.VLAN)))
	}
	if opts.Limit != 0 {
		args = append(args, "--limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Offset != 0 {
		args = append(args, "--offset", strconv.Itoa(int(opts.Offset)))
	}
	var reply platformv1.ListPXEDevicesResponse
	if err := c.runJSON(ctx, &reply, args...); err != nil {
		return nil, err
	}
	result := &ListDevicesResult{TotalCount: reply.GetTotalCount()}
	for _, d := range reply.GetDevices() {
		result.Devices = append(result.Devices, DeviceSummary{
			ID:          d.GetId(),
			MACAddress:  d.GetMacAddress(),
			PortID:      d.GetPortId(),
			State:       stateName(d.GetState()),
			CurrentVLAN: uint16(d.GetCurrentVlan()),
			CreatedAt:   timeOf(d.GetCreatedAt()),
			UpdatedAt:   timeOf(d.GetUpdatedAt()),
		})
	}
	return result, nil
}

// RemoveDevice is refused: platformctl pxe has no such verb; it
// stays API-only (docs/provisioning/architecture.md).
func (c *CLIAdapter) RemoveDevice(_ context.Context, _ string) (*RemoveDeviceResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "RemoveDevice"}
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState is refused: platformctl pxe has no such verb; it
// stays API-only (docs/provisioning/architecture.md).
func (c *CLIAdapter) UpdateDeviceState(_ context.Context, _ UpdateStateOptions) (*UpdateStateResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "UpdateDeviceState"}
}

// SetDeviceEnrolled is refused: platformctl pxe has no such verb; it
// stays API-only (docs/provisioning/architecture.md).
func (c *CLIAdapter) SetDeviceEnrolled(_ context.Context, _, _ string) (*SetEnrolledResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "SetDeviceEnrolled"}
}

// AuthorizeDevice runs `platformctl pxe authorize <device-id> --target-vlan`.
func (c *CLIAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	var reply platformv1.AuthorizePXEDeviceResponse
	if err := c.runJSON(ctx, &reply, "authorize", deviceID,
		"--target-vlan", strconv.Itoa(int(targetVLAN))); err != nil {
		return nil, err
	}
	d := reply.GetDevice()
	return &AuthorizeResult{
		ID:         d.GetId(),
		State:      stateName(d.GetState()),
		TargetVLAN: uint16(d.GetTargetVlan()),
		UpdatedAt:  timeOf(d.GetUpdatedAt()),
	}, nil
}

// QuarantineDevice runs `platformctl pxe quarantine <device-id> --reason`.
func (c *CLIAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	var reply platformv1.QuarantinePXEDeviceResponse
	if err := c.runJSON(ctx, &reply, "quarantine", deviceID, "--reason", reason); err != nil {
		return nil, err
	}
	d := reply.GetDevice()
	return &QuarantineResult{
		ID:          d.GetId(),
		State:       stateName(d.GetState()),
		Reason:      d.GetStateReason(),
		CurrentVLAN: uint16(d.GetCurrentVlan()),
		UpdatedAt:   timeOf(d.GetUpdatedAt()),
	}, nil
}

// RetryDevice runs `platformctl pxe retry <device-id>`.
func (c *CLIAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	var reply platformv1.RetryPXEDeviceResponse
	if err := c.runJSON(ctx, &reply, "retry", deviceID); err != nil {
		return nil, err
	}
	d := reply.GetDevice()
	return &RetryResult{
		ID:         d.GetId(),
		State:      stateName(d.GetState()),
		RetryCount: int(d.GetRetryCount()),
		UpdatedAt:  timeOf(d.GetUpdatedAt()),
	}, nil
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents runs `platformctl pxe events <device-id>`.
func (c *CLIAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	var reply platformv1.GetPXEEventsResponse
	if err := c.runJSON(ctx, &reply, "events", deviceID); err != nil {
		return nil, err
	}
	result := &GetEventsResult{DeviceID: deviceID}
	for _, e := range reply.GetEvents() {
		result.Events = append(result.Events, ProvisioningEventInfo{
			ID:        e.GetId(),
			DeviceID:  e.GetDeviceId(),
			EventType: strings.ToLower(strings.TrimPrefix(e.GetEventType().String(), eventTypePrefix)),
			FromState: stateName(e.GetFromState()),
			ToState:   stateName(e.GetToState()),
			Details:   e.GetDetails(),
			Error:     e.GetError(),
			Timestamp: timeOf(e.GetTimestamp()),
		})
	}
	return result, nil
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus is refused: platformctl pxe has no such verb; it
// stays API-only (docs/provisioning/architecture.md).
func (c *CLIAdapter) GetStatus(_ context.Context) (*GetStatusResult, error) {
	return nil, ErrCLIPXENotImplemented{Method: "GetStatus"}
}

// Ensure CLIAdapter implements PXECommands interface.
var _ PXECommands = (*CLIAdapter)(nil)
