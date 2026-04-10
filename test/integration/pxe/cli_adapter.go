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

// ErrCLIOutputParseFailed is returned when CLI output cannot be parsed.
type ErrCLIOutputParseFailed struct {
	Operation string
	Output    string
	Err       error
}

func (e ErrCLIOutputParseFailed) Error() string {
	return fmt.Sprintf("failed to parse CLI output for %s: %v (output: %s)", e.Operation, e.Err, e.Output)
}

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
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

	_, err := c.runCommand(ctx, "version")
	if err != nil {
		return fmt.Errorf("CLI binary verification failed: %w", err)
	}

	return nil
}

// Teardown performs cleanup (no-op for CLI adapter).
func (c *CLIAdapter) Teardown() error {
	return nil
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

	if c.socketPath != "" && c.socketPath != DefaultPlatformdSocket {
		fullArgs = append(fullArgs, "--socket", c.socketPath)
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
// =============================================================================

// RegisterDevice registers a new device via CLI.
func (c *CLIAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	args := []string{"pxe", "device", "register", opts.MACAddress}

	if opts.PortID != "" {
		args = append(args, "--port-id", opts.PortID)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliRegisterDeviceResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "RegisterDevice", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// GetDevice retrieves device information via CLI.
func (c *CLIAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	args := []string{"pxe", "device", "get", deviceID}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliGetDeviceResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetDevice", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// GetDeviceByMAC retrieves a device by MAC address via CLI.
func (c *CLIAdapter) GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error) {
	args := []string{"pxe", "device", "get", "--mac", mac}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliGetDeviceResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetDeviceByMAC", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// ListDevices lists devices via CLI.
func (c *CLIAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	args := []string{"pxe", "device", "list"}

	if opts.State != "" {
		args = append(args, "--state", opts.State)
	}
	if opts.MACAddress != "" {
		args = append(args, "--mac", opts.MACAddress)
	}
	if opts.VLAN > 0 {
		args = append(args, "--vlan", strconv.FormatUint(uint64(opts.VLAN), 10))
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", strconv.FormatInt(int64(opts.Offset), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliListDevicesResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "ListDevices", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// RemoveDevice removes a device via CLI.
func (c *CLIAdapter) RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error) {
	args := []string{"pxe", "device", "remove", deviceID, "--force"}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliRemoveDeviceResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "RemoveDevice", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState updates device state via CLI.
func (c *CLIAdapter) UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error) {
	args := []string{"pxe", "state", "update", opts.DeviceID, opts.State}

	if opts.Reason != "" {
		args = append(args, "--reason", opts.Reason)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliUpdateStateResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "UpdateDeviceState", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// SetDeviceEnrolled sets a device as enrolled via CLI.
func (c *CLIAdapter) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error) {
	args := []string{"pxe", "state", "enrolled", deviceID, "--cert-serial", certSerial}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliSetEnrolledResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "SetDeviceEnrolled", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// AuthorizeDevice authorizes a device via CLI.
func (c *CLIAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	args := []string{"pxe", "state", "authorize", deviceID, "--target-vlan", strconv.FormatUint(uint64(targetVLAN), 10)}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliAuthorizeResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "AuthorizeDevice", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// QuarantineDevice quarantines a device via CLI.
func (c *CLIAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	args := []string{"pxe", "state", "quarantine", deviceID}

	if reason != "" {
		args = append(args, "--reason", reason)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliQuarantineResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "QuarantineDevice", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// RetryDevice retries a device via CLI.
func (c *CLIAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	args := []string{"pxe", "state", "retry", deviceID}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliRetryResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "RetryDevice", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents retrieves device events via CLI.
func (c *CLIAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	args := []string{"pxe", "events", "list", deviceID}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliGetEventsResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetEvents", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus retrieves service status via CLI.
func (c *CLIAdapter) GetStatus(ctx context.Context) (*GetStatusResult, error) {
	args := []string{"pxe", "status"}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliGetStatusResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetStatus", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// CLI Response Types and Conversion
// =============================================================================

type cliRegisterDeviceResponse struct {
	ID          string `json:"id,omitempty"`
	MACAddress  string `json:"mac_address,omitempty"`
	PortID      string `json:"port_id,omitempty"`
	State       string `json:"state,omitempty"`
	StateReason string `json:"state_reason,omitempty"`
	CurrentVLAN uint16 `json:"current_vlan,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
}

func (r *cliRegisterDeviceResponse) toResult() *RegisterDeviceResult {
	return &RegisterDeviceResult{
		ID:          r.ID,
		MACAddress:  r.MACAddress,
		PortID:      r.PortID,
		State:       r.State,
		StateReason: r.StateReason,
		CurrentVLAN: r.CurrentVLAN,
		CreatedAt:   time.Unix(r.CreatedAt, 0),
	}
}

type cliGetDeviceResponse struct {
	ID                string `json:"id,omitempty"`
	MACAddress        string `json:"mac_address,omitempty"`
	PortID            string `json:"port_id,omitempty"`
	State             string `json:"state,omitempty"`
	StateReason       string `json:"state_reason,omitempty"`
	CertificateSerial string `json:"certificate_serial,omitempty"`
	CurrentVLAN       uint16 `json:"current_vlan,omitempty"`
	TargetVLAN        uint16 `json:"target_vlan,omitempty"`
	RetryCount        int    `json:"retry_count,omitempty"`
	CreatedAt         int64  `json:"created_at,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
	StateChangedAt    int64  `json:"state_changed_at,omitempty"`
}

func (r *cliGetDeviceResponse) toResult() *GetDeviceResult {
	return &GetDeviceResult{
		ID:                r.ID,
		MACAddress:        r.MACAddress,
		PortID:            r.PortID,
		State:             r.State,
		StateReason:       r.StateReason,
		CertificateSerial: r.CertificateSerial,
		CurrentVLAN:       r.CurrentVLAN,
		TargetVLAN:        r.TargetVLAN,
		RetryCount:        r.RetryCount,
		CreatedAt:         time.Unix(r.CreatedAt, 0),
		UpdatedAt:         time.Unix(r.UpdatedAt, 0),
		StateChangedAt:    time.Unix(r.StateChangedAt, 0),
	}
}

type cliListDevicesResponse struct {
	Devices    []cliDeviceSummary `json:"devices,omitempty"`
	TotalCount int32              `json:"total_count,omitempty"`
	HasMore    bool               `json:"has_more,omitempty"`
}

type cliDeviceSummary struct {
	ID          string `json:"id,omitempty"`
	MACAddress  string `json:"mac_address,omitempty"`
	PortID      string `json:"port_id,omitempty"`
	State       string `json:"state,omitempty"`
	CurrentVLAN uint16 `json:"current_vlan,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

func (r *cliListDevicesResponse) toResult() *ListDevicesResult {
	result := &ListDevicesResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
	}

	for _, d := range r.Devices {
		result.Devices = append(result.Devices, DeviceSummary{
			ID:          d.ID,
			MACAddress:  d.MACAddress,
			PortID:      d.PortID,
			State:       d.State,
			CurrentVLAN: d.CurrentVLAN,
			CreatedAt:   time.Unix(d.CreatedAt, 0),
			UpdatedAt:   time.Unix(d.UpdatedAt, 0),
		})
	}

	return result
}

type cliRemoveDeviceResponse struct {
	ID      string `json:"id,omitempty"`
	Removed bool   `json:"removed,omitempty"`
}

func (r *cliRemoveDeviceResponse) toResult() *RemoveDeviceResult {
	return &RemoveDeviceResult{
		ID:      r.ID,
		Removed: r.Removed,
	}
}

type cliUpdateStateResponse struct {
	ID        string `json:"id,omitempty"`
	FromState string `json:"from_state,omitempty"`
	ToState   string `json:"to_state,omitempty"`
	Reason    string `json:"reason,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

func (r *cliUpdateStateResponse) toResult() *UpdateStateResult {
	return &UpdateStateResult{
		ID:        r.ID,
		FromState: r.FromState,
		ToState:   r.ToState,
		Reason:    r.Reason,
		UpdatedAt: time.Unix(r.UpdatedAt, 0),
	}
}

type cliSetEnrolledResponse struct {
	ID                string `json:"id,omitempty"`
	State             string `json:"state,omitempty"`
	CertificateSerial string `json:"certificate_serial,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
}

func (r *cliSetEnrolledResponse) toResult() *SetEnrolledResult {
	return &SetEnrolledResult{
		ID:                r.ID,
		State:             r.State,
		CertificateSerial: r.CertificateSerial,
		UpdatedAt:         time.Unix(r.UpdatedAt, 0),
	}
}

type cliAuthorizeResponse struct {
	ID         string `json:"id,omitempty"`
	State      string `json:"state,omitempty"`
	TargetVLAN uint16 `json:"target_vlan,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

func (r *cliAuthorizeResponse) toResult() *AuthorizeResult {
	return &AuthorizeResult{
		ID:         r.ID,
		State:      r.State,
		TargetVLAN: r.TargetVLAN,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type cliQuarantineResponse struct {
	ID          string `json:"id,omitempty"`
	State       string `json:"state,omitempty"`
	Reason      string `json:"reason,omitempty"`
	CurrentVLAN uint16 `json:"current_vlan,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

func (r *cliQuarantineResponse) toResult() *QuarantineResult {
	return &QuarantineResult{
		ID:          r.ID,
		State:       r.State,
		Reason:      r.Reason,
		CurrentVLAN: r.CurrentVLAN,
		UpdatedAt:   time.Unix(r.UpdatedAt, 0),
	}
}

type cliRetryResponse struct {
	ID         string `json:"id,omitempty"`
	State      string `json:"state,omitempty"`
	RetryCount int    `json:"retry_count,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

func (r *cliRetryResponse) toResult() *RetryResult {
	return &RetryResult{
		ID:         r.ID,
		State:      r.State,
		RetryCount: r.RetryCount,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type cliGetEventsResponse struct {
	DeviceID string         `json:"device_id,omitempty"`
	Events   []cliEventInfo `json:"events,omitempty"`
}

type cliEventInfo struct {
	ID        string            `json:"id,omitempty"`
	DeviceID  string            `json:"device_id,omitempty"`
	EventType string            `json:"event_type,omitempty"`
	FromState string            `json:"from_state,omitempty"`
	ToState   string            `json:"to_state,omitempty"`
	Details   map[string]string `json:"details,omitempty"`
	Error     string            `json:"error,omitempty"`
	Timestamp int64             `json:"timestamp,omitempty"`
}

func (r *cliGetEventsResponse) toResult() *GetEventsResult {
	result := &GetEventsResult{
		DeviceID: r.DeviceID,
	}

	for _, e := range r.Events {
		result.Events = append(result.Events, ProvisioningEventInfo{
			ID:        e.ID,
			DeviceID:  e.DeviceID,
			EventType: e.EventType,
			FromState: e.FromState,
			ToState:   e.ToState,
			Details:   e.Details,
			Error:     e.Error,
			Timestamp: time.Unix(e.Timestamp, 0),
		})
	}

	return result
}

type cliGetStatusResponse struct {
	Running          bool   `json:"running,omitempty"`
	DeviceCount      int    `json:"device_count,omitempty"`
	StartTime        int64  `json:"start_time,omitempty"`
	IPXEServerAddr   string `json:"ipxe_server_addr,omitempty"`
	QuarantineVLAN   uint16 `json:"quarantine_vlan,omitempty"`
	ProvisioningVLAN uint16 `json:"provisioning_vlan,omitempty"`
}

func (r *cliGetStatusResponse) toResult() *GetStatusResult {
	return &GetStatusResult{
		Running:          r.Running,
		DeviceCount:      r.DeviceCount,
		StartTime:        time.Unix(r.StartTime, 0),
		IPXEServerAddr:   r.IPXEServerAddr,
		QuarantineVLAN:   r.QuarantineVLAN,
		ProvisioningVLAN: r.ProvisioningVLAN,
	}
}

// Ensure CLIAdapter implements PXECommands interface.
var _ PXECommands = (*CLIAdapter)(nil)
