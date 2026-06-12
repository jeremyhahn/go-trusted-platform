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

// This file implements the BMCCommands interface using the platformctl CLI binary.

//go:build integration

package bmc_integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// CLIAdapter implements BMCCommands using the platformctl CLI binary.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	grpcEndpoint   string
	serverURL      string
	commandTimeout time.Duration
	configPath     string
	configDir      string
}

// NewCLIAdapter creates a new CLI adapter for BMC integration testing.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := getEnvOrDefault(EnvPlatformctlBinary, DefaultPlatformctlBinary)
	socketPath := getEnvOrDefault(EnvPlatformdSocket, DefaultPlatformdSocket)
	grpcEndpoint := getEnvOrDefault(EnvPlatformGRPCEndpoint, DefaultPlatformGRPCEndpoint)
	serverURL := getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint)

	return &CLIAdapter{
		binaryPath:     binaryPath,
		socketPath:     socketPath,
		grpcEndpoint:   grpcEndpoint,
		serverURL:      serverURL,
		commandTimeout: DefaultCommandTimeout,
	}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary exists and creates a temporary config file.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	if err := c.createTestConfig(); err != nil {
		return ErrCLICommandFailed{Command: "setup", Err: err}
	}

	// Verify binary works by running version command
	_, err := c.runCommand(ctx, "version")
	if err != nil {
		return ErrCLICommandFailed{Command: "version", Err: err}
	}

	return nil
}

// Teardown cleans up temporary config files created during setup.
func (c *CLIAdapter) Teardown() error {
	if c.configDir != "" {
		os.RemoveAll(c.configDir)
		c.configDir = ""
		c.configPath = ""
	}
	return nil
}

// =============================================================================
// Config File Management
// =============================================================================

// createTestConfig creates a temporary YAML config file.
func (c *CLIAdapter) createTestConfig() error {
	tmpDir, err := os.MkdirTemp("", "platformctl-bmc-test-*")
	if err != nil {
		return ErrCLIConfigCreationFailed{Cause: err}
	}
	c.configDir = tmpDir

	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := fmt.Sprintf(`current_context: integration-test
contexts:
  - name: integration-test
    type: local
    local:
      socket_path: %s
      grpc_addr: %s
`, c.socketPath, c.grpcEndpoint)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		return ErrCLIConfigCreationFailed{Cause: err}
	}

	c.configPath = configPath
	return nil
}

// =============================================================================
// Command Execution
// =============================================================================

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	fullArgs := []string{
		"--output", "json",
	}

	if c.configPath != "" {
		fullArgs = append(fullArgs, "--config", c.configPath, "--context", "integration-test")
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
// Power Operations
// =============================================================================

// PowerOn powers on a BMC-managed system via CLI.
func (c *CLIAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	output, err := c.runCommand(ctx, "bmc", "power-on",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return nil, err
	}

	var resp cliPowerActionResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "PowerOn", Output: string(output), Err: err}
	}

	return &bmcsvc.PowerResponse{
		CurrentState: bmcsvc.PowerStateOn,
	}, nil
}

// PowerOff powers off a BMC-managed system via CLI.
func (c *CLIAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	output, err := c.runCommand(ctx, "bmc", "power-off",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return nil, err
	}

	var resp cliPowerActionResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "PowerOff", Output: string(output), Err: err}
	}

	return &bmcsvc.PowerResponse{
		CurrentState: bmcsvc.PowerStateOff,
	}, nil
}

// PowerStatus queries the current power state via CLI.
func (c *CLIAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	output, err := c.runCommand(ctx, "bmc", "power-status",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return bmcsvc.PowerStateUnspecified, err
	}

	var resp cliPowerStatusResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return bmcsvc.PowerStateUnspecified, ErrCLIOutputParseFailed{Operation: "PowerStatus", Output: string(output), Err: err}
	}

	state, ok := bmcsvc.ParsePowerState(resp.PowerState)
	if !ok {
		return bmcsvc.PowerStateUnknown, nil
	}
	return state, nil
}

// =============================================================================
// Boot Device Operations
// =============================================================================

// SetBootDevice sets the boot device via CLI.
func (c *CLIAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	args := []string{
		"bmc", "set-boot-device",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10),
		"--device", strings.ToLower(string(device)),
	}
	if persistent {
		args = append(args, "--persistent")
	}

	_, err := c.runCommand(ctx, args...)
	return err
}

// GetBootDevice queries the current boot device via CLI.
func (c *CLIAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	output, err := c.runCommand(ctx, "bmc", "get-boot-device",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return bmcsvc.BootDeviceUnspecified, err
	}

	var resp cliBootDeviceResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return bmcsvc.BootDeviceUnspecified, ErrCLIOutputParseFailed{Operation: "GetBootDevice", Output: string(output), Err: err}
	}

	device, ok := bmcsvc.ParseBootDevice(resp.Device)
	if !ok {
		return bmcsvc.BootDeviceUnspecified, nil
	}
	return device, nil
}

// =============================================================================
// Virtual Media Operations
// =============================================================================

// MountISO mounts an ISO via CLI.
func (c *CLIAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	_, err := c.runCommand(ctx, "bmc", "mount-iso",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10),
		"--iso-url", isoURL)
	return err
}

// UnmountISO unmounts virtual media via CLI.
func (c *CLIAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	_, err := c.runCommand(ctx, "bmc", "unmount-iso",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	return err
}

// VirtualMediaStatus queries virtual media status via CLI.
func (c *CLIAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	output, err := c.runCommand(ctx, "bmc", "media-status",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return nil, err
	}

	var resp cliMediaStatusResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "VirtualMediaStatus", Output: string(output), Err: err}
	}

	return &bmcsvc.VirtualMediaInfo{
		Mounted:  resp.Mounted,
		ImageURL: resp.ISOURL,
	}, nil
}

// =============================================================================
// Sensor Operations
// =============================================================================

// GetSensors queries sensor readings via CLI.
func (c *CLIAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	output, err := c.runCommand(ctx, "bmc", "sensors",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return nil, err
	}

	var resp cliSensorsResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetSensors", Output: string(output), Err: err}
	}

	sensors := make([]bmcsvc.SensorReading, len(resp.Sensors))
	for i, s := range resp.Sensors {
		sensors[i] = bmcsvc.SensorReading{
			Name:   s.Name,
			Value:  s.Value,
			Units:  s.Units,
			Status: bmcsvc.SensorStatus(s.Status),
		}
	}
	return sensors, nil
}

// =============================================================================
// System Info Operations
// =============================================================================

// GetSystemInfo queries system information via CLI.
func (c *CLIAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	output, err := c.runCommand(ctx, "bmc", "system-info",
		"--server-url", c.serverURL,
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return nil, err
	}

	var resp cliSystemInfoResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetSystemInfo", Output: string(output), Err: err}
	}

	powerState, _ := bmcsvc.ParsePowerState(resp.PowerState)

	return &bmcsvc.SystemInfo{
		Manufacturer:    resp.Manufacturer,
		Product:         resp.Model,
		SerialNumber:    resp.SerialNumber,
		FirmwareVersion: resp.BMCVersion,
		BIOSVersion:     resp.BIOSVersion,
		PowerState:      powerState,
	}, nil
}

// =============================================================================
// Certificate Operations
// =============================================================================

// GetWebCertificate queries the BMC web certificate via CLI.
func (c *CLIAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	output, err := c.runCommand(ctx, "bmc", "cert", "get",
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return nil, err
	}

	var resp bmcsvc.CertificateInfo
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetWebCertificate", Output: string(output), Err: err}
	}

	return &resp, nil
}

// =============================================================================
// User Management Operations
// =============================================================================

// ListUsers lists BMC users via CLI.
func (c *CLIAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	output, err := c.runCommand(ctx, "bmc", "user", "list",
		"--profile-id", strconv.FormatUint(profileID, 10))
	if err != nil {
		return nil, err
	}

	var users []bmcsvc.User
	if err := json.Unmarshal(output, &users); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "ListUsers", Output: string(output), Err: err}
	}

	return users, nil
}

// =============================================================================
// Enrollment Operations
// =============================================================================

// EnrollBMC runs the BMC enrollment ceremony via the platformctl CLI.
// It shells out to `platformctl bmc enroll --profile-id N [--output json]`
// and parses the JSON EnrollResult emitted to stdout.
func (c *CLIAdapter) EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error) {
	args := []string{
		"bmc", "enroll",
		"--profile-id", strconv.FormatUint(profileID, 10),
	}
	if opts != nil {
		if opts.ReplaceCertificate != nil {
			args = append(args, "--replace-certificate="+strconv.FormatBool(*opts.ReplaceCertificate))
		}
		if opts.RotatePassword != nil {
			args = append(args, "--rotate-password="+strconv.FormatBool(*opts.RotatePassword))
		}
		if opts.DNSRegister != nil {
			args = append(args, "--dns-register="+strconv.FormatBool(*opts.DNSRegister))
		}
		if opts.DANEPublish != nil {
			args = append(args, "--dane-publish="+strconv.FormatBool(*opts.DANEPublish))
		}
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliEnrollResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "EnrollBMC", Output: string(output), Err: err}
	}

	return cliEnrollResultToDomain(&result), nil
}

// cliEnrollResultToDomain converts the CLI JSON response to the local domain type.
func cliEnrollResultToDomain(r *cliEnrollResult) *EnrollResult {
	if r == nil {
		return &EnrollResult{}
	}
	steps := make([]EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	return &EnrollResult{
		DeviceID:      r.DeviceID,
		Endpoint:      r.Endpoint,
		Hostname:      r.Hostname,
		DNSName:       r.DNSName,
		PinSPKISHA256: r.PinSPKISHA256,
		FactoryCertMeta: EnrollFactoryCertMeta{
			Subject:      r.FactoryCertMeta.Subject,
			Issuer:       r.FactoryCertMeta.Issuer,
			SerialNumber: r.FactoryCertMeta.SerialNumber,
			NotBefore:    r.FactoryCertMeta.NotBefore,
			NotAfter:     r.FactoryCertMeta.NotAfter,
			SPKISHA256:   r.FactoryCertMeta.SPKISHA256,
			SHA256:       r.FactoryCertMeta.SHA256,
			CapturedAt:   r.FactoryCertMeta.CapturedAt,
		},
		Steps: steps,
	}
}

// =============================================================================
// Factory Certificate Restore Operations
// =============================================================================

// RestoreBMC runs the BMC factory-certificate restore ceremony via the platformctl CLI.
// It shells out to `platformctl bmc cert restore --profile-id N --factory [--output json]`
// and parses the JSON RestoreResult emitted to stdout.
func (c *CLIAdapter) RestoreBMC(ctx context.Context, profileID uint64) (*RestoreResult, error) {
	args := []string{
		"bmc", "cert", "restore",
		"--profile-id", strconv.FormatUint(profileID, 10),
		"--factory",
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliRestoreResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "RestoreBMC", Output: string(output), Err: err}
	}

	return cliRestoreResultToDomain(&result), nil
}

// cliRestoreResultToDomain converts the CLI JSON response to the local domain type.
func cliRestoreResultToDomain(r *cliRestoreResult) *RestoreResult {
	if r == nil {
		return &RestoreResult{}
	}
	steps := make([]EnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = EnrollStep{Name: s.Name, OK: s.OK, Detail: s.Detail}
	}
	return &RestoreResult{
		DeviceID: r.DeviceID,
		Endpoint: r.Endpoint,
		Hostname: r.Hostname,
		NewCertMeta: RestoreFactoryCertMeta{
			Subject:      r.NewCertMeta.Subject,
			Issuer:       r.NewCertMeta.Issuer,
			SerialNumber: r.NewCertMeta.SerialNumber,
			NotBefore:    r.NewCertMeta.NotBefore,
			NotAfter:     r.NewCertMeta.NotAfter,
			SPKISHA256:   r.NewCertMeta.SPKISHA256,
			SHA256:       r.NewCertMeta.SHA256,
			CapturedAt:   r.NewCertMeta.CapturedAt,
		},
		Steps: steps,
	}
}

// =============================================================================
// CLI Response Types
// =============================================================================

type cliPowerStatusResponse struct {
	ProfileID  string `json:"profile_id"`
	PowerState string `json:"power_state"`
}

type cliPowerActionResponse struct {
	ProfileID string `json:"profile_id"`
	Action    string `json:"action"`
	Status    string `json:"status"`
}

type cliBootDeviceResponse struct {
	ProfileID  string `json:"profile_id"`
	Device     string `json:"device"`
	Persistent bool   `json:"persistent"`
}

type cliMediaStatusResponse struct {
	ProfileID string `json:"profile_id"`
	Mounted   bool   `json:"mounted"`
	ISOURL    string `json:"iso_url,omitempty"`
}

type cliSensorReading struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Units  string  `json:"units"`
	Status string  `json:"status"`
}

type cliSensorsResponse struct {
	ProfileID string             `json:"profile_id"`
	Sensors   []cliSensorReading `json:"sensors"`
}

type cliSystemInfoResponse struct {
	ProfileID    string `json:"profile_id"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	BIOSVersion  string `json:"bios_version"`
	BMCVersion   string `json:"bmc_version"`
	PowerState   string `json:"power_state"`
	Health       string `json:"health"`
}

// cliEnrollStep is the JSON shape of one enrollment step in CLI output.
type cliEnrollStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// cliFactoryCertMeta is the JSON shape of factory cert metadata in CLI output.
type cliFactoryCertMeta struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SPKISHA256   string    `json:"spki_sha256"`
	SHA256       string    `json:"sha256"`
	CapturedAt   time.Time `json:"captured_at"`
}

// cliEnrollResult is the JSON output shape of `platformctl bmc enroll --output json`.
// DeviceID is a string to match the `json:"device_id,string"` convention used
// across the platform's REST API (preserving uint64 precision in JavaScript).
type cliEnrollResult struct {
	DeviceID        uint64             `json:"device_id,string"`
	Endpoint        string             `json:"endpoint"`
	Hostname        string             `json:"hostname"`
	DNSName         string             `json:"dns_name,omitempty"`
	PinSPKISHA256   string             `json:"pin_spki_sha256"`
	FactoryCertMeta cliFactoryCertMeta `json:"factory_cert_meta"`
	Steps           []cliEnrollStep    `json:"steps"`
}

// cliRestoreResult is the JSON output shape of
// `platformctl bmc cert restore --factory --output json`.
// DeviceID is a string to match the `json:"device_id,string"` convention.
type cliRestoreResult struct {
	DeviceID    uint64             `json:"device_id,string"`
	Endpoint    string             `json:"endpoint"`
	Hostname    string             `json:"hostname"`
	NewCertMeta cliFactoryCertMeta `json:"new_cert_meta"`
	Steps       []cliEnrollStep    `json:"steps"`
}

// Ensure CLIAdapter implements BMCCommands interface.
var _ BMCCommands = (*CLIAdapter)(nil)
