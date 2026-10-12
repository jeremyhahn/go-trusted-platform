//go:build integration

package device

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// CLIAdapterError represents an error from the CLI adapter
type CLIAdapterError struct {
	Operation string
	Message   string
	Output    string
}

func (e *CLIAdapterError) Error() string {
	return fmt.Sprintf("CLI adapter error [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// CLIAdapter implements DeviceCommands using the platformctl CLI
type CLIAdapter struct {
	cliPath string
}

// NewCLIAdapter creates a new CLI adapter
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup prepares the adapter for testing
func (a *CLIAdapter) Setup(ctx context.Context) error {
	// Verify CLI is available
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return &CLIAdapterError{
			Operation: "Setup",
			Message:   "CLI not found",
		}
	}
	return nil
}

// Teardown cleans up after testing
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command and returns the output
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, a.cliPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    string(output),
		}
	}
	return output, nil
}

// ============================================================================
// Device CRUD Operations
// ============================================================================

// RegisterDevice registers a new device
func (a *CLIAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	args := []string{"device", "register",
		"--tenant-id", opts.TenantID,
		"--serial", opts.Serial,
		"--output", "json",
	}

	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}
	if opts.EKCert != "" {
		args = append(args, "--ek-cert", opts.EKCert)
	}
	if opts.AttestPub != "" {
		args = append(args, "--attest-pub", opts.AttestPub)
	}
	if opts.AttestCert != "" {
		args = append(args, "--attest-cert", opts.AttestCert)
	}
	if opts.SigningPub != "" {
		args = append(args, "--signing-pub", opts.SigningPub)
	}
	if opts.HashAlgoId > 0 {
		args = append(args, "--hash-algo", fmt.Sprintf("%d", opts.HashAlgoId))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(output, &device); err != nil {
		return nil, &CLIAdapterError{
			Operation: "RegisterDevice",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &RegisterDeviceResult{Device: &device}, nil
}

// GetDevice retrieves a device by its key
func (a *CLIAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	args := []string{"device", "get",
		"--tenant-id", opts.TenantID,
		"--device-id", opts.DeviceID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(output, &device); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetDevice",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetDeviceResult{Device: &device}, nil
}

// UpdateDevice updates an existing device
func (a *CLIAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	args := []string{"device", "update",
		"--tenant-id", opts.TenantID,
		"--device-id", opts.DeviceID,
		"--output", "json",
	}

	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}
	if opts.EKCert != "" {
		args = append(args, "--ek-cert", opts.EKCert)
	}
	if opts.AttestPub != "" {
		args = append(args, "--attest-pub", opts.AttestPub)
	}
	if opts.AttestCert != "" {
		args = append(args, "--attest-cert", opts.AttestCert)
	}
	if opts.SigningPub != "" {
		args = append(args, "--signing-pub", opts.SigningPub)
	}
	if opts.HashAlgoId > 0 {
		args = append(args, "--hash-algo", fmt.Sprintf("%d", opts.HashAlgoId))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(output, &device); err != nil {
		return nil, &CLIAdapterError{
			Operation: "UpdateDevice",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UpdateDeviceResult{Device: &device}, nil
}

// DeleteDevice removes a device
func (a *CLIAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	args := []string{"device", "delete",
		"--tenant-id", opts.TenantID,
		"--device-id", opts.DeviceID,
		"--output", "json",
	}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &DeleteDeviceResult{Success: true}, nil
}

// ListDevices lists all devices with optional filtering
func (a *CLIAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	args := []string{"device", "list",
		"--tenant-id", opts.TenantID,
		"--output", "json",
	}

	if opts.ProfileID != "" {
		args = append(args, "--profile-id", opts.ProfileID)
	}
	if opts.Status != "" {
		args = append(args, "--status", opts.Status)
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListDevicesResult
	if err := json.Unmarshal(output, &result); err != nil {
		// Try parsing as array
		var devices []*entities.Device
		if err := json.Unmarshal(output, &devices); err != nil {
			return nil, &CLIAdapterError{
				Operation: "ListDevices",
				Message:   "failed to parse response",
				Output:    string(output),
			}
		}
		result.Devices = devices
		result.Total = len(devices)
	}

	return &result, nil
}

// ============================================================================
// Device Lookups
// ============================================================================

// FindBySerial finds a device by its serial number
func (a *CLIAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	args := []string{"device", "find-by-serial",
		"--tenant-id", opts.TenantID,
		"--serial", opts.Serial,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var device entities.Device
	if err := json.Unmarshal(output, &device); err != nil {
		return nil, &CLIAdapterError{
			Operation: "FindBySerial",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &FindBySerialResult{Device: &device}, nil
}

// ============================================================================
// Profile CRUD Operations
// ============================================================================

// CreateProfile creates a new device profile
func (a *CLIAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	args := []string{"device", "profile", "create",
		"--tenant-id", opts.TenantID,
		"--name", opts.Name,
		"--output", "json",
	}

	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}
	if opts.Role != "" {
		args = append(args, "--role", string(opts.Role))
	}
	if opts.MACPrefix != "" {
		args = append(args, "--mac-prefix", opts.MACPrefix)
	}
	if opts.SerialPrefix != "" {
		args = append(args, "--serial-prefix", opts.SerialPrefix)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateProfile",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateProfileResult{Profile: &profile}, nil
}

// GetProfile retrieves a profile by its key
func (a *CLIAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	args := []string{"device", "profile", "get",
		"--tenant-id", opts.TenantID,
		"--profile-id", opts.ProfileID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetProfile",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetProfileResult{Profile: &profile}, nil
}

// UpdateProfile updates an existing profile
func (a *CLIAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	args := []string{"device", "profile", "update",
		"--tenant-id", opts.TenantID,
		"--profile-id", opts.ProfileID,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}
	if opts.Role != "" {
		args = append(args, "--role", string(opts.Role))
	}
	if opts.MACPrefix != "" {
		args = append(args, "--mac-prefix", opts.MACPrefix)
	}
	if opts.SerialPrefix != "" {
		args = append(args, "--serial-prefix", opts.SerialPrefix)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "UpdateProfile",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UpdateProfileResult{Profile: &profile}, nil
}

// DeleteProfile removes a profile
func (a *CLIAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	args := []string{"device", "profile", "delete",
		"--tenant-id", opts.TenantID,
		"--profile-id", opts.ProfileID,
		"--output", "json",
	}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &DeleteProfileResult{Success: true}, nil
}

// ListProfiles lists all profiles with optional filtering
func (a *CLIAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	args := []string{"device", "profile", "list",
		"--tenant-id", opts.TenantID,
		"--output", "json",
	}

	if opts.Role != "" {
		args = append(args, "--role", string(opts.Role))
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListProfilesResult
	if err := json.Unmarshal(output, &result); err != nil {
		// Try parsing as array
		var profiles []*entities.DeviceProfile
		if err := json.Unmarshal(output, &profiles); err != nil {
			return nil, &CLIAdapterError{
				Operation: "ListProfiles",
				Message:   "failed to parse response",
				Output:    string(output),
			}
		}
		result.Profiles = profiles
		result.Total = len(profiles)
	}

	return &result, nil
}

// ============================================================================
// Profile Lookups
// ============================================================================

// FindProfileByMACAddress finds a profile by MAC address prefix
func (a *CLIAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	args := []string{"device", "profile", "find-by-mac",
		"--tenant-id", opts.TenantID,
		"--mac-address", opts.MACAddress,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "FindProfileByMACAddress",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &FindProfileByMACAddressResult{Profile: &profile}, nil
}

// FindProfileBySerial finds a profile by serial pattern
func (a *CLIAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	args := []string{"device", "profile", "find-by-serial",
		"--tenant-id", opts.TenantID,
		"--serial", opts.Serial,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "FindProfileBySerial",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &FindProfileBySerialResult{Profile: &profile}, nil
}

// FindMatchingProfile finds a profile matching device attributes
func (a *CLIAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	args := []string{"device", "profile", "find-matching",
		"--tenant-id", opts.TenantID,
		"--output", "json",
	}

	if opts.MACAddress != "" {
		args = append(args, "--mac-address", opts.MACAddress)
	}
	if opts.Serial != "" {
		args = append(args, "--serial", opts.Serial)
	}
	if opts.Model != "" {
		args = append(args, "--model", opts.Model)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "FindMatchingProfile",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &FindMatchingProfileResult{Profile: &profile}, nil
}

// ============================================================================
// Attestation
// ============================================================================

// RecordAttestCert records the device's attestation certificate via
// platformctl device attest-cert record.
func (a *CLIAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	args := []string{"device", "attest-cert", "record", opts.DeviceID, "--output", "json"}
	if opts.Reissue {
		args = append(args, "--reissue")
	}
	if opts.ClearOnRefusal {
		args = append(args, "--clear-on-refusal")
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result RecordAttestCertResult
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, &CLIAdapterError{
			Operation: "RecordAttestCert",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}
	return &result, nil
}

// AttestDevice reports that platformctl has no device attestation command.
//
// This adapter used to shell `platformctl device attest`, a command that
// does not exist (pkg/cli/commands/device registers list, get, find-serial,
// register, delete and profile; docs/device/cli.md documents no attest
// verb). The resulting "unknown command" error was swallowed by the suite's
// skip guard, so the CLI lane reported attestation passing (#403).
//
// The error is returned rather than faked so the gap stays visible.
func (a *CLIAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	return nil, ErrAttestationTransportUnavailable{
		Transport: "CLI",
		Reason:    "platformctl has no `device attest` command",
	}
}

// ============================================================================
// Template CRUD Operations
// ============================================================================

// CreateTemplate creates a new device template
func (a *CLIAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	args := []string{"device", "template", "create",
		"--tenant-id", opts.TenantID,
		"--name", opts.Name,
		"--output", "json",
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	if opts.Role != "" {
		args = append(args, "--role", string(opts.Role))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := json.Unmarshal(output, &template); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateTemplate",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateTemplateResult{Template: &template}, nil
}

// GetTemplate retrieves a template by ID
func (a *CLIAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	args := []string{"device", "template", "get",
		"--tenant-id", opts.TenantID,
		"--template-id", opts.TemplateID,
		"--output", "json",
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := json.Unmarshal(output, &template); err != nil {
		return nil, &CLIAdapterError{
			Operation: "GetTemplate",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &GetTemplateResult{Template: &template}, nil
}

// UpdateTemplate updates an existing template
func (a *CLIAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	args := []string{"device", "template", "update",
		"--tenant-id", opts.TenantID,
		"--template-id", opts.TemplateID,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}
	if opts.Role != "" {
		args = append(args, "--role", string(opts.Role))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var template entities.DeviceTemplate
	if err := json.Unmarshal(output, &template); err != nil {
		return nil, &CLIAdapterError{
			Operation: "UpdateTemplate",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &UpdateTemplateResult{Template: &template}, nil
}

// DeleteTemplate removes a template
func (a *CLIAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	args := []string{"device", "template", "delete",
		"--tenant-id", opts.TenantID,
		"--template-id", opts.TemplateID,
		"--output", "json",
	}

	_, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	return &DeleteTemplateResult{Success: true}, nil
}

// ListTemplates lists all templates
func (a *CLIAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	args := []string{"device", "template", "list",
		"--tenant-id", opts.TenantID,
		"--output", "json",
	}

	if opts.Role != "" {
		args = append(args, "--role", string(opts.Role))
	}
	if opts.Limit > 0 {
		args = append(args, "--limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.Offset > 0 {
		args = append(args, "--offset", fmt.Sprintf("%d", opts.Offset))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result ListTemplatesResult
	if err := json.Unmarshal(output, &result); err != nil {
		// Try parsing as array
		var templates []*entities.DeviceTemplate
		if err := json.Unmarshal(output, &templates); err != nil {
			return nil, &CLIAdapterError{
				Operation: "ListTemplates",
				Message:   "failed to parse response",
				Output:    string(output),
			}
		}
		result.Templates = templates
		result.Total = len(templates)
	}

	return &result, nil
}

// ============================================================================
// Template Operations
// ============================================================================

// CreateProfileFromTemplate creates a profile from a template
func (a *CLIAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	args := []string{"device", "template", "create-profile",
		"--tenant-id", opts.TenantID,
		"--template-id", opts.TemplateID,
		"--output", "json",
	}

	if opts.Name != "" {
		args = append(args, "--name", opts.Name)
	}
	if opts.EKSerial != "" {
		args = append(args, "--ek-serial", opts.EKSerial)
	}
	if opts.MACAddress != "" {
		args = append(args, "--mac-address", opts.MACAddress)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "CreateProfileFromTemplate",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &CreateProfileResult{Profile: &profile}, nil
}

// FindConfigForDevice finds the config for a device by EK serial or MAC
func (a *CLIAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	args := []string{"device", "profile", "find-config",
		"--tenant-id", opts.TenantID,
		"--output", "json",
	}

	if opts.EKSerial != "" {
		args = append(args, "--ek-serial", opts.EKSerial)
	}
	if opts.MACAddress != "" {
		args = append(args, "--mac-address", opts.MACAddress)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "FindConfigForDevice",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &FindConfigForDeviceResult{Profile: &profile}, nil
}

// AssignProfileToDevice assigns a profile to a device identity
func (a *CLIAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	args := []string{"device", "profile", "assign",
		"--tenant-id", opts.TenantID,
		"--profile-id", opts.ProfileID,
		"--output", "json",
	}

	if opts.EKSerial != "" {
		args = append(args, "--ek-serial", opts.EKSerial)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(output, &profile); err != nil {
		return nil, &CLIAdapterError{
			Operation: "AssignProfileToDevice",
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}

	return &AssignProfileToDeviceResult{Profile: &profile}, nil
}

// Verify CLIAdapter implements DeviceCommands
var _ DeviceCommands = (*CLIAdapter)(nil)
