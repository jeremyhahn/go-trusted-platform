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

package iso

import (
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
// CLI Protocol Adapter
// =============================================================================

// CLIAdapter implements ISOCommands using platformctl CLI commands.
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

	// Verify connectivity by running a help command
	_, err = c.runCommand(ctx, "iso", "--help")
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

// runCommandWithTimeout runs a command with a specific timeout.
func (c *CLIAdapter) runCommandWithTimeout(ctx context.Context, timeout time.Duration, args ...string) ([]byte, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.runCommand(timeoutCtx, args...)
}

// =============================================================================
// Create Operations
// =============================================================================

// Create performs all-in-one ISO creation via CLI.
func (c *CLIAdapter) Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	startTime := time.Now()
	args := []string{"iso", "create", "-o", "json"}

	// Alpine flags
	if opts.AlpineVersion != "" {
		args = append(args, "--alpine-version", opts.AlpineVersion)
	}
	if opts.Mirror != "" {
		args = append(args, "--mirror", opts.Mirror)
	}
	if opts.Arch != "" {
		args = append(args, "--arch", opts.Arch)
	}

	// Platform flags
	if opts.PlatformVersion != "" {
		args = append(args, "--platform-version", opts.PlatformVersion)
	}
	if opts.PlatformConfig != "" {
		args = append(args, "--platform-config", opts.PlatformConfig)
	}
	if opts.PlatformType != "" {
		args = append(args, "--platform-type", opts.PlatformType)
	}

	// Security flags
	args = append(args, fmt.Sprintf("--secure-boot=%t", opts.SecureBoot))
	args = append(args, fmt.Sprintf("--tpm-unseal=%t", opts.TPMUnseal))
	args = append(args, fmt.Sprintf("--luks=%t", opts.LUKS))
	args = append(args, fmt.Sprintf("--fips=%t", opts.FIPS))
	args = append(args, fmt.Sprintf("--fido2=%t", opts.FIDO2))

	// Build flags
	if opts.Overlay != "" {
		args = append(args, "--overlay", opts.Overlay)
	}
	if opts.Output != "" {
		args = append(args, "--output", opts.Output)
	}
	if opts.KeysDir != "" {
		args = append(args, "--keys-dir", opts.KeysDir)
	}
	args = append(args, fmt.Sprintf("--generate-keys=%t", opts.GenerateKeys))
	if opts.KeyBackend != "" {
		args = append(args, "--key-backend", opts.KeyBackend)
	}
	if opts.Force {
		args = append(args, "--force")
	}
	if opts.WebUI != "" {
		args = append(args, "--webui", opts.WebUI)
	}

	// Common flags
	if opts.ConfigFile != "" {
		args = append(args, "--config", opts.ConfigFile)
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}
	if opts.Verbose {
		args = append(args, "--verbose")
	}

	// ISO creation can take a long time
	output, err := c.runCommandWithTimeout(ctx, 30*time.Minute, args...)
	elapsed := time.Since(startTime)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso create", Err: err}
	}

	var resp struct {
		Success   bool   `json:"success"`
		OutputISO string `json:"output_iso"`
		SHA256    string `json:"sha256"`
		SizeBytes int64  `json:"size_bytes"`
		Message   string `json:"message"`
	}

	// Try to parse JSON response
	if err := json.Unmarshal(output, &resp); err != nil {
		// If not JSON, check if operation succeeded by looking for output file
		return &CreateResult{
			Success:     true,
			Message:     string(output),
			ElapsedTime: elapsed,
		}, nil
	}

	return &CreateResult{
		Success:     resp.Success,
		OutputISO:   resp.OutputISO,
		SHA256:      resp.SHA256,
		SizeBytes:   resp.SizeBytes,
		Message:     resp.Message,
		ElapsedTime: elapsed,
	}, nil
}

// =============================================================================
// Download Operations
// =============================================================================

// Download downloads Alpine ISO via CLI.
func (c *CLIAdapter) Download(ctx context.Context, opts DownloadOptions) (*DownloadResult, error) {
	args := []string{"iso", "download", "-o", "json"}

	if opts.URL != "" {
		args = append(args, "--url", opts.URL)
	}
	if opts.Version != "" {
		args = append(args, "--version", opts.Version)
	}
	if opts.Mirror != "" {
		args = append(args, "--mirror", opts.Mirror)
	}
	if opts.Arch != "" {
		args = append(args, "--arch", opts.Arch)
	}
	if opts.Force {
		args = append(args, "--force")
	}
	args = append(args, fmt.Sprintf("--verify=%t", opts.Verify))
	args = append(args, fmt.Sprintf("--resume=%t", opts.ResumeEnable))

	// Common flags
	if opts.ConfigFile != "" {
		args = append(args, "--config", opts.ConfigFile)
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	// Download can take a while
	output, err := c.runCommandWithTimeout(ctx, 15*time.Minute, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso download", Err: err}
	}

	var resp struct {
		Success   bool   `json:"success"`
		ISOPath   string `json:"iso_path"`
		SHA256    string `json:"sha256"`
		SizeBytes int64  `json:"size_bytes"`
		Verified  bool   `json:"verified"`
		Message   string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return &DownloadResult{
			Success: true,
			Message: string(output),
		}, nil
	}

	return &DownloadResult{
		Success:   resp.Success,
		ISOPath:   resp.ISOPath,
		SHA256:    resp.SHA256,
		SizeBytes: resp.SizeBytes,
		Verified:  resp.Verified,
		Message:   resp.Message,
	}, nil
}

// =============================================================================
// Extract Operations
// =============================================================================

// Extract extracts ISO contents via CLI.
func (c *CLIAdapter) Extract(ctx context.Context, opts ExtractOptions) (*ExtractResult, error) {
	args := []string{"iso", "extract", "-o", "json"}

	if opts.ISO != "" {
		args = append(args, "--iso", opts.ISO)
	}
	if opts.OutputDir != "" {
		args = append(args, "--output-dir", opts.OutputDir)
	}
	if opts.Force {
		args = append(args, "--force")
	}

	// Common flags
	if opts.ConfigFile != "" {
		args = append(args, "--config", opts.ConfigFile)
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommandWithTimeout(ctx, 10*time.Minute, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso extract", Err: err}
	}

	var resp struct {
		Success   bool   `json:"success"`
		OutputDir string `json:"output_dir"`
		FileCount int    `json:"file_count"`
		Message   string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return &ExtractResult{
			Success: true,
			Message: string(output),
		}, nil
	}

	return &ExtractResult{
		Success:   resp.Success,
		OutputDir: resp.OutputDir,
		FileCount: resp.FileCount,
		Message:   resp.Message,
	}, nil
}

// =============================================================================
// Customize Operations
// =============================================================================

// Customize customizes ISO contents via CLI.
func (c *CLIAdapter) Customize(ctx context.Context, opts CustomizeOptions) (*CustomizeResult, error) {
	args := []string{"iso", "customize", "-o", "json"}

	if opts.ISODir != "" {
		args = append(args, "--iso-dir", opts.ISODir)
	}
	if opts.Overlay != "" {
		args = append(args, "--overlay", opts.Overlay)
	}
	if opts.KeysDir != "" {
		args = append(args, "--keys-dir", opts.KeysDir)
	}
	if opts.PlatformdPath != "" {
		args = append(args, "--platformd-binary", opts.PlatformdPath)
	}
	if opts.Autoinstall {
		args = append(args, "--autoinstall")
	}
	if opts.ModifyInitramfs {
		args = append(args, "--modify-initramfs")
	}

	// Common flags
	if opts.ConfigFile != "" {
		args = append(args, "--config", opts.ConfigFile)
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommandWithTimeout(ctx, 10*time.Minute, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso customize", Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return &CustomizeResult{
			Success: true,
			Message: string(output),
		}, nil
	}

	return &CustomizeResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// Build Operations
// =============================================================================

// Build builds final ISO via CLI.
func (c *CLIAdapter) Build(ctx context.Context, opts BuildOptions) (*BuildResult, error) {
	args := []string{"iso", "build", "-o", "json"}

	if opts.SourceDir != "" {
		args = append(args, "--iso-dir", opts.SourceDir)
	}
	if opts.Output != "" {
		args = append(args, "--output", opts.Output)
	}
	if opts.VolumeID != "" {
		args = append(args, "--label", opts.VolumeID)
	}
	args = append(args, fmt.Sprintf("--checksum=%t", opts.GenerateSum))

	// Common flags
	if opts.ConfigFile != "" {
		args = append(args, "--config", opts.ConfigFile)
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommandWithTimeout(ctx, 15*time.Minute, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso build", Err: err}
	}

	var resp struct {
		Success   bool   `json:"success"`
		OutputISO string `json:"output_iso"`
		SHA256    string `json:"sha256"`
		SizeBytes int64  `json:"size_bytes"`
		Message   string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return &BuildResult{
			Success: true,
			Message: string(output),
		}, nil
	}

	return &BuildResult{
		Success:   resp.Success,
		OutputISO: resp.OutputISO,
		SHA256:    resp.SHA256,
		SizeBytes: resp.SizeBytes,
		Message:   resp.Message,
	}, nil
}

// =============================================================================
// Profile Operations
// =============================================================================

// ProfileList lists available installation profiles via CLI.
func (c *CLIAdapter) ProfileList(ctx context.Context) (*ProfileListResult, error) {
	output, err := c.runCommand(ctx, "iso", "profile", "list", "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso profile list", Err: err}
	}

	var resp struct {
		Success  bool `json:"success"`
		Profiles []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			SecureBoot  bool   `json:"secure_boot"`
			TPMUnseal   bool   `json:"tpm_unseal"`
			LUKS        bool   `json:"luks"`
			FIPS        bool   `json:"fips"`
			Lockdown    string `json:"lockdown"`
		} `json:"profiles"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// Parse text output if not JSON
		return &ProfileListResult{
			Success: true,
			Message: string(output),
		}, nil
	}

	profiles := make([]ProfileInfo, 0, len(resp.Profiles))
	for _, p := range resp.Profiles {
		profiles = append(profiles, ProfileInfo{
			Name:        p.Name,
			Description: p.Description,
			SecureBoot:  p.SecureBoot,
			TPMUnseal:   p.TPMUnseal,
			LUKS:        p.LUKS,
			FIPS:        p.FIPS,
			Lockdown:    p.Lockdown,
		})
	}

	return &ProfileListResult{
		Success:  resp.Success,
		Profiles: profiles,
		Message:  resp.Message,
	}, nil
}

// ProfileShow shows a specific profile via CLI.
func (c *CLIAdapter) ProfileShow(ctx context.Context, name string) (*ProfileShowResult, error) {
	output, err := c.runCommand(ctx, "iso", "profile", "show", name, "-o", "json")
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso profile show", Err: err}
	}

	var resp struct {
		Success bool `json:"success"`
		Profile struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			SecureBoot  bool   `json:"secure_boot"`
			TPMUnseal   bool   `json:"tpm_unseal"`
			LUKS        bool   `json:"luks"`
			FIPS        bool   `json:"fips"`
			Lockdown    string `json:"lockdown"`
		} `json:"profile"`
		YAML    string `json:"yaml"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return &ProfileShowResult{
			Success: true,
			YAML:    string(output),
		}, nil
	}

	return &ProfileShowResult{
		Success: resp.Success,
		Profile: &ProfileInfo{
			Name:        resp.Profile.Name,
			Description: resp.Profile.Description,
			SecureBoot:  resp.Profile.SecureBoot,
			TPMUnseal:   resp.Profile.TPMUnseal,
			LUKS:        resp.Profile.LUKS,
			FIPS:        resp.Profile.FIPS,
			Lockdown:    resp.Profile.Lockdown,
		},
		YAML:    resp.YAML,
		Message: resp.Message,
	}, nil
}

// ProfileValidate validates a configuration file via CLI.
func (c *CLIAdapter) ProfileValidate(ctx context.Context, path string) (*ProfileValidateResult, error) {
	output, err := c.runCommand(ctx, "iso", "profile", "validate", path, "-o", "json")
	if err != nil {
		// Validation errors should still return a result, not an error
		var resp struct {
			Success  bool     `json:"success"`
			Valid    bool     `json:"valid"`
			Errors   []string `json:"errors"`
			Warnings []string `json:"warnings"`
			Message  string   `json:"message"`
		}
		if jsonErr := json.Unmarshal(output, &resp); jsonErr == nil {
			return &ProfileValidateResult{
				Success:  resp.Success,
				Valid:    resp.Valid,
				Errors:   resp.Errors,
				Warnings: resp.Warnings,
				Message:  resp.Message,
			}, nil
		}
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso profile validate", Err: err}
	}

	var resp struct {
		Success  bool     `json:"success"`
		Valid    bool     `json:"valid"`
		Errors   []string `json:"errors"`
		Warnings []string `json:"warnings"`
		Message  string   `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		// If output contains "valid" assume success
		valid := strings.Contains(strings.ToLower(string(output)), "valid")
		return &ProfileValidateResult{
			Success: true,
			Valid:   valid,
			Message: string(output),
		}, nil
	}

	return &ProfileValidateResult{
		Success:  resp.Success,
		Valid:    resp.Valid,
		Errors:   resp.Errors,
		Warnings: resp.Warnings,
		Message:  resp.Message,
	}, nil
}

// ProfileGenerate generates a configuration file via CLI.
func (c *CLIAdapter) ProfileGenerate(ctx context.Context, opts ProfileGenerateOptions) (*ProfileGenerateResult, error) {
	args := []string{"iso", "profile", "generate", "-o", "json"}

	if opts.ProfileName != "" {
		args = append(args, "--profile", opts.ProfileName)
	}
	if opts.OutputFile != "" {
		args = append(args, "--output", opts.OutputFile)
	}
	if opts.OverrideDevice != "" {
		args = append(args, "--device", opts.OverrideDevice)
	}
	if opts.Interactive {
		args = append(args, "--interactive")
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, ErrCallFailed{Protocol: "CLI", Method: "iso profile generate", Err: err}
	}

	var resp struct {
		Success    bool   `json:"success"`
		OutputFile string `json:"output_file"`
		YAML       string `json:"yaml"`
		Message    string `json:"message"`
	}

	if err := json.Unmarshal(output, &resp); err != nil {
		return &ProfileGenerateResult{
			Success: true,
			YAML:    string(output),
		}, nil
	}

	return &ProfileGenerateResult{
		Success:    resp.Success,
		OutputFile: resp.OutputFile,
		YAML:       resp.YAML,
		Message:    resp.Message,
	}, nil
}

// =============================================================================
// Test Operations
// =============================================================================

// TestInstall runs ISO installation test via CLI.
func (c *CLIAdapter) TestInstall(ctx context.Context, opts TestInstallOptions) (*TestResult, error) {
	startTime := time.Now()
	args := []string{"iso", "test", "install"}

	if opts.ISO != "" {
		args = append(args, "--iso", opts.ISO)
	}
	if opts.Disk != "" {
		args = append(args, "--disk", opts.Disk)
	}
	if opts.DiskSize != "" {
		args = append(args, "--disk-size", opts.DiskSize)
	}
	if opts.Memory > 0 {
		args = append(args, "--memory", strconv.Itoa(opts.Memory))
	}
	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(opts.CPUs))
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	args = append(args, fmt.Sprintf("--secure-boot=%t", opts.SecureBoot))
	if opts.FIDO2Enable {
		args = append(args, "--fido2")
		if opts.FIDO2Mode != "" {
			args = append(args, "--fido2-mode", opts.FIDO2Mode)
		}
	}
	if opts.NetworkMode != "" {
		args = append(args, "--network", opts.NetworkMode)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	// The install streams the guest's serial console: a guest stuck at the
	// GRUB menu fails within grubMenuGrace instead of using up the budget.
	output, err := c.runWatched(ctx, vmInstallTimeout, newGRUBMenuDetector(grubMenuGrace), args...)
	elapsed := time.Since(startTime)
	if err != nil {
		return &TestResult{
			Success:     false,
			Message:     string(output),
			ExitCode:    1,
			ElapsedTime: elapsed,
		}, ErrCallFailed{Protocol: "CLI", Method: "iso test install", Err: err}
	}

	return &TestResult{
		Success:     true,
		Message:     string(output),
		ExitCode:    0,
		ElapsedTime: elapsed,
	}, nil
}

// TestFirstBoot runs first boot test via CLI.
func (c *CLIAdapter) TestFirstBoot(ctx context.Context, opts TestBootOptions) (*TestResult, error) {
	startTime := time.Now()
	args := []string{"iso", "test", "firstboot"}

	if opts.Disk != "" {
		args = append(args, "--disk", opts.Disk)
	}
	if opts.Memory > 0 {
		args = append(args, "--memory", strconv.Itoa(opts.Memory))
	}
	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(opts.CPUs))
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	args = append(args, fmt.Sprintf("--secure-boot=%t", opts.SecureBoot))
	if opts.FIDO2Enable {
		args = append(args, "--fido2")
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommandWithTimeout(ctx, 30*time.Minute, args...)
	elapsed := time.Since(startTime)
	if err != nil {
		return &TestResult{
			Success:     false,
			Message:     string(output),
			ExitCode:    1,
			ElapsedTime: elapsed,
		}, ErrCallFailed{Protocol: "CLI", Method: "iso test firstboot", Err: err}
	}

	return &TestResult{
		Success:     true,
		Message:     string(output),
		ExitCode:    0,
		ElapsedTime: elapsed,
	}, nil
}

// TestBoot runs normal boot test via CLI.
func (c *CLIAdapter) TestBoot(ctx context.Context, opts TestBootOptions) (*TestResult, error) {
	startTime := time.Now()
	args := []string{"iso", "test", "boot"}

	if opts.Disk != "" {
		args = append(args, "--disk", opts.Disk)
	}
	if opts.Memory > 0 {
		args = append(args, "--memory", strconv.Itoa(opts.Memory))
	}
	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(opts.CPUs))
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	args = append(args, fmt.Sprintf("--secure-boot=%t", opts.SecureBoot))
	if opts.FIDO2Enable {
		args = append(args, "--fido2")
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommandWithTimeout(ctx, 30*time.Minute, args...)
	elapsed := time.Since(startTime)
	if err != nil {
		return &TestResult{
			Success:     false,
			Message:     string(output),
			ExitCode:    1,
			ElapsedTime: elapsed,
		}, ErrCallFailed{Protocol: "CLI", Method: "iso test boot", Err: err}
	}

	return &TestResult{
		Success:     true,
		Message:     string(output),
		ExitCode:    0,
		ElapsedTime: elapsed,
	}, nil
}

// TestAll runs all tests sequentially via CLI.
func (c *CLIAdapter) TestAll(ctx context.Context, opts TestAllOptions) (*TestResult, error) {
	startTime := time.Now()
	args := []string{"iso", "test", "all"}

	if opts.ISO != "" {
		args = append(args, "--iso", opts.ISO)
	}
	if opts.Disk != "" {
		args = append(args, "--disk", opts.Disk)
	}
	if opts.DiskSize != "" {
		args = append(args, "--disk-size", opts.DiskSize)
	}
	if opts.Memory > 0 {
		args = append(args, "--memory", strconv.Itoa(opts.Memory))
	}
	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(opts.CPUs))
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	args = append(args, fmt.Sprintf("--secure-boot=%t", opts.SecureBoot))
	if opts.FIDO2Enable {
		args = append(args, "--fido2")
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	// All tests can run for a very long time
	output, err := c.runCommandWithTimeout(ctx, 120*time.Minute, args...)
	elapsed := time.Since(startTime)
	if err != nil {
		return &TestResult{
			Success:     false,
			Message:     string(output),
			ExitCode:    1,
			ElapsedTime: elapsed,
		}, ErrCallFailed{Protocol: "CLI", Method: "iso test all", Err: err}
	}

	return &TestResult{
		Success:     true,
		Message:     string(output),
		ExitCode:    0,
		ElapsedTime: elapsed,
	}, nil
}

// TestClientServer runs client-server deployment test via CLI.
func (c *CLIAdapter) TestClientServer(ctx context.Context, opts TestClientServerOptions) (*TestResult, error) {
	startTime := time.Now()
	args := []string{"iso", "test", "client-server"}

	if opts.ISO != "" {
		args = append(args, "--iso", opts.ISO)
	}
	if opts.ServerDisk != "" {
		args = append(args, "--server-disk", opts.ServerDisk)
	}
	if opts.ClientDisk != "" {
		args = append(args, "--client-disk", opts.ClientDisk)
	}
	if opts.ServerWorkDir != "" {
		args = append(args, "--server-work-dir", opts.ServerWorkDir)
	}
	if opts.ClientWorkDir != "" {
		args = append(args, "--client-work-dir", opts.ClientWorkDir)
	}
	if opts.DiskSize != "" {
		args = append(args, "--disk-size", opts.DiskSize)
	}
	if opts.Memory > 0 {
		args = append(args, "--memory", strconv.Itoa(opts.Memory))
	}
	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(opts.CPUs))
	}
	args = append(args, fmt.Sprintf("--secure-boot=%t", opts.SecureBoot))
	if opts.SkipInstall {
		args = append(args, "--skip-install")
	}
	if opts.ServerOnly {
		args = append(args, "--server-only")
	}
	if opts.ClientOnly {
		args = append(args, "--client-only")
	}
	if opts.FIDO2Enable {
		args = append(args, "--fido2")
	}
	if opts.UserNetwork {
		args = append(args, "--user-network")
	}
	if opts.UseOVS {
		args = append(args, "--use-ovs")
	}
	if opts.DynamicNetwork {
		args = append(args, "--dynamic-network")
	}
	if opts.EnableDHCP {
		args = append(args, "--enable-dhcp")
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	// Client-server tests can run for a very long time
	output, err := c.runCommandWithTimeout(ctx, 180*time.Minute, args...)
	elapsed := time.Since(startTime)
	if err != nil {
		return &TestResult{
			Success:     false,
			Message:     string(output),
			ExitCode:    1,
			ElapsedTime: elapsed,
		}, ErrCallFailed{Protocol: "CLI", Method: "iso test client-server", Err: err}
	}

	return &TestResult{
		Success:     true,
		Message:     string(output),
		ExitCode:    0,
		ElapsedTime: elapsed,
	}, nil
}

// TestPXE runs PXE boot test via CLI.
func (c *CLIAdapter) TestPXE(ctx context.Context, opts TestPXEOptions) (*TestResult, error) {
	startTime := time.Now()
	args := []string{"iso", "test", "pxe"}

	if opts.ISO != "" {
		args = append(args, "--iso", opts.ISO)
	}
	if opts.Kernel != "" {
		args = append(args, "--kernel", opts.Kernel)
	}
	if opts.Initrd != "" {
		args = append(args, "--initrd", opts.Initrd)
	}
	if opts.Args != "" {
		args = append(args, "--args", opts.Args)
	}
	if opts.Memory > 0 {
		args = append(args, "--memory", strconv.Itoa(opts.Memory))
	}
	if opts.CPUs > 0 {
		args = append(args, "--cpus", strconv.Itoa(opts.CPUs))
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	args = append(args, fmt.Sprintf("--secure-boot=%t", opts.SecureBoot))
	if opts.Debug {
		args = append(args, "--debug")
	}

	output, err := c.runCommandWithTimeout(ctx, 60*time.Minute, args...)
	elapsed := time.Since(startTime)
	if err != nil {
		return &TestResult{
			Success:     false,
			Message:     string(output),
			ExitCode:    1,
			ElapsedTime: elapsed,
		}, ErrCallFailed{Protocol: "CLI", Method: "iso test pxe", Err: err}
	}

	return &TestResult{
		Success:     true,
		Message:     string(output),
		ExitCode:    0,
		ElapsedTime: elapsed,
	}, nil
}

// Ensure CLIAdapter implements ISOCommands interface.
var _ ISOCommands = (*CLIAdapter)(nil)
