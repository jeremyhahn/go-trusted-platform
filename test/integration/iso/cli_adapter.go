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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
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
	// platformctl leads its own process group, so cancelling kills the
	// QEMU it started as well: QEMU would otherwise outlive it and hold the
	// output pipe open, and CombinedOutput would never return.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// The software TPM runs in a group of its own and, with --debug,
	// writes to this pipe too: stop waiting for the pipe this long after
	// the kill.
	cmd.WaitDelay = commandWaitDelay
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

// vmCommandTimeout passes --timeout when the caller bounds the VM run and
// returns how long to wait for platformctl: the VM bound plus the time it
// takes to stop QEMU and the software TPM, or fallback when the run is
// unbounded.
func vmCommandTimeout(args []string, timeout, fallback time.Duration) ([]string, time.Duration) {
	if timeout <= 0 {
		return args, fallback
	}
	return append(args, "--timeout", timeout.String()), timeout + vmStopGrace
}

// runVerb runs an iso verb and decodes its result from stdout. stderr carries
// the pkg/iso progress log, so it is kept out of the result and reported only
// when the verb fails. A verb that prints its result before failing (profile
// validate on an invalid config) still has it decoded into result.
func (c *CLIAdapter) runVerb(ctx context.Context, timeout time.Duration, method string, decode func([]byte, any) error, result any, args ...string) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, c.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	if stdout.Len() > 0 {
		if err := decode(stdout.Bytes(), result); err != nil {
			return ErrCallFailed{Protocol: "CLI", Method: method, Err: err}
		}
	}
	if runErr != nil {
		return ErrCallFailed{Protocol: "CLI", Method: method, Err: ErrVerbFailed{Stderr: stderr.String(), Err: runErr}}
	}
	if stdout.Len() == 0 {
		return ErrCallFailed{Protocol: "CLI", Method: method, Err: ErrVerbFailed{Stderr: "verb printed no result: " + stderr.String()}}
	}
	return nil
}

// =============================================================================
// Create Operations
// =============================================================================

// Create performs all-in-one ISO creation via CLI.
func (c *CLIAdapter) Create(ctx context.Context, opts CreateOptions) (*CreateResult, error) {
	startTime := time.Now()
	args := []string{"iso", "create"}

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

	// ISO creation can take a long time. Its local --output shadows the
	// global format flag, so the result object prints as YAML
	// (docs/installer/cli.md §4).
	var resp struct {
		Success   bool   `yaml:"success"`
		OutputISO string `yaml:"output_iso"`
		SHA256    string `yaml:"sha256"`
		SizeBytes int64  `yaml:"size_bytes"`
		Message   string `yaml:"message"`
	}
	if err := c.runVerb(ctx, 30*time.Minute, "iso create", yaml.Unmarshal, &resp, args...); err != nil {
		return nil, err
	}

	return &CreateResult{
		Success:     resp.Success,
		OutputISO:   resp.OutputISO,
		SHA256:      resp.SHA256,
		SizeBytes:   resp.SizeBytes,
		Message:     resp.Message,
		ElapsedTime: time.Since(startTime),
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
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	result := &DownloadResult{}
	if err := c.runVerb(ctx, 15*time.Minute, "iso download", json.Unmarshal, result, args...); err != nil {
		return nil, err
	}
	return result, nil
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
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	result := &ExtractResult{}
	if err := c.runVerb(ctx, 10*time.Minute, "iso extract", json.Unmarshal, result, args...); err != nil {
		return nil, err
	}
	return result, nil
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
	if opts.PlatformConfig != "" {
		args = append(args, "--platform-config", opts.PlatformConfig)
	}
	if opts.ConfigFile != "" {
		args = append(args, "--config", opts.ConfigFile)
	}
	if opts.WorkDir != "" {
		args = append(args, "--work-dir", opts.WorkDir)
	}
	if opts.Debug {
		args = append(args, "--debug")
	}

	result := &CustomizeResult{}
	if err := c.runVerb(ctx, 10*time.Minute, "iso customize", json.Unmarshal, result, args...); err != nil {
		return nil, err
	}
	return result, nil
}

// =============================================================================
// Build Operations
// =============================================================================

// Build builds final ISO via CLI. The verb's --output names the ISO and
// shadows the global -o, so it prints its result as YAML.
func (c *CLIAdapter) Build(ctx context.Context, opts BuildOptions) (*BuildResult, error) {
	args := []string{"iso", "build"}

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
	if opts.Debug {
		args = append(args, "--debug")
	}

	result := &BuildResult{}
	if err := c.runVerb(ctx, 15*time.Minute, "iso build", yaml.Unmarshal, result, args...); err != nil {
		return nil, err
	}
	return result, nil
}

// =============================================================================
// Profile Operations
// =============================================================================

// ProfileList lists available installation profiles via CLI.
func (c *CLIAdapter) ProfileList(ctx context.Context) (*ProfileListResult, error) {
	result := &ProfileListResult{}
	if err := c.runVerb(ctx, time.Minute, "iso profile list", json.Unmarshal, result,
		"iso", "profile", "list", "-o", "json"); err != nil {
		return nil, err
	}
	return result, nil
}

// ProfileShow shows a specific profile via CLI.
func (c *CLIAdapter) ProfileShow(ctx context.Context, name string) (*ProfileShowResult, error) {
	result := &ProfileShowResult{}
	if err := c.runVerb(ctx, time.Minute, "iso profile show", json.Unmarshal, result,
		"iso", "profile", "show", name, "-o", "json"); err != nil {
		return nil, err
	}
	return result, nil
}

// ProfileValidate validates a configuration file via CLI. An invalid config
// exits non-zero after printing valid=false and its errors; that result is
// returned together with the error.
func (c *CLIAdapter) ProfileValidate(ctx context.Context, path string) (*ProfileValidateResult, error) {
	result := &ProfileValidateResult{}
	if err := c.runVerb(ctx, time.Minute, "iso profile validate", json.Unmarshal, result,
		"iso", "profile", "validate", path, "-o", "json"); err != nil {
		return result, err
	}
	return result, nil
}

// ProfileGenerate generates a configuration file via CLI. The verb's --output
// names the config file and shadows the global -o, so it prints YAML.
func (c *CLIAdapter) ProfileGenerate(ctx context.Context, opts ProfileGenerateOptions) (*ProfileGenerateResult, error) {
	args := []string{"iso", "profile", "generate"}

	if opts.ProfileName != "" {
		args = append(args, "--profile", opts.ProfileName)
	}
	if opts.OutputFile != "" {
		args = append(args, "--output", opts.OutputFile)
	}
	if opts.OverrideDevice != "" {
		args = append(args, "--device", opts.OverrideDevice)
	}

	result := &ProfileGenerateResult{}
	if err := c.runVerb(ctx, time.Minute, "iso profile generate", yaml.Unmarshal, result, args...); err != nil {
		return nil, err
	}
	return result, nil
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

	args, wait := vmCommandTimeout(args, opts.Timeout, 60*time.Minute)
	output, err := c.runCommandWithTimeout(ctx, wait, args...)
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

	args, wait := vmCommandTimeout(args, opts.Timeout, 30*time.Minute)
	output, err := c.runCommandWithTimeout(ctx, wait, args...)
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
