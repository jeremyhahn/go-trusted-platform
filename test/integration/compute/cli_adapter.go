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

package compute_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrCLINotFound indicates the platformctl binary was not found.
type ErrCLINotFound struct {
	Path string
}

func (e ErrCLINotFound) Error() string {
	return fmt.Sprintf("compute: CLI binary not found at %s", e.Path)
}

// ErrCLIExecution indicates a CLI command execution failure.
type ErrCLIExecution struct {
	Operation string
	Message   string
	Output    string
}

func (e ErrCLIExecution) Error() string {
	return fmt.Sprintf("compute: CLI execution error [%s]: %s (output: %s)",
		e.Operation, e.Message, e.Output)
}

// ErrCLIParse indicates a failure to parse CLI JSON output.
type ErrCLIParse struct {
	Operation string
	Message   string
}

func (e ErrCLIParse) Error() string {
	return fmt.Sprintf("compute: CLI parse error [%s]: %s", e.Operation, e.Message)
}

// =============================================================================
// CLI Adapter
// =============================================================================

// CLIAdapter implements ComputeCommands using the platformctl CLI. Every
// command prints JSON whose shape is the Go SDK compute type it renders
// (computesvc.VM, computesvc.VMStatus, computesvc.ListVMsResult), so the
// adapter decodes into those types and shares the gRPC adapter's converters.
type CLIAdapter struct {
	cliPath    string
	configDir  string
	configPath string
}

// NewCLIAdapter creates a new CLI adapter.
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup verifies the CLI binary is available and writes the config file that
// points it at the harness daemon.
func (a *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(a.cliPath); err != nil {
		return ErrCLINotFound{Path: a.cliPath}
	}

	dir, path, err := helpers.WriteTempLocalCLIConfig(GetSocketPath(), GetGRPCEndpoint())
	if err != nil {
		return err
	}
	a.configDir, a.configPath = dir, path
	return nil
}

// Teardown removes the config file Setup wrote.
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	if a.configDir == "" {
		return nil
	}
	return os.RemoveAll(a.configDir)
}

// Name returns the adapter name.
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command with JSON output and returns its stdout.
// platformctl has no --socket flag; the harness socket reaches it through the
// config file Setup wrote (#540).
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	fullArgs := []string{"--output", "json"}
	if a.configPath != "" {
		fullArgs = append(fullArgs, "--config", a.configPath)
	}
	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, a.cliPath, fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, ErrCLIExecution{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    stdout.String() + stderr.String(),
		}
	}
	return stdout.Bytes(), nil
}

// runJSON executes a CLI command and decodes its JSON output into out.
func (a *CLIAdapter) runJSON(ctx context.Context, operation string, out any, args ...string) error {
	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(output, out); err != nil {
		return ErrCLIParse{Operation: operation, Message: err.Error()}
	}
	return nil
}

// runVerb executes a VM lifecycle verb and returns the status it prints.
func (a *CLIAdapter) runVerb(ctx context.Context, operation string, args ...string) (*computesvc.VMStatus, error) {
	status := &computesvc.VMStatus{}
	if err := a.runJSON(ctx, operation, status, args...); err != nil {
		return nil, err
	}
	return status, nil
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via the CLI.
func (a *CLIAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	args := []string{
		"compute", "create",
		"--name", opts.Name,
		"--cpus", fmt.Sprint(opts.CPUs),
		"--memory", fmt.Sprint(opts.MemoryMB),
		"--disk-size", fmt.Sprint(opts.DiskSizeGB),
	}

	if opts.Firmware != "" {
		args = append(args, "--firmware", opts.Firmware)
	}
	if opts.SecureBoot {
		args = append(args, "--secure-boot")
	}
	if opts.TPM {
		args = append(args, "--tpm")
	}
	if opts.Start {
		args = append(args, "--start")
	}
	for k, v := range opts.Labels {
		args = append(args, "--label", k+"="+v)
	}

	vm := &computesvc.VM{}
	if err := a.runJSON(ctx, "CreateVM", vm, args...); err != nil {
		return nil, err
	}
	return createVMResultFromDomain(vm), nil
}

// StartVM starts a virtual machine via the CLI.
func (a *CLIAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.runVerb(ctx, "StartVM", "compute", "start", opts.VMID)
	if err != nil {
		return nil, err
	}
	return &StartVMResult{Success: status.Success, Message: status.Message}, nil
}

// StopVM stops a virtual machine via the CLI.
func (a *CLIAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	args := []string{"compute", "stop", opts.VMID}
	if opts.Force {
		args = append(args, "--force")
	}
	if opts.TimeoutSeconds > 0 {
		args = append(args, "--timeout", fmt.Sprint(opts.TimeoutSeconds))
	}

	status, err := a.runVerb(ctx, "StopVM", args...)
	if err != nil {
		return nil, err
	}
	return &StopVMResult{Success: status.Success, Message: status.Message}, nil
}

// RebootVM restarts a running virtual machine via the CLI.
func (a *CLIAdapter) RebootVM(ctx context.Context, opts RebootVMOptions) (*RebootVMResult, error) {
	args := []string{"compute", "reboot", opts.VMID}
	if opts.Force {
		args = append(args, "--force")
	}

	status, err := a.runVerb(ctx, "RebootVM", args...)
	if err != nil {
		return nil, err
	}
	return &RebootVMResult{Success: status.Success, Message: status.Message}, nil
}

// SuspendVM pauses a running virtual machine via the CLI.
func (a *CLIAdapter) SuspendVM(ctx context.Context, opts SuspendVMOptions) (*SuspendVMResult, error) {
	status, err := a.runVerb(ctx, "SuspendVM", "compute", "suspend", opts.VMID)
	if err != nil {
		return nil, err
	}
	return &SuspendVMResult{Success: status.Success, Message: status.Message}, nil
}

// ResumeVM continues a suspended virtual machine via the CLI.
func (a *CLIAdapter) ResumeVM(ctx context.Context, opts ResumeVMOptions) (*ResumeVMResult, error) {
	status, err := a.runVerb(ctx, "ResumeVM", "compute", "resume", opts.VMID)
	if err != nil {
		return nil, err
	}
	return &ResumeVMResult{Success: status.Success, Message: status.Message}, nil
}

// DeleteVM deletes a virtual machine via the CLI.
func (a *CLIAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	args := []string{"compute", "delete", opts.VMID}
	if opts.DeleteDisks {
		args = append(args, "--delete-disks")
	}

	status, err := a.runVerb(ctx, "DeleteVM", args...)
	if err != nil {
		return nil, err
	}
	return &DeleteVMResult{Success: status.Success, Message: status.Message}, nil
}

// GetVM retrieves a virtual machine via the CLI.
func (a *CLIAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	vm := &computesvc.VM{}
	if err := a.runJSON(ctx, "GetVM", vm, "compute", "get", opts.VMID); err != nil {
		return nil, err
	}
	return getVMResultFromDomain(vm), nil
}

// ListVMs lists virtual machines via the CLI. It passes --all because the
// CLI otherwise lists only running VMs, which no other transport does.
func (a *CLIAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	args := []string{"compute", "list", "--all"}

	if opts.StateFilter != "" {
		args = append(args, "--filter", "state="+opts.StateFilter)
	}
	if opts.PageSize > 0 {
		args = append(args, "--limit", fmt.Sprint(opts.PageSize))
	}
	for k, v := range opts.Labels {
		args = append(args, "--filter", "label="+k+"="+v)
	}

	result := &computesvc.ListVMsResult{}
	if err := a.runJSON(ctx, "ListVMs", result, args...); err != nil {
		return nil, err
	}
	return listVMsResultFromDomain(result), nil
}
