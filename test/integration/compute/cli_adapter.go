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
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
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
// CLI Response Types
// =============================================================================

// cliVMResponse represents the JSON output from CLI VM commands.
type cliVMResponse struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	State   string            `json:"state"`
	CPUs    uint32            `json:"cpus"`
	Memory  uint64            `json:"memory_mb"`
	Labels  map[string]string `json:"labels"`
	Status  *cliStatus        `json:"status,omitempty"`
	Success bool              `json:"success"`
	Message string            `json:"message"`
}

// cliStatus represents a status message from CLI output.
type cliStatus struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// cliListResponse represents the JSON output from CLI list commands.
type cliListResponse struct {
	VMs        []cliVMResponse `json:"vms"`
	TotalItems uint64          `json:"total_items"`
}

// =============================================================================
// CLI Adapter
// =============================================================================

// CLIAdapter implements ComputeCommands using the platformctl CLI.
type CLIAdapter struct {
	cliPath string
}

// NewCLIAdapter creates a new CLI adapter.
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup verifies the CLI binary is available.
func (a *CLIAdapter) Setup(ctx context.Context) error {
	_, err := exec.LookPath(a.cliPath)
	if err != nil {
		return ErrCLINotFound{Path: a.cliPath}
	}
	return nil
}

// Teardown cleans up after testing.
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name.
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a CLI command and returns the combined output.
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, a.cliPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, ErrCLIExecution{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    string(output),
		}
	}
	return output, nil
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
		"--output", "json",
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

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliVMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIParse{
			Operation: "CreateVM",
			Message:   err.Error(),
		}
	}

	return &CreateVMResult{
		VMID:    resp.ID,
		Name:    resp.Name,
		State:   resp.State,
		Success: resp.Success,
		Labels:  resp.Labels,
	}, nil
}

// StartVM starts a virtual machine via the CLI.
func (a *CLIAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	args := []string{"compute", "start", "--id", opts.VMID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliVMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIParse{
			Operation: "StartVM",
			Message:   err.Error(),
		}
	}

	return &StartVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// StopVM stops a virtual machine via the CLI.
func (a *CLIAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	args := []string{"compute", "stop", "--id", opts.VMID, "--output", "json"}

	if opts.Force {
		args = append(args, "--force")
	}
	if opts.TimeoutSeconds > 0 {
		args = append(args, "--timeout", fmt.Sprint(opts.TimeoutSeconds))
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliVMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIParse{
			Operation: "StopVM",
			Message:   err.Error(),
		}
	}

	return &StopVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// DeleteVM deletes a virtual machine via the CLI.
func (a *CLIAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	args := []string{"compute", "delete", "--id", opts.VMID, "--output", "json"}

	if opts.DeleteDisks {
		args = append(args, "--delete-disks")
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliVMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIParse{
			Operation: "DeleteVM",
			Message:   err.Error(),
		}
	}

	return &DeleteVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// GetVM retrieves a virtual machine via the CLI.
func (a *CLIAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	args := []string{"compute", "get", "--id", opts.VMID, "--output", "json"}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliVMResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIParse{
			Operation: "GetVM",
			Message:   err.Error(),
		}
	}

	return &GetVMResult{
		VMID:     resp.ID,
		Name:     resp.Name,
		State:    resp.State,
		CPUs:     resp.CPUs,
		MemoryMB: resp.Memory,
		Labels:   resp.Labels,
	}, nil
}

// ListVMs lists virtual machines via the CLI.
func (a *CLIAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	args := []string{"compute", "list", "--output", "json"}

	if opts.StateFilter != "" {
		args = append(args, "--state", opts.StateFilter)
	}
	if opts.PageSize > 0 {
		args = append(args, "--page-size", fmt.Sprint(opts.PageSize))
	}
	for k, v := range opts.Labels {
		args = append(args, "--label", k+"="+v)
	}

	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var resp cliListResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, ErrCLIParse{
			Operation: "ListVMs",
			Message:   err.Error(),
		}
	}

	vms := make([]VMSummary, len(resp.VMs))
	for i, vm := range resp.VMs {
		vms[i] = VMSummary{
			VMID:   vm.ID,
			Name:   vm.Name,
			State:  vm.State,
			Labels: vm.Labels,
		}
	}

	return &ListVMsResult{
		VMs:        vms,
		TotalItems: resp.TotalItems,
	}, nil
}
