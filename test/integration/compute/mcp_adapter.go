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
	"fmt"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Registers the MCP transport that platform.Connect dials.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPConnectFailed indicates the SDK client could not connect over MCP.
type ErrMCPConnectFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPConnectFailed) Error() string {
	return fmt.Sprintf("compute: MCP connect to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrMCPConnectFailed) Unwrap() error {
	return e.Err
}

// ErrMCPCallFailed indicates an SDK call over MCP failed. The SDK MCP
// transport reports a tool's JSON-RPC error as the gRPC status of its class,
// so the wrapped error carries the same code as over gRPC.
type ErrMCPCallFailed struct {
	Method string
	Err    error
}

func (e ErrMCPCallFailed) Error() string {
	return fmt.Sprintf("compute: MCP call %s failed: %v", e.Method, e.Err)
}

func (e ErrMCPCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// MCP Adapter
// =============================================================================

// MCPAdapter implements ComputeCommands using the compute SDK client over
// MCP. Each VM call is its vm_* tool, which takes the full gRPC request
// (pkg/api/mcp/vm_lifecycle_tools.go), so every option reaches the daemon.
type MCPAdapter struct {
	endpoint string
	client   platform.Client
	compute  *computesvc.Client
}

// NewMCPAdapter creates a new MCP adapter.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		endpoint: GetMCPEndpoint(),
	}
}

// Setup connects the SDK client over MCP only.
func (a *MCPAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, platform.NewOptions(
		platform.WithOnlyProtocol(platform.ProtocolMCP),
		platform.WithMCPAddr(a.endpoint),
		platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
	))
	if err != nil {
		return ErrMCPConnectFailed{Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.compute = computesvc.NewClientFromGRPC(client.Compute())
	return nil
}

// Teardown closes the SDK client.
func (a *MCPAdapter) Teardown(ctx context.Context) error {
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

// Name returns the adapter name.
func (a *MCPAdapter) Name() string {
	return "MCP"
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine through the vm_create tool.
func (a *MCPAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	vm, err := a.compute.CreateVMDomain(ctx, createVMParamsFromOptions(opts))
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "CreateVM", Err: err}
	}
	return createVMResultFromDomain(vm), nil
}

// StartVM starts a virtual machine through the vm_start tool.
func (a *MCPAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.compute.StartVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "StartVM", Err: err}
	}

	result := &StartVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// StopVM stops a virtual machine through the vm_stop tool.
func (a *MCPAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	status, err := a.compute.StopVMDomain(ctx, &computesvc.StopVMParams{
		ID:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	})
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "StopVM", Err: err}
	}

	result := &StopVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// RebootVM restarts a running virtual machine through the vm_reboot tool.
func (a *MCPAdapter) RebootVM(ctx context.Context, opts RebootVMOptions) (*RebootVMResult, error) {
	status, err := a.compute.RebootVMDomain(ctx, opts.VMID, opts.Force)
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "RebootVM", Err: err}
	}

	result := &RebootVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// SuspendVM pauses a running virtual machine through the vm_suspend tool.
func (a *MCPAdapter) SuspendVM(ctx context.Context, opts SuspendVMOptions) (*SuspendVMResult, error) {
	status, err := a.compute.SuspendVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "SuspendVM", Err: err}
	}

	result := &SuspendVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// ResumeVM continues a suspended virtual machine through the vm_resume tool.
func (a *MCPAdapter) ResumeVM(ctx context.Context, opts ResumeVMOptions) (*ResumeVMResult, error) {
	status, err := a.compute.ResumeVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "ResumeVM", Err: err}
	}

	result := &ResumeVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// DeleteVM deletes a virtual machine through the vm_delete tool.
func (a *MCPAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	status, err := a.compute.DeleteVMDomain(ctx, &computesvc.DeleteVMParams{
		ID:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	})
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "DeleteVM", Err: err}
	}

	result := &DeleteVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// GetVM retrieves a virtual machine through the vm_get tool.
func (a *MCPAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	vm, err := a.compute.GetVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "GetVM", Err: err}
	}

	if vm == nil {
		return nil, ErrMCPCallFailed{
			Method: "GetVM",
			Err:    ErrVMNotFound(opts),
		}
	}

	return getVMResultFromDomain(vm), nil
}

// ListVMs lists virtual machines through the vm_list tool.
func (a *MCPAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	domainResult, err := a.compute.ListVMsDomain(ctx, listVMsParamsFromOptions(opts))
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "ListVMs", Err: err}
	}

	return listVMsResultFromDomain(domainResult), nil
}

// =============================================================================
// SnapshotCommands and AttestCommands Implementation
// =============================================================================

// CreateSnapshot snapshots a running VM through the vm_snapshot_create tool.
func (a *MCPAdapter) CreateSnapshot(ctx context.Context, opts CreateSnapshotOptions) (*SnapshotSummary, error) {
	snapshot, err := a.compute.CreateSnapshot(ctx, opts.VMID, fullSnapshotConfig(opts))
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "CreateSnapshot", Err: err}
	}

	summary := snapshotSummary(snapshot)
	return &summary, nil
}

// RestoreSnapshot restores a VM from a snapshot through the
// vm_snapshot_restore tool.
func (a *MCPAdapter) RestoreSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.compute.RestoreSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrMCPCallFailed{Method: "RestoreSnapshot", Err: err}
	}
	return nil
}

// DeleteSnapshot deletes a VM snapshot through the vm_snapshot_delete tool.
func (a *MCPAdapter) DeleteSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.compute.DeleteSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrMCPCallFailed{Method: "DeleteSnapshot", Err: err}
	}
	return nil
}

// ListSnapshots lists a VM's snapshots through the vm_snapshot_list tool.
func (a *MCPAdapter) ListSnapshots(ctx context.Context, vmID string) ([]SnapshotSummary, error) {
	snapshots, err := a.compute.ListSnapshots(ctx, vmID)
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "ListSnapshots", Err: err}
	}
	return snapshotSummaries(snapshots), nil
}

// AttestVM generates a VM's vTPM quote through the vm_attest tool, which
// quotes the SHA-256 bank.
func (a *MCPAdapter) AttestVM(ctx context.Context, opts AttestVMOptions) (*VMQuote, error) {
	resp, err := a.compute.AttestVM(ctx, opts.VMID, opts.Nonce, opts.PCRIndices, pb.PCRBank_PCR_BANK_SHA256)
	if err != nil {
		return nil, ErrMCPCallFailed{Method: "AttestVM", Err: err}
	}
	return vmQuote(resp), nil
}

// VerifyVMAttestation verifies VM quote evidence through the
// vm_attest_verify tool.
func (a *MCPAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (bool, error) {
	resp, err := a.compute.VerifyVMAttestation(ctx, verifyVMAttestationRequest(opts))
	if err != nil {
		return false, ErrMCPCallFailed{Method: "VerifyVMAttestation", Err: err}
	}
	return resp.GetVerified(), nil
}
