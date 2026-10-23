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
	"strings"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("compute: gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("compute: gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// gRPC Adapter
// =============================================================================

// GRPCAdapter implements ComputeCommands using the compute SDK client over gRPC.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   *computesvc.Client
}

// NewGRPCAdapter creates a new gRPC adapter.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint: GetGRPCEndpoint(),
	}
}

// Setup prepares the gRPC adapter for testing.
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	tlsConfig := helpers.TLSConfigOrInsecure()

	conn, err := grpc.NewClient(a.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{
			Endpoint: a.endpoint,
			Err:      err,
		}
	}

	a.conn = conn
	a.client = computesvc.NewClientFromGRPC(pb.NewComputeServiceClient(conn))
	return nil
}

// Teardown cleans up the gRPC connection.
func (a *GRPCAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name.
func (a *GRPCAdapter) Name() string {
	return "gRPC"
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via the SDK client over gRPC.
func (a *GRPCAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	vm, err := a.client.CreateVMDomain(ctx, createVMParamsFromOptions(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateVM", Err: err}
	}

	return createVMResultFromDomain(vm), nil
}

// StartVM starts a virtual machine via the SDK client over gRPC.
func (a *GRPCAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.client.StartVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "StartVM", Err: err}
	}

	result := &StartVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// StopVM stops a virtual machine via the SDK client over gRPC.
func (a *GRPCAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	status, err := a.client.StopVMDomain(ctx, &computesvc.StopVMParams{
		ID:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "StopVM", Err: err}
	}

	result := &StopVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// RebootVM restarts a running virtual machine via gRPC.
func (a *GRPCAdapter) RebootVM(ctx context.Context, opts RebootVMOptions) (*RebootVMResult, error) {
	status, err := a.client.RebootVMDomain(ctx, opts.VMID, opts.Force)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RebootVM", Err: err}
	}

	result := &RebootVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// SuspendVM pauses a running virtual machine via gRPC.
func (a *GRPCAdapter) SuspendVM(ctx context.Context, opts SuspendVMOptions) (*SuspendVMResult, error) {
	status, err := a.client.SuspendVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "SuspendVM", Err: err}
	}

	result := &SuspendVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// ResumeVM continues a suspended virtual machine via gRPC.
func (a *GRPCAdapter) ResumeVM(ctx context.Context, opts ResumeVMOptions) (*ResumeVMResult, error) {
	status, err := a.client.ResumeVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ResumeVM", Err: err}
	}

	result := &ResumeVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// DeleteVM deletes a virtual machine via the SDK client over gRPC.
func (a *GRPCAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	status, err := a.client.DeleteVMDomain(ctx, &computesvc.DeleteVMParams{
		ID:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteVM", Err: err}
	}

	result := &DeleteVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// GetVM retrieves a virtual machine via the SDK client over gRPC.
func (a *GRPCAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	vm, err := a.client.GetVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetVM", Err: err}
	}

	if vm == nil {
		return nil, ErrGRPCCallFailed{
			Method: "GetVM",
			Err:    ErrVMNotFound(opts),
		}
	}

	return getVMResultFromDomain(vm), nil
}

// ListVMs lists virtual machines via the SDK client over gRPC.
func (a *GRPCAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	domainResult, err := a.client.ListVMsDomain(ctx, listVMsParamsFromOptions(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListVMs", Err: err}
	}

	return listVMsResultFromDomain(domainResult), nil
}

// CreateSnapshot snapshots a VM via the gRPC SDK client.
func (a *GRPCAdapter) CreateSnapshot(ctx context.Context, opts CreateSnapshotOptions) (*SnapshotSummary, error) {
	snapshot, err := a.client.CreateSnapshot(ctx, opts.VMID, fullSnapshotConfig(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateSnapshot", Err: err}
	}

	summary := snapshotSummary(snapshot)
	return &summary, nil
}

// RestoreSnapshot restores a VM from a snapshot via the gRPC SDK client.
func (a *GRPCAdapter) RestoreSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.client.RestoreSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrGRPCCallFailed{Method: "RestoreSnapshot", Err: err}
	}
	return nil
}

// GetSnapshot returns one VM snapshot via the gRPC SDK client.
func (a *GRPCAdapter) GetSnapshot(ctx context.Context, opts SnapshotOptions) (*SnapshotSummary, error) {
	snapshot, err := a.client.GetSnapshot(ctx, opts.VMID, opts.SnapshotID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetSnapshot", Err: err}
	}

	summary := snapshotSummary(snapshot)
	return &summary, nil
}

// PrepareMigration starts a migration receiver via the gRPC SDK client.
func (a *GRPCAdapter) PrepareMigration(ctx context.Context, opts PrepareMigrationOptions) (*MigrationReceiverSummary, error) {
	resp, err := a.client.PrepareMigration(ctx, prepareMigrationRequest(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "PrepareMigration", Err: err}
	}
	return migrationReceiverSummary(resp), nil
}

// FinalizeMigration commits or aborts a migration receiver via the gRPC SDK client.
func (a *GRPCAdapter) FinalizeMigration(ctx context.Context, receiverID string, commit bool) error {
	if err := a.client.FinalizeMigration(ctx, receiverID, commit); err != nil {
		return ErrGRPCCallFailed{Method: "FinalizeMigration", Err: err}
	}
	return nil
}

// DeleteSnapshot deletes a VM snapshot via the gRPC SDK client.
func (a *GRPCAdapter) DeleteSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.client.DeleteSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrGRPCCallFailed{Method: "DeleteSnapshot", Err: err}
	}
	return nil
}

// ListSnapshots lists a VM's snapshots via the gRPC SDK client.
func (a *GRPCAdapter) ListSnapshots(ctx context.Context, vmID string) ([]SnapshotSummary, error) {
	snapshots, err := a.client.ListSnapshots(ctx, vmID)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListSnapshots", Err: err}
	}
	return snapshotSummaries(snapshots), nil
}

// AttestVM generates a VM's vTPM quote via the gRPC SDK client.
func (a *GRPCAdapter) AttestVM(ctx context.Context, opts AttestVMOptions) (*VMQuote, error) {
	resp, err := a.client.AttestVM(ctx, opts.VMID, opts.Nonce, opts.PCRIndices, pb.PCRBank_PCR_BANK_SHA256)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AttestVM", Err: err}
	}
	return vmQuote(resp), nil
}

// VerifyVMAttestation verifies VM quote evidence via the gRPC SDK client.
func (a *GRPCAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (bool, error) {
	resp, err := a.client.VerifyVMAttestation(ctx, verifyVMAttestationRequest(opts))
	if err != nil {
		return false, ErrGRPCCallFailed{Method: "VerifyVMAttestation", Err: err}
	}
	return resp.GetVerified(), nil
}

// =============================================================================
// Shared SDK Domain Mapping Helpers
// =============================================================================

// createVMParamsFromOptions converts CreateVMOptions to SDK CreateVMParams.
func createVMParamsFromOptions(opts CreateVMOptions) *computesvc.CreateVMParams {
	return &computesvc.CreateVMParams{
		Name:       opts.Name,
		Firmware:   firmwareTypeFromString(opts.Firmware),
		CPUs:       opts.CPUs,
		MemoryMB:   opts.MemoryMB,
		DiskSizeGB: opts.DiskSizeGB,
		SecureBoot: opts.SecureBoot,
		TPM:        opts.TPM,
		Start:      opts.Start,
		Labels:     opts.Labels,
	}
}

// listVMsParamsFromOptions converts ListVMsOptions to SDK ListVMsParams.
func listVMsParamsFromOptions(opts ListVMsOptions) *computesvc.ListVMsParams {
	params := &computesvc.ListVMsParams{
		Labels:   opts.Labels,
		PageSize: opts.PageSize,
	}

	if opts.StateFilter != "" {
		if state, ok := computesvc.ParseVMState(opts.StateFilter); ok {
			params.States = []computesvc.VMState{state}
		}
	}

	return params
}

// createVMResultFromDomain converts a SDK domain VM to a CreateVMResult.
func createVMResultFromDomain(vm *computesvc.VM) *CreateVMResult {
	result := &CreateVMResult{
		Success: vm != nil,
	}

	if vm != nil {
		result.VMID = vm.ID
		result.State = normalizeVMState(vm.State)
		if vm.Config != nil {
			result.Name = vm.Config.Name
			result.Labels = vm.Config.Labels
		}
	}

	return result
}

// getVMResultFromDomain converts a SDK domain VM to a GetVMResult.
func getVMResultFromDomain(vm *computesvc.VM) *GetVMResult {
	result := &GetVMResult{
		VMID:  vm.ID,
		State: normalizeVMState(vm.State),
	}

	if vm.Config != nil {
		result.Name = vm.Config.Name
		result.Labels = vm.Config.Labels
		if vm.Config.CPU != nil {
			result.CPUs = vm.Config.CPU.Cores
		}
		if vm.Config.Memory != nil {
			result.MemoryMB = vm.Config.Memory.SizeMB
		}
	}

	return result
}

// listVMsResultFromDomain converts a SDK domain list result to a ListVMsResult.
func listVMsResultFromDomain(domainResult *computesvc.ListVMsResult) *ListVMsResult {
	result := &ListVMsResult{}
	if domainResult == nil {
		return result
	}

	result.TotalItems = uint64(domainResult.TotalItems)
	result.VMs = make([]VMSummary, len(domainResult.VMs))
	for i, vm := range domainResult.VMs {
		summary := VMSummary{}
		if vm != nil {
			summary.VMID = vm.ID
			summary.State = normalizeVMState(vm.State)
			if vm.Config != nil {
				summary.Name = vm.Config.Name
				summary.Labels = vm.Config.Labels
			}
		}
		result.VMs[i] = summary
	}

	return result
}

// firmwareTypeFromString converts a firmware string to the SDK domain enum.
func firmwareTypeFromString(firmware string) computesvc.FirmwareType {
	fw, ok := computesvc.StringToFirmwareType[strings.ToLower(firmware)]
	if !ok {
		return computesvc.FirmwareUnspecified
	}
	return fw
}

// normalizeVMState normalizes a SDK domain VMState to its lowercase form.
// The SDK domain state is "RUNNING"; this normalizes to "running".
func normalizeVMState(state computesvc.VMState) string {
	return strings.ToLower(string(state))
}

// ErrVMNotFound indicates a VM was not found.
type ErrVMNotFound struct {
	VMID string
}

func (e ErrVMNotFound) Error() string {
	return fmt.Sprintf("compute: VM %s not found", e.VMID)
}
