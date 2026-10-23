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

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixConnectionFailed indicates a Unix socket connection failure.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("compute: Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("compute: Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Adapter
// =============================================================================

// UnixAdapter implements ComputeCommands using the compute SDK client over a
// gRPC connection on a Unix domain socket.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     *computesvc.Client
}

// NewUnixAdapter creates a new Unix socket adapter.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup creates a gRPC connection over the Unix domain socket.
func (a *UnixAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.NewClient("unix://"+a.socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return ErrUnixConnectionFailed{
			Path: a.socketPath,
			Err:  err,
		}
	}

	a.conn = conn
	a.client = computesvc.NewClientFromGRPC(pb.NewComputeServiceClient(conn))
	return nil
}

// Teardown closes the gRPC connection.
func (a *UnixAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name.
func (a *UnixAdapter) Name() string {
	return "Unix"
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	vm, err := a.client.CreateVMDomain(ctx, createVMParamsFromOptions(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateVM", Err: err}
	}

	return createVMResultFromDomain(vm), nil
}

// StartVM starts a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.client.StartVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StartVM", Err: err}
	}

	result := &StartVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// StopVM stops a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	status, err := a.client.StopVMDomain(ctx, &computesvc.StopVMParams{
		ID:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StopVM", Err: err}
	}

	result := &StopVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// RebootVM restarts a running virtual machine via the Unix socket.
func (a *UnixAdapter) RebootVM(ctx context.Context, opts RebootVMOptions) (*RebootVMResult, error) {
	status, err := a.client.RebootVMDomain(ctx, opts.VMID, opts.Force)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RebootVM", Err: err}
	}

	result := &RebootVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// SuspendVM pauses a running virtual machine via the Unix socket.
func (a *UnixAdapter) SuspendVM(ctx context.Context, opts SuspendVMOptions) (*SuspendVMResult, error) {
	status, err := a.client.SuspendVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "SuspendVM", Err: err}
	}

	result := &SuspendVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// ResumeVM continues a suspended virtual machine via the Unix socket.
func (a *UnixAdapter) ResumeVM(ctx context.Context, opts ResumeVMOptions) (*ResumeVMResult, error) {
	status, err := a.client.ResumeVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ResumeVM", Err: err}
	}

	result := &ResumeVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// DeleteVM deletes a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	status, err := a.client.DeleteVMDomain(ctx, &computesvc.DeleteVMParams{
		ID:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteVM", Err: err}
	}

	result := &DeleteVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// GetVM retrieves a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	vm, err := a.client.GetVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetVM", Err: err}
	}

	if vm == nil {
		return nil, ErrUnixRPCFailed{
			Method: "GetVM",
			Err:    ErrVMNotFound(opts),
		}
	}

	return getVMResultFromDomain(vm), nil
}

// ListVMs lists virtual machines via the SDK client over Unix socket.
func (a *UnixAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	domainResult, err := a.client.ListVMsDomain(ctx, listVMsParamsFromOptions(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListVMs", Err: err}
	}

	return listVMsResultFromDomain(domainResult), nil
}

// CreateSnapshot snapshots a running VM via the Unix socket SDK client.
func (a *UnixAdapter) CreateSnapshot(ctx context.Context, opts CreateSnapshotOptions) (*SnapshotSummary, error) {
	snapshot, err := a.client.CreateSnapshot(ctx, opts.VMID, fullSnapshotConfig(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateSnapshot", Err: err}
	}

	summary := snapshotSummary(snapshot)
	return &summary, nil
}

// RestoreSnapshot restores a VM from a snapshot via the Unix socket SDK client.
func (a *UnixAdapter) RestoreSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.client.RestoreSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrUnixRPCFailed{Method: "RestoreSnapshot", Err: err}
	}
	return nil
}

// GetSnapshot returns one VM snapshot via the Unix socket SDK client.
func (a *UnixAdapter) GetSnapshot(ctx context.Context, opts SnapshotOptions) (*SnapshotSummary, error) {
	snapshot, err := a.client.GetSnapshot(ctx, opts.VMID, opts.SnapshotID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetSnapshot", Err: err}
	}

	summary := snapshotSummary(snapshot)
	return &summary, nil
}

// PrepareMigration starts a migration receiver via the Unix socket SDK client.
func (a *UnixAdapter) PrepareMigration(ctx context.Context, opts PrepareMigrationOptions) (*MigrationReceiverSummary, error) {
	resp, err := a.client.PrepareMigration(ctx, prepareMigrationRequest(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "PrepareMigration", Err: err}
	}
	return migrationReceiverSummary(resp), nil
}

// FinalizeMigration commits or aborts a migration receiver via the Unix socket SDK client.
func (a *UnixAdapter) FinalizeMigration(ctx context.Context, receiverID string, commit bool) error {
	if err := a.client.FinalizeMigration(ctx, receiverID, commit); err != nil {
		return ErrUnixRPCFailed{Method: "FinalizeMigration", Err: err}
	}
	return nil
}

// DeleteSnapshot deletes a VM snapshot via the Unix socket SDK client.
func (a *UnixAdapter) DeleteSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.client.DeleteSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrUnixRPCFailed{Method: "DeleteSnapshot", Err: err}
	}
	return nil
}

// ListSnapshots lists a VM's snapshots via the Unix socket SDK client.
func (a *UnixAdapter) ListSnapshots(ctx context.Context, vmID string) ([]SnapshotSummary, error) {
	snapshots, err := a.client.ListSnapshots(ctx, vmID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListSnapshots", Err: err}
	}
	return snapshotSummaries(snapshots), nil
}

// AttestVM generates a VM's vTPM quote via the Unix socket SDK client.
func (a *UnixAdapter) AttestVM(ctx context.Context, opts AttestVMOptions) (*VMQuote, error) {
	resp, err := a.client.AttestVM(ctx, opts.VMID, opts.Nonce, opts.PCRIndices, pb.PCRBank_PCR_BANK_SHA256)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AttestVM", Err: err}
	}
	return vmQuote(resp), nil
}

// VerifyVMAttestation verifies VM quote evidence via the Unix socket SDK
// client.
func (a *UnixAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (bool, error) {
	resp, err := a.client.VerifyVMAttestation(ctx, verifyVMAttestationRequest(opts))
	if err != nil {
		return false, ErrUnixRPCFailed{Method: "VerifyVMAttestation", Err: err}
	}
	return resp.GetVerified(), nil
}
