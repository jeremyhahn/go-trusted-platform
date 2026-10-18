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

	// Registers the QUIC transport that platform.Connect dials.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICConnectFailed indicates the SDK could not connect over QUIC.
type ErrQUICConnectFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectFailed) Error() string {
	return fmt.Sprintf("compute: QUIC connect to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectFailed) Unwrap() error {
	return e.Err
}

// ErrQUICCallFailed indicates a compute call over QUIC failed.
type ErrQUICCallFailed struct {
	Method string
	Err    error
}

func (e ErrQUICCallFailed) Error() string {
	return fmt.Sprintf("compute: QUIC %s failed: %v", e.Method, e.Err)
}

func (e ErrQUICCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements ComputeCommands with the Go SDK over its QUIC
// transport. Every VM verb travels as an OpVMExtendedCategory sub-opcode.
type QUICAdapter struct {
	endpoint string
	client   platform.Client
	compute  *computesvc.Client
}

// NewQUICAdapter creates a new QUIC adapter.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint: GetQUICEndpoint(),
	}
}

// Setup connects the SDK to the daemon over QUIC only.
func (a *QUICAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, platform.NewOptions(
		platform.WithOnlyProtocol(platform.ProtocolQUIC),
		platform.WithQUICAddr(a.endpoint),
		platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
	))
	if err != nil {
		return ErrQUICConnectFailed{Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.compute = computesvc.NewClientFromGRPC(client.Compute())
	return nil
}

// Teardown closes the SDK connection.
func (a *QUICAdapter) Teardown(ctx context.Context) error {
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

// Name returns the adapter name.
func (a *QUICAdapter) Name() string {
	return "QUIC"
}

// CreateVM creates a virtual machine over QUIC.
func (a *QUICAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	vm, err := a.compute.CreateVMDomain(ctx, createVMParamsFromOptions(opts))
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "CreateVM", Err: err}
	}

	return createVMResultFromDomain(vm), nil
}

// StartVM starts a virtual machine over QUIC.
func (a *QUICAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.compute.StartVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "StartVM", Err: err}
	}

	result := &StartVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// StopVM stops a virtual machine over QUIC.
func (a *QUICAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	status, err := a.compute.StopVMDomain(ctx, &computesvc.StopVMParams{
		ID:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	})
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "StopVM", Err: err}
	}

	result := &StopVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// RebootVM restarts a running virtual machine over QUIC.
func (a *QUICAdapter) RebootVM(ctx context.Context, opts RebootVMOptions) (*RebootVMResult, error) {
	status, err := a.compute.RebootVMDomain(ctx, opts.VMID, opts.Force)
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "RebootVM", Err: err}
	}

	result := &RebootVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// SuspendVM pauses a running virtual machine over QUIC.
func (a *QUICAdapter) SuspendVM(ctx context.Context, opts SuspendVMOptions) (*SuspendVMResult, error) {
	status, err := a.compute.SuspendVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "SuspendVM", Err: err}
	}

	result := &SuspendVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// ResumeVM continues a suspended virtual machine over QUIC.
func (a *QUICAdapter) ResumeVM(ctx context.Context, opts ResumeVMOptions) (*ResumeVMResult, error) {
	status, err := a.compute.ResumeVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "ResumeVM", Err: err}
	}

	result := &ResumeVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// DeleteVM deletes a virtual machine over QUIC.
func (a *QUICAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	status, err := a.compute.DeleteVMDomain(ctx, &computesvc.DeleteVMParams{
		ID:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	})
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "DeleteVM", Err: err}
	}

	result := &DeleteVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// GetVM reads a virtual machine over QUIC.
func (a *QUICAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	vm, err := a.compute.GetVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "GetVM", Err: err}
	}

	if vm == nil {
		return nil, ErrQUICCallFailed{Method: "GetVM", Err: ErrVMNotFound(opts)}
	}

	return getVMResultFromDomain(vm), nil
}

// ListVMs lists virtual machines over QUIC.
func (a *QUICAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	domainResult, err := a.compute.ListVMsDomain(ctx, listVMsParamsFromOptions(opts))
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "ListVMs", Err: err}
	}

	return listVMsResultFromDomain(domainResult), nil
}

// CreateSnapshot snapshots a VM via the QUIC SDK client.
func (a *QUICAdapter) CreateSnapshot(ctx context.Context, opts CreateSnapshotOptions) (*SnapshotSummary, error) {
	snapshot, err := a.compute.CreateSnapshot(ctx, opts.VMID, fullSnapshotConfig(opts))
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "CreateSnapshot", Err: err}
	}

	summary := snapshotSummary(snapshot)
	return &summary, nil
}

// RestoreSnapshot restores a VM from a snapshot via the QUIC SDK client.
func (a *QUICAdapter) RestoreSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.compute.RestoreSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrQUICCallFailed{Method: "RestoreSnapshot", Err: err}
	}
	return nil
}

// DeleteSnapshot deletes a VM snapshot via the QUIC SDK client.
func (a *QUICAdapter) DeleteSnapshot(ctx context.Context, opts SnapshotOptions) error {
	if err := a.compute.DeleteSnapshot(ctx, opts.VMID, opts.SnapshotID); err != nil {
		return ErrQUICCallFailed{Method: "DeleteSnapshot", Err: err}
	}
	return nil
}

// ListSnapshots lists a VM's snapshots via the QUIC SDK client.
func (a *QUICAdapter) ListSnapshots(ctx context.Context, vmID string) ([]SnapshotSummary, error) {
	snapshots, err := a.compute.ListSnapshots(ctx, vmID)
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "ListSnapshots", Err: err}
	}
	return snapshotSummaries(snapshots), nil
}

// AttestVM generates a VM's vTPM quote via the QUIC SDK client.
func (a *QUICAdapter) AttestVM(ctx context.Context, opts AttestVMOptions) (*VMQuote, error) {
	resp, err := a.compute.AttestVM(ctx, opts.VMID, opts.Nonce, opts.PCRIndices, pb.PCRBank_PCR_BANK_SHA256)
	if err != nil {
		return nil, ErrQUICCallFailed{Method: "AttestVM", Err: err}
	}
	return vmQuote(resp), nil
}

// VerifyVMAttestation verifies VM quote evidence via the QUIC SDK client.
func (a *QUICAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (bool, error) {
	resp, err := a.compute.VerifyVMAttestation(ctx, verifyVMAttestationRequest(opts))
	if err != nil {
		return false, ErrQUICCallFailed{Method: "VerifyVMAttestation", Err: err}
	}
	return resp.GetVerified(), nil
}
