//go:build integration

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

package attestation

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
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
	return fmt.Sprintf("Unix connection failed to %s: %v", e.Path, e.Err)
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
	return fmt.Sprintf("Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// UnixAdapter implements AttestationCommands using gRPC over Unix domain socket.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     platformv1.AttestationServiceClient
}

// NewUnixAdapter creates a new Unix socket adapter.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup prepares the adapter for testing.
func (a *UnixAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.NewClient("unix://"+a.socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return ErrUnixConnectionFailed{
			Path: a.socketPath,
			Err:  err,
		}
	}

	a.conn = conn
	a.client = platformv1.NewAttestationServiceClient(conn)

	return nil
}

// Teardown cleans up after testing.
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
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM via CollectVMAttestation over Unix socket.
func (a *UnixAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	req := collectVMAttestationRequest(opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	resp, err := a.client.CollectVMAttestation(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GenerateVMQuote", Err: err}
	}

	result, err := vmQuoteResult(resp)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GenerateVMQuote", Err: err}
	}
	return result, nil
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "GetVMIdentity"}
}

// GetVMAttestation generates a full VM attestation via CollectVMAttestation over Unix socket.
func (a *UnixAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	req := collectVMAttestationRequest(opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	resp, err := a.client.CollectVMAttestation(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetVMAttestation", Err: err}
	}

	result, err := vmAttestationResult(resp)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetVMAttestation", Err: err}
	}
	return result, nil
}

// VerifyVMAttestation verifies a VM attestation via VerifyAttestationQuote over Unix socket.
func (a *UnixAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	resp, err := a.client.VerifyAttestationQuote(ctx, verifyAttestationQuoteRequest(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyVMAttestation", Err: err}
	}
	return verifyVMAttestationResult(opts, resp), nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations via BuildManifest over Unix socket.
func (a *UnixAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	resp, err := a.client.BuildManifest(ctx, buildManifestRequest(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "BuildManifest", Err: err}
	}

	result, err := buildManifestResult(resp)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "BuildManifest", Err: err}
	}
	return result, nil
}

// SignManifest signs a manifest with the host TPM.
// No dedicated gRPC RPC exists; signing is done during BuildManifest with Sign=true.
func (a *UnixAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "SignManifest"}
}

// VerifyManifest verifies a signed manifest via VerifyManifest over Unix socket.
func (a *UnixAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	getResp, err := a.client.GetManifest(ctx, &platformv1.GetManifestRequest{Id: opts.ManifestID})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest/GetManifest", Err: err}
	}
	manifest, err := storedManifest(getResp)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest/GetManifest", Err: err}
	}

	resp, err := a.client.VerifyManifest(ctx, verifyManifestRequest(manifest))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest", Err: err}
	}

	result, err := verifyManifestResult(opts, manifest, resp)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest", Err: err}
	}
	return result, nil
}

// GetManifest retrieves a manifest by ID via GetManifest over Unix socket.
func (a *UnixAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	resp, err := a.client.GetManifest(ctx, &platformv1.GetManifestRequest{Id: opts.ManifestID})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetManifest", Err: err}
	}

	result, err := getManifestResult(resp)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetManifest", Err: err}
	}
	return result, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "PushAttestation"}
}

// PushAttestationBatch pushes to multiple targets concurrently.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "PushAttestationBatch"}
}

// GetPushStatus retrieves the status of a push operation.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "GetPushStatus"}
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "ExtendWorkloadChain"}
}

// GetWorkloadChainHistory retrieves the chain history.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "GetWorkloadChainHistory"}
}

// VerifyWorkloadChain verifies the chain against expected PCR.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "VerifyWorkloadChain"}
}

// GetWorkloadChainStats retrieves chain statistics.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "GetWorkloadChainStats"}
}

func (a *UnixAdapter) reporting() reportingRPC {
	return reportingRPC{
		client:    a.client,
		transport: a.Name(),
		wrap: func(method string, err error) error {
			return ErrUnixRPCFailed{Method: method, Err: err}
		},
	}
}

// ListDeviceReports reads every cached device report over the Unix socket.
func (a *UnixAdapter) ListDeviceReports(ctx context.Context) (*DeviceReportsResult, error) {
	return a.reporting().list(ctx)
}

// GetDeviceReport reads one device's cached report over the Unix socket.
func (a *UnixAdapter) GetDeviceReport(ctx context.Context, opts DeviceReportOptions) (*DeviceReport, error) {
	return a.reporting().get(ctx, opts)
}

// RefreshDeviceReport asks the collector to re-collect one device over the
// Unix socket.
func (a *UnixAdapter) RefreshDeviceReport(ctx context.Context, opts DeviceReportOptions) (*RefreshDeviceReportResult, error) {
	return a.reporting().refresh(ctx, opts)
}

// DescribeCallerPolicy reads the node's caller-admission policy over the
// Unix socket.
func (a *UnixAdapter) DescribeCallerPolicy(ctx context.Context) (*calleradmission.Description, error) {
	return a.reporting().callers(ctx)
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify UnixAdapter implements AttestationCommands
var _ AttestationCommands = (*UnixAdapter)(nil)
