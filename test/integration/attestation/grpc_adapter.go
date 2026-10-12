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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
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
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
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
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements AttestationCommands using gRPC API.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   platformv1.AttestationServiceClient
}

// NewGRPCAdapter creates a new gRPC adapter.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint: GetGRPCEndpoint(),
	}
}

// Setup prepares the adapter for testing.
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
	a.client = platformv1.NewAttestationServiceClient(conn)

	return nil
}

// Teardown cleans up after testing.
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
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM via the GetAttestationQuote RPC.
func (a *GRPCAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	req := collectVMAttestationRequest(opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	resp, err := a.client.CollectVMAttestation(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GenerateVMQuote", Err: err}
	}

	result, err := vmQuoteResult(resp)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GenerateVMQuote", Err: err}
	}
	return result, nil
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "GetVMIdentity"}
}

// GetVMAttestation generates a full VM attestation via CollectVMAttestation RPC.
func (a *GRPCAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	req := collectVMAttestationRequest(opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	resp, err := a.client.CollectVMAttestation(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetVMAttestation", Err: err}
	}

	result, err := vmAttestationResult(resp)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetVMAttestation", Err: err}
	}
	return result, nil
}

// VerifyVMAttestation verifies a VM attestation via VerifyAttestationQuote RPC.
func (a *GRPCAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	resp, err := a.client.VerifyAttestationQuote(ctx, verifyAttestationQuoteRequest(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyVMAttestation", Err: err}
	}
	return verifyVMAttestationResult(opts, resp), nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations via BuildManifest RPC.
func (a *GRPCAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	resp, err := a.client.BuildManifest(ctx, buildManifestRequest(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "BuildManifest", Err: err}
	}

	result, err := buildManifestResult(resp)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "BuildManifest", Err: err}
	}
	return result, nil
}

// SignManifest signs a manifest with the host TPM.
// No dedicated gRPC RPC exists; signing is done during BuildManifest with Sign=true.
func (a *GRPCAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "SignManifest"}
}

// VerifyManifest verifies a signed manifest via VerifyManifest RPC.
func (a *GRPCAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	getResp, err := a.client.GetManifest(ctx, &platformv1.GetManifestRequest{Id: opts.ManifestID})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest/GetManifest", Err: err}
	}
	manifest, err := storedManifest(getResp)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest/GetManifest", Err: err}
	}

	resp, err := a.client.VerifyManifest(ctx, verifyManifestRequest(manifest))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest", Err: err}
	}

	result, err := verifyManifestResult(opts, manifest, resp)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest", Err: err}
	}
	return result, nil
}

// GetManifest retrieves a manifest by ID via GetManifest RPC.
func (a *GRPCAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	resp, err := a.client.GetManifest(ctx, &platformv1.GetManifestRequest{Id: opts.ManifestID})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetManifest", Err: err}
	}

	result, err := getManifestResult(resp)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetManifest", Err: err}
	}
	return result, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "PushAttestation"}
}

// PushAttestationBatch pushes to multiple targets concurrently.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "PushAttestationBatch"}
}

// GetPushStatus retrieves the status of a push operation.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "GetPushStatus"}
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "ExtendWorkloadChain"}
}

// GetWorkloadChainHistory retrieves the chain history.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "GetWorkloadChainHistory"}
}

// VerifyWorkloadChain verifies the chain against expected PCR.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "VerifyWorkloadChain"}
}

// GetWorkloadChainStats retrieves chain statistics.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *GRPCAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "GetWorkloadChainStats"}
}

// Verify GRPCAdapter implements AttestationCommands
var _ AttestationCommands = (*GRPCAdapter)(nil)
