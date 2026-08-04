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
	"net"
	"strings"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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
	conn, err := grpc.DialContext(ctx, "unix://"+a.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			socketAddr := strings.TrimPrefix(addr, "unix://")
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketAddr)
		}),
	)
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
	pcrIndices := make([]uint32, len(opts.PCRIndices))
	for i, idx := range opts.PCRIndices {
		pcrIndices[i] = uint32(idx)
	}

	req := &platformv1.CollectVMAttestationRequest{
		VmId: opts.VMID,
		Config: &platformv1.AttestationQuoteConfig{
			PcrIndices:    pcrIndices,
			HashAlgorithm: hashAlgorithmFromString(opts.HashAlgorithm),
		},
		Nonce: opts.Nonce,
	}

	resp, err := a.client.CollectVMAttestation(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GenerateVMQuote", Err: err}
	}

	attest := resp.GetAttestation()
	if attest == nil {
		return nil, ErrUnixRPCFailed{Method: "GenerateVMQuote", Err: fmt.Errorf("nil attestation in response")}
	}

	var ts time.Time
	if attest.GetTimestamp() != nil {
		ts = attest.GetTimestamp().AsTime()
	}

	return &GenerateVMQuoteResult{
		QuoteData:     attest.GetQuoteData(),
		Signature:     attest.GetSignature(),
		PCRDigest:     attest.GetPcrDigest(),
		AIKPublicKey:  attest.GetAikPublicKey(),
		Timestamp:     ts,
		HashAlgorithm: hashAlgorithmToString(attest.GetHashAlgorithm()),
	}, nil
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	return nil, ErrNotImplemented{Feature: "GetVMIdentity via Unix"}
}

// GetVMAttestation generates a full VM attestation via CollectVMAttestation over Unix socket.
func (a *UnixAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	pcrIndices := make([]uint32, len(opts.PCRIndices))
	for i, idx := range opts.PCRIndices {
		pcrIndices[i] = uint32(idx)
	}

	req := &platformv1.CollectVMAttestationRequest{
		VmId: opts.VMID,
		Config: &platformv1.AttestationQuoteConfig{
			PcrIndices:    pcrIndices,
			HashAlgorithm: hashAlgorithmFromString(opts.HashAlgorithm),
		},
		Nonce: opts.Nonce,
	}

	resp, err := a.client.CollectVMAttestation(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetVMAttestation", Err: err}
	}

	attest := resp.GetAttestation()
	if attest == nil {
		return nil, ErrUnixRPCFailed{Method: "GetVMAttestation", Err: fmt.Errorf("nil attestation in response")}
	}

	pcrs := pcrValuesFromProto(attest.GetPcrs())

	var ts time.Time
	if attest.GetTimestamp() != nil {
		ts = attest.GetTimestamp().AsTime()
	}

	return &GetVMAttestationResult{
		AttestationID: attest.GetVmId(),
		VMID:          attest.GetVmId(),
		HostID:        attest.GetHostId(),
		QuoteData:     attest.GetQuoteData(),
		Signature:     attest.GetSignature(),
		PCRs:          pcrs,
		PCRDigest:     attest.GetPcrDigest(),
		WorkloadPCR:   attest.GetWorkloadPcr(),
		AIKPublicKey:  attest.GetAikPublicKey(),
		EKCertPEM:     string(attest.GetEkCertificate()),
		Timestamp:     ts,
		Metadata:      attest.GetMetadata(),
	}, nil
}

// VerifyVMAttestation verifies a VM attestation via VerifyAttestationQuote over Unix socket.
func (a *UnixAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	expectedPCRs := make([]*platformv1.AttestationPCRValue, len(opts.ExpectedPCRs))
	for i, pcrVal := range opts.ExpectedPCRs {
		expectedPCRs[i] = &platformv1.AttestationPCRValue{
			Index: uint32(i),
			Value: pcrVal,
		}
	}

	req := &platformv1.VerifyAttestationQuoteRequest{
		ExpectedNonce: opts.ExpectedNonce,
		ExpectedPcrs:  expectedPCRs,
	}

	resp, err := a.client.VerifyAttestationQuote(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyVMAttestation", Err: err}
	}

	var errors []string
	if resp.GetMessage() != "" {
		errors = append(errors, resp.GetMessage())
	}

	return &VerifyVMAttestationResult{
		Valid:          resp.GetVerified(),
		AttestationID:  opts.AttestationID,
		NonceMatch:     resp.GetVerified(),
		SignatureValid: resp.GetVerified(),
		PCRsMatch:      resp.GetVerified(),
		EKTrusted:      resp.GetVerified(),
		Errors:         errors,
	}, nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations via BuildManifest over Unix socket.
func (a *UnixAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	req := &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{
			HostId:        opts.HostID,
			HashAlgorithm: hashAlgorithmFromString(opts.HashAlgorithm),
			Version:       opts.Version,
		},
		IncludeVms:        len(opts.VMAttestations) > 0,
		IncludeContainers: len(opts.ContainerAttestations) > 0,
		Sign:              true,
	}

	resp, err := a.client.BuildManifest(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "BuildManifest", Err: err}
	}

	manifest := resp.GetManifest()
	if manifest == nil {
		return nil, ErrUnixRPCFailed{Method: "BuildManifest", Err: fmt.Errorf("nil manifest in response")}
	}

	var ts time.Time
	if manifest.GetTimestamp() != nil {
		ts = manifest.GetTimestamp().AsTime()
	}

	return &BuildManifestResult{
		ManifestID:     manifest.GetId(),
		HostID:         manifest.GetHostId(),
		MerkleRoot:     manifest.GetMerkleRoot(),
		VMCount:        len(manifest.GetVms()),
		ContainerCount: len(manifest.GetContainers()),
		Timestamp:      ts,
		Version:        manifest.GetVersion(),
		Metadata:       manifest.GetMetadata(),
	}, nil
}

// SignManifest signs a manifest with the host TPM.
// No dedicated gRPC RPC exists; signing is done during BuildManifest with Sign=true.
func (a *UnixAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	return nil, ErrNotImplemented{Feature: "SignManifest via Unix"}
}

// VerifyManifest verifies a signed manifest via VerifyManifest over Unix socket.
func (a *UnixAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	// First retrieve the manifest to verify
	getResp, err := a.client.GetManifest(ctx, &platformv1.GetManifestRequest{
		Id: opts.ManifestID,
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest/GetManifest", Err: err}
	}

	manifest := getResp.GetManifest()
	if manifest == nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest", Err: fmt.Errorf("manifest not found: %s", opts.ManifestID)}
	}

	req := &platformv1.VerifyManifestRequest{
		Manifest: manifest,
		Config: &platformv1.ManifestVerifierConfig{
			RequireHostAttestation: true,
			VerifyMerkleRoot:       true,
		},
	}

	resp, err := a.client.VerifyManifest(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest", Err: err}
	}

	result := resp.GetResult()
	if result == nil {
		return nil, ErrUnixRPCFailed{Method: "VerifyManifest", Err: fmt.Errorf("nil verification result")}
	}

	valid := result.GetStatus() == platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED

	hostIDMatch := true
	if opts.ExpectedHostID != "" {
		hostIDMatch = manifest.GetHostId() == opts.ExpectedHostID
	}

	return &VerifyManifestResult{
		Valid:           valid,
		ManifestID:      opts.ManifestID,
		SignatureValid:  result.GetSignatureValid(),
		MerkleRootValid: result.GetMerkleRootValid(),
		HostIDMatch:     hostIDMatch,
		SignerTrusted:   result.GetSignatureValid(),
		Errors:          result.GetErrors(),
	}, nil
}

// GetManifest retrieves a manifest by ID via GetManifest over Unix socket.
func (a *UnixAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	req := &platformv1.GetManifestRequest{
		Id: opts.ManifestID,
	}

	resp, err := a.client.GetManifest(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetManifest", Err: err}
	}

	manifest := resp.GetManifest()
	if manifest == nil {
		return nil, ErrUnixRPCFailed{Method: "GetManifest", Err: fmt.Errorf("manifest not found: %s", opts.ManifestID)}
	}

	var ts time.Time
	if manifest.GetTimestamp() != nil {
		ts = manifest.GetTimestamp().AsTime()
	}

	return &GetManifestResult{
		ManifestID:     manifest.GetId(),
		HostID:         manifest.GetHostId(),
		MerkleRoot:     manifest.GetMerkleRoot(),
		Signature:      manifest.GetSignature(),
		VMCount:        len(manifest.GetVms()),
		ContainerCount: len(manifest.GetContainers()),
		Timestamp:      ts,
		Version:        manifest.GetVersion(),
		Metadata:       manifest.GetMetadata(),
	}, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	return nil, ErrNotImplemented{Feature: "PushAttestation via Unix"}
}

// PushAttestationBatch pushes to multiple targets concurrently.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	return nil, ErrNotImplemented{Feature: "PushAttestationBatch via Unix"}
}

// GetPushStatus retrieves the status of a push operation.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	return nil, ErrNotImplemented{Feature: "GetPushStatus via Unix"}
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	return nil, ErrNotImplemented{Feature: "ExtendWorkloadChain via Unix"}
}

// GetWorkloadChainHistory retrieves the chain history.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	return nil, ErrNotImplemented{Feature: "GetWorkloadChainHistory via Unix"}
}

// VerifyWorkloadChain verifies the chain against expected PCR.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	return nil, ErrNotImplemented{Feature: "VerifyWorkloadChain via Unix"}
}

// GetWorkloadChainStats retrieves chain statistics.
// No corresponding gRPC RPC exists in the AttestationService proto.
func (a *UnixAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	return nil, ErrNotImplemented{Feature: "GetWorkloadChainStats via Unix"}
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify UnixAdapter implements AttestationCommands
var _ AttestationCommands = (*UnixAdapter)(nil)
