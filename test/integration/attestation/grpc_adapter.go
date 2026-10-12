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
	"strings"
	"time"

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
		return nil, ErrGRPCCallFailed{Method: "GenerateVMQuote", Err: err}
	}

	attest := resp.GetAttestation()
	if attest == nil {
		return nil, ErrGRPCCallFailed{Method: "GenerateVMQuote", Err: fmt.Errorf("nil attestation in response")}
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
func (a *GRPCAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "GetVMIdentity"}
}

// GetVMAttestation generates a full VM attestation via CollectVMAttestation RPC.
func (a *GRPCAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "GetVMAttestation", Err: err}
	}

	attest := resp.GetAttestation()
	if attest == nil {
		return nil, ErrGRPCCallFailed{Method: "GetVMAttestation", Err: fmt.Errorf("nil attestation in response")}
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

// VerifyVMAttestation verifies a VM attestation via VerifyAttestationQuote RPC.
func (a *GRPCAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "VerifyVMAttestation", Err: err}
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

// BuildManifest builds a host manifest with attestations via BuildManifest RPC.
func (a *GRPCAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "BuildManifest", Err: err}
	}

	manifest := resp.GetManifest()
	if manifest == nil {
		return nil, ErrGRPCCallFailed{Method: "BuildManifest", Err: fmt.Errorf("nil manifest in response")}
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
func (a *GRPCAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "SignManifest"}
}

// VerifyManifest verifies a signed manifest via VerifyManifest RPC.
func (a *GRPCAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	// First retrieve the manifest to verify
	getResp, err := a.client.GetManifest(ctx, &platformv1.GetManifestRequest{
		Id: opts.ManifestID,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest/GetManifest", Err: err}
	}

	manifest := getResp.GetManifest()
	if manifest == nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest", Err: fmt.Errorf("manifest not found: %s", opts.ManifestID)}
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
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest", Err: err}
	}

	result := resp.GetResult()
	if result == nil {
		return nil, ErrGRPCCallFailed{Method: "VerifyManifest", Err: fmt.Errorf("nil verification result")}
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

// GetManifest retrieves a manifest by ID via GetManifest RPC.
func (a *GRPCAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	req := &platformv1.GetManifestRequest{
		Id: opts.ManifestID,
	}

	resp, err := a.client.GetManifest(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetManifest", Err: err}
	}

	manifest := resp.GetManifest()
	if manifest == nil {
		return nil, ErrGRPCCallFailed{Method: "GetManifest", Err: fmt.Errorf("manifest not found: %s", opts.ManifestID)}
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

// =============================================================================
// Proto Conversion Helpers
// =============================================================================

// hashAlgorithmFromString converts a string hash algorithm name to the proto enum.
func hashAlgorithmFromString(algo string) platformv1.AttestationHashAlgorithm {
	hashAlgorithmMap := map[string]platformv1.AttestationHashAlgorithm{
		"sha1":   platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1,
		"sha256": platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
		"sha384": platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384,
		"sha512": platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512,
	}

	if v, ok := hashAlgorithmMap[strings.ToLower(algo)]; ok {
		return v
	}
	return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED
}

// hashAlgorithmToString converts the proto enum to a string hash algorithm name.
func hashAlgorithmToString(algo platformv1.AttestationHashAlgorithm) string {
	hashAlgorithmStringMap := map[platformv1.AttestationHashAlgorithm]string{
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1:   "sha1",
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256: "sha256",
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384: "sha384",
		platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512: "sha512",
	}

	if v, ok := hashAlgorithmStringMap[algo]; ok {
		return v
	}
	return ""
}

// pcrValuesFromProto converts proto PCR values to the test adapter PCRValueResult slice.
func pcrValuesFromProto(pcrs []*platformv1.AttestationPCRValue) []PCRValueResult {
	results := make([]PCRValueResult, len(pcrs))
	for i, pcr := range pcrs {
		results[i] = PCRValueResult{
			Index:     int(pcr.GetIndex()),
			Value:     pcr.GetValue(),
			Algorithm: hashAlgorithmToString(pcr.GetAlgorithm()),
		}
	}
	return results
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify GRPCAdapter implements AttestationCommands
var _ AttestationCommands = (*GRPCAdapter)(nil)
