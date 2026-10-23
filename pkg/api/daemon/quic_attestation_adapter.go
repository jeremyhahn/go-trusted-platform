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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// attestationQUICAdapter serves the daemon-native QUIC attestation opcodes
// (0x76, 0x77, 0x7C-0x7F) from the same AttestationServiceServer that gRPC,
// Unix and MCP call. It converts between the QUIC handler's manifest types
// and the gRPC messages and adds no attestation logic of its own, so every
// result, and every refusal, is the one the gRPC servicer gives. Going
// through the servicer also keeps the quote channel binding (§5.1a of
// docs/attestation/api.md), which reads the QUIC connection's TLS state from
// the context.
type attestationQUICAdapter struct {
	grpc *AttestationServiceServer
}

var _ quic.AttestationServiceInterface = (*attestationQUICAdapter)(nil)

// newAttestationQUICAdapter returns the QUIC attestation service over the
// shared attestation gRPC servicer.
func newAttestationQUICAdapter(svc *AttestationServiceServer) *attestationQUICAdapter {
	return &attestationQUICAdapter{grpc: svc}
}

// GetManifest fetches a stored manifest through GetManifest.
func (a *attestationQUICAdapter) GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error) {
	resp, err := a.grpc.GetManifest(ctx, &platformv1.GetManifestRequest{Id: id})
	if err != nil {
		return nil, ErrQUICAttestationRefused{Op: "GetManifest", Cause: err}
	}
	return a.grpc.protoToHostManifest(resp.GetManifest()), nil
}

// BuildManifest builds (and, when asked, signs) a manifest through BuildManifest.
func (a *attestationQUICAdapter) BuildManifest(ctx context.Context, config *quic.AttestationBuildManifestConfig) (*manifest.HostManifest, error) {
	resp, err := a.grpc.BuildManifest(ctx, &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{
			HostId:        config.HostID,
			HashAlgorithm: a.grpc.hashAlgorithmToProto(config.HashAlgorithm),
			PcrIndices:    pcrIndicesToProto(config.PCRIndices),
		},
		Nonce:             config.Nonce,
		IncludeVms:        config.IncludeVMs,
		IncludeContainers: config.IncludeContainers,
		VmIds:             config.VMIDs,
		ContainerIds:      config.ContainerIDs,
		Sign:              config.Sign,
	})
	if err != nil {
		return nil, ErrQUICAttestationRefused{Op: "BuildManifest", Cause: err}
	}
	return a.grpc.protoToHostManifest(resp.GetManifest()), nil
}

// VerifyManifest verifies a manifest through VerifyManifest. A request
// carrying a public key is refused there (the signature is not checked,
// #304), and that refusal is what QUIC carries.
func (a *attestationQUICAdapter) VerifyManifest(ctx context.Context, m *manifest.HostManifest, opts *quic.AttestationVerifyManifestOptions) (*manifest.VerificationResult, error) {
	req := &platformv1.VerifyManifestRequest{Manifest: a.grpc.hostManifestToProto(m)}
	if opts != nil {
		req.ExpectedNonce = opts.ExpectedNonce
		req.PublicKeyPem = opts.PublicKeyPEM
		if len(opts.ExpectedPCRs) > 0 {
			req.ExpectedPcrs = make(map[uint32][]byte, len(opts.ExpectedPCRs))
			for index, value := range opts.ExpectedPCRs {
				req.ExpectedPcrs[uint32(index)] = value
			}
		}
	}
	resp, err := a.grpc.VerifyManifest(ctx, req)
	if err != nil {
		return nil, ErrQUICAttestationRefused{Op: "VerifyManifest", Cause: err}
	}
	return protoToVerificationResult(resp.GetResult()), nil
}

// CollectHostAttestation quotes the host TPM through CollectHostAttestation,
// bound to the QUIC connection exactly as OpAttestCollectHost (0x72) is.
func (a *attestationQUICAdapter) CollectHostAttestation(ctx context.Context, opts *quic.AttestationCollectOptions) (*manifest.HostAttestation, error) {
	// The QUIC handler already bound opts.Nonce to this connection (#482);
	// the servicer's CollectHostAttestation would bind it a second time, so
	// the bound nonce goes to the service the servicer wraps.
	if err := a.grpc.requireService(); err != nil {
		return nil, ErrQUICAttestationRefused{Op: "CollectHostAttestation", Cause: err}
	}
	config := a.grpc.protoToAttestationQuoteConfig(a.quoteConfig(opts))
	attestation, err := a.grpc.service.CollectHostAttestation(ctx, config, opts.Nonce)
	if err != nil {
		return nil, ErrQUICAttestationRefused{Op: "CollectHostAttestation", Cause: a.grpc.mapError(err)}
	}
	return attestation, nil
}

// AttestVM collects a VM's attestation through CollectVMAttestation.
func (a *attestationQUICAdapter) AttestVM(ctx context.Context, vmID string, opts *quic.AttestationCollectOptions) (*manifest.VMAttestation, error) {
	resp, err := a.grpc.CollectVMAttestation(ctx, &platformv1.CollectVMAttestationRequest{
		VmId:   vmID,
		Config: a.quoteConfig(opts),
		Nonce:  opts.Nonce,
	})
	if err != nil {
		return nil, ErrQUICAttestationRefused{Op: "CollectVMAttestation", Cause: err}
	}
	return a.grpc.protoToVMAttestation(resp.GetAttestation()), nil
}

// AttestContainer collects a container's attestation through
// CollectContainerAttestation.
func (a *attestationQUICAdapter) AttestContainer(ctx context.Context, containerID string, _ *quic.AttestationCollectOptions) (*manifest.ContainerAttestation, error) {
	resp, err := a.grpc.CollectContainerAttestation(ctx, &platformv1.CollectContainerAttestationRequest{
		ContainerId: containerID,
	})
	if err != nil {
		return nil, ErrQUICAttestationRefused{Op: "CollectContainerAttestation", Cause: err}
	}
	return a.grpc.protoToContainerAttestation(resp.GetAttestation()), nil
}

// AttestDevice is refused: no transport serves device workload attestation
// (docs/attestation/api.md §2, docs/13 G7).
func (a *attestationQUICAdapter) AttestDevice(context.Context, string, *quic.AttestationCollectOptions) (*quic.AttestationDeviceResult, error) {
	return nil, ErrQUICAttestationNoService{Op: "AttestDevice"}
}

// ListReports is refused: no transport serves an attestation report store
// (docs/attestation/api.md §2, docs/13 G7).
func (a *attestationQUICAdapter) ListReports(context.Context, *quic.AttestationReportFilter) ([]*quic.AttestationReport, int, error) {
	return nil, 0, ErrQUICAttestationNoService{Op: "ListReports"}
}

// GetReport is refused: no transport serves an attestation report store
// (docs/attestation/api.md §2, docs/13 G7).
func (a *attestationQUICAdapter) GetReport(context.Context, string) (*quic.AttestationReport, error) {
	return nil, ErrQUICAttestationNoService{Op: "GetReport"}
}

// CreatePolicy is refused: no transport serves an attestation policy store
// (docs/attestation/api.md §2, docs/13 G7).
func (a *attestationQUICAdapter) CreatePolicy(context.Context, *quic.AttestationPolicyCreateRequest) (*quic.AttestationPolicy, error) {
	return nil, ErrQUICAttestationNoService{Op: "CreatePolicy"}
}

// ListPolicies is refused: no transport serves an attestation policy store
// (docs/attestation/api.md §2, docs/13 G7).
func (a *attestationQUICAdapter) ListPolicies(context.Context, *quic.AttestationPolicyListFilter) ([]*quic.AttestationPolicy, int, error) {
	return nil, 0, ErrQUICAttestationNoService{Op: "ListPolicies"}
}

// quoteConfig is the gRPC quote configuration for the QUIC collect options.
// The AK handle is left zero, as every other transport leaves it, so the
// backend quotes with its configured attestation key.
func (a *attestationQUICAdapter) quoteConfig(opts *quic.AttestationCollectOptions) *platformv1.AttestationQuoteConfig {
	return &platformv1.AttestationQuoteConfig{
		PcrIndices:    pcrIndicesToProto(opts.PCRIndices),
		HashAlgorithm: a.grpc.hashAlgorithmToProto(opts.HashAlgorithm),
	}
}

// pcrIndicesToProto converts PCR indices to their proto form. The QUIC
// handler has already refused any index outside 0-23.
func pcrIndicesToProto(indices []int) []uint32 {
	out := make([]uint32, 0, len(indices))
	for _, index := range indices {
		out = append(out, uint32(index))
	}
	return out
}

// protoToVerificationResult is the inverse of verificationResultToProto.
func protoToVerificationResult(r *platformv1.ManifestVerificationResult) *manifest.VerificationResult {
	if r == nil {
		return nil
	}
	return &manifest.VerificationResult{
		Status:                     verificationStatuses[r.GetStatus()],
		SignatureValid:             r.GetSignatureValid(),
		MerkleRootValid:            r.GetMerkleRootValid(),
		NonceValid:                 r.GetNonceValid(),
		TimestampValid:             r.GetTimestampValid(),
		HostAttestationValid:       r.GetHostAttestationValid(),
		VMAttestationsValid:        r.GetVmAttestationsValid(),
		ContainerAttestationsValid: r.GetContainerAttestationsValid(),
		VerifiedAt:                 r.GetVerifiedAt().AsTime(),
		Errors:                     r.GetErrors(),
		VMErrors:                   r.GetVmErrors(),
		ContainerErrors:            r.GetContainerErrors(),
	}
}

// verificationStatuses maps each proto verification status to its manifest
// status; UNSPECIFIED is absent and so reads as the zero status.
var verificationStatuses = map[platformv1.ManifestVerificationStatus]manifest.VerificationStatus{
	platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_UNKNOWN:  manifest.VerificationStatusUnknown,
	platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_PENDING:  manifest.VerificationStatusPending,
	platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED: manifest.VerificationStatusVerified,
	platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_FAILED:   manifest.VerificationStatusFailed,
}
