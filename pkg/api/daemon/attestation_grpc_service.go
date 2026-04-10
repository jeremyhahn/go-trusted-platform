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

//go:build attestation_grpc

// NOTE: This file requires proto generation before it can compile.
// Run `make proto` or `cd pkg/api/grpc && buf generate` to generate the
// required platformv1.AttestationService* types from attestation.proto.
// Then build with: go build -tags attestation_grpc ./...

package daemon

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
)

// AttestationService provides attestation operations including manifest
// building, signing, and verification. Implementations should delegate to
// the appropriate manifest builder, signer, and verifier components.
type AttestationService interface {
	// GetManifest retrieves an existing attestation manifest by ID.
	GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error)

	// BuildManifest builds a new attestation manifest for the host and its workloads.
	BuildManifest(ctx context.Context, config *manifest.BuilderConfig, nonce []byte, options *BuildManifestOptions) (*manifest.HostManifest, error)

	// VerifyManifest verifies an attestation manifest including signature and Merkle root.
	VerifyManifest(ctx context.Context, m *manifest.HostManifest, config *manifest.VerifierConfig, expectedNonce []byte, publicKey []byte, expectedPCRs map[int][]byte) (*manifest.VerificationResult, error)

	// ListManifests lists attestation manifests with optional filtering.
	ListManifests(ctx context.Context, filter *ListManifestsFilter) ([]*manifest.HostManifest, int, error)

	// DeleteManifest removes an attestation manifest.
	DeleteManifest(ctx context.Context, id string) error

	// GetQuote generates a TPM quote for the specified PCRs.
	GetQuote(ctx context.Context, config *QuoteConfig, nonce []byte) (*QuoteResult, error)

	// VerifyQuote verifies a TPM quote against expected values.
	VerifyQuote(ctx context.Context, quote *QuoteResult, akPublicKey []byte, expectedNonce []byte, expectedPCRs []manifest.PCRValue) (*QuoteVerificationResult, error)

	// CollectHostAttestation collects attestation data from the host TPM.
	CollectHostAttestation(ctx context.Context, config *QuoteConfig, nonce []byte) (*manifest.HostAttestation, error)

	// CollectVMAttestation collects attestation data from a VM's vTPM.
	CollectVMAttestation(ctx context.Context, vmID string, config *QuoteConfig, nonce []byte) (*manifest.VMAttestation, error)

	// CollectContainerAttestation collects attestation data for a container.
	CollectContainerAttestation(ctx context.Context, containerID string) (*manifest.ContainerAttestation, error)
}

// BuildManifestOptions contains options for building a manifest.
type BuildManifestOptions struct {
	IncludeVMs        bool
	IncludeContainers bool
	VMIDs             []string
	ContainerIDs      []string
	Sign              bool
}

// ListManifestsFilter contains filters for listing manifests.
type ListManifestsFilter struct {
	HostID    string
	StartTime int64
	EndTime   int64
	Limit     int
	Offset    int
}

// QuoteConfig contains configuration for TPM quote generation.
type QuoteConfig struct {
	AKHandle      uint32
	PCRIndices    []int
	HashAlgorithm manifest.HashAlgorithm
}

// QuoteResult contains the result of a TPM quote operation.
type QuoteResult struct {
	QuoteData []byte
	Signature []byte
	PCRValues []manifest.PCRValue
	Nonce     []byte
	EventLog  []byte
}

// QuoteVerificationResult contains the result of quote verification.
type QuoteVerificationResult struct {
	Verified   bool
	Message    string
	ActualPCRs []manifest.PCRValue
}

// AttestationServiceServer implements the gRPC AttestationService interface.
// It wraps the AttestationService interface to provide gRPC access to
// attestation manifest operations.
type AttestationServiceServer struct {
	platformv1.UnimplementedAttestationServiceServer
	service AttestationService
	logger  *slog.Logger
}

// NewAttestationServiceServer creates a new AttestationServiceServer.
func NewAttestationServiceServer(service AttestationService, logger *slog.Logger) *AttestationServiceServer {
	return &AttestationServiceServer{
		service: service,
		logger:  logger,
	}
}

// =============================================================================
// Manifest Operations
// =============================================================================

// GetManifest retrieves an existing attestation manifest by ID.
func (s *AttestationServiceServer) GetManifest(
	ctx context.Context,
	req *platformv1.GetManifestRequest,
) (*platformv1.GetManifestResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "manifest id is required")
	}

	m, err := s.service.GetManifest(ctx, req.GetId())
	if err != nil {
		s.logger.Error("GetManifest failed", "error", err, "id", req.GetId())
		return nil, s.mapError(err)
	}

	return &platformv1.GetManifestResponse{
		Manifest: s.hostManifestToProto(m),
	}, nil
}

// BuildManifest builds a new attestation manifest for the host and its workloads.
func (s *AttestationServiceServer) BuildManifest(
	ctx context.Context,
	req *platformv1.BuildManifestRequest,
) (*platformv1.BuildManifestResponse, error) {

	config := s.protoToBuilderConfig(req.GetConfig())
	if config == nil {
		return nil, status.Error(codes.InvalidArgument, "builder config is required")
	}

	options := &BuildManifestOptions{
		IncludeVMs:        req.GetIncludeVms(),
		IncludeContainers: req.GetIncludeContainers(),
		VMIDs:             req.GetVmIds(),
		ContainerIDs:      req.GetContainerIds(),
		Sign:              req.GetSign(),
	}

	m, err := s.service.BuildManifest(ctx, config, req.GetNonce(), options)
	if err != nil {
		s.logger.Error("BuildManifest failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.BuildManifestResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "manifest built successfully",
		},
		Manifest: s.hostManifestToProto(m),
	}, nil
}

// VerifyManifest verifies an attestation manifest including signature and Merkle root.
func (s *AttestationServiceServer) VerifyManifest(
	ctx context.Context,
	req *platformv1.VerifyManifestRequest,
) (*platformv1.VerifyManifestResponse, error) {

	if req.GetManifest() == nil {
		return nil, status.Error(codes.InvalidArgument, "manifest is required")
	}

	m := s.protoToHostManifest(req.GetManifest())
	config := s.protoToVerifierConfig(req.GetConfig())
	if config == nil {
		// Use default config
		config = &manifest.VerifierConfig{
			RequireHostAttestation: true,
			VerifyMerkleRoot:       true,
			HashAlgorithm:          manifest.HashAlgorithmSHA256,
		}
	}

	// Convert expected PCRs
	var expectedPCRs map[int][]byte
	if req.GetExpectedPcrs() != nil {
		expectedPCRs = make(map[int][]byte)
		for k, v := range req.GetExpectedPcrs() {
			expectedPCRs[int(k)] = v
		}
	}

	result, err := s.service.VerifyManifest(ctx, m, config, req.GetExpectedNonce(), req.GetPublicKeyPem(), expectedPCRs)
	if err != nil {
		s.logger.Error("VerifyManifest failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.VerifyManifestResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "manifest verification completed",
		},
		Result: s.verificationResultToProto(result),
	}, nil
}

// ListManifests lists attestation manifests with optional filtering.
func (s *AttestationServiceServer) ListManifests(
	ctx context.Context,
	req *platformv1.ListManifestsRequest,
) (*platformv1.ListManifestsResponse, error) {

	filter := &ListManifestsFilter{
		HostID: req.GetHostId(),
		Limit:  int(req.GetLimit()),
		Offset: int(req.GetOffset()),
	}

	if req.GetStartTime() != nil {
		filter.StartTime = req.GetStartTime().AsTime().Unix()
	}
	if req.GetEndTime() != nil {
		filter.EndTime = req.GetEndTime().AsTime().Unix()
	}

	manifests, total, err := s.service.ListManifests(ctx, filter)
	if err != nil {
		s.logger.Error("ListManifests failed", "error", err)
		return nil, s.mapError(err)
	}

	protoManifests := make([]*platformv1.HostManifest, 0, len(manifests))
	for _, m := range manifests {
		protoManifests = append(protoManifests, s.hostManifestToProto(m))
	}

	return &platformv1.ListManifestsResponse{
		Manifests: protoManifests,
		Total:     uint32(total),
	}, nil
}

// DeleteManifest removes an attestation manifest.
func (s *AttestationServiceServer) DeleteManifest(
	ctx context.Context,
	req *platformv1.DeleteManifestRequest,
) (*platformv1.DeleteManifestResponse, error) {

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "manifest id is required")
	}

	err := s.service.DeleteManifest(ctx, req.GetId())
	if err != nil {
		s.logger.Error("DeleteManifest failed", "error", err, "id", req.GetId())
		return nil, s.mapError(err)
	}

	return &platformv1.DeleteManifestResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "manifest deleted successfully",
		},
	}, nil
}

// =============================================================================
// Quote Operations
// =============================================================================

// GetAttestationQuote generates a TPM quote for the specified PCRs.
func (s *AttestationServiceServer) GetAttestationQuote(
	ctx context.Context,
	req *platformv1.GetAttestationQuoteRequest,
) (*platformv1.GetAttestationQuoteResponse, error) {

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "quote config is required")
	}

	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nonce is required")
	}

	config := s.protoToAttestationQuoteConfig(req.GetConfig())

	result, err := s.service.GetQuote(ctx, config, req.GetNonce())
	if err != nil {
		s.logger.Error("GetAttestationQuote failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.GetAttestationQuoteResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "quote generated successfully",
		},
		Quote: s.quoteResultToProto(result),
	}, nil
}

// VerifyAttestationQuote verifies a TPM quote against expected values.
func (s *AttestationServiceServer) VerifyAttestationQuote(
	ctx context.Context,
	req *platformv1.VerifyAttestationQuoteRequest,
) (*platformv1.VerifyAttestationQuoteResponse, error) {

	if req.GetQuote() == nil {
		return nil, status.Error(codes.InvalidArgument, "quote is required")
	}

	quote := s.protoToQuoteResult(req.GetQuote())
	expectedPCRs := s.protoToPCRValues(req.GetExpectedPcrs())

	result, err := s.service.VerifyQuote(ctx, quote, req.GetAkPublicKeyPem(), req.GetExpectedNonce(), expectedPCRs)
	if err != nil {
		s.logger.Error("VerifyAttestationQuote failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.VerifyAttestationQuoteResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "quote verification completed",
		},
		Verified:   result.Verified,
		Message:    result.Message,
		ActualPcrs: s.pcrValuesToProto(result.ActualPCRs),
	}, nil
}

// =============================================================================
// Attestation Collection Operations
// =============================================================================

// CollectHostAttestation collects attestation data from the host TPM.
func (s *AttestationServiceServer) CollectHostAttestation(
	ctx context.Context,
	req *platformv1.CollectHostAttestationRequest,
) (*platformv1.CollectHostAttestationResponse, error) {

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "quote config is required")
	}

	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nonce is required")
	}

	config := s.protoToAttestationQuoteConfig(req.GetConfig())

	attestation, err := s.service.CollectHostAttestation(ctx, config, req.GetNonce())
	if err != nil {
		s.logger.Error("CollectHostAttestation failed", "error", err)
		return nil, s.mapError(err)
	}

	return &platformv1.CollectHostAttestationResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "host attestation collected successfully",
		},
		Attestation: s.hostAttestationToProto(attestation),
	}, nil
}

// CollectVMAttestation collects attestation data from a VM's vTPM.
func (s *AttestationServiceServer) CollectVMAttestation(
	ctx context.Context,
	req *platformv1.CollectVMAttestationRequest,
) (*platformv1.CollectVMAttestationResponse, error) {

	if req.GetVmId() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_id is required")
	}

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "quote config is required")
	}

	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "nonce is required")
	}

	config := s.protoToAttestationQuoteConfig(req.GetConfig())

	attestation, err := s.service.CollectVMAttestation(ctx, req.GetVmId(), config, req.GetNonce())
	if err != nil {
		s.logger.Error("CollectVMAttestation failed", "error", err, "vm_id", req.GetVmId())
		return nil, s.mapError(err)
	}

	return &platformv1.CollectVMAttestationResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VM attestation collected successfully",
		},
		Attestation: s.vmAttestationToProto(attestation),
	}, nil
}

// CollectContainerAttestation collects attestation data for a container.
func (s *AttestationServiceServer) CollectContainerAttestation(
	ctx context.Context,
	req *platformv1.CollectContainerAttestationRequest,
) (*platformv1.CollectContainerAttestationResponse, error) {

	if req.GetContainerId() == "" {
		return nil, status.Error(codes.InvalidArgument, "container_id is required")
	}

	attestation, err := s.service.CollectContainerAttestation(ctx, req.GetContainerId())
	if err != nil {
		s.logger.Error("CollectContainerAttestation failed", "error", err, "container_id", req.GetContainerId())
		return nil, s.mapError(err)
	}

	return &platformv1.CollectContainerAttestationResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "container attestation collected successfully",
		},
		Attestation: s.containerAttestationToProto(attestation),
	}, nil
}

// =============================================================================
// Conversion Helpers: Proto to Service Types
// =============================================================================

func (s *AttestationServiceServer) protoToBuilderConfig(cfg *platformv1.ManifestBuilderConfig) *manifest.BuilderConfig {
	if cfg == nil {
		return nil
	}

	pcrIndices := make([]int, 0, len(cfg.GetPcrIndices()))
	for _, idx := range cfg.GetPcrIndices() {
		pcrIndices = append(pcrIndices, int(idx))
	}

	return &manifest.BuilderConfig{
		HostID:        cfg.GetHostId(),
		HashAlgorithm: s.protoToHashAlgorithm(cfg.GetHashAlgorithm()),
		PCRIndices:    pcrIndices,
		NonceSize:     int(cfg.GetNonceSize()),
		Version:       cfg.GetVersion(),
	}
}

func (s *AttestationServiceServer) protoToVerifierConfig(cfg *platformv1.ManifestVerifierConfig) *manifest.VerifierConfig {
	if cfg == nil {
		return nil
	}

	return &manifest.VerifierConfig{
		MaxManifestAge:         cfg.GetMaxManifestAge(),
		RequireHostAttestation: cfg.GetRequireHostAttestation(),
		VerifyMerkleRoot:       cfg.GetVerifyMerkleRoot(),
		HashAlgorithm:          s.protoToHashAlgorithm(cfg.GetHashAlgorithm()),
		// Note: PlatformCACert and TrustedRoots need to be parsed from PEM
		// This would be handled by the service layer
	}
}

func (s *AttestationServiceServer) protoToAttestationQuoteConfig(cfg *platformv1.AttestationQuoteConfig) *QuoteConfig {
	if cfg == nil {
		return nil
	}

	pcrIndices := make([]int, 0, len(cfg.GetPcrIndices()))
	for _, idx := range cfg.GetPcrIndices() {
		pcrIndices = append(pcrIndices, int(idx))
	}

	return &QuoteConfig{
		AKHandle:      cfg.GetAkHandle(),
		PCRIndices:    pcrIndices,
		HashAlgorithm: s.protoToHashAlgorithm(cfg.GetHashAlgorithm()),
	}
}

func (s *AttestationServiceServer) protoToHostManifest(m *platformv1.HostManifest) *manifest.HostManifest {
	if m == nil {
		return nil
	}

	result := &manifest.HostManifest{
		ID:                 m.GetId(),
		HostID:             m.GetHostId(),
		Nonce:              m.GetNonce(),
		MerkleRoot:         m.GetMerkleRoot(),
		Signature:          m.GetSignature(),
		SignatureAlgorithm: m.GetSignatureAlgorithm(),
		Version:            m.GetVersion(),
		Metadata:           m.GetMetadata(),
	}

	if m.GetTimestamp() != nil {
		result.Timestamp = m.GetTimestamp().AsTime()
	}

	if m.GetHost() != nil {
		result.Host = s.protoToHostAttestation(m.GetHost())
	}

	for _, vm := range m.GetVms() {
		result.VMs = append(result.VMs, *s.protoToVMAttestation(vm))
	}

	for _, container := range m.GetContainers() {
		result.Containers = append(result.Containers, *s.protoToContainerAttestation(container))
	}

	return result
}

func (s *AttestationServiceServer) protoToHostAttestation(a *platformv1.HostAttestation) *manifest.HostAttestation {
	if a == nil {
		return nil
	}

	result := &manifest.HostAttestation{
		QuoteData:          a.GetQuoteData(),
		Signature:          a.GetSignature(),
		SignatureAlgorithm: a.GetSignatureAlgorithm(),
		PCRDigest:          a.GetPcrDigest(),
		Nonce:              a.GetNonce(),
		AKPublicKey:        a.GetAkPublicKey(),
		IDevIDCertificate:  a.GetIdevidCertificate(),
		HashAlgorithm:      s.protoToHashAlgorithm(a.GetHashAlgorithm()),
		FirmwareVersion:    a.GetFirmwareVersion(),
	}

	if a.GetTimestamp() != nil {
		result.Timestamp = a.GetTimestamp().AsTime()
	}

	for _, pcr := range a.GetPcrs() {
		result.PCRs = append(result.PCRs, manifest.PCRValue{
			Index:     int(pcr.GetIndex()),
			Value:     pcr.GetValue(),
			Algorithm: s.protoToHashAlgorithm(pcr.GetAlgorithm()),
		})
	}

	return result
}

func (s *AttestationServiceServer) protoToVMAttestation(a *platformv1.VMAttestation) *manifest.VMAttestation {
	if a == nil {
		return nil
	}

	result := &manifest.VMAttestation{
		VMID:               a.GetVmId(),
		HostID:             a.GetHostId(),
		QuoteData:          a.GetQuoteData(),
		Signature:          a.GetSignature(),
		SignatureAlgorithm: a.GetSignatureAlgorithm(),
		PCRDigest:          a.GetPcrDigest(),
		Nonce:              a.GetNonce(),
		AIKPublicKey:       a.GetAikPublicKey(),
		EKCertificate:      a.GetEkCertificate(),
		WorkloadPCR:        a.GetWorkloadPcr(),
		HashAlgorithm:      s.protoToHashAlgorithm(a.GetHashAlgorithm()),
		Metadata:           a.GetMetadata(),
	}

	if a.GetTimestamp() != nil {
		result.Timestamp = a.GetTimestamp().AsTime()
	}

	for _, pcr := range a.GetPcrs() {
		result.PCRs = append(result.PCRs, manifest.PCRValue{
			Index:     int(pcr.GetIndex()),
			Value:     pcr.GetValue(),
			Algorithm: s.protoToHashAlgorithm(pcr.GetAlgorithm()),
		})
	}

	return result
}

func (s *AttestationServiceServer) protoToContainerAttestation(a *platformv1.ContainerAttestation) *manifest.ContainerAttestation {
	if a == nil {
		return nil
	}

	result := &manifest.ContainerAttestation{
		ContainerID: a.GetContainerId(),
		ImageID:     a.GetImageId(),
		ImageDigest: a.GetImageDigest(),
		Digest:      a.GetDigest(),
		PCRValue:    a.GetPcrValue(),
		Metadata:    a.GetMetadata(),
	}

	if a.GetTimestamp() != nil {
		result.Timestamp = a.GetTimestamp().AsTime()
	}

	return result
}

func (s *AttestationServiceServer) protoToQuoteResult(q *platformv1.AttestationQuote) *QuoteResult {
	if q == nil {
		return nil
	}

	return &QuoteResult{
		QuoteData: q.GetQuoteData(),
		Signature: q.GetSignature(),
		PCRValues: s.protoToPCRValues(q.GetPcrValues()),
		Nonce:     q.GetNonce(),
		EventLog:  q.GetEventLog(),
	}
}

func (s *AttestationServiceServer) protoToPCRValues(pcrs []*platformv1.AttestationPCRValue) []manifest.PCRValue {
	result := make([]manifest.PCRValue, 0, len(pcrs))
	for _, pcr := range pcrs {
		result = append(result, manifest.PCRValue{
			Index:     int(pcr.GetIndex()),
			Value:     pcr.GetValue(),
			Algorithm: s.protoToHashAlgorithm(pcr.GetAlgorithm()),
		})
	}
	return result
}

func (s *AttestationServiceServer) protoToHashAlgorithm(alg platformv1.AttestationHashAlgorithm) manifest.HashAlgorithm {
	switch alg {
	case platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1:
		return manifest.HashAlgorithmSHA1
	case platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256:
		return manifest.HashAlgorithmSHA256
	case platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384:
		return manifest.HashAlgorithmSHA384
	case platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512:
		return manifest.HashAlgorithmSHA512
	default:
		return manifest.HashAlgorithmSHA256
	}
}

// =============================================================================
// Conversion Helpers: Service Types to Proto
// =============================================================================

func (s *AttestationServiceServer) hostManifestToProto(m *manifest.HostManifest) *platformv1.HostManifest {
	if m == nil {
		return nil
	}

	result := &platformv1.HostManifest{
		Id:                 m.ID,
		HostId:             m.HostID,
		Timestamp:          timestamppb.New(m.Timestamp),
		Nonce:              m.Nonce,
		Host:               s.hostAttestationToProto(m.Host),
		MerkleRoot:         m.MerkleRoot,
		Signature:          m.Signature,
		SignatureAlgorithm: m.SignatureAlgorithm,
		Version:            m.Version,
		Metadata:           m.Metadata,
	}

	for _, vm := range m.VMs {
		result.Vms = append(result.Vms, s.vmAttestationToProto(&vm))
	}

	for _, container := range m.Containers {
		result.Containers = append(result.Containers, s.containerAttestationToProto(&container))
	}

	return result
}

func (s *AttestationServiceServer) hostAttestationToProto(a *manifest.HostAttestation) *platformv1.HostAttestation {
	if a == nil {
		return nil
	}

	result := &platformv1.HostAttestation{
		QuoteData:          a.QuoteData,
		Signature:          a.Signature,
		SignatureAlgorithm: a.SignatureAlgorithm,
		Pcrs:               s.pcrValuesToProto(a.PCRs),
		PcrDigest:          a.PCRDigest,
		Nonce:              a.Nonce,
		Timestamp:          timestamppb.New(a.Timestamp),
		AkPublicKey:        a.AKPublicKey,
		IdevidCertificate:  a.IDevIDCertificate,
		HashAlgorithm:      s.hashAlgorithmToProto(a.HashAlgorithm),
		FirmwareVersion:    a.FirmwareVersion,
	}

	return result
}

func (s *AttestationServiceServer) vmAttestationToProto(a *manifest.VMAttestation) *platformv1.VMAttestation {
	if a == nil {
		return nil
	}

	return &platformv1.VMAttestation{
		VmId:               a.VMID,
		HostId:             a.HostID,
		QuoteData:          a.QuoteData,
		Signature:          a.Signature,
		SignatureAlgorithm: a.SignatureAlgorithm,
		Pcrs:               s.pcrValuesToProto(a.PCRs),
		PcrDigest:          a.PCRDigest,
		Nonce:              a.Nonce,
		Timestamp:          timestamppb.New(a.Timestamp),
		AikPublicKey:       a.AIKPublicKey,
		EkCertificate:      a.EKCertificate,
		WorkloadPcr:        a.WorkloadPCR,
		HashAlgorithm:      s.hashAlgorithmToProto(a.HashAlgorithm),
		Metadata:           a.Metadata,
	}
}

func (s *AttestationServiceServer) containerAttestationToProto(a *manifest.ContainerAttestation) *platformv1.ContainerAttestation {
	if a == nil {
		return nil
	}

	return &platformv1.ContainerAttestation{
		ContainerId: a.ContainerID,
		ImageId:     a.ImageID,
		ImageDigest: a.ImageDigest,
		Digest:      a.Digest,
		PcrValue:    a.PCRValue,
		Timestamp:   timestamppb.New(a.Timestamp),
		Metadata:    a.Metadata,
	}
}

func (s *AttestationServiceServer) verificationResultToProto(r *manifest.VerificationResult) *platformv1.ManifestVerificationResult {
	if r == nil {
		return nil
	}

	return &platformv1.ManifestVerificationResult{
		Status:                     s.verificationStatusToProto(r.Status),
		SignatureValid:             r.SignatureValid,
		MerkleRootValid:            r.MerkleRootValid,
		NonceValid:                 r.NonceValid,
		TimestampValid:             r.TimestampValid,
		HostAttestationValid:       r.HostAttestationValid,
		VmAttestationsValid:        r.VMAttestationsValid,
		ContainerAttestationsValid: r.ContainerAttestationsValid,
		VerifiedAt:                 timestamppb.New(r.VerifiedAt),
		Errors:                     r.Errors,
		VmErrors:                   r.VMErrors,
		ContainerErrors:            r.ContainerErrors,
	}
}

func (s *AttestationServiceServer) quoteResultToProto(q *QuoteResult) *platformv1.AttestationQuote {
	if q == nil {
		return nil
	}

	return &platformv1.AttestationQuote{
		QuoteData: q.QuoteData,
		Signature: q.Signature,
		PcrValues: s.pcrValuesToProto(q.PCRValues),
		Nonce:     q.Nonce,
		EventLog:  q.EventLog,
	}
}

func (s *AttestationServiceServer) pcrValuesToProto(pcrs []manifest.PCRValue) []*platformv1.AttestationPCRValue {
	result := make([]*platformv1.AttestationPCRValue, 0, len(pcrs))
	for _, pcr := range pcrs {
		result = append(result, &platformv1.AttestationPCRValue{
			Index:     uint32(pcr.Index),
			Value:     pcr.Value,
			Algorithm: s.hashAlgorithmToProto(pcr.Algorithm),
		})
	}
	return result
}

func (s *AttestationServiceServer) hashAlgorithmToProto(alg manifest.HashAlgorithm) platformv1.AttestationHashAlgorithm {
	switch alg {
	case manifest.HashAlgorithmSHA1:
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1
	case manifest.HashAlgorithmSHA256:
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256
	case manifest.HashAlgorithmSHA384:
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384
	case manifest.HashAlgorithmSHA512:
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512
	default:
		return platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_UNSPECIFIED
	}
}

func (s *AttestationServiceServer) verificationStatusToProto(status manifest.VerificationStatus) platformv1.ManifestVerificationStatus {
	switch status {
	case manifest.VerificationStatusUnknown:
		return platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_UNKNOWN
	case manifest.VerificationStatusPending:
		return platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_PENDING
	case manifest.VerificationStatusVerified:
		return platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED
	case manifest.VerificationStatusFailed:
		return platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_FAILED
	default:
		return platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_UNSPECIFIED
	}
}

// =============================================================================
// Error Mapping
// =============================================================================

// mapError converts attestation service errors to gRPC status errors.
func (s *AttestationServiceServer) mapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for typed errors
	var (
		errInvalidManifest      manifest.ErrInvalidManifest
		errManifestExpired      manifest.ErrManifestExpired
		errMerkleRootMismatch   manifest.ErrMerkleRootMismatch
		errBuilderNotInit       manifest.ErrBuilderNotInitialized
		errSignerNotInit        manifest.ErrSignerNotInitialized
		errVerifierNotInit      manifest.ErrVerifierNotInitialized
		errInvalidConfig        manifest.ErrInvalidConfig
		errContextCanceled      manifest.ErrContextCanceled
		errNonceMismatch        manifest.ErrNonceMismatch
		errTPMNotAvailable      manifest.ErrTPMNotAvailable
		errAKNotFound           manifest.ErrAKNotFound
		errSignatureInvalid     manifest.ErrSignatureInvalid
		errAttestationFailed    manifest.ErrAttestationFailed
		errInvalidHashAlgorithm manifest.ErrInvalidHashAlgorithm
		errHostNotAttested      manifest.ErrHostNotAttested
		errEmptyManifest        manifest.ErrEmptyManifest
		errManifestBuildFailed  manifest.ErrManifestBuildFailed
		errManifestSignFailed   manifest.ErrManifestSignFailed
		errManifestVerifyFailed manifest.ErrManifestVerifyFailed
	)

	switch {
	// Not Found errors
	case errors.As(err, &errAKNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.As(err, &errHostNotAttested):
		return status.Error(codes.NotFound, err.Error())

	// Invalid Argument errors
	case errors.As(err, &errInvalidManifest):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &errInvalidConfig):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &errInvalidHashAlgorithm):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &errNonceMismatch):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &errEmptyManifest):
		return status.Error(codes.InvalidArgument, err.Error())

	// Failed Precondition errors
	case errors.As(err, &errBuilderNotInit):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &errSignerNotInit):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &errVerifierNotInit):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &errTPMNotAvailable):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &errManifestExpired):
		return status.Error(codes.FailedPrecondition, err.Error())

	// Canceled errors
	case errors.As(err, &errContextCanceled):
		return status.Error(codes.Canceled, err.Error())

	// Verification failures
	case errors.As(err, &errSignatureInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &errMerkleRootMismatch):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.As(err, &errManifestVerifyFailed):
		return status.Error(codes.InvalidArgument, err.Error())

	// Internal errors
	case errors.As(err, &errAttestationFailed):
		return status.Error(codes.Internal, err.Error())
	case errors.As(err, &errManifestBuildFailed):
		return status.Error(codes.Internal, err.Error())
	case errors.As(err, &errManifestSignFailed):
		return status.Error(codes.Internal, err.Error())

	default:
		// Fall back to string matching for errors without typed variants
		errMsg := err.Error()
		if containsAny(errMsg, "not found", "does not exist", "no such") {
			return status.Error(codes.NotFound, errMsg)
		}
		if containsAny(errMsg, "already exists", "duplicate") {
			return status.Error(codes.AlreadyExists, errMsg)
		}
		if containsAny(errMsg, "invalid", "required", "must be", "cannot be") {
			return status.Error(codes.InvalidArgument, errMsg)
		}
		if containsAny(errMsg, "permission", "denied", "unauthorized", "forbidden") {
			return status.Error(codes.PermissionDenied, errMsg)
		}
		if containsAny(errMsg, "unavailable", "not available", "not ready") {
			return status.Error(codes.Unavailable, errMsg)
		}
		if containsAny(errMsg, "canceled", "cancelled") {
			return status.Error(codes.Canceled, errMsg)
		}
		return status.Error(codes.Internal, errMsg)
	}
}
