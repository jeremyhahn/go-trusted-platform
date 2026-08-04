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

package grpc

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Attestation gRPC service error types.

// ErrAttestationNilService is returned when the attestation service is nil.
type ErrAttestationNilService struct{}

func (e ErrAttestationNilService) Error() string {
	return "attestation service is nil"
}

// ErrAttestationMissingManifestID is returned when a manifest ID is required but not provided.
type ErrAttestationMissingManifestID struct{}

func (e ErrAttestationMissingManifestID) Error() string {
	return "manifest ID is required"
}

// ErrAttestationMissingBuilderConfig is returned when builder configuration is required but not provided.
type ErrAttestationMissingBuilderConfig struct{}

func (e ErrAttestationMissingBuilderConfig) Error() string {
	return "builder configuration is required"
}

// ErrAttestationMissingManifest is returned when a manifest is required but not provided.
type ErrAttestationMissingManifest struct{}

func (e ErrAttestationMissingManifest) Error() string {
	return "manifest is required"
}

// ErrAttestationMissingNonce is returned when a nonce is required but not provided.
type ErrAttestationMissingNonce struct{}

func (e ErrAttestationMissingNonce) Error() string {
	return "nonce is required"
}

// ErrAttestationMissingVMID is returned when a VM ID is required but not provided.
type ErrAttestationMissingVMID struct{}

func (e ErrAttestationMissingVMID) Error() string {
	return "VM ID is required"
}

// ErrAttestationMissingContainerID is returned when a container ID is required but not provided.
type ErrAttestationMissingContainerID struct{}

func (e ErrAttestationMissingContainerID) Error() string {
	return "container ID is required"
}

// ErrAttestationMissingQuote is returned when a quote is required but not provided.
type ErrAttestationMissingQuote struct{}

func (e ErrAttestationMissingQuote) Error() string {
	return "quote is required"
}

// ErrAttestationMissingAKPublicKey is returned when an AK public key is required but not provided.
type ErrAttestationMissingAKPublicKey struct{}

func (e ErrAttestationMissingAKPublicKey) Error() string {
	return "AK public key is required"
}

// AttestationService defines the interface for attestation operations.
// This mirrors the daemon.AttestationService interface for use by the gRPC service.
type AttestationService interface {
	// GetManifest retrieves an existing attestation manifest by ID.
	GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error)

	// BuildManifest builds a new attestation manifest for the host and its workloads.
	BuildManifest(ctx context.Context, config *manifest.BuilderConfig, nonce []byte, options *AttestationBuildOptions) (*manifest.HostManifest, error)

	// VerifyManifest verifies an attestation manifest including signature and Merkle root.
	VerifyManifest(ctx context.Context, m *manifest.HostManifest, config *manifest.VerifierConfig, expectedNonce []byte, publicKey []byte, expectedPCRs map[int][]byte) (*manifest.VerificationResult, error)

	// ListManifests lists attestation manifests with optional filtering.
	ListManifests(ctx context.Context, filter *AttestationListFilter) ([]*manifest.HostManifest, int, error)

	// DeleteManifest removes an attestation manifest.
	DeleteManifest(ctx context.Context, id string) error

	// CollectHostAttestation collects attestation data from the host TPM.
	CollectHostAttestation(ctx context.Context, config *AttestationQuoteConfig, nonce []byte) (*manifest.HostAttestation, error)

	// CollectVMAttestation collects attestation data from a VM's vTPM.
	CollectVMAttestation(ctx context.Context, vmID string, config *AttestationQuoteConfig, nonce []byte) (*manifest.VMAttestation, error)

	// CollectContainerAttestation collects attestation data for a container.
	CollectContainerAttestation(ctx context.Context, containerID string) (*manifest.ContainerAttestation, error)
}

// AttestationBuildOptions contains options for building a manifest.
type AttestationBuildOptions struct {
	IncludeVMs        bool
	IncludeContainers bool
	VMIDs             []string
	ContainerIDs      []string
	Sign              bool
}

// AttestationListFilter contains filters for listing manifests.
type AttestationListFilter struct {
	HostID    string
	StartTime int64
	EndTime   int64
	Limit     int
	Offset    int
}

// AttestationQuoteConfig contains configuration for TPM quote generation.
type AttestationQuoteConfig struct {
	AKHandle      uint32
	PCRIndices    []int
	HashAlgorithm manifest.HashAlgorithm
}

// AttestationGRPCService implements the gRPC AttestationService server interface.
// It wraps the AttestationService interface to provide gRPC access to attestation operations.
type AttestationGRPCService struct {
	platformv1.UnimplementedAttestationServiceServer
	logger  *logging.Logger
	service AttestationService
}

// NewAttestationGRPCService creates a new AttestationGRPCService instance.
func NewAttestationGRPCService(
	logger *logging.Logger,
	service AttestationService,
) *AttestationGRPCService {
	return &AttestationGRPCService{
		logger:  logger,
		service: service,
	}
}

// GetManifest retrieves an existing attestation manifest by ID.
func (s *AttestationGRPCService) GetManifest(
	ctx context.Context,
	req *platformv1.GetManifestRequest,
) (*platformv1.GetManifestResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingManifestID{}.Error())
	}

	m, err := s.service.GetManifest(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("GetManifest", err)
	}

	return &platformv1.GetManifestResponse{
		Manifest: hostManifestToProto(m),
	}, nil
}

// BuildManifest builds a new attestation manifest for the host and its workloads.
func (s *AttestationGRPCService) BuildManifest(
	ctx context.Context,
	req *platformv1.BuildManifestRequest,
) (*platformv1.BuildManifestResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingBuilderConfig{}.Error())
	}

	config := protoBuilderConfigToManifest(req.GetConfig())
	options := &AttestationBuildOptions{
		IncludeVMs:        req.GetIncludeVms(),
		IncludeContainers: req.GetIncludeContainers(),
		VMIDs:             req.GetVmIds(),
		ContainerIDs:      req.GetContainerIds(),
		Sign:              req.GetSign(),
	}

	m, err := s.service.BuildManifest(ctx, config, req.GetNonce(), options)
	if err != nil {
		return nil, s.mapError("BuildManifest", err)
	}

	return &platformv1.BuildManifestResponse{
		Status:   attestationSuccessStatus("manifest built successfully"),
		Manifest: hostManifestToProto(m),
	}, nil
}

// VerifyManifest verifies an attestation manifest including signature and Merkle root.
func (s *AttestationGRPCService) VerifyManifest(
	ctx context.Context,
	req *platformv1.VerifyManifestRequest,
) (*platformv1.VerifyManifestResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if req.GetManifest() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingManifest{}.Error())
	}

	m := protoToHostManifest(req.GetManifest())
	config := protoVerifierConfigToManifest(req.GetConfig())
	expectedPCRs := protoExpectedPCRsToMap(req.GetExpectedPcrs())

	result, err := s.service.VerifyManifest(ctx, m, config, req.GetExpectedNonce(), req.GetPublicKeyPem(), expectedPCRs)
	if err != nil {
		return nil, s.mapError("VerifyManifest", err)
	}

	return &platformv1.VerifyManifestResponse{
		Status: attestationSuccessStatus("manifest verification completed"),
		Result: verificationResultToProto(result),
	}, nil
}

// ListManifests lists attestation manifests with optional filtering.
func (s *AttestationGRPCService) ListManifests(
	ctx context.Context,
	req *platformv1.ListManifestsRequest,
) (*platformv1.ListManifestsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	filter := &AttestationListFilter{
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
		return nil, s.mapError("ListManifests", err)
	}

	protoManifests := make([]*platformv1.HostManifest, 0, len(manifests))
	for _, m := range manifests {
		protoManifests = append(protoManifests, hostManifestToProto(m))
	}

	return &platformv1.ListManifestsResponse{
		Manifests: protoManifests,
		Total:     uint32(total),
	}, nil
}

// DeleteManifest removes an attestation manifest.
func (s *AttestationGRPCService) DeleteManifest(
	ctx context.Context,
	req *platformv1.DeleteManifestRequest,
) (*platformv1.DeleteManifestResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingManifestID{}.Error())
	}

	err := s.service.DeleteManifest(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("DeleteManifest", err)
	}

	return &platformv1.DeleteManifestResponse{
		Status: attestationSuccessStatus("manifest deleted successfully"),
	}, nil
}

// GetAttestationQuote generates a TPM quote for the specified PCRs.
func (s *AttestationGRPCService) GetAttestationQuote(
	ctx context.Context,
	req *platformv1.GetAttestationQuoteRequest,
) (*platformv1.GetAttestationQuoteResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingNonce{}.Error())
	}

	config := protoQuoteConfigToInternal(req.GetConfig())

	attestation, err := s.service.CollectHostAttestation(ctx, config, req.GetNonce())
	if err != nil {
		return nil, s.mapError("GetAttestationQuote", err)
	}

	quote := &platformv1.AttestationQuote{
		QuoteData: attestation.QuoteData,
		Signature: attestation.Signature,
		PcrValues: pcrValuesToProto(attestation.PCRs),
		Nonce:     attestation.Nonce,
	}

	return &platformv1.GetAttestationQuoteResponse{
		Status: attestationSuccessStatus("quote generated successfully"),
		Quote:  quote,
	}, nil
}

// VerifyAttestationQuote verifies a TPM quote against expected values.
func (s *AttestationGRPCService) VerifyAttestationQuote(
	ctx context.Context,
	req *platformv1.VerifyAttestationQuoteRequest,
) (*platformv1.VerifyAttestationQuoteResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if req.GetQuote() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingQuote{}.Error())
	}

	if len(req.GetAkPublicKeyPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingAKPublicKey{}.Error())
	}

	// Create a host manifest from the quote for verification
	hostManifest := &manifest.HostManifest{
		ID:        "quote-verification",
		HostID:    "local",
		Timestamp: time.Now(),
		Nonce:     req.GetQuote().GetNonce(),
		Host: &manifest.HostAttestation{
			QuoteData:     req.GetQuote().GetQuoteData(),
			Signature:     req.GetQuote().GetSignature(),
			PCRs:          protoPCRsToManifest(req.GetQuote().GetPcrValues()),
			Nonce:         req.GetQuote().GetNonce(),
			Timestamp:     time.Now(),
			HashAlgorithm: manifest.HashAlgorithmSHA256,
		},
		MerkleRoot: []byte("placeholder"),
	}

	expectedPCRs := make(map[int][]byte)
	for _, pcr := range req.GetExpectedPcrs() {
		expectedPCRs[int(pcr.GetIndex())] = pcr.GetValue()
	}

	config := &manifest.VerifierConfig{
		RequireHostAttestation: true,
		VerifyMerkleRoot:       false,
		HashAlgorithm:          manifest.HashAlgorithmSHA256,
	}

	result, err := s.service.VerifyManifest(ctx, hostManifest, config, req.GetExpectedNonce(), req.GetAkPublicKeyPem(), expectedPCRs)
	if err != nil {
		return nil, s.mapError("VerifyAttestationQuote", err)
	}

	verified := result.Status == manifest.VerificationStatusVerified
	message := "quote verification completed"
	if !verified && len(result.Errors) > 0 {
		message = result.Errors[0]
	}

	actualPCRs := make([]*platformv1.AttestationPCRValue, 0, len(req.GetQuote().GetPcrValues()))
	actualPCRs = append(actualPCRs, req.GetQuote().GetPcrValues()...)

	return &platformv1.VerifyAttestationQuoteResponse{
		Status:     attestationSuccessStatus("quote verification completed"),
		Verified:   verified,
		Message:    message,
		ActualPcrs: actualPCRs,
	}, nil
}

// CollectHostAttestation collects attestation data from the host TPM.
func (s *AttestationGRPCService) CollectHostAttestation(
	ctx context.Context,
	req *platformv1.CollectHostAttestationRequest,
) (*platformv1.CollectHostAttestationResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingNonce{}.Error())
	}

	config := protoQuoteConfigToInternal(req.GetConfig())

	attestation, err := s.service.CollectHostAttestation(ctx, config, req.GetNonce())
	if err != nil {
		return nil, s.mapError("CollectHostAttestation", err)
	}

	return &platformv1.CollectHostAttestationResponse{
		Status:      attestationSuccessStatus("host attestation collected successfully"),
		Attestation: hostAttestationToProto(attestation),
	}, nil
}

// CollectVMAttestation collects attestation data from a VM's vTPM.
func (s *AttestationGRPCService) CollectVMAttestation(
	ctx context.Context,
	req *platformv1.CollectVMAttestationRequest,
) (*platformv1.CollectVMAttestationResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if req.GetVmId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingVMID{}.Error())
	}

	if len(req.GetNonce()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingNonce{}.Error())
	}

	config := protoQuoteConfigToInternal(req.GetConfig())

	attestation, err := s.service.CollectVMAttestation(ctx, req.GetVmId(), config, req.GetNonce())
	if err != nil {
		return nil, s.mapError("CollectVMAttestation", err)
	}

	return &platformv1.CollectVMAttestationResponse{
		Status:      attestationSuccessStatus("VM attestation collected successfully"),
		Attestation: vmAttestationToProto(attestation),
	}, nil
}

// CollectContainerAttestation collects attestation data for a container.
func (s *AttestationGRPCService) CollectContainerAttestation(
	ctx context.Context,
	req *platformv1.CollectContainerAttestationRequest,
) (*platformv1.CollectContainerAttestationResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrAttestationNilService{}.Error())
	}

	if req.GetContainerId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrAttestationMissingContainerID{}.Error())
	}

	attestation, err := s.service.CollectContainerAttestation(ctx, req.GetContainerId())
	if err != nil {
		return nil, s.mapError("CollectContainerAttestation", err)
	}

	return &platformv1.CollectContainerAttestationResponse{
		Status:      attestationSuccessStatus("container attestation collected successfully"),
		Attestation: containerAttestationToProto(attestation),
	}, nil
}

// Helper functions

func attestationSuccessStatus(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

func protoBuilderConfigToManifest(config *platformv1.ManifestBuilderConfig) *manifest.BuilderConfig {
	if config == nil {
		return &manifest.BuilderConfig{
			HashAlgorithm: manifest.HashAlgorithmSHA256,
			NonceSize:     32,
			Version:       "1.0",
		}
	}

	pcrIndices := make([]int, len(config.GetPcrIndices()))
	for i, idx := range config.GetPcrIndices() {
		pcrIndices[i] = int(idx)
	}

	nonceSize := int(config.GetNonceSize())
	if nonceSize < 16 {
		nonceSize = 32
	}

	return &manifest.BuilderConfig{
		HostID:        config.GetHostId(),
		HashAlgorithm: protoHashAlgorithmToManifest(config.GetHashAlgorithm()),
		PCRIndices:    pcrIndices,
		NonceSize:     nonceSize,
		Version:       config.GetVersion(),
	}
}

func protoVerifierConfigToManifest(config *platformv1.ManifestVerifierConfig) *manifest.VerifierConfig {
	if config == nil {
		return &manifest.VerifierConfig{
			RequireHostAttestation: true,
			VerifyMerkleRoot:       true,
			HashAlgorithm:          manifest.HashAlgorithmSHA256,
		}
	}

	return &manifest.VerifierConfig{
		MaxManifestAge:         config.GetMaxManifestAge(),
		RequireHostAttestation: config.GetRequireHostAttestation(),
		VerifyMerkleRoot:       config.GetVerifyMerkleRoot(),
		HashAlgorithm:          protoHashAlgorithmToManifest(config.GetHashAlgorithm()),
	}
}

func protoQuoteConfigToInternal(config *platformv1.AttestationQuoteConfig) *AttestationQuoteConfig {
	if config == nil {
		return &AttestationQuoteConfig{
			PCRIndices:    []int{0, 1, 2, 3, 4, 5, 6, 7},
			HashAlgorithm: manifest.HashAlgorithmSHA256,
		}
	}

	pcrIndices := make([]int, len(config.GetPcrIndices()))
	for i, idx := range config.GetPcrIndices() {
		pcrIndices[i] = int(idx)
	}

	return &AttestationQuoteConfig{
		AKHandle:      config.GetAkHandle(),
		PCRIndices:    pcrIndices,
		HashAlgorithm: protoHashAlgorithmToManifest(config.GetHashAlgorithm()),
	}
}

func protoHashAlgorithmToManifest(alg platformv1.AttestationHashAlgorithm) manifest.HashAlgorithm {
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

func manifestHashAlgorithmToProto(alg manifest.HashAlgorithm) platformv1.AttestationHashAlgorithm {
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

func protoExpectedPCRsToMap(expectedPCRs map[uint32][]byte) map[int][]byte {
	if expectedPCRs == nil {
		return nil
	}

	result := make(map[int][]byte, len(expectedPCRs))
	for idx, value := range expectedPCRs {
		result[int(idx)] = value
	}
	return result
}

func hostManifestToProto(m *manifest.HostManifest) *platformv1.HostManifest {
	if m == nil {
		return nil
	}

	proto := &platformv1.HostManifest{
		Id:                 m.ID,
		HostId:             m.HostID,
		Timestamp:          timestamppb.New(m.Timestamp),
		Nonce:              m.Nonce,
		MerkleRoot:         m.MerkleRoot,
		Signature:          m.Signature,
		SignatureAlgorithm: m.SignatureAlgorithm,
		Version:            m.Version,
		Metadata:           m.Metadata,
	}

	if m.Host != nil {
		proto.Host = hostAttestationToProto(m.Host)
	}

	proto.Vms = make([]*platformv1.VMAttestation, 0, len(m.VMs))
	for i := range m.VMs {
		proto.Vms = append(proto.Vms, vmAttestationToProto(&m.VMs[i]))
	}

	proto.Containers = make([]*platformv1.ContainerAttestation, 0, len(m.Containers))
	for i := range m.Containers {
		proto.Containers = append(proto.Containers, containerAttestationToProto(&m.Containers[i]))
	}

	return proto
}

func protoToHostManifest(proto *platformv1.HostManifest) *manifest.HostManifest {
	if proto == nil {
		return nil
	}

	m := &manifest.HostManifest{
		ID:                 proto.GetId(),
		HostID:             proto.GetHostId(),
		Nonce:              proto.GetNonce(),
		MerkleRoot:         proto.GetMerkleRoot(),
		Signature:          proto.GetSignature(),
		SignatureAlgorithm: proto.GetSignatureAlgorithm(),
		Version:            proto.GetVersion(),
		Metadata:           proto.GetMetadata(),
	}

	if proto.GetTimestamp() != nil {
		m.Timestamp = proto.GetTimestamp().AsTime()
	}

	if proto.GetHost() != nil {
		m.Host = protoToHostAttestation(proto.GetHost())
	}

	m.VMs = make([]manifest.VMAttestation, 0, len(proto.GetVms()))
	for _, vm := range proto.GetVms() {
		if vm != nil {
			m.VMs = append(m.VMs, *protoToVMAttestation(vm))
		}
	}

	m.Containers = make([]manifest.ContainerAttestation, 0, len(proto.GetContainers()))
	for _, c := range proto.GetContainers() {
		if c != nil {
			m.Containers = append(m.Containers, *protoToContainerAttestation(c))
		}
	}

	return m
}

func hostAttestationToProto(a *manifest.HostAttestation) *platformv1.HostAttestation {
	if a == nil {
		return nil
	}

	return &platformv1.HostAttestation{
		QuoteData:          a.QuoteData,
		Signature:          a.Signature,
		SignatureAlgorithm: a.SignatureAlgorithm,
		Pcrs:               pcrValuesToProto(a.PCRs),
		PcrDigest:          a.PCRDigest,
		Nonce:              a.Nonce,
		Timestamp:          timestamppb.New(a.Timestamp),
		AkPublicKey:        a.AKPublicKey,
		IdevidCertificate:  a.IDevIDCertificate,
		HashAlgorithm:      manifestHashAlgorithmToProto(a.HashAlgorithm),
		FirmwareVersion:    a.FirmwareVersion,
	}
}

func protoToHostAttestation(proto *platformv1.HostAttestation) *manifest.HostAttestation {
	if proto == nil {
		return nil
	}

	a := &manifest.HostAttestation{
		QuoteData:          proto.GetQuoteData(),
		Signature:          proto.GetSignature(),
		SignatureAlgorithm: proto.GetSignatureAlgorithm(),
		PCRs:               protoPCRsToManifest(proto.GetPcrs()),
		PCRDigest:          proto.GetPcrDigest(),
		Nonce:              proto.GetNonce(),
		AKPublicKey:        proto.GetAkPublicKey(),
		IDevIDCertificate:  proto.GetIdevidCertificate(),
		HashAlgorithm:      protoHashAlgorithmToManifest(proto.GetHashAlgorithm()),
		FirmwareVersion:    proto.GetFirmwareVersion(),
	}

	if proto.GetTimestamp() != nil {
		a.Timestamp = proto.GetTimestamp().AsTime()
	}

	return a
}

func vmAttestationToProto(a *manifest.VMAttestation) *platformv1.VMAttestation {
	if a == nil {
		return nil
	}

	return &platformv1.VMAttestation{
		VmId:               a.VMID,
		HostId:             a.HostID,
		QuoteData:          a.QuoteData,
		Signature:          a.Signature,
		SignatureAlgorithm: a.SignatureAlgorithm,
		Pcrs:               pcrValuesToProto(a.PCRs),
		PcrDigest:          a.PCRDigest,
		Nonce:              a.Nonce,
		Timestamp:          timestamppb.New(a.Timestamp),
		AikPublicKey:       a.AIKPublicKey,
		EkCertificate:      a.EKCertificate,
		WorkloadPcr:        a.WorkloadPCR,
		HashAlgorithm:      manifestHashAlgorithmToProto(a.HashAlgorithm),
		Metadata:           a.Metadata,
	}
}

func protoToVMAttestation(proto *platformv1.VMAttestation) *manifest.VMAttestation {
	if proto == nil {
		return nil
	}

	a := &manifest.VMAttestation{
		VMID:               proto.GetVmId(),
		HostID:             proto.GetHostId(),
		QuoteData:          proto.GetQuoteData(),
		Signature:          proto.GetSignature(),
		SignatureAlgorithm: proto.GetSignatureAlgorithm(),
		PCRs:               protoPCRsToManifest(proto.GetPcrs()),
		PCRDigest:          proto.GetPcrDigest(),
		Nonce:              proto.GetNonce(),
		AIKPublicKey:       proto.GetAikPublicKey(),
		EKCertificate:      proto.GetEkCertificate(),
		WorkloadPCR:        proto.GetWorkloadPcr(),
		HashAlgorithm:      protoHashAlgorithmToManifest(proto.GetHashAlgorithm()),
		Metadata:           proto.GetMetadata(),
	}

	if proto.GetTimestamp() != nil {
		a.Timestamp = proto.GetTimestamp().AsTime()
	}

	return a
}

func containerAttestationToProto(a *manifest.ContainerAttestation) *platformv1.ContainerAttestation {
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

func protoToContainerAttestation(proto *platformv1.ContainerAttestation) *manifest.ContainerAttestation {
	if proto == nil {
		return nil
	}

	a := &manifest.ContainerAttestation{
		ContainerID: proto.GetContainerId(),
		ImageID:     proto.GetImageId(),
		ImageDigest: proto.GetImageDigest(),
		Digest:      proto.GetDigest(),
		PCRValue:    proto.GetPcrValue(),
		Metadata:    proto.GetMetadata(),
	}

	if proto.GetTimestamp() != nil {
		a.Timestamp = proto.GetTimestamp().AsTime()
	}

	return a
}

func pcrValuesToProto(pcrs []manifest.PCRValue) []*platformv1.AttestationPCRValue {
	result := make([]*platformv1.AttestationPCRValue, 0, len(pcrs))
	for _, pcr := range pcrs {
		result = append(result, &platformv1.AttestationPCRValue{
			Index:     uint32(pcr.Index),
			Value:     pcr.Value,
			Algorithm: manifestHashAlgorithmToProto(pcr.Algorithm),
		})
	}
	return result
}

func protoPCRsToManifest(pcrs []*platformv1.AttestationPCRValue) []manifest.PCRValue {
	result := make([]manifest.PCRValue, 0, len(pcrs))
	for _, pcr := range pcrs {
		if pcr != nil {
			result = append(result, manifest.PCRValue{
				Index:     int(pcr.GetIndex()),
				Value:     pcr.GetValue(),
				Algorithm: protoHashAlgorithmToManifest(pcr.GetAlgorithm()),
			})
		}
	}
	return result
}

func verificationResultToProto(r *manifest.VerificationResult) *platformv1.ManifestVerificationResult {
	if r == nil {
		return nil
	}

	return &platformv1.ManifestVerificationResult{
		Status:                     manifestVerificationStatusToProto(r.Status),
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

func manifestVerificationStatusToProto(status manifest.VerificationStatus) platformv1.ManifestVerificationStatus {
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

// mapError maps attestation errors to appropriate gRPC status codes.
func (s *AttestationGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "attestation operation failed", "operation", operation)

	// Check for attestation-specific errors
	switch err.(type) {
	case ErrAttestationOperationFailed:
		return status.Errorf(codes.Internal, "attestation operation failed: %v", err)
	case ErrAttestationInvalidRequest:
		return status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	case ErrAttestationServiceUnavailable:
		return status.Error(codes.Unavailable, err.Error())
	}

	// Check for manifest-level errors
	switch err.(type) {
	case manifest.ErrInvalidManifest:
		return status.Errorf(codes.InvalidArgument, "invalid manifest: %v", err)
	case manifest.ErrInvalidConfig:
		return status.Errorf(codes.InvalidArgument, "invalid configuration: %v", err)
	case manifest.ErrInvalidHashAlgorithm:
		return status.Errorf(codes.InvalidArgument, "invalid hash algorithm: %v", err)
	}

	// Default to internal error
	return status.Error(codes.Internal, err.Error())
}

// Ensure AttestationGRPCService implements the AttestationServiceServer interface.
var _ platformv1.AttestationServiceServer = (*AttestationGRPCService)(nil)
