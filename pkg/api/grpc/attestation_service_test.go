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
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockAttestationService implements AttestationService for testing.
type mockAttestationService struct {
	getManifestResp                 *manifest.HostManifest
	getManifestErr                  error
	buildManifestResp               *manifest.HostManifest
	buildManifestErr                error
	verifyManifestResp              *manifest.VerificationResult
	verifyManifestErr               error
	listManifestsResp               []*manifest.HostManifest
	listManifestsTotal              int
	listManifestsErr                error
	deleteManifestErr               error
	collectHostAttestationResp      *manifest.HostAttestation
	collectHostAttestationErr       error
	collectVMAttestationResp        *manifest.VMAttestation
	collectVMAttestationErr         error
	collectContainerAttestationResp *manifest.ContainerAttestation
	collectContainerAttestationErr  error
}

func newMockAttestationService() *mockAttestationService {
	now := time.Now()
	return &mockAttestationService{
		getManifestResp: &manifest.HostManifest{
			ID:        "test-manifest-id",
			HostID:    "test-host-id",
			Timestamp: now,
			Nonce:     []byte("test-nonce-12345"),
			Host: &manifest.HostAttestation{
				QuoteData:          []byte("test-quote-data"),
				Signature:          []byte("test-signature"),
				SignatureAlgorithm: "RSA-PSS-SHA256",
				PCRs: []manifest.PCRValue{
					{Index: 0, Value: []byte("pcr0-value"), Algorithm: manifest.HashAlgorithmSHA256},
					{Index: 1, Value: []byte("pcr1-value"), Algorithm: manifest.HashAlgorithmSHA256},
				},
				PCRDigest:     []byte("pcr-digest"),
				Nonce:         []byte("host-nonce"),
				Timestamp:     now,
				AKPublicKey:   []byte("ak-public-key"),
				HashAlgorithm: manifest.HashAlgorithmSHA256,
			},
			VMs:        []manifest.VMAttestation{},
			Containers: []manifest.ContainerAttestation{},
			MerkleRoot: []byte("merkle-root-hash"),
			Signature:  []byte("manifest-signature"),
			Version:    "1.0",
		},
		buildManifestResp: &manifest.HostManifest{
			ID:        "new-manifest-id",
			HostID:    "test-host-id",
			Timestamp: now,
			Nonce:     []byte("new-nonce-12345"),
			Host: &manifest.HostAttestation{
				QuoteData:     []byte("new-quote-data"),
				Signature:     []byte("new-signature"),
				PCRs:          []manifest.PCRValue{{Index: 0, Value: []byte("pcr0"), Algorithm: manifest.HashAlgorithmSHA256}},
				Nonce:         []byte("new-nonce"),
				Timestamp:     now,
				HashAlgorithm: manifest.HashAlgorithmSHA256,
			},
			MerkleRoot: []byte("new-merkle-root"),
			Version:    "1.0",
		},
		verifyManifestResp: &manifest.VerificationResult{
			Status:                     manifest.VerificationStatusVerified,
			SignatureValid:             true,
			MerkleRootValid:            true,
			NonceValid:                 true,
			TimestampValid:             true,
			HostAttestationValid:       true,
			VMAttestationsValid:        true,
			ContainerAttestationsValid: true,
			VerifiedAt:                 now,
			Errors:                     []string{},
		},
		listManifestsResp: []*manifest.HostManifest{
			{ID: "manifest-1", HostID: "host-1", Timestamp: now, Nonce: []byte("nonce1"), MerkleRoot: []byte("root1")},
			{ID: "manifest-2", HostID: "host-1", Timestamp: now, Nonce: []byte("nonce2"), MerkleRoot: []byte("root2")},
		},
		listManifestsTotal: 2,
		collectHostAttestationResp: &manifest.HostAttestation{
			QuoteData:          []byte("host-quote-data"),
			Signature:          []byte("host-signature"),
			SignatureAlgorithm: "RSA-PSS-SHA256",
			PCRs: []manifest.PCRValue{
				{Index: 0, Value: []byte("pcr0"), Algorithm: manifest.HashAlgorithmSHA256},
			},
			PCRDigest:     []byte("host-pcr-digest"),
			Nonce:         []byte("request-nonce"),
			Timestamp:     now,
			AKPublicKey:   []byte("host-ak-key"),
			HashAlgorithm: manifest.HashAlgorithmSHA256,
		},
		collectVMAttestationResp: &manifest.VMAttestation{
			VMID:          "test-vm-id",
			HostID:        "test-host-id",
			QuoteData:     []byte("vm-quote-data"),
			Signature:     []byte("vm-signature"),
			PCRs:          []manifest.PCRValue{{Index: 0, Value: []byte("vm-pcr0"), Algorithm: manifest.HashAlgorithmSHA256}},
			Nonce:         []byte("vm-nonce"),
			Timestamp:     now,
			AIKPublicKey:  []byte("vm-aik-key"),
			HashAlgorithm: manifest.HashAlgorithmSHA256,
		},
		collectContainerAttestationResp: &manifest.ContainerAttestation{
			ContainerID: "test-container-id",
			ImageID:     "test-image-id",
			ImageDigest: "sha256:abc123",
			Digest:      []byte("container-digest"),
			PCRValue:    []byte("pcr14-value"),
			Timestamp:   now,
		},
	}
}

func (m *mockAttestationService) GetManifest(ctx context.Context, id string) (*manifest.HostManifest, error) {
	if m.getManifestErr != nil {
		return nil, m.getManifestErr
	}
	return m.getManifestResp, nil
}

func (m *mockAttestationService) BuildManifest(ctx context.Context, config *manifest.BuilderConfig, nonce []byte, options *AttestationBuildOptions) (*manifest.HostManifest, error) {
	if m.buildManifestErr != nil {
		return nil, m.buildManifestErr
	}
	return m.buildManifestResp, nil
}

func (m *mockAttestationService) VerifyManifest(ctx context.Context, mnfst *manifest.HostManifest, config *manifest.VerifierConfig, expectedNonce []byte, publicKey []byte, expectedPCRs map[int][]byte) (*manifest.VerificationResult, error) {
	if m.verifyManifestErr != nil {
		return nil, m.verifyManifestErr
	}
	return m.verifyManifestResp, nil
}

func (m *mockAttestationService) ListManifests(ctx context.Context, filter *AttestationListFilter) ([]*manifest.HostManifest, int, error) {
	if m.listManifestsErr != nil {
		return nil, 0, m.listManifestsErr
	}
	return m.listManifestsResp, m.listManifestsTotal, nil
}

func (m *mockAttestationService) DeleteManifest(ctx context.Context, id string) error {
	return m.deleteManifestErr
}

func (m *mockAttestationService) CollectHostAttestation(ctx context.Context, config *AttestationQuoteConfig, nonce []byte) (*manifest.HostAttestation, error) {
	if m.collectHostAttestationErr != nil {
		return nil, m.collectHostAttestationErr
	}
	return m.collectHostAttestationResp, nil
}

func (m *mockAttestationService) CollectVMAttestation(ctx context.Context, vmID string, config *AttestationQuoteConfig, nonce []byte) (*manifest.VMAttestation, error) {
	if m.collectVMAttestationErr != nil {
		return nil, m.collectVMAttestationErr
	}
	return m.collectVMAttestationResp, nil
}

func (m *mockAttestationService) CollectContainerAttestation(ctx context.Context, containerID string) (*manifest.ContainerAttestation, error) {
	if m.collectContainerAttestationErr != nil {
		return nil, m.collectContainerAttestationErr
	}
	return m.collectContainerAttestationResp, nil
}

// Ensure mockAttestationService implements AttestationService at compile time.
var _ AttestationService = (*mockAttestationService)(nil)

func newTestAttestationService() (*AttestationGRPCService, *mockAttestationService) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	mock := newMockAttestationService()
	service := NewAttestationGRPCService(logger, mock)
	return service, mock
}

// =============================================================================
// GetManifest Tests
// =============================================================================

func TestAttestationGRPCService_GetManifest_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.GetManifestRequest{
		Id: "test-manifest-id",
	}

	resp, err := service.GetManifest(ctx, req)
	if err != nil {
		t.Fatalf("GetManifest failed: %v", err)
	}

	if resp.GetManifest() == nil {
		t.Error("Expected manifest in response")
	}

	if resp.GetManifest().GetId() != "test-manifest-id" {
		t.Errorf("Expected manifest ID 'test-manifest-id', got '%s'", resp.GetManifest().GetId())
	}

	if resp.GetManifest().GetHostId() != "test-host-id" {
		t.Errorf("Expected host ID 'test-host-id', got '%s'", resp.GetManifest().GetHostId())
	}
}

func TestAttestationGRPCService_GetManifest_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GetManifestRequest{Id: "test-id"}

	_, err := service.GetManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_GetManifest_MissingID(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.GetManifestRequest{Id: ""}

	_, err := service.GetManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_GetManifest_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.getManifestErr = ErrAttestationOperationFailed{Operation: "GetManifest", Cause: errors.New("not found")}
	ctx := context.Background()

	req := &platformv1.GetManifestRequest{Id: "nonexistent"}

	_, err := service.GetManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal error, got %v", st.Code())
	}
}

// =============================================================================
// BuildManifest Tests
// =============================================================================

func TestAttestationGRPCService_BuildManifest_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{
			HostId:        "test-host",
			HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
			PcrIndices:    []uint32{0, 1, 2, 3, 4, 5, 6, 7},
			NonceSize:     32,
			Version:       "1.0",
		},
		Nonce:             []byte("request-nonce"),
		IncludeVms:        true,
		IncludeContainers: true,
		Sign:              true,
	}

	resp, err := service.BuildManifest(ctx, req)
	if err != nil {
		t.Fatalf("BuildManifest failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetManifest() == nil {
		t.Error("Expected manifest in response")
	}

	if resp.GetManifest().GetId() != "new-manifest-id" {
		t.Errorf("Expected manifest ID 'new-manifest-id', got '%s'", resp.GetManifest().GetId())
	}
}

func TestAttestationGRPCService_BuildManifest_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{HostId: "test"},
	}

	_, err := service.BuildManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_BuildManifest_MissingConfig(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.BuildManifestRequest{
		Nonce: []byte("test-nonce"),
	}

	_, err := service.BuildManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing config")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_BuildManifest_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.buildManifestErr = ErrAttestationOperationFailed{Operation: "BuildManifest", Cause: errors.New("TPM error")}
	ctx := context.Background()

	req := &platformv1.BuildManifestRequest{
		Config: &platformv1.ManifestBuilderConfig{HostId: "test"},
	}

	_, err := service.BuildManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// =============================================================================
// VerifyManifest Tests
// =============================================================================

func TestAttestationGRPCService_VerifyManifest_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.VerifyManifestRequest{
		Manifest: &platformv1.HostManifest{
			Id:         "test-manifest",
			HostId:     "test-host",
			Timestamp:  timestamppb.Now(),
			Nonce:      []byte("test-nonce"),
			MerkleRoot: []byte("merkle-root"),
			Host: &platformv1.HostAttestation{
				QuoteData:     []byte("quote"),
				Signature:     []byte("sig"),
				Pcrs:          []*platformv1.AttestationPCRValue{{Index: 0, Value: []byte("pcr0")}},
				Nonce:         []byte("nonce"),
				HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
			},
		},
		Config: &platformv1.ManifestVerifierConfig{
			RequireHostAttestation: true,
			VerifyMerkleRoot:       true,
			HashAlgorithm:          platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
		},
		ExpectedNonce: []byte("test-nonce"),
		PublicKeyPem:  []byte("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"),
	}

	resp, err := service.VerifyManifest(ctx, req)
	if err != nil {
		t.Fatalf("VerifyManifest failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetResult() == nil {
		t.Error("Expected verification result in response")
	}

	if resp.GetResult().GetStatus() != platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED {
		t.Errorf("Expected VERIFIED status, got %v", resp.GetResult().GetStatus())
	}
}

func TestAttestationGRPCService_VerifyManifest_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.VerifyManifestRequest{
		Manifest: &platformv1.HostManifest{Id: "test"},
	}

	_, err := service.VerifyManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_VerifyManifest_MissingManifest(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.VerifyManifestRequest{
		Config: &platformv1.ManifestVerifierConfig{},
	}

	_, err := service.VerifyManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing manifest")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_VerifyManifest_VerificationFailed(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.verifyManifestResp = &manifest.VerificationResult{
		Status:         manifest.VerificationStatusFailed,
		SignatureValid: false,
		Errors:         []string{"signature verification failed"},
		VerifiedAt:     time.Now(),
	}
	ctx := context.Background()

	req := &platformv1.VerifyManifestRequest{
		Manifest: &platformv1.HostManifest{
			Id:         "test-manifest",
			HostId:     "test-host",
			Nonce:      []byte("nonce"),
			MerkleRoot: []byte("root"),
		},
	}

	resp, err := service.VerifyManifest(ctx, req)
	if err != nil {
		t.Fatalf("VerifyManifest should not error on failed verification: %v", err)
	}

	if resp.GetResult().GetStatus() != platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_FAILED {
		t.Errorf("Expected FAILED status, got %v", resp.GetResult().GetStatus())
	}

	if len(resp.GetResult().GetErrors()) == 0 {
		t.Error("Expected errors in verification result")
	}
}

// =============================================================================
// ListManifests Tests
// =============================================================================

func TestAttestationGRPCService_ListManifests_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.ListManifestsRequest{
		HostId: "host-1",
		Limit:  10,
		Offset: 0,
	}

	resp, err := service.ListManifests(ctx, req)
	if err != nil {
		t.Fatalf("ListManifests failed: %v", err)
	}

	if len(resp.GetManifests()) != 2 {
		t.Errorf("Expected 2 manifests, got %d", len(resp.GetManifests()))
	}

	if resp.GetTotal() != 2 {
		t.Errorf("Expected total 2, got %d", resp.GetTotal())
	}
}

func TestAttestationGRPCService_ListManifests_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ListManifestsRequest{}

	_, err := service.ListManifests(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_ListManifests_WithTimeFilter(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	now := time.Now()
	req := &platformv1.ListManifestsRequest{
		StartTime: timestamppb.New(now.Add(-24 * time.Hour)),
		EndTime:   timestamppb.New(now),
		Limit:     100,
	}

	resp, err := service.ListManifests(ctx, req)
	if err != nil {
		t.Fatalf("ListManifests with time filter failed: %v", err)
	}

	if resp.GetManifests() == nil {
		t.Error("Expected manifests in response")
	}
}

func TestAttestationGRPCService_ListManifests_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.listManifestsErr = errors.New("database error")
	ctx := context.Background()

	req := &platformv1.ListManifestsRequest{}

	_, err := service.ListManifests(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// =============================================================================
// DeleteManifest Tests
// =============================================================================

func TestAttestationGRPCService_DeleteManifest_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.DeleteManifestRequest{
		Id: "manifest-to-delete",
	}

	resp, err := service.DeleteManifest(ctx, req)
	if err != nil {
		t.Fatalf("DeleteManifest failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestAttestationGRPCService_DeleteManifest_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.DeleteManifestRequest{Id: "test"}

	_, err := service.DeleteManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_DeleteManifest_MissingID(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.DeleteManifestRequest{Id: ""}

	_, err := service.DeleteManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_DeleteManifest_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.deleteManifestErr = errors.New("deletion failed")
	ctx := context.Background()

	req := &platformv1.DeleteManifestRequest{Id: "test-id"}

	_, err := service.DeleteManifest(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// =============================================================================
// GetAttestationQuote Tests
// =============================================================================

func TestAttestationGRPCService_GetAttestationQuote_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.GetAttestationQuoteRequest{
		Config: &platformv1.AttestationQuoteConfig{
			AkHandle:      0x81010001,
			PcrIndices:    []uint32{0, 1, 2, 3},
			HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
		},
		Nonce: []byte("quote-nonce-12345"),
	}

	resp, err := service.GetAttestationQuote(ctx, req)
	if err != nil {
		t.Fatalf("GetAttestationQuote failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetQuote() == nil {
		t.Error("Expected quote in response")
	}

	if len(resp.GetQuote().GetQuoteData()) == 0 {
		t.Error("Expected quote data in response")
	}
}

func TestAttestationGRPCService_GetAttestationQuote_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GetAttestationQuoteRequest{Nonce: []byte("nonce")}

	_, err := service.GetAttestationQuote(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_GetAttestationQuote_MissingNonce(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.GetAttestationQuoteRequest{
		Config: &platformv1.AttestationQuoteConfig{},
	}

	_, err := service.GetAttestationQuote(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing nonce")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_GetAttestationQuote_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.collectHostAttestationErr = ErrAttestationOperationFailed{Operation: "quote", Cause: errors.New("TPM error")}
	ctx := context.Background()

	req := &platformv1.GetAttestationQuoteRequest{
		Nonce: []byte("test-nonce"),
	}

	_, err := service.GetAttestationQuote(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// =============================================================================
// VerifyAttestationQuote Tests
// =============================================================================

func TestAttestationGRPCService_VerifyAttestationQuote_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.VerifyAttestationQuoteRequest{
		Quote: &platformv1.AttestationQuote{
			QuoteData: []byte("quote-data"),
			Signature: []byte("signature"),
			PcrValues: []*platformv1.AttestationPCRValue{
				{Index: 0, Value: []byte("pcr0"), Algorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256},
			},
			Nonce: []byte("quote-nonce"),
		},
		AkPublicKeyPem: []byte("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"),
		ExpectedNonce:  []byte("quote-nonce"),
	}

	resp, err := service.VerifyAttestationQuote(ctx, req)
	if err != nil {
		t.Fatalf("VerifyAttestationQuote failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if !resp.GetVerified() {
		t.Error("Expected quote to be verified")
	}
}

func TestAttestationGRPCService_VerifyAttestationQuote_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.VerifyAttestationQuoteRequest{
		Quote:          &platformv1.AttestationQuote{},
		AkPublicKeyPem: []byte("key"),
	}

	_, err := service.VerifyAttestationQuote(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_VerifyAttestationQuote_MissingQuote(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.VerifyAttestationQuoteRequest{
		AkPublicKeyPem: []byte("key"),
	}

	_, err := service.VerifyAttestationQuote(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing quote")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_VerifyAttestationQuote_MissingAKPublicKey(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.VerifyAttestationQuoteRequest{
		Quote: &platformv1.AttestationQuote{},
	}

	_, err := service.VerifyAttestationQuote(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing AK public key")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// =============================================================================
// CollectHostAttestation Tests
// =============================================================================

func TestAttestationGRPCService_CollectHostAttestation_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.CollectHostAttestationRequest{
		Config: &platformv1.AttestationQuoteConfig{
			PcrIndices:    []uint32{0, 1, 2},
			HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
		},
		Nonce: []byte("host-collection-nonce"),
	}

	resp, err := service.CollectHostAttestation(ctx, req)
	if err != nil {
		t.Fatalf("CollectHostAttestation failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetAttestation() == nil {
		t.Error("Expected attestation in response")
	}

	if len(resp.GetAttestation().GetQuoteData()) == 0 {
		t.Error("Expected quote data in attestation")
	}
}

func TestAttestationGRPCService_CollectHostAttestation_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.CollectHostAttestationRequest{Nonce: []byte("nonce")}

	_, err := service.CollectHostAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_CollectHostAttestation_MissingNonce(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.CollectHostAttestationRequest{
		Config: &platformv1.AttestationQuoteConfig{},
	}

	_, err := service.CollectHostAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing nonce")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_CollectHostAttestation_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.collectHostAttestationErr = errors.New("TPM not available")
	ctx := context.Background()

	req := &platformv1.CollectHostAttestationRequest{
		Nonce: []byte("nonce"),
	}

	_, err := service.CollectHostAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// =============================================================================
// CollectVMAttestation Tests
// =============================================================================

func TestAttestationGRPCService_CollectVMAttestation_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.CollectVMAttestationRequest{
		VmId: "test-vm-id",
		Config: &platformv1.AttestationQuoteConfig{
			PcrIndices: []uint32{0, 1, 14},
		},
		Nonce: []byte("vm-collection-nonce"),
	}

	resp, err := service.CollectVMAttestation(ctx, req)
	if err != nil {
		t.Fatalf("CollectVMAttestation failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetAttestation() == nil {
		t.Error("Expected attestation in response")
	}

	if resp.GetAttestation().GetVmId() != "test-vm-id" {
		t.Errorf("Expected VM ID 'test-vm-id', got '%s'", resp.GetAttestation().GetVmId())
	}
}

func TestAttestationGRPCService_CollectVMAttestation_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.CollectVMAttestationRequest{VmId: "vm", Nonce: []byte("nonce")}

	_, err := service.CollectVMAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_CollectVMAttestation_MissingVMID(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.CollectVMAttestationRequest{
		Nonce: []byte("nonce"),
	}

	_, err := service.CollectVMAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing VM ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_CollectVMAttestation_MissingNonce(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.CollectVMAttestationRequest{
		VmId: "test-vm",
	}

	_, err := service.CollectVMAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing nonce")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_CollectVMAttestation_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.collectVMAttestationErr = errors.New("VM not found")
	ctx := context.Background()

	req := &platformv1.CollectVMAttestationRequest{
		VmId:  "nonexistent-vm",
		Nonce: []byte("nonce"),
	}

	_, err := service.CollectVMAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// =============================================================================
// CollectContainerAttestation Tests
// =============================================================================

func TestAttestationGRPCService_CollectContainerAttestation_Success(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.CollectContainerAttestationRequest{
		ContainerId: "test-container-id",
	}

	resp, err := service.CollectContainerAttestation(ctx, req)
	if err != nil {
		t.Fatalf("CollectContainerAttestation failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetAttestation() == nil {
		t.Error("Expected attestation in response")
	}

	if resp.GetAttestation().GetContainerId() != "test-container-id" {
		t.Errorf("Expected container ID 'test-container-id', got '%s'", resp.GetAttestation().GetContainerId())
	}
}

func TestAttestationGRPCService_CollectContainerAttestation_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewAttestationGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.CollectContainerAttestationRequest{ContainerId: "container"}

	_, err := service.CollectContainerAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestAttestationGRPCService_CollectContainerAttestation_MissingContainerID(t *testing.T) {
	service, _ := newTestAttestationService()
	ctx := context.Background()

	req := &platformv1.CollectContainerAttestationRequest{ContainerId: ""}

	_, err := service.CollectContainerAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing container ID")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestAttestationGRPCService_CollectContainerAttestation_ServiceError(t *testing.T) {
	service, mock := newTestAttestationService()
	mock.collectContainerAttestationErr = errors.New("container not found")
	ctx := context.Background()

	req := &platformv1.CollectContainerAttestationRequest{
		ContainerId: "nonexistent-container",
	}

	_, err := service.CollectContainerAttestation(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestProtoBuilderConfigToManifest_NilConfig(t *testing.T) {
	result := protoBuilderConfigToManifest(nil)
	if result == nil {
		t.Fatal("Expected default config for nil input")
	}

	if result.HashAlgorithm != manifest.HashAlgorithmSHA256 {
		t.Errorf("Expected SHA256, got %s", result.HashAlgorithm)
	}

	if result.NonceSize != 32 {
		t.Errorf("Expected nonce size 32, got %d", result.NonceSize)
	}
}

func TestProtoBuilderConfigToManifest_ValidConfig(t *testing.T) {
	config := &platformv1.ManifestBuilderConfig{
		HostId:        "test-host",
		HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384,
		PcrIndices:    []uint32{0, 1, 7, 14},
		NonceSize:     64,
		Version:       "2.0",
	}

	result := protoBuilderConfigToManifest(config)

	if result.HostID != "test-host" {
		t.Errorf("Expected host ID 'test-host', got '%s'", result.HostID)
	}

	if result.HashAlgorithm != manifest.HashAlgorithmSHA384 {
		t.Errorf("Expected SHA384, got %s", result.HashAlgorithm)
	}

	if len(result.PCRIndices) != 4 {
		t.Errorf("Expected 4 PCR indices, got %d", len(result.PCRIndices))
	}

	if result.NonceSize != 64 {
		t.Errorf("Expected nonce size 64, got %d", result.NonceSize)
	}
}

func TestProtoBuilderConfigToManifest_SmallNonceSize(t *testing.T) {
	config := &platformv1.ManifestBuilderConfig{
		NonceSize: 8, // Too small
	}

	result := protoBuilderConfigToManifest(config)

	if result.NonceSize != 32 {
		t.Errorf("Expected default nonce size 32 for small value, got %d", result.NonceSize)
	}
}

func TestProtoVerifierConfigToManifest_NilConfig(t *testing.T) {
	result := protoVerifierConfigToManifest(nil)
	if result == nil {
		t.Fatal("Expected default config for nil input")
	}

	if !result.RequireHostAttestation {
		t.Error("Expected RequireHostAttestation to be true")
	}

	if !result.VerifyMerkleRoot {
		t.Error("Expected VerifyMerkleRoot to be true")
	}
}

func TestProtoQuoteConfigToLocal_NilConfig(t *testing.T) {
	result := protoQuoteConfigToInternal(nil)
	if result == nil {
		t.Fatal("Expected default config for nil input")
	}

	if len(result.PCRIndices) != 8 {
		t.Errorf("Expected 8 default PCR indices, got %d", len(result.PCRIndices))
	}
}

func TestHashAlgorithmConversions(t *testing.T) {
	testCases := []struct {
		proto    platformv1.AttestationHashAlgorithm
		manifest manifest.HashAlgorithm
	}{
		{platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA1, manifest.HashAlgorithmSHA1},
		{platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256, manifest.HashAlgorithmSHA256},
		{platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384, manifest.HashAlgorithmSHA384},
		{platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA512, manifest.HashAlgorithmSHA512},
	}

	for _, tc := range testCases {
		t.Run(tc.manifest.String(), func(t *testing.T) {
			// Test proto to manifest
			result := protoHashAlgorithmToManifest(tc.proto)
			if result != tc.manifest {
				t.Errorf("protoHashAlgorithmToManifest: expected %s, got %s", tc.manifest, result)
			}

			// Test manifest to proto
			protoResult := manifestHashAlgorithmToProto(tc.manifest)
			if protoResult != tc.proto {
				t.Errorf("manifestHashAlgorithmToProto: expected %v, got %v", tc.proto, protoResult)
			}
		})
	}
}

func TestProtoExpectedPCRsToMap_NilInput(t *testing.T) {
	result := protoExpectedPCRsToMap(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestProtoExpectedPCRsToMap_ValidInput(t *testing.T) {
	input := map[uint32][]byte{
		0: []byte("pcr0"),
		7: []byte("pcr7"),
	}

	result := protoExpectedPCRsToMap(input)

	if len(result) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(result))
	}

	if string(result[0]) != "pcr0" {
		t.Errorf("Expected 'pcr0' for index 0")
	}

	if string(result[7]) != "pcr7" {
		t.Errorf("Expected 'pcr7' for index 7")
	}
}

func TestHostManifestToProto_NilInput(t *testing.T) {
	result := hostManifestToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestProtoToHostManifest_NilInput(t *testing.T) {
	result := protoToHostManifest(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestHostAttestationToProto_NilInput(t *testing.T) {
	result := hostAttestationToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestVMAttestationToProto_NilInput(t *testing.T) {
	result := vmAttestationToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestContainerAttestationToProto_NilInput(t *testing.T) {
	result := containerAttestationToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestProtoToVMAttestation(t *testing.T) {
	t.Parallel()

	t.Run("NilInput", func(t *testing.T) {
		t.Parallel()
		result := protoToVMAttestation(nil)
		if result != nil {
			t.Error("Expected nil for nil input")
		}
	})

	t.Run("ValidInput", func(t *testing.T) {
		t.Parallel()
		ts := time.Now().UTC()
		proto := &platformv1.VMAttestation{
			VmId:               "vm-123",
			HostId:             "host-456",
			QuoteData:          []byte("quote-data"),
			Signature:          []byte("signature"),
			SignatureAlgorithm: "RSASSA-PKCS1-v1_5",
			Pcrs: []*platformv1.AttestationPCRValue{
				{Index: 0, Value: []byte("pcr0"), Algorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256},
				{Index: 7, Value: []byte("pcr7"), Algorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA384},
			},
			PcrDigest:     []byte("pcr-digest"),
			Nonce:         []byte("nonce"),
			AikPublicKey:  []byte("aik-key"),
			EkCertificate: []byte("ek-cert"),
			WorkloadPcr:   []byte("workload-pcr"),
			HashAlgorithm: platformv1.AttestationHashAlgorithm_ATTESTATION_HASH_ALGORITHM_SHA256,
			Timestamp:     timestamppb.New(ts),
			Metadata:      map[string]string{"key": "value"},
		}

		result := protoToVMAttestation(proto)
		if result == nil {
			t.Fatal("Expected non-nil result")
		}

		if result.VMID != "vm-123" {
			t.Errorf("Expected VMID 'vm-123', got '%s'", result.VMID)
		}
		if result.HostID != "host-456" {
			t.Errorf("Expected HostID 'host-456', got '%s'", result.HostID)
		}
		if string(result.QuoteData) != "quote-data" {
			t.Errorf("Expected QuoteData 'quote-data', got '%s'", string(result.QuoteData))
		}
		if string(result.Signature) != "signature" {
			t.Errorf("Expected Signature 'signature', got '%s'", string(result.Signature))
		}
		if result.SignatureAlgorithm != "RSASSA-PKCS1-v1_5" {
			t.Errorf("Expected SignatureAlgorithm 'RSASSA-PKCS1-v1_5', got '%s'", result.SignatureAlgorithm)
		}
		if len(result.PCRs) != 2 {
			t.Errorf("Expected 2 PCRs, got %d", len(result.PCRs))
		}
		if result.PCRs[0].Index != 0 {
			t.Errorf("Expected PCR index 0, got %d", result.PCRs[0].Index)
		}
		if string(result.WorkloadPCR) != "workload-pcr" {
			t.Errorf("Expected WorkloadPCR 'workload-pcr', got '%s'", string(result.WorkloadPCR))
		}
		if result.HashAlgorithm != manifest.HashAlgorithmSHA256 {
			t.Errorf("Expected HashAlgorithm SHA256, got %v", result.HashAlgorithm)
		}
		if result.Timestamp.Unix() != ts.Unix() {
			t.Errorf("Expected timestamp %v, got %v", ts, result.Timestamp)
		}
		if result.Metadata["key"] != "value" {
			t.Errorf("Expected metadata key='value', got '%s'", result.Metadata["key"])
		}
	})

	t.Run("NilTimestamp", func(t *testing.T) {
		t.Parallel()
		proto := &platformv1.VMAttestation{
			VmId:      "vm-no-ts",
			Timestamp: nil,
		}

		result := protoToVMAttestation(proto)
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if result.VMID != "vm-no-ts" {
			t.Errorf("Expected VMID 'vm-no-ts', got '%s'", result.VMID)
		}
		// Timestamp should be zero value when proto timestamp is nil
		if !result.Timestamp.IsZero() {
			t.Errorf("Expected zero timestamp, got %v", result.Timestamp)
		}
	})
}

func TestProtoToContainerAttestation(t *testing.T) {
	t.Parallel()

	t.Run("NilInput", func(t *testing.T) {
		t.Parallel()
		result := protoToContainerAttestation(nil)
		if result != nil {
			t.Error("Expected nil for nil input")
		}
	})

	t.Run("ValidInput", func(t *testing.T) {
		t.Parallel()
		ts := time.Now().UTC()
		proto := &platformv1.ContainerAttestation{
			ContainerId: "container-abc",
			ImageId:     "image-def",
			ImageDigest: "sha256:abcd1234",
			Digest:      []byte("container-digest"),
			PcrValue:    []byte("pcr-value"),
			Timestamp:   timestamppb.New(ts),
			Metadata:    map[string]string{"env": "test"},
		}

		result := protoToContainerAttestation(proto)
		if result == nil {
			t.Fatal("Expected non-nil result")
		}

		if result.ContainerID != "container-abc" {
			t.Errorf("Expected ContainerID 'container-abc', got '%s'", result.ContainerID)
		}
		if result.ImageID != "image-def" {
			t.Errorf("Expected ImageID 'image-def', got '%s'", result.ImageID)
		}
		if result.ImageDigest != "sha256:abcd1234" {
			t.Errorf("Expected ImageDigest 'sha256:abcd1234', got '%s'", result.ImageDigest)
		}
		if string(result.Digest) != "container-digest" {
			t.Errorf("Expected Digest 'container-digest', got '%s'", string(result.Digest))
		}
		if string(result.PCRValue) != "pcr-value" {
			t.Errorf("Expected PCRValue 'pcr-value', got '%s'", string(result.PCRValue))
		}
		if result.Timestamp.Unix() != ts.Unix() {
			t.Errorf("Expected timestamp %v, got %v", ts, result.Timestamp)
		}
		if result.Metadata["env"] != "test" {
			t.Errorf("Expected metadata env='test', got '%s'", result.Metadata["env"])
		}
	})

	t.Run("NilTimestamp", func(t *testing.T) {
		t.Parallel()
		proto := &platformv1.ContainerAttestation{
			ContainerId: "container-no-ts",
			Timestamp:   nil,
		}

		result := protoToContainerAttestation(proto)
		if result == nil {
			t.Fatal("Expected non-nil result")
		}
		if result.ContainerID != "container-no-ts" {
			t.Errorf("Expected ContainerID 'container-no-ts', got '%s'", result.ContainerID)
		}
		// Timestamp should be zero value when proto timestamp is nil
		if !result.Timestamp.IsZero() {
			t.Errorf("Expected zero timestamp, got %v", result.Timestamp)
		}
	})
}

func TestVerificationResultToProto_NilInput(t *testing.T) {
	result := verificationResultToProto(nil)
	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestVerificationStatusConversion(t *testing.T) {
	testCases := []struct {
		manifest manifest.VerificationStatus
		proto    platformv1.ManifestVerificationStatus
	}{
		{manifest.VerificationStatusUnknown, platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_UNKNOWN},
		{manifest.VerificationStatusPending, platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_PENDING},
		{manifest.VerificationStatusVerified, platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED},
		{manifest.VerificationStatusFailed, platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_FAILED},
	}

	for _, tc := range testCases {
		t.Run(string(tc.manifest), func(t *testing.T) {
			result := manifestVerificationStatusToProto(tc.manifest)
			if result != tc.proto {
				t.Errorf("Expected %v, got %v", tc.proto, result)
			}
		})
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrorTypes(t *testing.T) {
	t.Run("ErrAttestationNilService", func(t *testing.T) {
		err := ErrAttestationNilService{}
		if err.Error() != "attestation service is nil" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingManifestID", func(t *testing.T) {
		err := ErrAttestationMissingManifestID{}
		if err.Error() != "manifest ID is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingBuilderConfig", func(t *testing.T) {
		err := ErrAttestationMissingBuilderConfig{}
		if err.Error() != "builder configuration is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingManifest", func(t *testing.T) {
		err := ErrAttestationMissingManifest{}
		if err.Error() != "manifest is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingNonce", func(t *testing.T) {
		err := ErrAttestationMissingNonce{}
		if err.Error() != "nonce is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingVMID", func(t *testing.T) {
		err := ErrAttestationMissingVMID{}
		if err.Error() != "VM ID is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingContainerID", func(t *testing.T) {
		err := ErrAttestationMissingContainerID{}
		if err.Error() != "container ID is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingQuote", func(t *testing.T) {
		err := ErrAttestationMissingQuote{}
		if err.Error() != "quote is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrAttestationMissingAKPublicKey", func(t *testing.T) {
		err := ErrAttestationMissingAKPublicKey{}
		if err.Error() != "AK public key is required" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestMapError_AttestationOperationFailed(t *testing.T) {
	service, _ := newTestAttestationService()
	err := ErrAttestationOperationFailed{Operation: "test", Cause: errors.New("failed")}

	result := service.mapError("test", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

func TestMapError_AttestationInvalidRequest(t *testing.T) {
	service, _ := newTestAttestationService()
	err := ErrAttestationInvalidRequest{Reason: "bad input"}

	result := service.mapError("test", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapError_AttestationServiceUnavailable(t *testing.T) {
	service, _ := newTestAttestationService()
	err := ErrAttestationServiceUnavailable{}

	result := service.mapError("test", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Unavailable {
		t.Errorf("Expected Unavailable, got %v", st.Code())
	}
}

func TestMapError_ManifestInvalidManifest(t *testing.T) {
	service, _ := newTestAttestationService()
	err := manifest.ErrInvalidManifest{Field: "ID", Reason: "empty"}

	result := service.mapError("test", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapError_ManifestInvalidConfig(t *testing.T) {
	service, _ := newTestAttestationService()
	err := manifest.ErrInvalidConfig{Field: "HostID", Reason: "empty"}

	result := service.mapError("test", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapError_ManifestInvalidHashAlgorithm(t *testing.T) {
	service, _ := newTestAttestationService()
	err := manifest.ErrInvalidHashAlgorithm{Algorithm: "MD5"}

	result := service.mapError("test", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestMapError_NilError(t *testing.T) {
	service, _ := newTestAttestationService()
	result := service.mapError("test", nil)

	if result != nil {
		t.Error("Expected nil for nil input")
	}
}

func TestMapError_GenericError(t *testing.T) {
	service, _ := newTestAttestationService()
	err := errors.New("generic error")

	result := service.mapError("test", err)

	st, ok := status.FromError(result)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal, got %v", st.Code())
	}
}

// =============================================================================
// Interface Compliance Test
// =============================================================================

func TestAttestationGRPCService_ImplementsInterface(t *testing.T) {
	var _ platformv1.AttestationServiceServer = (*AttestationGRPCService)(nil)
}
