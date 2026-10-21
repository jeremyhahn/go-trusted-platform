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
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Mock Registry Service
// =============================================================================

type mockRegistryService struct {
	pushResp       *RegistryPushResponse
	pushErr        error
	pushStreamResp *RegistryPushResponse
	pushStreamErr  error
	pullResp       *RegistryPullResponse
	pullErr        error
	pullStreamResp *RegistryPullStreamResponse
	pullStreamErr  error
	listResp       *RegistryListResponse
	listErr        error
	inspectResp    *RegistryInspectResponse
	inspectErr     error
	deleteResp     *RegistryDeleteResponse
	deleteErr      error
	statusResp     *RegistryStatusResponse
	statusErr      error
}

func newMockRegistryService() *mockRegistryService {
	now := time.Now().UTC()
	return &mockRegistryService{
		pushResp: &RegistryPushResponse{
			Artifact: &RegistryArtifact{
				ID:         "test-artifact-id",
				Repository: "test/repo",
				Tag:        "v1.0.0",
				Digest:     "sha256:abc123",
				Type:       ArtifactTypeContainerImage,
				State:      ArtifactStateAvailable,
				Size:       1024,
				CreatedAt:  now,
				UpdatedAt:  now,
				PushedAt:   now,
			},
			BytesReceived: 1024,
			Timestamp:     now,
		},
		pushStreamResp: &RegistryPushResponse{
			Artifact: &RegistryArtifact{
				ID:         "test-stream-artifact-id",
				Repository: "test/repo",
				Tag:        "v1.0.0",
				Digest:     "sha256:def456",
				Type:       ArtifactTypeContainerImage,
				State:      ArtifactStateAvailable,
				Size:       2048,
				CreatedAt:  now,
				UpdatedAt:  now,
				PushedAt:   now,
			},
			BytesReceived: 2048,
			Timestamp:     now,
		},
		pullResp: &RegistryPullResponse{
			Artifact: &RegistryArtifact{
				ID:         "test-artifact-id",
				Repository: "test/repo",
				Tag:        "v1.0.0",
				Digest:     "sha256:abc123",
				Type:       ArtifactTypeContainerImage,
				State:      ArtifactStateAvailable,
				Size:       1024,
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			TotalSize: 1024,
			Data:      []byte("test artifact data"),
		},
		pullStreamResp: &RegistryPullStreamResponse{
			Artifact: &RegistryArtifact{
				ID:         "test-artifact-id",
				Repository: "test/repo",
				Tag:        "v1.0.0",
				Digest:     "sha256:abc123",
				Type:       ArtifactTypeContainerImage,
				State:      ArtifactStateAvailable,
				Size:       1024,
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			TotalSize: 1024,
			Reader:    bytes.NewReader([]byte("test artifact data")),
		},
		listResp: &RegistryListResponse{
			Artifacts: []*RegistryArtifact{
				{
					ID:         "artifact-1",
					Repository: "test/repo",
					Tag:        "v1.0.0",
					Digest:     "sha256:abc123",
					Type:       ArtifactTypeContainerImage,
					State:      ArtifactStateAvailable,
					Size:       1024,
					CreatedAt:  now,
				},
				{
					ID:         "artifact-2",
					Repository: "test/repo",
					Tag:        "v2.0.0",
					Digest:     "sha256:def456",
					Type:       ArtifactTypeContainerImage,
					State:      ArtifactStateAvailable,
					Size:       2048,
					CreatedAt:  now,
				},
			},
			Total:      2,
			NextCursor: "",
			HasMore:    false,
		},
		inspectResp: &RegistryInspectResponse{
			Detail: &RegistryArtifactDetail{
				Artifact: &RegistryArtifact{
					ID:         "test-artifact-id",
					Repository: "test/repo",
					Tag:        "v1.0.0",
					Digest:     "sha256:abc123",
					Type:       ArtifactTypeContainerImage,
					State:      ArtifactStateAvailable,
					Size:       1024,
					CreatedAt:  now,
					UpdatedAt:  now,
				},
				Tags: []string{"v1.0.0", "latest"},
			},
		},
		deleteResp: &RegistryDeleteResponse{
			Digest:     "sha256:abc123",
			BytesFreed: 1024,
			Timestamp:  now,
		},
		statusResp: &RegistryStatusResponse{
			Health:   RegistryHealthStatusHealthy,
			Version:  "1.0.0",
			ReadOnly: false,
			Storage: &RegistryStorageStats{
				TotalBytes:      1024 * 1024 * 1024,
				UsedBytes:       512 * 1024 * 1024,
				AvailableBytes:  512 * 1024 * 1024,
				ArtifactCount:   100,
				LayerCount:      500,
				RepositoryCount: 10,
			},
			StartedAt: now.Add(-time.Hour),
			Timestamp: now,
		},
	}
}

func (m *mockRegistryService) Push(ctx context.Context, req *RegistryPushRequest) (*RegistryPushResponse, error) {
	if m.pushErr != nil {
		return nil, m.pushErr
	}
	return m.pushResp, nil
}

func (m *mockRegistryService) PushStream(ctx context.Context, metadata *RegistryPushMetadata, reader io.Reader) (*RegistryPushResponse, error) {
	if m.pushStreamErr != nil {
		return nil, m.pushStreamErr
	}
	return m.pushStreamResp, nil
}

func (m *mockRegistryService) Pull(ctx context.Context, req *RegistryPullRequest) (*RegistryPullResponse, error) {
	if m.pullErr != nil {
		return nil, m.pullErr
	}
	return m.pullResp, nil
}

func (m *mockRegistryService) PullStream(ctx context.Context, req *RegistryPullRequest) (*RegistryPullStreamResponse, error) {
	if m.pullStreamErr != nil {
		return nil, m.pullStreamErr
	}
	return m.pullStreamResp, nil
}

func (m *mockRegistryService) List(ctx context.Context, req *RegistryListRequest) (*RegistryListResponse, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.listResp, nil
}

func (m *mockRegistryService) Inspect(ctx context.Context, req *RegistryInspectRequest) (*RegistryInspectResponse, error) {
	if m.inspectErr != nil {
		return nil, m.inspectErr
	}
	return m.inspectResp, nil
}

func (m *mockRegistryService) Delete(ctx context.Context, req *RegistryDeleteRequest) (*RegistryDeleteResponse, error) {
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	return m.deleteResp, nil
}

func (m *mockRegistryService) Status(ctx context.Context) (*RegistryStatusResponse, error) {
	if m.statusErr != nil {
		return nil, m.statusErr
	}
	return m.statusResp, nil
}

// =============================================================================
// RegistryGRPCService Tests
// =============================================================================

func TestNewRegistryGRPCService(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()

	svc := NewRegistryGRPCService(logger, mockSvc)
	if svc == nil {
		t.Fatal("NewRegistryGRPCService returned nil")
	}

	if svc.service != mockSvc {
		t.Error("service not set correctly")
	}
	if svc.logger != logger {
		t.Error("logger not set correctly")
	}
	if svc.chunkSize != defaultChunkSize {
		t.Errorf("expected default chunk size %d, got %d", defaultChunkSize, svc.chunkSize)
	}
}

func TestRegistryGRPCService_WithChunkSize(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()

	svc := NewRegistryGRPCService(logger, mockSvc).WithChunkSize(128 * 1024)
	if svc.chunkSize != 128*1024 {
		t.Errorf("expected chunk size 131072, got %d", svc.chunkSize)
	}

	// Test with zero chunk size (should not change)
	svc = NewRegistryGRPCService(logger, mockSvc).WithChunkSize(0)
	if svc.chunkSize != defaultChunkSize {
		t.Errorf("expected default chunk size %d, got %d", defaultChunkSize, svc.chunkSize)
	}

	// Test with negative chunk size (should not change)
	svc = NewRegistryGRPCService(logger, mockSvc).WithChunkSize(-1)
	if svc.chunkSize != defaultChunkSize {
		t.Errorf("expected default chunk size %d, got %d", defaultChunkSize, svc.chunkSize)
	}
}

func TestRegistryGRPCService_List_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.ListArtifactsRequest{
		Repository: "test/repo",
		Limit:      10,
	}

	resp, err := svc.List(context.Background(), req)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if len(resp.Artifacts) != 2 {
		t.Errorf("expected 2 artifacts, got %d", len(resp.Artifacts))
	}
	if resp.Total != 2 {
		t.Errorf("expected total 2, got %d", resp.Total)
	}
}

func TestRegistryGRPCService_List_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	svc := NewRegistryGRPCService(logger, nil)

	req := &platformv1.ListArtifactsRequest{
		Repository: "test/repo",
	}

	_, err := svc.List(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil service")
	}
}

func TestRegistryGRPCService_List_ServiceError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	mockSvc.listErr = ErrRegistryOperationFailed{Operation: "list", Reason: "internal error"}
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.ListArtifactsRequest{
		Repository: "test/repo",
	}

	_, err := svc.List(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for service error")
	}
}

func TestRegistryGRPCService_Inspect_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.InspectArtifactRequest{
		Repository: "test/repo",
		Reference:  "v1.0.0",
	}

	resp, err := svc.Inspect(context.Background(), req)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.Detail == nil {
		t.Fatal("detail is nil")
	}
	if resp.Detail.Artifact == nil {
		t.Fatal("artifact is nil")
	}
	if resp.Detail.Artifact.Repository != "test/repo" {
		t.Errorf("expected repository test/repo, got %s", resp.Detail.Artifact.Repository)
	}
}

func TestRegistryGRPCService_Inspect_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	svc := NewRegistryGRPCService(logger, nil)

	req := &platformv1.InspectArtifactRequest{
		Repository: "test/repo",
		Reference:  "v1.0.0",
	}

	_, err := svc.Inspect(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil service")
	}
}

func TestRegistryGRPCService_Inspect_MissingRepository(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.InspectArtifactRequest{
		Reference: "v1.0.0",
	}

	_, err := svc.Inspect(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing repository")
	}
}

func TestRegistryGRPCService_Inspect_MissingReference(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.InspectArtifactRequest{
		Repository: "test/repo",
	}

	_, err := svc.Inspect(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing reference")
	}
}

func TestRegistryGRPCService_Inspect_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	mockSvc.inspectErr = ErrArtifactNotFound{Repository: "test/repo", Reference: "missing"}
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.InspectArtifactRequest{
		Repository: "test/repo",
		Reference:  "missing",
	}

	_, err := svc.Inspect(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for not found artifact")
	}
}

func TestRegistryGRPCService_Delete_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.DeleteArtifactRequest{
		Repository: "test/repo",
		Reference:  "v1.0.0",
	}

	resp, err := svc.Delete(context.Background(), req)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.Digest != "sha256:abc123" {
		t.Errorf("expected digest sha256:abc123, got %s", resp.Digest)
	}
}

func TestRegistryGRPCService_Delete_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	svc := NewRegistryGRPCService(logger, nil)

	req := &platformv1.DeleteArtifactRequest{
		Repository: "test/repo",
		Reference:  "v1.0.0",
	}

	_, err := svc.Delete(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil service")
	}
}

func TestRegistryGRPCService_Delete_MissingRepository(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.DeleteArtifactRequest{
		Reference: "v1.0.0",
	}

	_, err := svc.Delete(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing repository")
	}
}

func TestRegistryGRPCService_Delete_MissingReference(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.DeleteArtifactRequest{
		Repository: "test/repo",
	}

	_, err := svc.Delete(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for missing reference")
	}
}

func TestRegistryGRPCService_Delete_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	mockSvc.deleteErr = ErrArtifactNotFound{Repository: "test/repo", Reference: "missing"}
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.DeleteArtifactRequest{
		Repository: "test/repo",
		Reference:  "missing",
	}

	_, err := svc.Delete(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for not found artifact")
	}
}

func TestRegistryGRPCService_Status_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.RegistryStatusRequest{}

	resp, err := svc.Status(context.Background(), req)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}
	if resp.Health != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY {
		t.Errorf("expected healthy status, got %v", resp.Health)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", resp.Version)
	}
	if resp.ReadOnly {
		t.Error("expected read-only to be false")
	}
	if resp.Storage == nil {
		t.Fatal("storage stats is nil")
	}
}

func TestRegistryGRPCService_Status_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	svc := NewRegistryGRPCService(logger, nil)

	req := &platformv1.RegistryStatusRequest{}

	_, err := svc.Status(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil service")
	}
}

func TestRegistryGRPCService_Status_Error(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSvc := newMockRegistryService()
	mockSvc.statusErr = ErrRegistryOperationFailed{Operation: "status", Reason: "unavailable"}
	svc := NewRegistryGRPCService(logger, mockSvc)

	req := &platformv1.RegistryStatusRequest{}

	_, err := svc.Status(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for service error")
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestRegistryErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrNilRegistryService",
			err:      ErrNilRegistryService{},
			expected: "registry service is nil",
		},
		{
			name:     "ErrMissingRepository",
			err:      ErrMissingRepository{},
			expected: "repository is required",
		},
		{
			name:     "ErrMissingReference",
			err:      ErrMissingReference{},
			expected: "reference (tag or digest) is required",
		},
		{
			name:     "ErrMissingPushMetadata",
			err:      ErrMissingPushMetadata{},
			expected: "push metadata is required",
		},
		{
			name:     "ErrArtifactNotFound",
			err:      ErrArtifactNotFound{Repository: "test/repo", Reference: "v1.0.0"},
			expected: "artifact not found: test/repo:v1.0.0",
		},
		{
			name:     "ErrArtifactAlreadyExists",
			err:      ErrArtifactAlreadyExists{Repository: "test/repo", Reference: "v1.0.0"},
			expected: "artifact already exists: test/repo:v1.0.0",
		},
		{
			name:     "ErrRegistryOperationFailed",
			err:      ErrRegistryOperationFailed{Operation: "push", Reason: "disk full"},
			expected: "registry operation push failed: disk full",
		},
		{
			name:     "ErrInvalidArtifactDigest",
			err:      ErrInvalidArtifactDigest{Digest: "invalid"},
			expected: "invalid artifact digest: invalid",
		},
		{
			name:     "ErrStreamClosed",
			err:      ErrStreamClosed{},
			expected: "stream closed unexpectedly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected error message '%s', got '%s'", tt.expected, tt.err.Error())
			}
		})
	}
}

// =============================================================================
// Type Constant Tests
// =============================================================================

func TestArtifactTypeConstants(t *testing.T) {
	tests := []struct {
		typ      ArtifactType
		expected int32
	}{
		{ArtifactTypeUnspecified, 0},
		{ArtifactTypeContainerImage, 1},
		{ArtifactTypeHelmChart, 2},
		{ArtifactTypeOCIArtifact, 3},
		{ArtifactTypeWASMModule, 4},
		{ArtifactTypeBinary, 5},
	}

	for _, tt := range tests {
		if int32(tt.typ) != tt.expected {
			t.Errorf("ArtifactType %v expected %d, got %d", tt.typ, tt.expected, int32(tt.typ))
		}
	}
}

func TestArtifactStateConstants(t *testing.T) {
	tests := []struct {
		state    ArtifactState
		expected int32
	}{
		{ArtifactStateUnspecified, 0},
		{ArtifactStateUploading, 1},
		{ArtifactStateAvailable, 2},
		{ArtifactStateQuarantined, 3},
		{ArtifactStateDeleting, 4},
		{ArtifactStateDeleted, 5},
	}

	for _, tt := range tests {
		if int32(tt.state) != tt.expected {
			t.Errorf("ArtifactState %v expected %d, got %d", tt.state, tt.expected, int32(tt.state))
		}
	}
}

func TestCompressionTypeConstants(t *testing.T) {
	tests := []struct {
		comp     CompressionType
		expected int32
	}{
		{CompressionTypeUnspecified, 0},
		{CompressionTypeNone, 1},
		{CompressionTypeGzip, 2},
		{CompressionTypeZstd, 3},
	}

	for _, tt := range tests {
		if int32(tt.comp) != tt.expected {
			t.Errorf("CompressionType %v expected %d, got %d", tt.comp, tt.expected, int32(tt.comp))
		}
	}
}

func TestVulnerabilitySeverityConstants(t *testing.T) {
	tests := []struct {
		sev      VulnerabilitySeverity
		expected int32
	}{
		{VulnerabilitySeverityUnspecified, 0},
		{VulnerabilitySeverityLow, 1},
		{VulnerabilitySeverityMedium, 2},
		{VulnerabilitySeverityHigh, 3},
		{VulnerabilitySeverityCritical, 4},
	}

	for _, tt := range tests {
		if int32(tt.sev) != tt.expected {
			t.Errorf("VulnerabilitySeverity %v expected %d, got %d", tt.sev, tt.expected, int32(tt.sev))
		}
	}
}

func TestRegistryHealthStatusConstants(t *testing.T) {
	tests := []struct {
		status   RegistryHealthStatus
		expected int32
	}{
		{RegistryHealthStatusUnspecified, 0},
		{RegistryHealthStatusHealthy, 1},
		{RegistryHealthStatusDegraded, 2},
		{RegistryHealthStatusUnhealthy, 3},
	}

	for _, tt := range tests {
		if int32(tt.status) != tt.expected {
			t.Errorf("RegistryHealthStatus %v expected %d, got %d", tt.status, tt.expected, int32(tt.status))
		}
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestProtoPushMetadataToRegistry(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		result := protoPushMetadataToRegistry(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid input converts correctly", func(t *testing.T) {
		meta := &platformv1.PushMetadata{
			Repository:   "test/repo",
			Tag:          "v1.0.0",
			Type:         platformv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE,
			MediaType:    "application/vnd.oci.image.manifest.v1+json",
			TotalSize:    1024,
			Digest:       "sha256:abc123",
			Labels:       map[string]string{"env": "test"},
			Annotations:  map[string]string{"note": "test annotation"},
			Os:           "linux",
			Architecture: "amd64",
		}

		result := protoPushMetadataToRegistry(meta)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Repository != "test/repo" {
			t.Errorf("expected test/repo, got %s", result.Repository)
		}
		if result.Tag != "v1.0.0" {
			t.Errorf("expected v1.0.0, got %s", result.Tag)
		}
		if result.Type != ArtifactTypeContainerImage {
			t.Errorf("expected ArtifactTypeContainerImage, got %v", result.Type)
		}
		if result.MediaType != "application/vnd.oci.image.manifest.v1+json" {
			t.Errorf("expected application/vnd.oci.image.manifest.v1+json, got %s", result.MediaType)
		}
		if result.TotalSize != 1024 {
			t.Errorf("expected 1024, got %d", result.TotalSize)
		}
		if result.Digest != "sha256:abc123" {
			t.Errorf("expected sha256:abc123, got %s", result.Digest)
		}
		if result.Labels["env"] != "test" {
			t.Errorf("expected label env=test, got %v", result.Labels)
		}
		if result.Annotations["note"] != "test annotation" {
			t.Errorf("expected annotation note=test annotation, got %v", result.Annotations)
		}
		if result.OS != "linux" {
			t.Errorf("expected linux, got %s", result.OS)
		}
		if result.Architecture != "amd64" {
			t.Errorf("expected amd64, got %s", result.Architecture)
		}
	})
}

func TestRegistryLayerToProto(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		result := registryLayerToProto(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid input converts correctly", func(t *testing.T) {
		layer := &RegistryArtifactLayer{
			Digest:      "sha256:layer123",
			Size:        512,
			MediaType:   "application/vnd.oci.image.layer.v1.tar+gzip",
			Compression: CompressionTypeGzip,
			Annotations: map[string]string{"layer": "data"},
		}

		result := registryLayerToProto(layer)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Digest != "sha256:layer123" {
			t.Errorf("expected sha256:layer123, got %s", result.Digest)
		}
		if result.Size != 512 {
			t.Errorf("expected 512, got %d", result.Size)
		}
		if result.MediaType != "application/vnd.oci.image.layer.v1.tar+gzip" {
			t.Errorf("expected application/vnd.oci.image.layer.v1.tar+gzip, got %s", result.MediaType)
		}
		if result.Compression != platformv1.CompressionType(CompressionTypeGzip) {
			t.Errorf("expected gzip compression, got %v", result.Compression)
		}
		if result.Annotations["layer"] != "data" {
			t.Errorf("expected annotation layer=data, got %v", result.Annotations)
		}
	})
}

func TestRegistrySignatureToProto(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		result := registrySignatureToProto(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid input converts correctly", func(t *testing.T) {
		now := time.Now().UTC()
		sig := &RegistryArtifactSignature{
			KeyID:     "key-123",
			Algorithm: "ECDSA-P256",
			Signature: []byte("signature-data"),
			SignedAt:  now,
			Signer:    "test-signer",
		}

		result := registrySignatureToProto(sig)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.KeyId != "key-123" {
			t.Errorf("expected key-123, got %s", result.KeyId)
		}
		if result.Algorithm != "ECDSA-P256" {
			t.Errorf("expected ECDSA-P256, got %s", result.Algorithm)
		}
		if !bytes.Equal(result.Signature, []byte("signature-data")) {
			t.Errorf("expected signature-data, got %v", result.Signature)
		}
		if result.Signer != "test-signer" {
			t.Errorf("expected test-signer, got %s", result.Signer)
		}
		if result.SignedAt == nil {
			t.Error("expected non-nil SignedAt")
		}
	})
}

func TestRegistryVulnerabilityToProto(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		result := registryVulnerabilityToProto(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid input converts correctly", func(t *testing.T) {
		vuln := &RegistryVulnerability{
			ID:             "CVE-2024-1234",
			Severity:       VulnerabilitySeverityHigh,
			PackageName:    "openssl",
			PackageVersion: "1.0.0",
			FixedVersion:   "1.0.1",
			Description:    "Buffer overflow vulnerability",
			Link:           "https://cve.org/CVE-2024-1234",
		}

		result := registryVulnerabilityToProto(vuln)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Id != "CVE-2024-1234" {
			t.Errorf("expected CVE-2024-1234, got %s", result.Id)
		}
		if result.Severity != platformv1.VulnerabilitySeverity(VulnerabilitySeverityHigh) {
			t.Errorf("expected high severity, got %v", result.Severity)
		}
		if result.PackageName != "openssl" {
			t.Errorf("expected openssl, got %s", result.PackageName)
		}
		if result.PackageVersion != "1.0.0" {
			t.Errorf("expected 1.0.0, got %s", result.PackageVersion)
		}
		if result.FixedVersion != "1.0.1" {
			t.Errorf("expected 1.0.1, got %s", result.FixedVersion)
		}
		if result.Description != "Buffer overflow vulnerability" {
			t.Errorf("expected Buffer overflow vulnerability, got %s", result.Description)
		}
		if result.Link != "https://cve.org/CVE-2024-1234" {
			t.Errorf("expected https://cve.org/CVE-2024-1234, got %s", result.Link)
		}
	})
}

func TestRegistryComponentHealthToProto(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		result := registryComponentHealthToProto(nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid input converts correctly", func(t *testing.T) {
		now := time.Now().UTC()
		health := &RegistryComponentHealth{
			Name:      "storage",
			Status:    RegistryHealthStatusHealthy,
			Message:   "Storage is operational",
			LastCheck: now,
			Details:   map[string]string{"disk_usage": "50%"},
		}

		result := registryComponentHealthToProto(health)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Name != "storage" {
			t.Errorf("expected storage, got %s", result.Name)
		}
		if result.Status != platformv1.HealthStatus(RegistryHealthStatusHealthy) {
			t.Errorf("expected healthy status, got %v", result.Status)
		}
		if result.Message != "Storage is operational" {
			t.Errorf("expected Storage is operational, got %s", result.Message)
		}
		if result.LastCheck == nil {
			t.Error("expected non-nil LastCheck")
		}
		if result.Details["disk_usage"] != "50%" {
			t.Errorf("expected disk_usage=50%%, got %v", result.Details)
		}
	})
}

// =============================================================================
// gRPC Streaming Mock Implementations
// =============================================================================

// mockPushStream implements grpc.ClientStreamingServer for Push testing
type mockPushStream struct {
	grpc.ClientStreamingServer[platformv1.PushRequest, platformv1.PushResponse]
	ctx       context.Context
	requests  []*platformv1.PushRequest
	idx       int
	recvErr   error
	response  *platformv1.PushResponse
	closeErr  error
	closeSent bool
}

func newMockPushStream(ctx context.Context, requests []*platformv1.PushRequest) *mockPushStream {
	return &mockPushStream{
		ctx:      ctx,
		requests: requests,
		idx:      0,
	}
}

func (m *mockPushStream) Context() context.Context {
	return m.ctx
}

func (m *mockPushStream) Recv() (*platformv1.PushRequest, error) {
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	if m.idx >= len(m.requests) {
		return nil, io.EOF
	}
	req := m.requests[m.idx]
	m.idx++
	return req, nil
}

func (m *mockPushStream) SendAndClose(resp *platformv1.PushResponse) error {
	if m.closeErr != nil {
		return m.closeErr
	}
	m.response = resp
	m.closeSent = true
	return nil
}

func (m *mockPushStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockPushStream) SendHeader(metadata.MD) error { return nil }
func (m *mockPushStream) SetTrailer(metadata.MD)       {}
func (m *mockPushStream) SendMsg(interface{}) error    { return nil }
func (m *mockPushStream) RecvMsg(interface{}) error    { return nil }

// mockPullStream implements grpc.ServerStreamingServer for Pull testing
type mockPullStream struct {
	grpc.ServerStreamingServer[platformv1.PullResponse]
	ctx       context.Context
	responses []*platformv1.PullResponse
	sendErr   error
}

func newMockPullStream(ctx context.Context) *mockPullStream {
	return &mockPullStream{
		ctx:       ctx,
		responses: make([]*platformv1.PullResponse, 0),
	}
}

func (m *mockPullStream) Context() context.Context {
	return m.ctx
}

func (m *mockPullStream) Send(resp *platformv1.PullResponse) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.responses = append(m.responses, resp)
	return nil
}

func (m *mockPullStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockPullStream) SendHeader(metadata.MD) error { return nil }
func (m *mockPullStream) SetTrailer(metadata.MD)       {}
func (m *mockPullStream) SendMsg(interface{}) error    { return nil }
func (m *mockPullStream) RecvMsg(interface{}) error    { return nil }

// =============================================================================
// gRPC Push Streaming Tests
// =============================================================================

func TestRegistryGRPCService_Push_Success(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	requests := []*platformv1.PushRequest{
		{
			Data: &platformv1.PushRequest_Metadata{
				Metadata: &platformv1.PushMetadata{
					Repository: "test/repo",
					Tag:        "v1.0.0",
					Type:       platformv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE,
				},
			},
		},
		{
			Data: &platformv1.PushRequest_Chunk{
				Chunk: []byte("chunk1"),
			},
		},
		{
			Data: &platformv1.PushRequest_Chunk{
				Chunk: []byte("chunk2"),
			},
		},
	}

	stream := newMockPushStream(context.Background(), requests)

	err := grpcSvc.Push(stream)
	if err != nil {
		t.Fatalf("Push failed: %v", err)
	}

	if !stream.closeSent {
		t.Error("expected SendAndClose to be called")
	}
	if stream.response == nil {
		t.Fatal("expected response to be set")
	}
	if stream.response.Artifact == nil {
		t.Error("expected artifact in response")
	}
}

func TestRegistryGRPCService_Push_NilService(t *testing.T) {
	t.Parallel()

	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), nil)

	requests := []*platformv1.PushRequest{
		{
			Data: &platformv1.PushRequest_Metadata{
				Metadata: &platformv1.PushMetadata{
					Repository: "test/repo",
				},
			},
		},
	}

	stream := newMockPushStream(context.Background(), requests)

	err := grpcSvc.Push(stream)
	if err == nil {
		t.Fatal("expected error for nil service")
	}
}

func TestRegistryGRPCService_Push_MissingMetadata(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	// Only chunks, no metadata
	requests := []*platformv1.PushRequest{
		{
			Data: &platformv1.PushRequest_Chunk{
				Chunk: []byte("chunk1"),
			},
		},
	}

	stream := newMockPushStream(context.Background(), requests)

	err := grpcSvc.Push(stream)
	if err == nil {
		t.Fatal("expected error for chunk before metadata")
	}
}

func TestRegistryGRPCService_Push_EmptyStream(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	// Empty stream - no metadata
	requests := []*platformv1.PushRequest{}

	stream := newMockPushStream(context.Background(), requests)

	err := grpcSvc.Push(stream)
	if err == nil {
		t.Fatal("expected error for empty stream")
	}
}

func TestRegistryGRPCService_Push_DuplicateMetadata(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	requests := []*platformv1.PushRequest{
		{
			Data: &platformv1.PushRequest_Metadata{
				Metadata: &platformv1.PushMetadata{
					Repository: "test/repo",
					Tag:        "v1.0.0",
				},
			},
		},
		{
			Data: &platformv1.PushRequest_Metadata{
				Metadata: &platformv1.PushMetadata{
					Repository: "another/repo",
					Tag:        "v2.0.0",
				},
			},
		},
	}

	stream := newMockPushStream(context.Background(), requests)

	err := grpcSvc.Push(stream)
	if err == nil {
		t.Fatal("expected error for duplicate metadata")
	}
}

func TestRegistryGRPCService_Push_MissingRepository(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	requests := []*platformv1.PushRequest{
		{
			Data: &platformv1.PushRequest_Metadata{
				Metadata: &platformv1.PushMetadata{
					Repository: "", // Empty repository
					Tag:        "v1.0.0",
				},
			},
		},
	}

	stream := newMockPushStream(context.Background(), requests)

	err := grpcSvc.Push(stream)
	if err == nil {
		t.Fatal("expected error for missing repository")
	}
}

func TestRegistryGRPCService_Push_RecvError(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	stream := newMockPushStream(context.Background(), nil)
	stream.recvErr = errors.New("connection reset")

	err := grpcSvc.Push(stream)
	if err == nil {
		t.Fatal("expected error for recv failure")
	}
}

func TestRegistryGRPCService_Push_ServiceError(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	mockSvc.pushStreamErr = errors.New("storage full")
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	requests := []*platformv1.PushRequest{
		{
			Data: &platformv1.PushRequest_Metadata{
				Metadata: &platformv1.PushMetadata{
					Repository: "test/repo",
					Tag:        "v1.0.0",
				},
			},
		},
	}

	stream := newMockPushStream(context.Background(), requests)

	err := grpcSvc.Push(stream)
	if err == nil {
		t.Fatal("expected error from service")
	}
}

// The Push handler answers a not-configured refusal from the service with
// FailedPrecondition on the wire, the code the CI leaf saw as Internal.
func TestRegistryGRPCService_Push_NotConfiguredIsFailedPrecondition(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	mockSvc.pushStreamErr = ErrRegistryNotConfigured{Reason: "registry: image signing not configured (ref=test/repo:v1.0.0)"}
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	stream := newMockPushStream(context.Background(), []*platformv1.PushRequest{
		{Data: &platformv1.PushRequest_Metadata{Metadata: &platformv1.PushMetadata{
			Repository:  "test/repo",
			Tag:         "v1.0.0",
			Annotations: map[string]string{"sign": "true"},
		}}},
	})

	err := grpcSvc.Push(stream)
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("Push error code = %v (%v), want FailedPrecondition", got, err)
	}
	if stream.closeSent {
		t.Error("a refused push sent a response")
	}
}

// =============================================================================
// gRPC Pull Streaming Tests
// =============================================================================

func TestRegistryGRPCService_Pull_Success(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc).WithChunkSize(1024)

	req := &platformv1.PullRequest{
		Repository: "test/repo",
		Reference:  "v1.0.0",
	}

	stream := newMockPullStream(context.Background())

	err := grpcSvc.Pull(req, stream)
	if err != nil {
		t.Fatalf("Pull failed: %v", err)
	}

	// Should have at least metadata response
	if len(stream.responses) < 1 {
		t.Error("expected at least one response")
	}

	// First response should be metadata
	first := stream.responses[0]
	if first.GetMetadata() == nil {
		t.Error("expected first response to be metadata")
	}
}

func TestRegistryGRPCService_Pull_NilService(t *testing.T) {
	t.Parallel()

	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), nil)

	req := &platformv1.PullRequest{
		Repository: "test/repo",
		Reference:  "v1.0.0",
	}

	stream := newMockPullStream(context.Background())

	err := grpcSvc.Pull(req, stream)
	if err == nil {
		t.Fatal("expected error for nil service")
	}
}

func TestRegistryGRPCService_Pull_MissingRepository(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	req := &platformv1.PullRequest{
		Repository: "",
		Reference:  "v1.0.0",
	}

	stream := newMockPullStream(context.Background())

	err := grpcSvc.Pull(req, stream)
	if err == nil {
		t.Fatal("expected error for missing repository")
	}
}

func TestRegistryGRPCService_Pull_MissingReference(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	req := &platformv1.PullRequest{
		Repository: "test/repo",
		Reference:  "",
		Digest:     "",
	}

	stream := newMockPullStream(context.Background())

	err := grpcSvc.Pull(req, stream)
	if err == nil {
		t.Fatal("expected error for missing reference and digest")
	}
}

func TestRegistryGRPCService_Pull_ByDigest(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	req := &platformv1.PullRequest{
		Repository: "test/repo",
		Digest:     "sha256:abc123",
	}

	stream := newMockPullStream(context.Background())

	err := grpcSvc.Pull(req, stream)
	if err != nil {
		t.Fatalf("Pull by digest failed: %v", err)
	}
}

func TestRegistryGRPCService_Pull_ServiceError(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	mockSvc.pullStreamErr = errors.New("artifact not found")
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	req := &platformv1.PullRequest{
		Repository: "test/repo",
		Reference:  "nonexistent",
	}

	stream := newMockPullStream(context.Background())

	err := grpcSvc.Pull(req, stream)
	if err == nil {
		t.Fatal("expected error from service")
	}
}

func TestRegistryGRPCService_Pull_SendMetadataError(t *testing.T) {
	t.Parallel()

	mockSvc := newMockRegistryService()
	grpcSvc := NewRegistryGRPCService(logging.DefaultLogger(), mockSvc)

	req := &platformv1.PullRequest{
		Repository: "test/repo",
		Reference:  "v1.0.0",
	}

	stream := newMockPullStream(context.Background())
	stream.sendErr = errors.New("connection closed")

	err := grpcSvc.Pull(req, stream)
	if err == nil {
		t.Fatal("expected error for send failure")
	}
}

// A malformed reference is the caller's error: the gRPC surface answers
// InvalidArgument, never Internal (m779, run 58285).
func TestRegistryErrorStatus_ClientErrorsAreInvalidArgument(t *testing.T) {
	for _, err := range []error{
		ErrInvalidArtifactReference{Reference: "Unix-1-push:v1", Reason: "invalid format"},
		ErrInvalidArtifactDigest{Digest: "sha256:zz"},
		ErrMissingRepository{},
		ErrMissingReference{},
	} {
		if got := status.Code(RegistryErrorStatus(err)); got != codes.InvalidArgument {
			t.Errorf("RegistryErrorStatus(%T) code = %v, want InvalidArgument", err, got)
		}
	}
}

func TestRegistryErrorStatus_UnknownErrorIsInternal(t *testing.T) {
	if got := status.Code(RegistryErrorStatus(errors.New("disk exploded"))); got != codes.Internal {
		t.Errorf("code = %v, want Internal", got)
	}
}

// A push the registry is not configured for (signing or encryption asked of
// a registry without a signer or encryptor) is a precondition failure the
// operator fixes, never Internal (m954, #973 run 59851).
func TestRegistryErrorStatus_NotConfiguredIsFailedPrecondition(t *testing.T) {
	err := ErrRegistryNotConfigured{Reason: "registry: image signing not configured (ref=apps/web:v1)"}
	st := RegistryErrorStatus(err)
	if got := status.Code(st); got != codes.FailedPrecondition {
		t.Fatalf("RegistryErrorStatus(ErrRegistryNotConfigured) code = %v, want FailedPrecondition", got)
	}
	if got := status.Convert(st).Message(); got != err.Reason {
		t.Errorf("status message = %q, want %q", got, err.Reason)
	}
}

// Only the typed error maps to FailedPrecondition: an untyped error that
// merely reads like one stays Internal.
func TestRegistryErrorStatus_UntypedNotConfiguredTextIsInternal(t *testing.T) {
	err := errors.New("registry: image signing not configured")
	if got := status.Code(RegistryErrorStatus(err)); got != codes.Internal {
		t.Errorf("RegistryErrorStatus(untyped) code = %v, want Internal", got)
	}
}
