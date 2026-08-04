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
	"io"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Default chunk size for streaming operations (64KB).
const defaultChunkSize = 64 * 1024

// RegistryGRPCService implements the gRPC RegistryService server interface.
// It wraps the RegistryService interface to provide gRPC access to registry operations.
type RegistryGRPCService struct {
	platformv1.UnimplementedRegistryServiceServer
	logger    *logging.Logger
	service   RegistryService
	chunkSize int
}

// NewRegistryGRPCService creates a new RegistryGRPCService instance.
func NewRegistryGRPCService(
	logger *logging.Logger,
	service RegistryService,
) *RegistryGRPCService {
	return &RegistryGRPCService{
		logger:    logger,
		service:   service,
		chunkSize: defaultChunkSize,
	}
}

// WithChunkSize sets the chunk size for streaming operations.
func (s *RegistryGRPCService) WithChunkSize(size int) *RegistryGRPCService {
	if size > 0 {
		s.chunkSize = size
	}
	return s
}

// Push handles client streaming push of artifact data to the registry.
func (s *RegistryGRPCService) Push(
	stream grpc.ClientStreamingServer[platformv1.PushRequest, platformv1.PushResponse],
) error {
	if s.service == nil {
		return status.Error(codes.FailedPrecondition, ErrNilRegistryService{}.Error())
	}

	var metadata *RegistryPushMetadata
	var buffer bytes.Buffer
	var bytesReceived int64

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			s.logger.Error(err, "failed to receive push request")
			return status.Error(codes.Internal, err.Error())
		}

		switch data := req.GetData().(type) {
		case *platformv1.PushRequest_Metadata:
			if metadata != nil {
				return status.Error(codes.InvalidArgument, "metadata already received")
			}
			metadata = protoPushMetadataToRegistry(data.Metadata)
			if metadata == nil {
				return status.Error(codes.InvalidArgument, ErrMissingPushMetadata{}.Error())
			}
			if metadata.Repository == "" {
				return status.Error(codes.InvalidArgument, ErrMissingRepository{}.Error())
			}

		case *platformv1.PushRequest_Chunk:
			if metadata == nil {
				return status.Error(codes.InvalidArgument, "metadata must be sent before chunks")
			}
			n, writeErr := buffer.Write(data.Chunk)
			if writeErr != nil {
				return status.Error(codes.Internal, writeErr.Error())
			}
			bytesReceived += int64(n)
		}
	}

	if metadata == nil {
		return status.Error(codes.InvalidArgument, ErrMissingPushMetadata{}.Error())
	}

	ctx := stream.Context()
	resp, err := s.service.PushStream(ctx, metadata, &buffer)
	if err != nil {
		return s.mapError("Push", err)
	}

	return stream.SendAndClose(&platformv1.PushResponse{
		Status:        registrySuccessStatus("artifact pushed successfully"),
		Artifact:      registryArtifactToProto(resp.Artifact),
		BytesReceived: bytesReceived,
		Timestamp:     timestamppb.New(resp.Timestamp),
	})
}

// Pull handles server streaming pull of artifact data from the registry.
func (s *RegistryGRPCService) Pull(
	req *platformv1.PullRequest,
	stream grpc.ServerStreamingServer[platformv1.PullResponse],
) error {
	if s.service == nil {
		return status.Error(codes.FailedPrecondition, ErrNilRegistryService{}.Error())
	}

	if req.GetRepository() == "" {
		return status.Error(codes.InvalidArgument, ErrMissingRepository{}.Error())
	}

	if req.GetReference() == "" && req.GetDigest() == "" {
		return status.Error(codes.InvalidArgument, ErrMissingReference{}.Error())
	}

	pullReq := &RegistryPullRequest{
		Repository: req.GetRepository(),
		Reference:  req.GetReference(),
		Digest:     req.GetDigest(),
	}

	ctx := stream.Context()
	resp, err := s.service.PullStream(ctx, pullReq)
	if err != nil {
		return s.mapError("Pull", err)
	}

	// Send metadata first.
	metadataResp := &platformv1.PullResponse{
		Data: &platformv1.PullResponse_Metadata{
			Metadata: &platformv1.PullMetadata{
				Artifact:  registryArtifactToProto(resp.Artifact),
				TotalSize: resp.TotalSize,
			},
		},
	}
	if err := stream.Send(metadataResp); err != nil {
		s.logger.Error(err, "failed to send pull metadata")
		return status.Error(codes.Internal, err.Error())
	}

	// Stream data chunks.
	chunk := make([]byte, s.chunkSize)
	for {
		n, readErr := resp.Reader.Read(chunk)
		if n > 0 {
			chunkResp := &platformv1.PullResponse{
				Data: &platformv1.PullResponse_Chunk{
					Chunk: chunk[:n],
				},
			}
			if sendErr := stream.Send(chunkResp); sendErr != nil {
				s.logger.Error(sendErr, "failed to send pull chunk")
				return status.Error(codes.Internal, sendErr.Error())
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			s.logger.Error(readErr, "failed to read artifact data")
			return status.Error(codes.Internal, readErr.Error())
		}
	}

	return nil
}

// List returns a paginated list of artifacts in the registry.
func (s *RegistryGRPCService) List(
	ctx context.Context,
	req *platformv1.ListArtifactsRequest,
) (*platformv1.ListArtifactsResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilRegistryService{}.Error())
	}

	listReq := &RegistryListRequest{
		Repository: req.GetRepository(),
		Type:       ArtifactType(req.GetType()),
		Selector:   protoLabelSelectorToRegistry(req.GetSelector()),
		Limit:      req.GetLimit(),
		Offset:     req.GetOffset(),
		Cursor:     req.GetCursor(),
		SortBy:     req.GetSortBy(),
		Ascending:  req.GetAscending(),
	}

	resp, err := s.service.List(ctx, listReq)
	if err != nil {
		return nil, s.mapError("List", err)
	}

	artifacts := make([]*platformv1.Artifact, 0, len(resp.Artifacts))
	for _, a := range resp.Artifacts {
		artifacts = append(artifacts, registryArtifactToProto(a))
	}

	return &platformv1.ListArtifactsResponse{
		Artifacts:  artifacts,
		Total:      resp.Total,
		NextCursor: resp.NextCursor,
		HasMore:    resp.HasMore,
		Pagination: registryPaginationToProto(resp.Pagination),
	}, nil
}

// Inspect retrieves detailed metadata about an artifact.
func (s *RegistryGRPCService) Inspect(
	ctx context.Context,
	req *platformv1.InspectArtifactRequest,
) (*platformv1.InspectArtifactResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilRegistryService{}.Error())
	}

	if req.GetRepository() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRepository{}.Error())
	}

	if req.GetReference() == "" && req.GetDigest() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingReference{}.Error())
	}

	inspectReq := &RegistryInspectRequest{
		Repository:        req.GetRepository(),
		Reference:         req.GetReference(),
		Digest:            req.GetDigest(),
		IncludeSignatures: req.GetIncludeSignatures(),
		IncludeScanResult: req.GetIncludeScanResult(),
	}

	resp, err := s.service.Inspect(ctx, inspectReq)
	if err != nil {
		return nil, s.mapError("Inspect", err)
	}

	return &platformv1.InspectArtifactResponse{
		Status: registrySuccessStatus("artifact inspected successfully"),
		Detail: registryArtifactDetailToProto(resp.Detail),
	}, nil
}

// Delete removes an artifact from the registry.
func (s *RegistryGRPCService) Delete(
	ctx context.Context,
	req *platformv1.DeleteArtifactRequest,
) (*platformv1.DeleteArtifactResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilRegistryService{}.Error())
	}

	if req.GetRepository() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingRepository{}.Error())
	}

	if req.GetReference() == "" && req.GetDigest() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingReference{}.Error())
	}

	deleteReq := &RegistryDeleteRequest{
		Repository: req.GetRepository(),
		Reference:  req.GetReference(),
		Digest:     req.GetDigest(),
		Force:      req.GetForce(),
	}

	resp, err := s.service.Delete(ctx, deleteReq)
	if err != nil {
		return nil, s.mapError("Delete", err)
	}

	return &platformv1.DeleteArtifactResponse{
		Status:     registrySuccessStatus("artifact deleted successfully"),
		Digest:     resp.Digest,
		BytesFreed: resp.BytesFreed,
		Timestamp:  timestamppb.New(resp.Timestamp),
	}, nil
}

// Status returns the current status of the registry.
func (s *RegistryGRPCService) Status(
	ctx context.Context,
	req *platformv1.RegistryStatusRequest,
) (*platformv1.RegistryStatusResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilRegistryService{}.Error())
	}

	resp, err := s.service.Status(ctx)
	if err != nil {
		return nil, s.mapError("Status", err)
	}

	components := make([]*platformv1.ComponentHealth, 0, len(resp.Components))
	for _, c := range resp.Components {
		components = append(components, registryComponentHealthToProto(c))
	}

	return &platformv1.RegistryStatusResponse{
		Status:     registrySuccessStatus("registry status retrieved"),
		Health:     platformv1.HealthStatus(resp.Health),
		Version:    resp.Version,
		Storage:    registryStorageStatsToProto(resp.Storage),
		ReadOnly:   resp.ReadOnly,
		Components: components,
		StartedAt:  timestamppb.New(resp.StartedAt),
		Timestamp:  timestamppb.New(resp.Timestamp),
	}, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func registrySuccessStatus(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

func protoPushMetadataToRegistry(meta *platformv1.PushMetadata) *RegistryPushMetadata {
	if meta == nil {
		return nil
	}
	return &RegistryPushMetadata{
		Repository:   meta.GetRepository(),
		Tag:          meta.GetTag(),
		Type:         ArtifactType(meta.GetType()),
		MediaType:    meta.GetMediaType(),
		TotalSize:    meta.GetTotalSize(),
		Digest:       meta.GetDigest(),
		Labels:       meta.GetLabels(),
		Annotations:  meta.GetAnnotations(),
		OS:           meta.GetOs(),
		Architecture: meta.GetArchitecture(),
	}
}

func protoLabelSelectorToRegistry(selector *platformv1.LabelSelector) *RegistryLabelSelector {
	if selector == nil {
		return nil
	}
	return &RegistryLabelSelector{
		MatchLabels:      selector.GetMatchLabels(),
		MatchExpressions: selector.GetMatchExpressions(),
	}
}

func registryArtifactToProto(artifact *RegistryArtifact) *platformv1.Artifact {
	if artifact == nil {
		return nil
	}
	return &platformv1.Artifact{
		Id:           artifact.ID,
		Repository:   artifact.Repository,
		Tag:          artifact.Tag,
		Digest:       artifact.Digest,
		Type:         platformv1.ArtifactType(artifact.Type),
		State:        platformv1.ArtifactState(artifact.State),
		Size:         artifact.Size,
		Manifest:     registryManifestToProto(artifact.Manifest),
		Labels:       artifact.Labels,
		Annotations:  artifact.Annotations,
		Os:           artifact.OS,
		Architecture: artifact.Architecture,
		Author:       artifact.Author,
		CreatedAt:    timestamppb.New(artifact.CreatedAt),
		UpdatedAt:    timestamppb.New(artifact.UpdatedAt),
		PushedAt:     timestamppb.New(artifact.PushedAt),
		LastPulledAt: timestamppb.New(artifact.LastPulledAt),
		PullCount:    artifact.PullCount,
	}
}

func registryManifestToProto(manifest *RegistryArtifactManifest) *platformv1.ArtifactManifest {
	if manifest == nil {
		return nil
	}
	layers := make([]*platformv1.ArtifactLayer, 0, len(manifest.Layers))
	for _, l := range manifest.Layers {
		layers = append(layers, registryLayerToProto(l))
	}
	return &platformv1.ArtifactManifest{
		Digest:       manifest.Digest,
		MediaType:    manifest.MediaType,
		Size:         manifest.Size,
		ConfigDigest: manifest.ConfigDigest,
		Layers:       layers,
		Annotations:  manifest.Annotations,
	}
}

func registryLayerToProto(layer *RegistryArtifactLayer) *platformv1.ArtifactLayer {
	if layer == nil {
		return nil
	}
	return &platformv1.ArtifactLayer{
		Digest:      layer.Digest,
		Size:        layer.Size,
		MediaType:   layer.MediaType,
		Compression: platformv1.CompressionType(layer.Compression),
		Annotations: layer.Annotations,
	}
}

func registryArtifactDetailToProto(detail *RegistryArtifactDetail) *platformv1.ArtifactDetail {
	if detail == nil {
		return nil
	}
	signatures := make([]*platformv1.ArtifactSignature, 0, len(detail.Signatures))
	for _, sig := range detail.Signatures {
		signatures = append(signatures, registrySignatureToProto(sig))
	}
	return &platformv1.ArtifactDetail{
		Artifact:   registryArtifactToProto(detail.Artifact),
		Signatures: signatures,
		ScanResult: registryScanResultToProto(detail.ScanResult),
		Tags:       detail.Tags,
	}
}

func registrySignatureToProto(sig *RegistryArtifactSignature) *platformv1.ArtifactSignature {
	if sig == nil {
		return nil
	}
	return &platformv1.ArtifactSignature{
		KeyId:     sig.KeyID,
		Algorithm: sig.Algorithm,
		Signature: sig.Signature,
		SignedAt:  timestamppb.New(sig.SignedAt),
		Signer:    sig.Signer,
	}
}

func registryScanResultToProto(scan *RegistryScanResult) *platformv1.ScanResult {
	if scan == nil {
		return nil
	}
	vulns := make([]*platformv1.Vulnerability, 0, len(scan.Vulnerabilities))
	for _, v := range scan.Vulnerabilities {
		vulns = append(vulns, registryVulnerabilityToProto(v))
	}
	return &platformv1.ScanResult{
		Scanner:         scan.Scanner,
		ScannedAt:       timestamppb.New(scan.ScannedAt),
		Vulnerabilities: vulns,
		LowCount:        scan.LowCount,
		MediumCount:     scan.MediumCount,
		HighCount:       scan.HighCount,
		CriticalCount:   scan.CriticalCount,
	}
}

func registryVulnerabilityToProto(vuln *RegistryVulnerability) *platformv1.Vulnerability {
	if vuln == nil {
		return nil
	}
	return &platformv1.Vulnerability{
		Id:             vuln.ID,
		Severity:       platformv1.VulnerabilitySeverity(vuln.Severity),
		PackageName:    vuln.PackageName,
		PackageVersion: vuln.PackageVersion,
		FixedVersion:   vuln.FixedVersion,
		Description:    vuln.Description,
		Link:           vuln.Link,
	}
}

func registryPaginationToProto(pagination *RegistryPaginationResponse) *platformv1.PaginationResponse {
	if pagination == nil {
		return nil
	}
	return &platformv1.PaginationResponse{
		Page:       pagination.Page,
		PageSize:   pagination.PageSize,
		TotalPages: pagination.TotalPages,
		TotalItems: pagination.TotalItems,
	}
}

func registryStorageStatsToProto(stats *RegistryStorageStats) *platformv1.StorageStats {
	if stats == nil {
		return nil
	}
	return &platformv1.StorageStats{
		TotalBytes:      stats.TotalBytes,
		UsedBytes:       stats.UsedBytes,
		AvailableBytes:  stats.AvailableBytes,
		ArtifactCount:   stats.ArtifactCount,
		LayerCount:      stats.LayerCount,
		RepositoryCount: stats.RepositoryCount,
	}
}

func registryComponentHealthToProto(health *RegistryComponentHealth) *platformv1.ComponentHealth {
	if health == nil {
		return nil
	}
	return &platformv1.ComponentHealth{
		Name:      health.Name,
		Status:    platformv1.HealthStatus(health.Status),
		Message:   health.Message,
		LastCheck: timestamppb.New(health.LastCheck),
		Details:   health.Details,
	}
}

// mapError maps registry errors to appropriate gRPC status codes.
func (s *RegistryGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "registry operation failed", "operation", operation)

	switch e := err.(type) {
	case ErrArtifactNotFound:
		return status.Error(codes.NotFound, e.Error())
	case ErrArtifactAlreadyExists:
		return status.Error(codes.AlreadyExists, e.Error())
	case ErrInvalidArtifactDigest:
		return status.Error(codes.InvalidArgument, e.Error())
	case ErrRegistryOperationFailed:
		return status.Errorf(codes.Internal, "registry operation %s failed: %s", e.Operation, e.Reason)
	case ErrStreamClosed:
		return status.Error(codes.Aborted, e.Error())
	}

	return status.Error(codes.Internal, err.Error())
}

// Ensure RegistryGRPCService implements the RegistryServiceServer interface.
var _ platformv1.RegistryServiceServer = (*RegistryGRPCService)(nil)

// =============================================================================
// In-Memory Registry Service Implementation (for testing/development)
// =============================================================================

// InMemoryRegistryService provides an in-memory implementation of RegistryService.
// This is useful for testing and development purposes.
type InMemoryRegistryService struct {
	artifacts map[string]*RegistryArtifact
	data      map[string][]byte
	startedAt time.Time
}

// NewInMemoryRegistryService creates a new in-memory registry service.
func NewInMemoryRegistryService() *InMemoryRegistryService {
	return &InMemoryRegistryService{
		artifacts: make(map[string]*RegistryArtifact),
		data:      make(map[string][]byte),
		startedAt: time.Now().UTC(),
	}
}

// Push pushes an artifact to the registry.
func (s *InMemoryRegistryService) Push(
	ctx context.Context,
	req *RegistryPushRequest,
) (*RegistryPushResponse, error) {
	if req.Metadata == nil {
		return nil, ErrMissingPushMetadata{}
	}
	if req.Metadata.Repository == "" {
		return nil, ErrMissingRepository{}
	}

	key := s.makeKey(req.Metadata.Repository, req.Metadata.Tag)
	now := time.Now().UTC()

	artifact := &RegistryArtifact{
		ID:           key,
		Repository:   req.Metadata.Repository,
		Tag:          req.Metadata.Tag,
		Digest:       req.Metadata.Digest,
		Type:         req.Metadata.Type,
		State:        ArtifactStateAvailable,
		Size:         int64(len(req.Data)),
		Labels:       req.Metadata.Labels,
		Annotations:  req.Metadata.Annotations,
		OS:           req.Metadata.OS,
		Architecture: req.Metadata.Architecture,
		CreatedAt:    now,
		UpdatedAt:    now,
		PushedAt:     now,
	}

	s.artifacts[key] = artifact
	s.data[key] = req.Data

	return &RegistryPushResponse{
		Artifact:      artifact,
		BytesReceived: int64(len(req.Data)),
		Timestamp:     now,
	}, nil
}

// PushStream handles streaming push of artifact data.
func (s *InMemoryRegistryService) PushStream(
	ctx context.Context,
	metadata *RegistryPushMetadata,
	reader io.Reader,
) (*RegistryPushResponse, error) {
	if metadata == nil {
		return nil, ErrMissingPushMetadata{}
	}
	if metadata.Repository == "" {
		return nil, ErrMissingRepository{}
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, ErrRegistryOperationFailed{Operation: "PushStream", Reason: err.Error()}
	}

	key := s.makeKey(metadata.Repository, metadata.Tag)
	now := time.Now().UTC()

	artifact := &RegistryArtifact{
		ID:           key,
		Repository:   metadata.Repository,
		Tag:          metadata.Tag,
		Digest:       metadata.Digest,
		Type:         metadata.Type,
		State:        ArtifactStateAvailable,
		Size:         int64(len(data)),
		Labels:       metadata.Labels,
		Annotations:  metadata.Annotations,
		OS:           metadata.OS,
		Architecture: metadata.Architecture,
		CreatedAt:    now,
		UpdatedAt:    now,
		PushedAt:     now,
	}

	s.artifacts[key] = artifact
	s.data[key] = data

	return &RegistryPushResponse{
		Artifact:      artifact,
		BytesReceived: int64(len(data)),
		Timestamp:     now,
	}, nil
}

// Pull pulls an artifact from the registry.
func (s *InMemoryRegistryService) Pull(
	ctx context.Context,
	req *RegistryPullRequest,
) (*RegistryPullResponse, error) {
	if req.Repository == "" {
		return nil, ErrMissingRepository{}
	}
	if req.Reference == "" && req.Digest == "" {
		return nil, ErrMissingReference{}
	}

	key := s.makeKeyFromRequest(req)
	artifact, ok := s.artifacts[key]
	if !ok {
		return nil, ErrArtifactNotFound{Repository: req.Repository, Reference: req.Reference}
	}

	data, ok := s.data[key]
	if !ok {
		return nil, ErrArtifactNotFound{Repository: req.Repository, Reference: req.Reference}
	}

	artifact.LastPulledAt = time.Now().UTC()
	artifact.PullCount++

	return &RegistryPullResponse{
		Artifact:  artifact,
		TotalSize: int64(len(data)),
		Data:      data,
	}, nil
}

// PullStream returns a reader for streaming artifact data.
func (s *InMemoryRegistryService) PullStream(
	ctx context.Context,
	req *RegistryPullRequest,
) (*RegistryPullStreamResponse, error) {
	if req.Repository == "" {
		return nil, ErrMissingRepository{}
	}
	if req.Reference == "" && req.Digest == "" {
		return nil, ErrMissingReference{}
	}

	key := s.makeKeyFromRequest(req)
	artifact, ok := s.artifacts[key]
	if !ok {
		return nil, ErrArtifactNotFound{Repository: req.Repository, Reference: req.Reference}
	}

	data, ok := s.data[key]
	if !ok {
		return nil, ErrArtifactNotFound{Repository: req.Repository, Reference: req.Reference}
	}

	artifact.LastPulledAt = time.Now().UTC()
	artifact.PullCount++

	return &RegistryPullStreamResponse{
		Artifact:  artifact,
		TotalSize: int64(len(data)),
		Reader:    bytes.NewReader(data),
	}, nil
}

// List returns a paginated list of artifacts.
func (s *InMemoryRegistryService) List(
	ctx context.Context,
	req *RegistryListRequest,
) (*RegistryListResponse, error) {
	var artifacts []*RegistryArtifact

	for _, a := range s.artifacts {
		if req.Repository != "" && a.Repository != req.Repository {
			continue
		}
		if req.Type != ArtifactTypeUnspecified && a.Type != req.Type {
			continue
		}
		if req.Selector != nil && !s.matchesSelector(a, req.Selector) {
			continue
		}
		artifacts = append(artifacts, a)
	}

	total := int32(len(artifacts))
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}

	start := int(offset)
	end := start + int(limit)
	if start >= len(artifacts) {
		artifacts = nil
	} else {
		if end > len(artifacts) {
			end = len(artifacts)
		}
		artifacts = artifacts[start:end]
	}

	return &RegistryListResponse{
		Artifacts:  artifacts,
		Total:      total,
		HasMore:    int32(end) < total,
		NextCursor: "",
		Pagination: &RegistryPaginationResponse{
			Page:       uint32(offset/limit) + 1,
			PageSize:   uint32(limit),
			TotalPages: uint32((total + limit - 1) / limit),
			TotalItems: uint64(total),
		},
	}, nil
}

// Inspect retrieves detailed metadata about an artifact.
func (s *InMemoryRegistryService) Inspect(
	ctx context.Context,
	req *RegistryInspectRequest,
) (*RegistryInspectResponse, error) {
	if req.Repository == "" {
		return nil, ErrMissingRepository{}
	}
	if req.Reference == "" && req.Digest == "" {
		return nil, ErrMissingReference{}
	}

	key := s.makeKeyFromInspectRequest(req)
	artifact, ok := s.artifacts[key]
	if !ok {
		return nil, ErrArtifactNotFound{Repository: req.Repository, Reference: req.Reference}
	}

	detail := &RegistryArtifactDetail{
		Artifact: artifact,
		Tags:     []string{artifact.Tag},
	}

	return &RegistryInspectResponse{
		Detail: detail,
	}, nil
}

// Delete removes an artifact from the registry.
func (s *InMemoryRegistryService) Delete(
	ctx context.Context,
	req *RegistryDeleteRequest,
) (*RegistryDeleteResponse, error) {
	if req.Repository == "" {
		return nil, ErrMissingRepository{}
	}
	if req.Reference == "" && req.Digest == "" {
		return nil, ErrMissingReference{}
	}

	key := s.makeKeyFromDeleteRequest(req)
	artifact, ok := s.artifacts[key]
	if !ok {
		return nil, ErrArtifactNotFound{Repository: req.Repository, Reference: req.Reference}
	}

	data := s.data[key]
	bytesFreed := int64(len(data))

	delete(s.artifacts, key)
	delete(s.data, key)

	return &RegistryDeleteResponse{
		Digest:     artifact.Digest,
		BytesFreed: bytesFreed,
		Timestamp:  time.Now().UTC(),
	}, nil
}

// Status returns the current status of the registry.
func (s *InMemoryRegistryService) Status(ctx context.Context) (*RegistryStatusResponse, error) {
	var totalSize int64
	for _, data := range s.data {
		totalSize += int64(len(data))
	}

	return &RegistryStatusResponse{
		Health:   RegistryHealthStatusHealthy,
		Version:  "1.0.0",
		ReadOnly: false,
		Storage: &RegistryStorageStats{
			TotalBytes:      1024 * 1024 * 1024,
			UsedBytes:       totalSize,
			AvailableBytes:  1024*1024*1024 - totalSize,
			ArtifactCount:   int64(len(s.artifacts)),
			LayerCount:      0,
			RepositoryCount: int64(s.countRepositories()),
		},
		Components: []*RegistryComponentHealth{
			{
				Name:      "storage",
				Status:    RegistryHealthStatusHealthy,
				Message:   "storage backend healthy",
				LastCheck: time.Now().UTC(),
			},
		},
		StartedAt: s.startedAt,
		Timestamp: time.Now().UTC(),
	}, nil
}

func (s *InMemoryRegistryService) makeKey(repository, tag string) string {
	if tag == "" {
		tag = "latest"
	}
	return repository + ":" + tag
}

func (s *InMemoryRegistryService) makeKeyFromRequest(req *RegistryPullRequest) string {
	if req.Digest != "" {
		return req.Repository + "@" + req.Digest
	}
	return s.makeKey(req.Repository, req.Reference)
}

func (s *InMemoryRegistryService) makeKeyFromInspectRequest(req *RegistryInspectRequest) string {
	if req.Digest != "" {
		return req.Repository + "@" + req.Digest
	}
	return s.makeKey(req.Repository, req.Reference)
}

func (s *InMemoryRegistryService) makeKeyFromDeleteRequest(req *RegistryDeleteRequest) string {
	if req.Digest != "" {
		return req.Repository + "@" + req.Digest
	}
	return s.makeKey(req.Repository, req.Reference)
}

func (s *InMemoryRegistryService) matchesSelector(
	artifact *RegistryArtifact,
	selector *RegistryLabelSelector,
) bool {
	if selector.MatchLabels != nil {
		for k, v := range selector.MatchLabels {
			if artifact.Labels[k] != v {
				return false
			}
		}
	}
	return true
}

func (s *InMemoryRegistryService) countRepositories() int {
	repos := make(map[string]struct{})
	for _, a := range s.artifacts {
		repos[a.Repository] = struct{}{}
	}
	return len(repos)
}

// Ensure InMemoryRegistryService implements RegistryService.
var _ RegistryService = (*InMemoryRegistryService)(nil)
