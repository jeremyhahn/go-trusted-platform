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
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/objectstorage"
)

// ObjectStorageGRPCService serves platform.v1.ObjectStorageService over the
// SDK's ObjectStorage group. REST, MCP and QUIC reach the same instance.
type ObjectStorageGRPCService struct {
	platformv1.UnimplementedObjectStorageServiceServer

	service *appservices.ObjectStorageService
	logger  *logging.Logger
}

// NewObjectStorageGRPCService returns the object storage gRPC server. A nil
// service answers every call Unavailable.
func NewObjectStorageGRPCService(logger *logging.Logger, service *appservices.ObjectStorageService) *ObjectStorageGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	if service == nil {
		service = appservices.NewObjectStorageService(nil)
	}
	return &ObjectStorageGRPCService{service: service, logger: logger}
}

// PutObject stores an object.
func (s *ObjectStorageGRPCService) PutObject(ctx context.Context, req *platformv1.PutObjectRequest) (*platformv1.PutObjectResponse, error) {
	resp, err := s.service.Put(ctx, &objectstorage.PutObjectRequest{
		Key:               req.GetKey(),
		Value:             req.GetValue(),
		ContentType:       req.GetContentType(),
		TenantID:          req.GetTenantId(),
		ShardID:           req.GetShardId(),
		Tags:              req.GetTags(),
		ReplicationPolicy: replicationPolicyFromPb(req.GetReplicationPolicy()),
		ArchivePolicy:     archivePolicyFromPb(req.GetArchivePolicy()),
		RetentionPolicy:   retentionPolicyFromPb(req.GetRetentionPolicy()),
		TargetBackend:     req.GetTargetBackend(),
		Checksum:          req.GetChecksum(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage put", err)
	}
	return &platformv1.PutObjectResponse{
		Key:             resp.Key,
		ObjectId:        resp.ObjectID,
		Checksum:        resp.Checksum,
		Size:            resp.Size,
		Backend:         resp.Backend,
		Version:         resp.Version,
		CreatedAtUnixMs: nanosToMillis(resp.CreatedAt),
	}, nil
}

// GetObject returns an object with its data.
func (s *ObjectStorageGRPCService) GetObject(ctx context.Context, req *platformv1.GetObjectRequest) (*platformv1.GetObjectResponse, error) {
	resp, err := s.service.Get(ctx, &objectstorage.GetObjectRequest{
		Key:             req.GetKey(),
		TenantID:        req.GetTenantId(),
		IncludeMetadata: req.GetIncludeMetadata(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage get", err)
	}
	return &platformv1.GetObjectResponse{
		Key:              resp.Key,
		Value:            resp.Value,
		ContentType:      resp.ContentType,
		Size:             resp.Size,
		Checksum:         resp.Checksum,
		Version:          resp.Version,
		Tags:             resp.Tags,
		TenantId:         resp.TenantID,
		CreatedAtUnixMs:  nanosToMillis(resp.CreatedAt),
		ModifiedAtUnixMs: nanosToMillis(resp.ModifiedAt),
		Backend:          resp.Backend,
	}, nil
}

// DeleteObject removes an object.
func (s *ObjectStorageGRPCService) DeleteObject(ctx context.Context, req *platformv1.DeleteObjectRequest) (*platformv1.DeleteObjectResponse, error) {
	resp, err := s.service.Delete(ctx, &objectstorage.DeleteObjectRequest{Key: req.GetKey(), TenantID: req.GetTenantId()})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage delete", err)
	}
	return &platformv1.DeleteObjectResponse{
		Key:             resp.Key,
		Deleted:         resp.Success,
		Size:            resp.Size,
		DeletedAtUnixMs: nanosToMillis(resp.Timestamp),
	}, nil
}

// HeadObject returns the metadata of an object without its data.
func (s *ObjectStorageGRPCService) HeadObject(ctx context.Context, req *platformv1.HeadObjectRequest) (*platformv1.HeadObjectResponse, error) {
	resp, err := s.service.Head(ctx, &objectstorage.HeadObjectRequest{Key: req.GetKey(), TenantID: req.GetTenantId()})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage head", err)
	}
	return &platformv1.HeadObjectResponse{
		Key:                resp.Key,
		Exists:             resp.Exists,
		ContentType:        resp.ContentType,
		Size:               resp.Size,
		Checksum:           resp.Checksum,
		Version:            resp.Version,
		Tags:               resp.Tags,
		TenantId:           resp.TenantID,
		Status:             resp.Status,
		CreatedAtUnixMs:    nanosToMillis(resp.CreatedAt),
		ModifiedAtUnixMs:   nanosToMillis(resp.ModifiedAt),
		LastAccessAtUnixMs: nanosToMillis(resp.LastAccessAt),
		Backend:            resp.Backend,
		ReplicaCount:       appInt32(resp.ReplicaCount),
	}, nil
}

// ListObjects lists the objects under a key prefix.
func (s *ObjectStorageGRPCService) ListObjects(ctx context.Context, req *platformv1.ListObjectsRequest) (*platformv1.ListObjectsResponse, error) {
	resp, err := s.service.List(ctx, &objectstorage.ListObjectsRequest{
		Prefix:      req.GetPrefix(),
		TenantID:    req.GetTenantId(),
		Limit:       int(req.GetLimit()),
		Cursor:      req.GetCursor(),
		IncludeTags: req.GetIncludeTags(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage list", err)
	}
	return objectListToPb(resp.Objects, resp.NextCursor, resp.HasMore, resp.TotalCount, resp.Timestamp), nil
}

// CopyObject copies an object to a new key.
func (s *ObjectStorageGRPCService) CopyObject(ctx context.Context, req *platformv1.CopyObjectRequest) (*platformv1.CopyObjectResponse, error) {
	resp, err := s.service.Copy(ctx, &objectstorage.CopyObjectRequest{
		SourceKey:         req.GetSourceKey(),
		DestinationKey:    req.GetDestinationKey(),
		TenantID:          req.GetTenantId(),
		OverwriteExisting: req.GetOverwriteExisting(),
		TargetBackend:     req.GetTargetBackend(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage copy", err)
	}
	return &platformv1.CopyObjectResponse{
		Key:             resp.Key,
		ObjectId:        resp.ObjectID,
		Size:            resp.Size,
		Checksum:        resp.Checksum,
		Version:         resp.Version,
		Backend:         resp.Backend,
		CreatedAtUnixMs: nanosToMillis(resp.CreatedAt),
	}, nil
}

// ListObjectsByTag lists the objects whose tag has a value.
func (s *ObjectStorageGRPCService) ListObjectsByTag(ctx context.Context, req *platformv1.ListObjectsByTagRequest) (*platformv1.ListObjectsResponse, error) {
	resp, err := s.service.ListByTag(ctx, &objectstorage.ListByTagRequest{
		TagName:  req.GetTagName(),
		TagValue: req.GetTagValue(),
		TenantID: req.GetTenantId(),
		Limit:    int(req.GetLimit()),
		Cursor:   req.GetCursor(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage list by tag", err)
	}
	return objectListToPb(resp.Objects, resp.NextCursor, resp.HasMore, resp.TotalCount, resp.Timestamp), nil
}

// ListTenantObjects lists the objects one tenant owns.
func (s *ObjectStorageGRPCService) ListTenantObjects(ctx context.Context, req *platformv1.ListTenantObjectsRequest) (*platformv1.ListObjectsResponse, error) {
	resp, err := s.service.ListByTenant(ctx, &objectstorage.ListByTenantRequest{
		TenantID:    req.GetTenantId(),
		Limit:       int(req.GetLimit()),
		Cursor:      req.GetCursor(),
		IncludeTags: req.GetIncludeTags(),
	})
	if err != nil {
		return nil, appServiceError(s.logger, "object storage list tenant objects", err)
	}
	return objectListToPb(resp.Objects, resp.NextCursor, resp.HasMore, resp.TotalCount, resp.Timestamp), nil
}

// objectListToPb builds the one listing page the three list RPCs share.
func objectListToPb(objects []*objectstorage.ObjectSummary, nextCursor string, hasMore bool, total, listedAt int64) *platformv1.ListObjectsResponse {
	page := &platformv1.ListObjectsResponse{
		Objects:        make([]*platformv1.ObjectSummary, 0, len(objects)),
		NextCursor:     nextCursor,
		HasMore:        hasMore,
		TotalCount:     total,
		ListedAtUnixMs: nanosToMillis(listedAt),
	}
	for _, object := range objects {
		if object == nil {
			continue
		}
		page.Objects = append(page.Objects, &platformv1.ObjectSummary{
			Key:              object.Key,
			Size:             object.Size,
			ContentType:      object.ContentType,
			Version:          object.Version,
			Status:           object.Status,
			Tags:             object.Tags,
			CreatedAtUnixMs:  nanosToMillis(object.CreatedAt),
			ModifiedAtUnixMs: nanosToMillis(object.ModifiedAt),
		})
	}
	return page
}

func replicationPolicyFromPb(policy *platformv1.ObjectReplicationPolicy) *objectstorage.ReplicationPolicy {
	if policy == nil {
		return nil
	}
	return &objectstorage.ReplicationPolicy{
		Enabled:      policy.GetEnabled(),
		MinReplicas:  int(policy.GetMinReplicas()),
		TargetStores: policy.GetTargetStores(),
		Mode:         objectstorage.ReplicationMode(policy.GetMode()),
		Priority:     int(policy.GetPriority()),
	}
}

func archivePolicyFromPb(policy *platformv1.ObjectArchivePolicy) *objectstorage.ArchivePolicy {
	if policy == nil {
		return nil
	}
	return &objectstorage.ArchivePolicy{
		Enabled:           policy.GetEnabled(),
		ArchiveAfterDays:  int(policy.GetArchiveAfterDays()),
		TargetStore:       policy.GetTargetStore(),
		DeleteFromPrimary: policy.GetDeleteFromPrimary(),
		CompressionLevel:  int(policy.GetCompressionLevel()),
	}
}

func retentionPolicyFromPb(policy *platformv1.ObjectRetentionPolicy) *objectstorage.RetentionPolicy {
	if policy == nil {
		return nil
	}
	return &objectstorage.RetentionPolicy{
		Enabled:       policy.GetEnabled(),
		RetentionDays: int(policy.GetRetentionDays()),
		MaxVersions:   int(policy.GetMaxVersions()),
		DeleteAfter:   policy.GetDeleteAfter(),
	}
}

// nanosToMillis converts the SDK's Unix nanoseconds to the Unix milliseconds
// every platform.v1 timestamp carries.
func nanosToMillis(ns int64) int64 {
	return ns / int64(time.Millisecond)
}
