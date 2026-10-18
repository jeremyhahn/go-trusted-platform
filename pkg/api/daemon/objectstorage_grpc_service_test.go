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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/objectstorage"
)

// recordingObjectStorage answers each operation with a fixed response and
// keeps the request it got, so the conversions in both directions show.
type recordingObjectStorage struct {
	objectstorage.Client

	put  *objectstorage.PutObjectRequest
	copy *objectstorage.CopyObjectRequest

	putResp  *objectstorage.PutObjectResponse
	getResp  *objectstorage.GetObjectResponse
	delResp  *objectstorage.DeleteObjectResponse
	headResp *objectstorage.HeadObjectResponse
	copyResp *objectstorage.CopyObjectResponse
	listResp *objectstorage.ListObjectsResponse
}

func (r *recordingObjectStorage) PutObject(_ context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	r.put = req
	return r.putResp, nil
}

func (r *recordingObjectStorage) GetObject(context.Context, *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	return r.getResp, nil
}

func (r *recordingObjectStorage) DeleteObject(context.Context, *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	return r.delResp, nil
}

func (r *recordingObjectStorage) HeadObject(context.Context, *objectstorage.HeadObjectRequest) (*objectstorage.HeadObjectResponse, error) {
	return r.headResp, nil
}

func (r *recordingObjectStorage) CopyObject(_ context.Context, req *objectstorage.CopyObjectRequest) (*objectstorage.CopyObjectResponse, error) {
	r.copy = req
	return r.copyResp, nil
}

func (r *recordingObjectStorage) ListObjects(context.Context, *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	return r.listResp, nil
}

func objectStorageServerWith(client objectstorage.Client) *ObjectStorageGRPCService {
	return NewObjectStorageGRPCService(nil, appservices.NewObjectStorageService(func() objectstorage.Client { return client }))
}

// Unix nanoseconds the fake stores answer with, and the milliseconds the
// responses must carry.
const (
	objectCreatedNs  = int64(1_700_000_000_123_456_789)
	objectCreatedMs  = int64(1_700_000_000_123)
	objectModifiedNs = int64(1_700_000_100_999_000_000)
	objectModifiedMs = int64(1_700_000_100_999)
)

func TestObjectStorageGRPCService_PutObjectConvertsPoliciesAndTimes(t *testing.T) {
	client := &recordingObjectStorage{putResp: &objectstorage.PutObjectResponse{
		Key: "docs:a.txt", ObjectID: 9, Checksum: []byte{1}, Size: 1, Backend: "local", Version: 2, CreatedAt: objectCreatedNs,
	}}
	resp, err := objectStorageServerWith(client).PutObject(context.Background(), &platformv1.PutObjectRequest{
		Key: "docs:a.txt", Value: []byte("a"), ContentType: "text/plain", TenantId: "acme", ShardId: 4,
		Tags:              map[string]string{"env": "prod"},
		ReplicationPolicy: &platformv1.ObjectReplicationPolicy{Enabled: true, MinReplicas: 3, TargetStores: []string{"s3"}, Mode: "quorum", Priority: 7},
		ArchivePolicy:     &platformv1.ObjectArchivePolicy{Enabled: true, ArchiveAfterDays: 30, TargetStore: "glacier", DeleteFromPrimary: true, CompressionLevel: 6},
		RetentionPolicy:   &platformv1.ObjectRetentionPolicy{Enabled: true, RetentionDays: 90, MaxVersions: 5, DeleteAfter: 1_800_000_000},
		TargetBackend:     "local",
		Checksum:          []byte{0xAB},
	})
	require.NoError(t, err)

	assert.Equal(t, &objectstorage.PutObjectRequest{
		Key: "docs:a.txt", Value: []byte("a"), ContentType: "text/plain", TenantID: "acme", ShardID: 4,
		Tags:              map[string]string{"env": "prod"},
		ReplicationPolicy: &objectstorage.ReplicationPolicy{Enabled: true, MinReplicas: 3, TargetStores: []string{"s3"}, Mode: objectstorage.ReplicationModeQuorum, Priority: 7},
		ArchivePolicy:     &objectstorage.ArchivePolicy{Enabled: true, ArchiveAfterDays: 30, TargetStore: "glacier", DeleteFromPrimary: true, CompressionLevel: 6},
		RetentionPolicy:   &objectstorage.RetentionPolicy{Enabled: true, RetentionDays: 90, MaxVersions: 5, DeleteAfter: 1_800_000_000},
		TargetBackend:     "local",
		Checksum:          []byte{0xAB},
	}, client.put)
	assert.Equal(t, uint64(9), resp.GetObjectId())
	assert.Equal(t, uint64(2), resp.GetVersion())
	assert.Equal(t, objectCreatedMs, resp.GetCreatedAtUnixMs())
}

func TestObjectStorageGRPCService_PutObjectWithoutPoliciesSendsNone(t *testing.T) {
	client := &recordingObjectStorage{putResp: &objectstorage.PutObjectResponse{Key: "docs:a.txt"}}
	_, err := objectStorageServerWith(client).PutObject(context.Background(), &platformv1.PutObjectRequest{Key: "docs:a.txt", TargetBackend: "local"})
	require.NoError(t, err)
	assert.Nil(t, client.put.ReplicationPolicy)
	assert.Nil(t, client.put.ArchivePolicy)
	assert.Nil(t, client.put.RetentionPolicy)
}

func TestObjectStorageGRPCService_ReadsConvertTimes(t *testing.T) {
	client := &recordingObjectStorage{
		getResp: &objectstorage.GetObjectResponse{
			Key: "docs:a.txt", Value: []byte("a"), TenantID: "acme", CreatedAt: objectCreatedNs, ModifiedAt: objectModifiedNs,
		},
		delResp: &objectstorage.DeleteObjectResponse{Key: "docs:a.txt", Success: true, Size: 5, Timestamp: objectModifiedNs},
		headResp: &objectstorage.HeadObjectResponse{
			Key: "docs:a.txt", Exists: true, Status: "archived", ReplicaCount: 3,
			CreatedAt: objectCreatedNs, ModifiedAt: objectModifiedNs, LastAccessAt: objectModifiedNs,
		},
		copyResp: &objectstorage.CopyObjectResponse{Key: "docs:b.txt", ObjectID: 11, CreatedAt: objectCreatedNs},
	}
	server := objectStorageServerWith(client)
	ctx := context.Background()

	got, err := server.GetObject(ctx, &platformv1.GetObjectRequest{Key: "docs:a.txt"})
	require.NoError(t, err)
	assert.Equal(t, "acme", got.GetTenantId())
	assert.Equal(t, objectCreatedMs, got.GetCreatedAtUnixMs())
	assert.Equal(t, objectModifiedMs, got.GetModifiedAtUnixMs())

	deleted, err := server.DeleteObject(ctx, &platformv1.DeleteObjectRequest{Key: "docs:a.txt"})
	require.NoError(t, err)
	assert.True(t, deleted.GetDeleted())
	assert.Equal(t, int64(5), deleted.GetSize())
	assert.Equal(t, objectModifiedMs, deleted.GetDeletedAtUnixMs())

	head, err := server.HeadObject(ctx, &platformv1.HeadObjectRequest{Key: "docs:a.txt"})
	require.NoError(t, err)
	assert.Equal(t, "archived", head.GetStatus())
	assert.Equal(t, int32(3), head.GetReplicaCount())
	assert.Equal(t, objectModifiedMs, head.GetLastAccessAtUnixMs())

	copied, err := server.CopyObject(ctx, &platformv1.CopyObjectRequest{
		SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt", OverwriteExisting: true, TargetBackend: "s3",
	})
	require.NoError(t, err)
	assert.Equal(t, &objectstorage.CopyObjectRequest{
		SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt", OverwriteExisting: true, TargetBackend: "s3",
	}, client.copy)
	assert.Equal(t, uint64(11), copied.GetObjectId())
	assert.Equal(t, objectCreatedMs, copied.GetCreatedAtUnixMs())
}

func TestObjectStorageGRPCService_ListSkipsNilSummaries(t *testing.T) {
	client := &recordingObjectStorage{listResp: &objectstorage.ListObjectsResponse{
		Objects: []*objectstorage.ObjectSummary{
			{Key: "docs:a.txt", Size: 1, Tags: map[string]string{"env": "prod"}, CreatedAt: objectCreatedNs, ModifiedAt: objectModifiedNs},
			nil,
		},
		NextCursor: "c2", HasMore: true, TotalCount: 2, Timestamp: objectModifiedNs,
	}}
	page, err := objectStorageServerWith(client).ListObjects(context.Background(), &platformv1.ListObjectsRequest{Prefix: "docs:"})
	require.NoError(t, err)
	require.Len(t, page.GetObjects(), 1)
	object := page.GetObjects()[0]
	assert.Equal(t, "docs:a.txt", object.GetKey())
	assert.Equal(t, "prod", object.GetTags()["env"])
	assert.Equal(t, objectCreatedMs, object.GetCreatedAtUnixMs())
	assert.Equal(t, objectModifiedMs, object.GetModifiedAtUnixMs())
	assert.Equal(t, "c2", page.GetNextCursor())
	assert.True(t, page.GetHasMore())
	assert.Equal(t, int64(2), page.GetTotalCount())
	assert.Equal(t, objectModifiedMs, page.GetListedAtUnixMs())
}

func TestObjectStorageGRPCService_InvalidRequestsAreInvalidArgument(t *testing.T) {
	server := objectStorageServerWith(&recordingObjectStorage{})
	ctx := context.Background()
	calls := map[string]func() error{
		"put bad mode": func() error {
			_, err := server.PutObject(ctx, &platformv1.PutObjectRequest{Key: "a:b", TargetBackend: "local",
				ReplicationPolicy: &platformv1.ObjectReplicationPolicy{Mode: "eventual"}})
			return err
		},
		"put without target backend": func() error {
			_, err := server.PutObject(ctx, &platformv1.PutObjectRequest{Key: "a:b"})
			return err
		},
		"list negative limit": func() error {
			_, err := server.ListObjects(ctx, &platformv1.ListObjectsRequest{Limit: -1})
			return err
		},
		"copy without target backend": func() error {
			_, err := server.CopyObject(ctx, &platformv1.CopyObjectRequest{SourceKey: "a:b", DestinationKey: "a:c"})
			return err
		},
		"copy without destination": func() error {
			_, err := server.CopyObject(ctx, &platformv1.CopyObjectRequest{SourceKey: "a:b"})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.InvalidArgument, status.Code(call()))
		})
	}
}

func TestNewObjectStorageGRPCService_NilServiceIsUnavailable(t *testing.T) {
	_, err := NewObjectStorageGRPCService(nil, nil).HeadObject(context.Background(), &platformv1.HeadObjectRequest{Key: "a:b"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestNanosToMillis(t *testing.T) {
	assert.Equal(t, objectCreatedMs, nanosToMillis(objectCreatedNs))
	assert.Equal(t, int64(0), nanosToMillis(0), "an unset SDK time stays unset")
	assert.Equal(t, int64(0), nanosToMillis(999_999), "less than a millisecond truncates")
}
