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

package appservices

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/objectstorage"
)

// fakeObjectStorageClient records the last request of each operation. The
// embedded interface is nil: an operation the tests do not exercise panics,
// which names it.
type fakeObjectStorageClient struct {
	objectstorage.Client

	err  error
	last any
}

func (f *fakeObjectStorageClient) PutObject(_ context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.PutObjectResponse{Key: req.Key, Version: 1}, nil
}

func (f *fakeObjectStorageClient) GetObject(_ context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.GetObjectResponse{Key: req.Key, Value: []byte("data")}, nil
}

func (f *fakeObjectStorageClient) DeleteObject(_ context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.DeleteObjectResponse{Key: req.Key, Success: true}, nil
}

func (f *fakeObjectStorageClient) HeadObject(_ context.Context, req *objectstorage.HeadObjectRequest) (*objectstorage.HeadObjectResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.HeadObjectResponse{Key: req.Key, Exists: true}, nil
}

func (f *fakeObjectStorageClient) ListObjects(_ context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.ListObjectsResponse{TotalCount: 2}, nil
}

func (f *fakeObjectStorageClient) CopyObject(_ context.Context, req *objectstorage.CopyObjectRequest) (*objectstorage.CopyObjectResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.CopyObjectResponse{Key: req.DestinationKey}, nil
}

func (f *fakeObjectStorageClient) ListByTag(_ context.Context, req *objectstorage.ListByTagRequest) (*objectstorage.ListByTagResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.ListByTagResponse{TotalCount: 3}, nil
}

func (f *fakeObjectStorageClient) ListByTenant(_ context.Context, req *objectstorage.ListByTenantRequest) (*objectstorage.ListByTenantResponse, error) {
	f.last = req
	if f.err != nil {
		return nil, f.err
	}
	return &objectstorage.ListByTenantResponse{TotalCount: 4}, nil
}

func objectStorageWith(client *fakeObjectStorageClient) *ObjectStorageService {
	return NewObjectStorageService(func() objectstorage.Client { return client })
}

// objectStorageOp runs one operation with a valid request and returns the
// request it sent, so a table can cover every operation.
type objectStorageOp struct {
	op   string
	call func(*ObjectStorageService) (any, error)
	req  any
}

func objectStorageOps() map[string]objectStorageOp {
	ctx := context.Background()
	put := &objectstorage.PutObjectRequest{Key: "docs:a.txt", Value: []byte("a"), TargetBackend: "default",
		ReplicationPolicy: &objectstorage.ReplicationPolicy{Mode: objectstorage.ReplicationModeQuorum}}
	get := &objectstorage.GetObjectRequest{Key: "docs:a.txt"}
	del := &objectstorage.DeleteObjectRequest{Key: "docs:a.txt"}
	head := &objectstorage.HeadObjectRequest{Key: "docs:a.txt"}
	list := &objectstorage.ListObjectsRequest{Prefix: "docs:", Limit: 10}
	copyReq := &objectstorage.CopyObjectRequest{SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt", TargetBackend: "default"}
	byTag := &objectstorage.ListByTagRequest{TagName: "env", TagValue: "prod"}
	byTenant := &objectstorage.ListByTenantRequest{TenantID: "acme"}
	return map[string]objectStorageOp{
		"put":            {"put", func(s *ObjectStorageService) (any, error) { return s.Put(ctx, put) }, put},
		"get":            {"get", func(s *ObjectStorageService) (any, error) { return s.Get(ctx, get) }, get},
		"delete":         {"delete", func(s *ObjectStorageService) (any, error) { return s.Delete(ctx, del) }, del},
		"head":           {"head", func(s *ObjectStorageService) (any, error) { return s.Head(ctx, head) }, head},
		"list":           {"list", func(s *ObjectStorageService) (any, error) { return s.List(ctx, list) }, list},
		"copy":           {"copy", func(s *ObjectStorageService) (any, error) { return s.Copy(ctx, copyReq) }, copyReq},
		"list by tag":    {"list by tag", func(s *ObjectStorageService) (any, error) { return s.ListByTag(ctx, byTag) }, byTag},
		"list by tenant": {"list by tenant", func(s *ObjectStorageService) (any, error) { return s.ListByTenant(ctx, byTenant) }, byTenant},
	}
}

func TestObjectStorageService_ForwardsEveryOperation(t *testing.T) {
	for name, tc := range objectStorageOps() {
		t.Run(name, func(t *testing.T) {
			client := &fakeObjectStorageClient{}
			resp, err := tc.call(objectStorageWith(client))
			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Same(t, tc.req, client.last, "the request reaches the SDK unchanged")
		})
	}
}

func TestObjectStorageService_WrapsSDKErrors(t *testing.T) {
	for name, tc := range objectStorageOps() {
		t.Run(name, func(t *testing.T) {
			_, err := tc.call(objectStorageWith(&fakeObjectStorageClient{err: errSDK}))
			assertCallFailed(t, err, ServiceObjectStorage, tc.op)
		})
	}
}

func TestObjectStorageService_NotConfigured(t *testing.T) {
	services := map[string]*ObjectStorageService{
		"no resolver":         NewObjectStorageService(nil),
		"resolver yields nil": NewObjectStorageService(func() objectstorage.Client { return nil }),
	}
	for name, svc := range services {
		t.Run(name, func(t *testing.T) {
			for op, tc := range objectStorageOps() {
				_, err := tc.call(svc)
				assert.Equal(t, ErrNotConfigured{Service: ServiceObjectStorage}, err, op)
			}
		})
	}
}

func TestObjectStorageService_RefusesInvalidRequests(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		call  func(*ObjectStorageService) error
		field string
	}{
		"put nil": {func(s *ObjectStorageService) error { _, err := s.Put(ctx, nil); return err }, "request"},
		"put no key": {func(s *ObjectStorageService) error {
			_, err := s.Put(ctx, &objectstorage.PutObjectRequest{})
			return err
		}, "key"},
		"put no target backend": {func(s *ObjectStorageService) error {
			_, err := s.Put(ctx, &objectstorage.PutObjectRequest{Key: "a:b"})
			return err
		}, "target_backend"},
		"put bad replication mode": {func(s *ObjectStorageService) error {
			_, err := s.Put(ctx, &objectstorage.PutObjectRequest{Key: "a:b", TargetBackend: "default",
				ReplicationPolicy: &objectstorage.ReplicationPolicy{Mode: "eventual"}})
			return err
		}, "replication_policy.mode"},
		"get no key": {func(s *ObjectStorageService) error {
			_, err := s.Get(ctx, &objectstorage.GetObjectRequest{})
			return err
		}, "key"},
		"delete no key": {func(s *ObjectStorageService) error {
			_, err := s.Delete(ctx, &objectstorage.DeleteObjectRequest{})
			return err
		}, "key"},
		"head no key": {func(s *ObjectStorageService) error {
			_, err := s.Head(ctx, &objectstorage.HeadObjectRequest{})
			return err
		}, "key"},
		"list negative limit": {func(s *ObjectStorageService) error {
			_, err := s.List(ctx, &objectstorage.ListObjectsRequest{Limit: -1})
			return err
		}, "limit"},
		"copy no source": {func(s *ObjectStorageService) error {
			_, err := s.Copy(ctx, &objectstorage.CopyObjectRequest{DestinationKey: "a:b"})
			return err
		}, "source_key"},
		"copy no destination": {func(s *ObjectStorageService) error {
			_, err := s.Copy(ctx, &objectstorage.CopyObjectRequest{SourceKey: "a:b"})
			return err
		}, "destination_key"},
		"copy no target backend": {func(s *ObjectStorageService) error {
			_, err := s.Copy(ctx, &objectstorage.CopyObjectRequest{SourceKey: "a:b", DestinationKey: "a:c"})
			return err
		}, "target_backend"},
		"by tag no name": {func(s *ObjectStorageService) error {
			_, err := s.ListByTag(ctx, &objectstorage.ListByTagRequest{TagValue: "prod"})
			return err
		}, "tag_name"},
		"by tag negative limit": {func(s *ObjectStorageService) error {
			_, err := s.ListByTag(ctx, &objectstorage.ListByTagRequest{TagName: "env", Limit: -1})
			return err
		}, "limit"},
		"by tenant no tenant": {func(s *ObjectStorageService) error {
			_, err := s.ListByTenant(ctx, &objectstorage.ListByTenantRequest{})
			return err
		}, "tenant_id"},
		"by tenant negative limit": {func(s *ObjectStorageService) error {
			_, err := s.ListByTenant(ctx, &objectstorage.ListByTenantRequest{TenantID: "acme", Limit: -5})
			return err
		}, "limit"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client := &fakeObjectStorageClient{}
			assertInvalid(t, tc.call(objectStorageWith(client)), tc.field)
			assert.Nil(t, client.last, "an invalid request must not reach the SDK")
		})
	}
}

func TestObjectStorageService_AcceptsEveryReplicationMode(t *testing.T) {
	for mode := range validReplicationModes {
		client := &fakeObjectStorageClient{}
		_, err := objectStorageWith(client).Put(context.Background(), &objectstorage.PutObjectRequest{
			Key: "a:b", TargetBackend: "default", ReplicationPolicy: &objectstorage.ReplicationPolicy{Mode: mode}})
		require.NoError(t, err, "mode %q", mode)
	}
}

func TestObjectStorageService_MissingBackendNamesTheUpstreamGap(t *testing.T) {
	_, err := objectStorageWith(&fakeObjectStorageClient{}).Put(context.Background(),
		&objectstorage.PutObjectRequest{Key: "a:b"})
	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Contains(t, invalid.Reason, "no primary backend")
	assert.Contains(t, invalid.Reason, "DefaultObjectStoreDefaults")
}
