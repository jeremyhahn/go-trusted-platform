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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/objectstorage"
)

// ObjectStorageService serves the SDK's ObjectStorage group: it validates
// each request, resolves the group and calls it.
type ObjectStorageService struct {
	resolver Resolver[objectstorage.Client]
}

// NewObjectStorageService returns the object storage service. resolver
// yields the SDK's ObjectStorage group, or nil while the SDK is not serving.
func NewObjectStorageService(resolver Resolver[objectstorage.Client]) *ObjectStorageService {
	return &ObjectStorageService{resolver: resolver}
}

// Put stores an object.
func (s *ObjectStorageService) Put(ctx context.Context, req *objectstorage.PutObjectRequest) (*objectstorage.PutObjectResponse, error) {
	return objectStorageCall(ctx, s.resolver, "put", req, validatePutObject, objectstorage.Client.PutObject)
}

// Get returns an object with its data.
func (s *ObjectStorageService) Get(ctx context.Context, req *objectstorage.GetObjectRequest) (*objectstorage.GetObjectResponse, error) {
	validate := func(req *objectstorage.GetObjectRequest) error { return requireObjectKey("key", req.Key) }
	return objectStorageCall(ctx, s.resolver, "get", req, validate, objectstorage.Client.GetObject)
}

// Delete removes an object.
func (s *ObjectStorageService) Delete(ctx context.Context, req *objectstorage.DeleteObjectRequest) (*objectstorage.DeleteObjectResponse, error) {
	validate := func(req *objectstorage.DeleteObjectRequest) error { return requireObjectKey("key", req.Key) }
	return objectStorageCall(ctx, s.resolver, "delete", req, validate, objectstorage.Client.DeleteObject)
}

// Head returns the metadata of an object without its data.
func (s *ObjectStorageService) Head(ctx context.Context, req *objectstorage.HeadObjectRequest) (*objectstorage.HeadObjectResponse, error) {
	validate := func(req *objectstorage.HeadObjectRequest) error { return requireObjectKey("key", req.Key) }
	return objectStorageCall(ctx, s.resolver, "head", req, validate, objectstorage.Client.HeadObject)
}

// List lists the objects under a key prefix.
func (s *ObjectStorageService) List(ctx context.Context, req *objectstorage.ListObjectsRequest) (*objectstorage.ListObjectsResponse, error) {
	validate := func(req *objectstorage.ListObjectsRequest) error { return requireLimit(req.Limit) }
	return objectStorageCall(ctx, s.resolver, "list", req, validate, objectstorage.Client.ListObjects)
}

// Copy copies an object to a new key.
func (s *ObjectStorageService) Copy(ctx context.Context, req *objectstorage.CopyObjectRequest) (*objectstorage.CopyObjectResponse, error) {
	validate := func(req *objectstorage.CopyObjectRequest) error {
		if err := requireObjectKey("source_key", req.SourceKey); err != nil {
			return err
		}
		if err := requireObjectKey("destination_key", req.DestinationKey); err != nil {
			return err
		}
		return requireTargetBackend(req.TargetBackend)
	}
	return objectStorageCall(ctx, s.resolver, "copy", req, validate, objectstorage.Client.CopyObject)
}

// ListByTag lists the objects whose tag has a value.
func (s *ObjectStorageService) ListByTag(ctx context.Context, req *objectstorage.ListByTagRequest) (*objectstorage.ListByTagResponse, error) {
	validate := func(req *objectstorage.ListByTagRequest) error {
		if err := requireName(ServiceObjectStorage, "tag_name", req.TagName); err != nil {
			return err
		}
		return requireLimit(req.Limit)
	}
	return objectStorageCall(ctx, s.resolver, "list by tag", req, validate, objectstorage.Client.ListByTag)
}

// ListByTenant lists the objects one tenant owns.
func (s *ObjectStorageService) ListByTenant(ctx context.Context, req *objectstorage.ListByTenantRequest) (*objectstorage.ListByTenantResponse, error) {
	validate := func(req *objectstorage.ListByTenantRequest) error {
		if err := requireName(ServiceObjectStorage, "tenant_id", req.TenantID); err != nil {
			return err
		}
		return requireLimit(req.Limit)
	}
	return objectStorageCall(ctx, s.resolver, "list by tenant", req, validate, objectstorage.Client.ListByTenant)
}

// objectStorageCall is the shape of every object storage operation: refuse a
// missing or invalid request before it reaches the SDK, resolve the group,
// then call it. call is a method expression of objectstorage.Client.
func objectStorageCall[Req, Resp any](
	ctx context.Context,
	resolver Resolver[objectstorage.Client],
	op string,
	req *Req,
	validate func(*Req) error,
	call func(objectstorage.Client, context.Context, *Req) (*Resp, error),
) (*Resp, error) {
	if req == nil {
		return nil, ErrInvalidArgument{Service: ServiceObjectStorage, Field: "request", Reason: "is required"}
	}
	if err := validate(req); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceObjectStorage, resolver)
	if err != nil {
		return nil, err
	}
	resp, err := call(client, ctx, req)
	return resp, callFailed(ServiceObjectStorage, op, err)
}

func validatePutObject(req *objectstorage.PutObjectRequest) error {
	if err := requireObjectKey("key", req.Key); err != nil {
		return err
	}
	if err := requireTargetBackend(req.TargetBackend); err != nil {
		return err
	}
	if req.ReplicationPolicy == nil {
		return nil
	}
	return validateReplicationMode(req.ReplicationPolicy.Mode)
}

// validReplicationModes are the modes the SDK accepts; empty takes the
// store default.
var validReplicationModes = map[objectstorage.ReplicationMode]bool{
	"":                                  true,
	objectstorage.ReplicationModeSync:   true,
	objectstorage.ReplicationModeAsync:  true,
	objectstorage.ReplicationModeQuorum: true,
}

func validateReplicationMode(mode objectstorage.ReplicationMode) error {
	if !validReplicationModes[mode] {
		return ErrInvalidArgument{Service: ServiceObjectStorage, Field: "replication_policy.mode", Reason: "must be sync, async or quorum"}
	}
	return nil
}

func requireObjectKey(field, key string) error {
	return requireName(ServiceObjectStorage, field, key)
}

// noPrimaryBackendReason is the reason a put or copy without a target backend
// is refused. The pinned go-quicbaas server builds its object store from
// config.DefaultObjectStoreDefaults(), which names no primary backend, so
// the store fails an empty backend name instead of choosing one.
const noPrimaryBackendReason = "required: the go-quicbaas object store has no primary backend to choose " +
	"(DefaultObjectStoreDefaults sets none), so name the backend"

func requireTargetBackend(backend string) error {
	if backend == "" {
		return ErrInvalidArgument{Service: ServiceObjectStorage, Field: "target_backend", Reason: noPrimaryBackendReason}
	}
	return nil
}

func requireLimit(limit int) error {
	return requireNotNegative(ServiceObjectStorage, "limit", limit)
}
