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

package object

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/jeremyhahn/go-objstore/pkg/common"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
)

// ObjStoreAdapter wraps a QuicBaaS ObjectStorage client to implement
// go-objstore's common.Storage interface. This reverse adapter enables
// go-trusted-ca's CertificateAuthority interface (which requires
// ObjectStore() common.Storage) to work with QuicBaaS ObjectStorage.
type ObjStoreAdapter struct {
	client    objectstorage.Client
	tenantID  string
	backend   string
	namespace string
	prefix    string
}

// NewObjStoreAdapter creates a new adapter that wraps a QuicBaaS
// ObjectStorage client and implements go-objstore's common.Storage interface.
func NewObjStoreAdapter(client objectstorage.Client) common.Storage {
	return &ObjStoreAdapter{
		client:    client,
		backend:   DefaultBackend,
		namespace: DefaultNamespace,
	}
}

// NewObjStoreAdapterWithTenant creates a new adapter with tenant isolation.
func NewObjStoreAdapterWithTenant(client objectstorage.Client, tenantID string) common.Storage {
	return &ObjStoreAdapter{
		client:    client,
		tenantID:  tenantID,
		backend:   DefaultBackend,
		namespace: DefaultNamespace,
	}
}

// Configure stores the path setting as a prefix for key construction.
func (a *ObjStoreAdapter) Configure(settings map[string]string) error {
	if p, ok := settings["path"]; ok {
		a.prefix = p
	}
	return nil
}

// formatKey converts a raw key to QuicBaaS "namespace:path" format.
// Leading slashes are stripped from the path since QuicBaaS catalog
// keys must not start or end with slashes.
func (a *ObjStoreAdapter) formatKey(key string) string {
	var path string
	if a.prefix != "" {
		path = strings.TrimLeft(a.prefix, "/") + "/" + strings.TrimLeft(key, "/")
	} else {
		path = strings.TrimLeft(key, "/")
	}
	return a.namespace + ":" + path
}

// Put stores an object via the QuicBaaS ObjectStorage client.
func (a *ObjStoreAdapter) Put(key string, data io.Reader) error {
	return a.PutWithContext(context.Background(), key, data)
}

// PutWithContext stores an object with context support.
func (a *ObjStoreAdapter) PutWithContext(ctx context.Context, key string, data io.Reader) error {
	value, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	_, err = a.client.PutObject(ctx, &objectstorage.PutObjectRequest{
		Key:           a.formatKey(key),
		Value:         value,
		TenantID:      a.tenantID,
		TargetBackend: a.backend,
	})
	return err
}

// PutWithMetadata stores an object with metadata via the QuicBaaS client.
func (a *ObjStoreAdapter) PutWithMetadata(ctx context.Context, key string, data io.Reader, metadata *common.Metadata) error {
	value, err := io.ReadAll(data)
	if err != nil {
		return err
	}
	req := &objectstorage.PutObjectRequest{
		Key:           a.formatKey(key),
		Value:         value,
		TenantID:      a.tenantID,
		TargetBackend: a.backend,
	}
	if metadata != nil {
		req.ContentType = metadata.ContentType
		req.Tags = metadata.Custom
	}
	_, err = a.client.PutObject(ctx, req)
	return err
}

// Get retrieves an object from the QuicBaaS ObjectStorage client.
func (a *ObjStoreAdapter) Get(key string) (io.ReadCloser, error) {
	return a.GetWithContext(context.Background(), key)
}

// GetWithContext retrieves an object with context support.
func (a *ObjStoreAdapter) GetWithContext(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := a.client.GetObject(ctx, &objectstorage.GetObjectRequest{
		Key:      a.formatKey(key),
		TenantID: a.tenantID,
	})
	if err != nil {
		if isNotFoundError(err) {
			return nil, errors.New("object not found: " + key)
		}
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(resp.Value)), nil
}

// GetMetadata retrieves metadata for an object.
func (a *ObjStoreAdapter) GetMetadata(ctx context.Context, key string) (*common.Metadata, error) {
	resp, err := a.client.HeadObject(ctx, &objectstorage.HeadObjectRequest{
		Key:      a.formatKey(key),
		TenantID: a.tenantID,
	})
	if err != nil {
		return nil, err
	}
	if !resp.Exists {
		return nil, errors.New("object not found: " + key)
	}
	return &common.Metadata{
		ContentType: resp.ContentType,
		Size:        resp.Size,
		Custom:      resp.Tags,
	}, nil
}

// UpdateMetadata updates metadata for an existing object.
// QuicBaaS ObjectStorage does not support metadata-only updates,
// so this reads the object and re-puts it with new metadata.
func (a *ObjStoreAdapter) UpdateMetadata(ctx context.Context, key string, metadata *common.Metadata) error {
	resp, err := a.client.GetObject(ctx, &objectstorage.GetObjectRequest{
		Key:      a.formatKey(key),
		TenantID: a.tenantID,
	})
	if err != nil {
		return err
	}
	return a.PutWithMetadata(ctx, key, bytes.NewReader(resp.Value), metadata)
}

// Delete removes an object from the QuicBaaS ObjectStorage client.
func (a *ObjStoreAdapter) Delete(key string) error {
	return a.DeleteWithContext(context.Background(), key)
}

// DeleteWithContext removes an object with context support.
func (a *ObjStoreAdapter) DeleteWithContext(ctx context.Context, key string) error {
	_, err := a.client.DeleteObject(ctx, &objectstorage.DeleteObjectRequest{
		Key:      a.formatKey(key),
		TenantID: a.tenantID,
	})
	return err
}

// Exists checks if an object exists in the QuicBaaS ObjectStorage.
func (a *ObjStoreAdapter) Exists(ctx context.Context, key string) (bool, error) {
	resp, err := a.client.HeadObject(ctx, &objectstorage.HeadObjectRequest{
		Key:      a.formatKey(key),
		TenantID: a.tenantID,
	})
	if err != nil {
		return false, err
	}
	return resp.Exists, nil
}

// List returns all keys matching the given prefix.
func (a *ObjStoreAdapter) List(prefix string) ([]string, error) {
	return a.ListWithContext(context.Background(), prefix)
}

// ListWithContext returns all keys with context support.
func (a *ObjStoreAdapter) ListWithContext(ctx context.Context, prefix string) ([]string, error) {
	resp, err := a.client.ListObjects(ctx, &objectstorage.ListObjectsRequest{
		Prefix:   a.formatKey(prefix),
		TenantID: a.tenantID,
	})
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(resp.Objects))
	for _, obj := range resp.Objects {
		keys = append(keys, obj.Key)
	}
	return keys, nil
}

// ListWithOptions returns a paginated list of objects with full metadata.
func (a *ObjStoreAdapter) ListWithOptions(ctx context.Context, opts *common.ListOptions) (*common.ListResult, error) {
	req := &objectstorage.ListObjectsRequest{
		TenantID: a.tenantID,
	}
	if opts != nil {
		req.Prefix = opts.Prefix
		req.Limit = opts.MaxResults
		req.Cursor = opts.ContinueFrom
	}
	resp, err := a.client.ListObjects(ctx, req)
	if err != nil {
		return nil, err
	}
	objects := make([]*common.ObjectInfo, 0, len(resp.Objects))
	for _, obj := range resp.Objects {
		objects = append(objects, &common.ObjectInfo{
			Key: obj.Key,
			Metadata: &common.Metadata{
				ContentType: obj.ContentType,
				Size:        obj.Size,
			},
		})
	}
	return &common.ListResult{
		Objects:   objects,
		NextToken: resp.NextCursor,
		Truncated: resp.HasMore,
	}, nil
}

// Archive copies an object to an archive destination. QuicBaaS uses its own
// archive operations, so this is not supported via this adapter.
func (a *ObjStoreAdapter) Archive(key string, destination common.Archiver) error {
	return errors.New("archive not supported via ObjStoreAdapter, use QuicBaaS archive policies")
}

// AddPolicy is a no-op since QuicBaaS manages lifecycle policies internally.
func (a *ObjStoreAdapter) AddPolicy(policy common.LifecyclePolicy) error {
	return nil
}

// RemovePolicy is a no-op since QuicBaaS manages lifecycle policies internally.
func (a *ObjStoreAdapter) RemovePolicy(id string) error {
	return nil
}

// GetPolicies returns an empty list since QuicBaaS manages policies internally.
func (a *ObjStoreAdapter) GetPolicies() ([]common.LifecyclePolicy, error) {
	return nil, nil
}

// Compile-time interface check.
var _ common.Storage = (*ObjStoreAdapter)(nil)
