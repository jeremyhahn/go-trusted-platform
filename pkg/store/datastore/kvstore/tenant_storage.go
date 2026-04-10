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

package kvstore

import (
	"context"
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// TenantStorage wraps a Storage backend with tenant-scoped key prefixing.
// All entity types are prefixed with "{tenantID}/" for namespace isolation,
// ensuring that tenants cannot access each other's data even when sharing
// the same underlying storage backend.
type TenantStorage struct {
	inner    Storage
	tenantID string
	prefix   string
}

// NewTenantStorage creates a new TenantStorage decorator that prefixes all
// entity types with the given tenant ID. The tenantID must not be empty
// and must not contain the "/" separator character.
func NewTenantStorage(inner Storage, tenantID string) (*TenantStorage, error) {
	if inner == nil {
		return nil, ErrTenantStorageInnerNil{}
	}
	if tenantID == "" {
		return nil, ErrTenantIDEmpty{}
	}
	if strings.Contains(tenantID, "/") {
		return nil, ErrTenantIDInvalid{TenantID: tenantID, Reason: "must not contain '/'"}
	}

	return &TenantStorage{
		inner:    inner,
		tenantID: tenantID,
		prefix:   tenantID + "/",
	}, nil
}

// Start delegates to the inner storage backend.
func (ts *TenantStorage) Start(ctx context.Context) error {
	return ts.inner.Start(ctx)
}

// Stop delegates to the inner storage backend.
func (ts *TenantStorage) Stop(ctx context.Context) error {
	return ts.inner.Stop(ctx)
}

// IsStarted delegates to the inner storage backend.
func (ts *TenantStorage) IsStarted() bool {
	return ts.inner.IsStarted()
}

// IsClosed delegates to the inner storage backend.
func (ts *TenantStorage) IsClosed() bool {
	return ts.inner.IsClosed()
}

// Put stores a key-value pair with the entity type prefixed by the tenant ID.
func (ts *TenantStorage) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	return ts.inner.Put(ctx, ts.prefix+entityType, id, data, shardID)
}

// Get retrieves a value with the entity type prefixed by the tenant ID.
func (ts *TenantStorage) Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error) {
	return ts.inner.Get(ctx, ts.prefix+entityType, id, shardID)
}

// Delete removes an entity with the entity type prefixed by the tenant ID.
func (ts *TenantStorage) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	return ts.inner.Delete(ctx, ts.prefix+entityType, id, shardID)
}

// List retrieves entities with pagination, using the tenant-prefixed entity type.
func (ts *TenantStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	return ts.inner.List(ctx, ts.prefix+entityType, pageSize, pageToken, shardID)
}

// Query searches for entities using secondary indexes, with the tenant-prefixed entity type.
func (ts *TenantStorage) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	return ts.inner.Query(ctx, ts.prefix+entityType, indexField, value, shardID)
}

// TenantID returns the tenant ID for this storage decorator.
func (ts *TenantStorage) TenantID() string {
	return ts.tenantID
}

// Prefix returns the full prefix applied to entity types.
func (ts *TenantStorage) Prefix() string {
	return ts.prefix
}

// Ensure TenantStorage implements Storage at compile time.
var _ Storage = (*TenantStorage)(nil)
