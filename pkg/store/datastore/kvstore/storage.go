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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// Storage defines the interface for key-value storage operations.
// This interface enables dependency injection and mocking for unit tests.
type Storage interface {
	// Start initializes the storage backend. Must be called before other operations.
	Start(ctx context.Context) error

	// Stop gracefully shuts down the storage backend.
	Stop(ctx context.Context) error

	// IsStarted returns true if the storage is ready to accept operations.
	IsStarted() bool

	// IsClosed returns true if the storage has been shut down.
	IsClosed() bool

	// Put stores a key-value pair.
	// shardID specifies which Raft shard handles this operation (0 = default shard).
	Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error

	// Get retrieves a value by entity type and ID.
	// Returns (data, found, error) where found=false if the entity doesn't exist.
	// shardID specifies which Raft shard handles this operation (0 = default shard).
	Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error)

	// Delete removes an entity.
	// shardID specifies which Raft shard handles this operation (0 = default shard).
	Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error

	// List retrieves entities with pagination.
	// Returns (entities, nextPageToken, error).
	// shardID specifies which Raft shard handles this operation (0 = default shard).
	List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error)

	// Query searches for entities using secondary indexes.
	// shardID specifies which Raft shard handles this operation (0 = default shard).
	Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error)
}
