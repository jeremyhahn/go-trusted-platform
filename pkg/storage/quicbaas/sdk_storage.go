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

package quicbaas

import (
	"context"
	"strings"
	"sync/atomic"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/query"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// SDKStorage implements the Storage interface using the go-quicbaas SDK.
// This adapter enables DAOs to work with the SDK client in both embedded
// and remote modes, providing a unified storage abstraction.
type SDKStorage struct {
	sdk     quicbaas.Client
	started atomic.Bool
	closed  atomic.Bool
}

// NewSDKStorage creates a new SDK-based Storage implementation.
// The provided SDK client must be properly initialized.
func NewSDKStorage(sdk quicbaas.Client) (*SDKStorage, error) {
	if sdk == nil {
		return nil, ErrSDKClientNil{}
	}
	return &SDKStorage{
		sdk: sdk,
	}, nil
}

// Start marks the storage as ready. The SDK client is expected to be
// already initialized, so this is primarily for interface compliance.
func (s *SDKStorage) Start(ctx context.Context) error {
	if s.closed.Load() {
		return ErrStorageClosed{}
	}
	s.started.Store(true)
	return nil
}

// Stop marks the storage as stopped. The SDK client lifecycle is
// managed externally by the Factory.
func (s *SDKStorage) Stop(ctx context.Context) error {
	s.started.Store(false)
	s.closed.Store(true)
	return nil
}

// IsStarted returns true if the storage is ready to accept operations.
func (s *SDKStorage) IsStarted() bool {
	return s.started.Load() && !s.closed.Load()
}

// IsClosed returns true if the storage has been shut down.
func (s *SDKStorage) IsClosed() bool {
	return s.closed.Load()
}

// Put stores a key-value pair using the SDK's KV client.
func (s *SDKStorage) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	if !s.IsStarted() {
		return ErrStorageNotStarted{}
	}

	req := &service.PutRequest{
		EntityType:  entityType,
		ID:          id,
		Data:        data,
		ShardID:     shardID,
		Consistency: service.ConsistencyLevelLinearizable,
	}

	_, err := s.sdk.KV().Put(ctx, req)
	return err
}

// Get retrieves a value by entity type and ID using the SDK's KV client.
func (s *SDKStorage) Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error) {
	if !s.IsStarted() {
		return nil, false, ErrStorageNotStarted{}
	}

	req := &service.GetRequest{
		EntityType:  entityType,
		ID:          id,
		ShardID:     shardID,
		Consistency: service.ConsistencyLevelLinearizable,
	}

	resp, err := s.sdk.KV().Get(ctx, req)
	if err != nil {
		// QuicBaaS returns an error (not Found=false) for missing keys.
		// Convert to the Storage interface convention: found=false, no error.
		// Check both typed errors and string patterns since errors may be
		// wrapped through multiple transport layers.
		if IsNotFound(err) || isNotFoundString(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	return resp.Data, resp.Found, nil
}

// Delete removes an entity using the SDK's KV client.
func (s *SDKStorage) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	if !s.IsStarted() {
		return ErrStorageNotStarted{}
	}

	req := &service.DeleteRequest{
		EntityType:  entityType,
		ID:          id,
		ShardID:     shardID,
		Consistency: service.ConsistencyLevelLinearizable,
	}

	_, err := s.sdk.KV().Delete(ctx, req)
	return err
}

// List retrieves entities with pagination using the SDK's KV client.
func (s *SDKStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	if !s.IsStarted() {
		return nil, "", ErrStorageNotStarted{}
	}

	req := &service.ListRequest{
		EntityType: entityType,
		PageSize:   pageSize,
		PageToken:  pageToken,
		ShardID:    shardID,
	}

	resp, err := s.sdk.KV().List(ctx, req)
	if err != nil {
		return nil, "", err
	}

	return resp.Entities, resp.NextPageToken, nil
}

// Query searches for entities using secondary indexes via the SDK's Query client.
func (s *SDKStorage) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	if !s.IsStarted() {
		return nil, ErrStorageNotStarted{}
	}

	req := &query.QueryRequest{
		EntityType: entityType,
		Index:      indexField,
		Value:      value,
		Operator:   query.OpEqual,
	}

	resp, err := s.sdk.Query().Execute(ctx, req)
	if err != nil {
		return nil, err
	}

	// Convert query results to entities
	entities := make([]*service.Entity, 0, len(resp.Results))
	for _, result := range resp.Results {
		entities = append(entities, &service.Entity{
			Data: result.Value,
		})
	}

	return entities, nil
}

// SDK returns the underlying go-quicbaas SDK client for advanced operations.
func (s *SDKStorage) SDK() quicbaas.Client {
	return s.sdk
}

// isNotFoundString checks if an error message indicates a not-found condition.
// This is a fallback for errors wrapped through multiple transport layers
// where typed error matching via errors.As may not work.
func isNotFoundString(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "not_found")
}

// Ensure SDKStorage implements Storage interface at compile time.
var _ Storage = (*SDKStorage)(nil)
