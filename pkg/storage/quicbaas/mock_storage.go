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
	"encoding/binary"
	"sync"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

// MockStorage provides an in-memory implementation of the Storage interface
// for fast unit testing without requiring a real QuicBaaS instance.
type MockStorage struct {
	mu           sync.RWMutex
	data         map[string]map[uint64][]byte                       // entityType -> id -> data
	queryResults map[string]map[string]map[string][]*service.Entity // entityType -> field -> value -> results
	started      bool
	closed       bool

	// Error injection for testing error paths
	PutError    error
	GetError    error
	DeleteError error
	ListError   error
	QueryError  error
	StartError  error
	StopError   error
}

// NewMockStorage creates a new mock storage instance.
func NewMockStorage() *MockStorage {
	return &MockStorage{
		data:         make(map[string]map[uint64][]byte),
		queryResults: make(map[string]map[string]map[string][]*service.Entity),
	}
}

// Start simulates starting the storage backend.
func (m *MockStorage) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.StartError != nil {
		return m.StartError
	}
	if m.closed {
		return ErrServerClosed{}
	}
	m.started = true
	return nil
}

// Stop simulates stopping the storage backend.
func (m *MockStorage) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.StopError != nil {
		return m.StopError
	}
	m.started = false
	m.closed = true
	return nil
}

// IsStarted returns true if the mock storage is started.
func (m *MockStorage) IsStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}

// IsClosed returns true if the mock storage is closed.
func (m *MockStorage) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

// Put stores data in the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockStorage) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.PutError != nil {
		return m.PutError
	}
	if !m.started {
		return ErrServerNotStarted{}
	}

	if m.data[entityType] == nil {
		m.data[entityType] = make(map[uint64][]byte)
	}
	m.data[entityType][id] = data
	return nil
}

// Get retrieves data from the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockStorage) Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.GetError != nil {
		return nil, false, m.GetError
	}
	if !m.started {
		return nil, false, ErrServerNotStarted{}
	}

	if entities, ok := m.data[entityType]; ok {
		if data, found := entities[id]; found {
			return data, true, nil
		}
	}
	return nil, false, nil
}

// Delete removes data from the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockStorage) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.DeleteError != nil {
		return m.DeleteError
	}
	if !m.started {
		return ErrServerNotStarted{}
	}

	if entities, ok := m.data[entityType]; ok {
		delete(entities, id)
	}
	return nil
}

// List returns paginated entities from the mock storage.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.ListError != nil {
		return nil, "", m.ListError
	}
	if !m.started {
		return nil, "", ErrServerNotStarted{}
	}

	var entities []*service.Entity
	entities = make([]*service.Entity, 0)

	if typeData, ok := m.data[entityType]; ok {
		// Parse page token to get starting ID
		var startID uint64 = 0
		if pageToken != "" {
			startID = parsePageToken(pageToken)
		}

		// Collect entities after startID
		count := uint64(0)
		var lastID uint64
		for id, data := range typeData {
			if id > startID {
				entities = append(entities, &service.Entity{
					ID:   id,
					Data: data,
				})
				lastID = id
				count++
				if pageSize > 0 && count >= pageSize {
					break
				}
			}
		}

		// Return next page token if there are more results
		if pageSize > 0 && count >= pageSize {
			return entities, formatPageToken(lastID), nil
		}
	}

	return entities, "", nil
}

// Query searches for entities by index.
// First checks for pre-configured query results, then falls back to returning all entities.
// shardID is accepted for interface compatibility but ignored in mock implementation.
func (m *MockStorage) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.QueryError != nil {
		return nil, m.QueryError
	}
	if !m.started {
		return nil, ErrServerNotStarted{}
	}

	// Check for pre-configured query results first
	if typeResults, ok := m.queryResults[entityType]; ok {
		if fieldResults, ok := typeResults[indexField]; ok {
			if results, ok := fieldResults[string(value)]; ok {
				return results, nil
			}
		}
	}

	// Fall back to returning all entities of the type
	var entities []*service.Entity
	if typeData, ok := m.data[entityType]; ok {
		for id, data := range typeData {
			entities = append(entities, &service.Entity{
				ID:   id,
				Data: data,
			})
		}
	}

	return entities, nil
}

// Reset clears all data and resets the mock state.
func (m *MockStorage) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.data = make(map[string]map[uint64][]byte)
	m.queryResults = make(map[string]map[string]map[string][]*service.Entity)
	m.started = false
	m.closed = false
	m.PutError = nil
	m.GetError = nil
	m.DeleteError = nil
	m.ListError = nil
	m.QueryError = nil
	m.StartError = nil
	m.StopError = nil
}

// SetQueryResult pre-configures query results for index-based queries.
// This allows tests to simulate secondary index lookups.
func (m *MockStorage) SetQueryResult(entityType, indexField string, value []byte, results []*service.Entity) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.queryResults[entityType] == nil {
		m.queryResults[entityType] = make(map[string]map[string][]*service.Entity)
	}
	if m.queryResults[entityType][indexField] == nil {
		m.queryResults[entityType][indexField] = make(map[string][]*service.Entity)
	}
	m.queryResults[entityType][indexField][string(value)] = results
}

// SetData allows tests to pre-populate data.
func (m *MockStorage) SetData(entityType string, id uint64, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.data[entityType] == nil {
		m.data[entityType] = make(map[uint64][]byte)
	}
	m.data[entityType][id] = data
}

// GetAllData returns all stored data for a given entity type.
func (m *MockStorage) GetAllData(entityType string) map[uint64][]byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[uint64][]byte)
	if typeData, ok := m.data[entityType]; ok {
		for id, data := range typeData {
			result[id] = data
		}
	}
	return result
}

// Count returns the number of entities of a given type.
func (m *MockStorage) Count(entityType string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if typeData, ok := m.data[entityType]; ok {
		return len(typeData)
	}
	return 0
}

// parsePageToken converts a page token string to an ID.
func parsePageToken(token string) uint64 {
	if len(token) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64([]byte(token))
}

// formatPageToken converts an ID to a page token string.
func formatPageToken(id uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, id)
	return string(buf)
}

// Ensure MockStorage implements Storage interface
var _ Storage = (*MockStorage)(nil)
