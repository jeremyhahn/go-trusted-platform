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
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memoryStorage is a minimal in-memory Storage implementation for unit testing.
type memoryStorage struct {
	mu      sync.RWMutex
	data    map[string]map[uint64][]byte
	started bool
	closed  bool
}

func newMemoryStorage() *memoryStorage {
	return &memoryStorage{
		data: make(map[string]map[uint64][]byte),
	}
}

func (m *memoryStorage) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = true
	return nil
}

func (m *memoryStorage) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.started = false
	m.closed = true
	return nil
}

func (m *memoryStorage) IsStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started && !m.closed
}

func (m *memoryStorage) IsClosed() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.closed
}

func (m *memoryStorage) Put(ctx context.Context, entityType string, id uint64, data []byte, shardID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data[entityType] == nil {
		m.data[entityType] = make(map[uint64][]byte)
	}
	m.data[entityType][id] = data
	return nil
}

func (m *memoryStorage) Get(ctx context.Context, entityType string, id uint64, shardID uint64) ([]byte, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if entities, ok := m.data[entityType]; ok {
		if data, found := entities[id]; found {
			return data, true, nil
		}
	}
	return nil, false, nil
}

func (m *memoryStorage) Delete(ctx context.Context, entityType string, id uint64, shardID uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entities, ok := m.data[entityType]; ok {
		delete(entities, id)
	}
	return nil
}

func (m *memoryStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*service.Entity, 0)
	if typeData, ok := m.data[entityType]; ok {
		for id, data := range typeData {
			result = append(result, &service.Entity{ID: id, Data: data})
		}
	}
	return result, "", nil
}

func (m *memoryStorage) Query(ctx context.Context, entityType, indexField string, value []byte, shardID uint64) ([]*service.Entity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*service.Entity, 0)
	if typeData, ok := m.data[entityType]; ok {
		for id, data := range typeData {
			result = append(result, &service.Entity{ID: id, Data: data})
		}
	}
	return result, nil
}

// allEntityTypes returns all entity type keys stored in the memory backend.
func (m *memoryStorage) allEntityTypes() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	types := make([]string, 0, len(m.data))
	for k := range m.data {
		types = append(types, k)
	}
	return types
}

func TestNewTenantStorage(t *testing.T) {
	inner := newMemoryStorage()

	t.Run("valid construction", func(t *testing.T) {
		ts, err := NewTenantStorage(inner, "tenant-abc")
		require.NoError(t, err)
		require.NotNil(t, ts)
		assert.Equal(t, "tenant-abc", ts.TenantID())
		assert.Equal(t, "tenant-abc/", ts.Prefix())
	})

	t.Run("empty tenant ID returns error", func(t *testing.T) {
		ts, err := NewTenantStorage(inner, "")
		assert.Nil(t, ts)
		require.Error(t, err)
		var tenantErr ErrTenantIDEmpty
		assert.True(t, errors.As(err, &tenantErr))
	})

	t.Run("nil inner storage returns error", func(t *testing.T) {
		ts, err := NewTenantStorage(nil, "tenant-abc")
		assert.Nil(t, ts)
		require.Error(t, err)
		var nilErr ErrTenantStorageInnerNil
		assert.True(t, errors.As(err, &nilErr))
	})

	t.Run("tenant ID with slash returns error", func(t *testing.T) {
		ts, err := NewTenantStorage(inner, "tenant/abc")
		assert.Nil(t, ts)
		require.Error(t, err)
		var invalidErr ErrTenantIDInvalid
		assert.True(t, errors.As(err, &invalidErr))
		assert.Equal(t, "tenant/abc", invalidErr.TenantID)
	})
}

func TestTenantStorage_PutGet(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryStorage()
	require.NoError(t, inner.Start(ctx))

	ts, err := NewTenantStorage(inner, "tenant-1")
	require.NoError(t, err)

	t.Run("put and get with tenant prefix", func(t *testing.T) {
		data := []byte(`{"name":"test"}`)
		err := ts.Put(ctx, "users", 42, data, 0)
		require.NoError(t, err)

		// Retrieve through tenant storage
		got, found, err := ts.Get(ctx, "users", 42, 0)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, data, got)

		// Verify the inner storage has the prefixed key
		innerData, innerFound, err := inner.Get(ctx, "tenant-1/users", 42, 0)
		require.NoError(t, err)
		assert.True(t, innerFound)
		assert.Equal(t, data, innerData)

		// Verify unprefixed key does not exist in inner storage
		_, unprefixedFound, err := inner.Get(ctx, "users", 42, 0)
		require.NoError(t, err)
		assert.False(t, unprefixedFound)
	})

	t.Run("get nonexistent returns not found", func(t *testing.T) {
		_, found, err := ts.Get(ctx, "users", 9999, 0)
		require.NoError(t, err)
		assert.False(t, found)
	})
}

func TestTenantStorage_Delete(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryStorage()
	require.NoError(t, inner.Start(ctx))

	ts, err := NewTenantStorage(inner, "tenant-del")
	require.NoError(t, err)

	t.Run("delete removes tenant-prefixed entry", func(t *testing.T) {
		data := []byte(`{"id":1}`)
		require.NoError(t, ts.Put(ctx, "items", 1, data, 0))

		// Confirm it exists
		_, found, err := ts.Get(ctx, "items", 1, 0)
		require.NoError(t, err)
		assert.True(t, found)

		// Delete it
		require.NoError(t, ts.Delete(ctx, "items", 1, 0))

		// Confirm it is gone
		_, found, err = ts.Get(ctx, "items", 1, 0)
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("delete nonexistent does not error", func(t *testing.T) {
		err := ts.Delete(ctx, "items", 9999, 0)
		require.NoError(t, err)
	})
}

func TestTenantStorage_List(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryStorage()
	require.NoError(t, inner.Start(ctx))

	ts, err := NewTenantStorage(inner, "tenant-list")
	require.NoError(t, err)

	t.Run("list returns tenant-scoped entities", func(t *testing.T) {
		require.NoError(t, ts.Put(ctx, "docs", 10, []byte(`{"v":10}`), 0))
		require.NoError(t, ts.Put(ctx, "docs", 20, []byte(`{"v":20}`), 0))

		// Also store data directly in inner with a different prefix
		require.NoError(t, inner.Put(ctx, "other-tenant/docs", 30, []byte(`{"v":30}`), 0))

		entities, nextToken, err := ts.List(ctx, "docs", 100, "", 0)
		require.NoError(t, err)
		assert.Empty(t, nextToken)
		assert.Len(t, entities, 2)
	})

	t.Run("list empty entity type returns empty", func(t *testing.T) {
		entities, nextToken, err := ts.List(ctx, "nonexistent", 100, "", 0)
		require.NoError(t, err)
		assert.Empty(t, nextToken)
		assert.Empty(t, entities)
	})
}

func TestTenantStorage_Query(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryStorage()
	require.NoError(t, inner.Start(ctx))

	ts, err := NewTenantStorage(inner, "tenant-query")
	require.NoError(t, err)

	t.Run("query uses tenant-prefixed entity type", func(t *testing.T) {
		require.NoError(t, ts.Put(ctx, "profiles", 1, []byte(`{"email":"a@b.com"}`), 0))

		entities, err := ts.Query(ctx, "profiles", "email", []byte("a@b.com"), 0)
		require.NoError(t, err)
		assert.Len(t, entities, 1)
	})

	t.Run("query with no matching data returns empty", func(t *testing.T) {
		entities, err := ts.Query(ctx, "empty_type", "field", []byte("val"), 0)
		require.NoError(t, err)
		assert.Empty(t, entities)
	})
}

func TestTenantStorage_Isolation(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryStorage()
	require.NoError(t, inner.Start(ctx))

	ts1, err := NewTenantStorage(inner, "tenant-A")
	require.NoError(t, err)

	ts2, err := NewTenantStorage(inner, "tenant-B")
	require.NoError(t, err)

	t.Run("tenants do not see each other data", func(t *testing.T) {
		// Tenant A stores data
		require.NoError(t, ts1.Put(ctx, "secrets", 1, []byte(`{"secret":"A"}`), 0))

		// Tenant B stores data with same entity type and ID
		require.NoError(t, ts2.Put(ctx, "secrets", 1, []byte(`{"secret":"B"}`), 0))

		// Tenant A reads its own data
		dataA, foundA, err := ts1.Get(ctx, "secrets", 1, 0)
		require.NoError(t, err)
		assert.True(t, foundA)
		assert.Equal(t, []byte(`{"secret":"A"}`), dataA)

		// Tenant B reads its own data
		dataB, foundB, err := ts2.Get(ctx, "secrets", 1, 0)
		require.NoError(t, err)
		assert.True(t, foundB)
		assert.Equal(t, []byte(`{"secret":"B"}`), dataB)

		// Tenant A cannot see Tenant B data via List
		entitiesA, _, err := ts1.List(ctx, "secrets", 100, "", 0)
		require.NoError(t, err)
		assert.Len(t, entitiesA, 1)
		assert.Equal(t, []byte(`{"secret":"A"}`), entitiesA[0].Data)

		// Tenant B cannot see Tenant A data via List
		entitiesB, _, err := ts2.List(ctx, "secrets", 100, "", 0)
		require.NoError(t, err)
		assert.Len(t, entitiesB, 1)
		assert.Equal(t, []byte(`{"secret":"B"}`), entitiesB[0].Data)
	})

	t.Run("deleting from one tenant does not affect other", func(t *testing.T) {
		require.NoError(t, ts1.Put(ctx, "items", 5, []byte(`{"item":"A5"}`), 0))
		require.NoError(t, ts2.Put(ctx, "items", 5, []byte(`{"item":"B5"}`), 0))

		// Delete from tenant A
		require.NoError(t, ts1.Delete(ctx, "items", 5, 0))

		// Tenant A should not find it
		_, foundA, err := ts1.Get(ctx, "items", 5, 0)
		require.NoError(t, err)
		assert.False(t, foundA)

		// Tenant B should still have it
		dataB, foundB, err := ts2.Get(ctx, "items", 5, 0)
		require.NoError(t, err)
		assert.True(t, foundB)
		assert.Equal(t, []byte(`{"item":"B5"}`), dataB)
	})
}

func TestTenantStorage_Lifecycle(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryStorage()

	ts, err := NewTenantStorage(inner, "tenant-lc")
	require.NoError(t, err)

	t.Run("delegates Start to inner", func(t *testing.T) {
		assert.False(t, ts.IsStarted())
		require.NoError(t, ts.Start(ctx))
		assert.True(t, ts.IsStarted())
	})

	t.Run("delegates IsClosed to inner", func(t *testing.T) {
		assert.False(t, ts.IsClosed())
	})

	t.Run("delegates Stop to inner", func(t *testing.T) {
		require.NoError(t, ts.Stop(ctx))
		assert.True(t, ts.IsClosed())
		assert.False(t, ts.IsStarted())
	})
}

func TestTenantStorage_InnerKeyVerification(t *testing.T) {
	ctx := context.Background()
	inner := newMemoryStorage()
	require.NoError(t, inner.Start(ctx))

	ts, err := NewTenantStorage(inner, "org-123")
	require.NoError(t, err)

	t.Run("inner storage stores with prefixed entity type", func(t *testing.T) {
		require.NoError(t, ts.Put(ctx, "certificates", 7, []byte(`cert-data`), 0))

		// The inner storage should have the key under "org-123/certificates"
		types := inner.allEntityTypes()
		assert.Contains(t, types, "org-123/certificates")
		assert.NotContains(t, types, "certificates")
	})
}

func TestTenantStorage_ErrorTypes(t *testing.T) {
	t.Run("ErrTenantStorageInnerNil message", func(t *testing.T) {
		err := ErrTenantStorageInnerNil{}
		assert.Contains(t, err.Error(), "inner storage cannot be nil")
	})

	t.Run("ErrTenantIDEmpty message", func(t *testing.T) {
		err := ErrTenantIDEmpty{}
		assert.Contains(t, err.Error(), "tenant ID cannot be empty")
	})

	t.Run("ErrTenantIDInvalid message", func(t *testing.T) {
		err := ErrTenantIDInvalid{TenantID: "bad/id", Reason: "contains slash"}
		assert.Contains(t, err.Error(), "bad/id")
		assert.Contains(t, err.Error(), "contains slash")
	})
}

func TestTenantStorage_CompileTimeInterfaceCheck(t *testing.T) {
	// This test verifies the compile-time interface assertion exists
	// and that TenantStorage fully satisfies the Storage interface.
	var _ Storage = (*TenantStorage)(nil)
}
