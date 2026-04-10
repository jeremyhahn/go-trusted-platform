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

package eab

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDAO(t *testing.T) (*QuicBaaSDAO, *quicbaas.MockStorage) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	dao := NewQuicBaaSDAO(mockStorage, logger)
	return dao, mockStorage
}

func TestNewQuicBaaSDAO(t *testing.T) {
	dao, _ := testDAO(t)
	assert.NotNil(t, dao)
	assert.NotNil(t, dao.GenericDAO)
	assert.NotNil(t, dao.storage)
	assert.NotNil(t, dao.logger)
}

func TestQuicBaaSDAO_Save(t *testing.T) {
	t.Run("saves credential successfully", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		ctx := context.Background()

		entity := &EABCredential{
			ID:        1,
			KeyID:     "test-key",
			HMACKey:   []byte("secret"),
			ProfileID: 100,
			TenantID:  "tenant-1",
			Status:    uint8(StatusActive),
			CreatedAt: time.Now().Unix(),
		}

		err := dao.Save(ctx, entity)
		assert.NoError(t, err)

		count := mockStorage.Count(entityTypeEABCredential)
		assert.Equal(t, 1, count)
	})

	t.Run("generates ID when zero", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		entity := &EABCredential{
			ID:        0,
			KeyID:     "test-key",
			HMACKey:   []byte("secret"),
			ProfileID: 100,
			TenantID:  "tenant-1",
		}

		err := dao.Save(ctx, entity)
		assert.NoError(t, err)
		assert.NotZero(t, entity.ID)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		ctx := context.Background()

		mockStorage.PutError = errors.New("storage error")

		entity := &EABCredential{
			ID:    1,
			KeyID: "test-key",
		}

		err := dao.Save(ctx, entity)
		assert.Error(t, err)
	})
}

func TestQuicBaaSDAO_Get(t *testing.T) {
	t.Run("retrieves existing credential", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		entity := &EABCredential{
			ID:        1,
			KeyID:     "test-key",
			HMACKey:   []byte("secret"),
			ProfileID: 100,
			TenantID:  "tenant-1",
		}

		err := dao.Save(ctx, entity)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, 1)
		assert.NoError(t, err)
		assert.Equal(t, entity.KeyID, retrieved.KeyID)
		assert.Equal(t, entity.ProfileID, retrieved.ProfileID)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		_, err := dao.Get(ctx, 999)
		assert.Error(t, err)
		var notFound quicbaas.ErrNotFound
		assert.ErrorAs(t, err, &notFound)
	})
}

func TestQuicBaaSDAO_Delete(t *testing.T) {
	t.Run("deletes existing credential", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		ctx := context.Background()

		entity := &EABCredential{ID: 1, KeyID: "test-key"}
		err := dao.Save(ctx, entity)
		require.NoError(t, err)

		err = dao.Delete(ctx, entity)
		assert.NoError(t, err)

		count := mockStorage.Count(entityTypeEABCredential)
		assert.Equal(t, 0, count)
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		entity := &EABCredential{ID: 0}
		err := dao.Delete(ctx, entity)
		assert.Error(t, err)
	})
}

func TestQuicBaaSDAO_Count(t *testing.T) {
	t.Run("returns zero for empty store", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		count, err := dao.Count(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("returns correct count", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		for i := 1; i <= 5; i++ {
			entity := &EABCredential{ID: uint64(i), KeyID: "key"}
			err := dao.Save(ctx, entity)
			require.NoError(t, err)
		}

		count, err := dao.Count(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 5, count)
	})
}

func TestQuicBaaSDAO_FindByKeyID(t *testing.T) {
	t.Run("finds by KeyID using scan", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		entity := &EABCredential{
			ID:        1,
			KeyID:     "unique-key-id",
			ProfileID: 100,
		}
		err := dao.Save(ctx, entity)
		require.NoError(t, err)

		found, err := dao.FindByKeyID(ctx, "unique-key-id")
		assert.NoError(t, err)
		assert.Equal(t, entity.ID, found.ID)
		assert.Equal(t, entity.KeyID, found.KeyID)
	})

	t.Run("finds by KeyID using index", func(t *testing.T) {
		dao, mockStorage := testDAO(t)
		ctx := context.Background()

		entity := &EABCredential{
			ID:        1,
			KeyID:     "indexed-key-id",
			ProfileID: 100,
		}
		entityJSON, _ := json.Marshal(entity)

		mockStorage.SetQueryResult(entityTypeEABCredential, "KeyID", []byte("indexed-key-id"), []*service.Entity{
			{ID: 1, Data: entityJSON},
		})

		found, err := dao.FindByKeyID(ctx, "indexed-key-id")
		assert.NoError(t, err)
		assert.Equal(t, entity.ID, found.ID)
	})

	t.Run("returns error for non-existent KeyID", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		_, err := dao.FindByKeyID(ctx, "non-existent")
		assert.Error(t, err)
		var notFound quicbaas.ErrNotFoundByIndex
		assert.ErrorAs(t, err, &notFound)
	})
}

func TestQuicBaaSDAO_FindByProfileID(t *testing.T) {
	t.Run("finds all credentials for profile", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		for i := 1; i <= 3; i++ {
			entity := &EABCredential{
				ID:        uint64(i),
				KeyID:     "key",
				ProfileID: 100,
			}
			err := dao.Save(ctx, entity)
			require.NoError(t, err)
		}

		entity := &EABCredential{
			ID:        4,
			KeyID:     "key",
			ProfileID: 200, // Different profile
		}
		err := dao.Save(ctx, entity)
		require.NoError(t, err)

		found, err := dao.FindByProfileID(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, found, 3)
	})

	t.Run("returns empty slice for non-existent profile", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		found, err := dao.FindByProfileID(ctx, 999)
		assert.NoError(t, err)
		assert.Empty(t, found)
	})
}

func TestQuicBaaSDAO_FindByTenantID(t *testing.T) {
	t.Run("finds all credentials for tenant", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		for i := 1; i <= 2; i++ {
			entity := &EABCredential{
				ID:        uint64(i),
				KeyID:     "key",
				TenantID:  "tenant-a",
				ProfileID: 1,
			}
			err := dao.Save(ctx, entity)
			require.NoError(t, err)
		}

		entity := &EABCredential{
			ID:        3,
			KeyID:     "key",
			TenantID:  "tenant-b",
			ProfileID: 1,
		}
		err := dao.Save(ctx, entity)
		require.NoError(t, err)

		found, err := dao.FindByTenantID(ctx, "tenant-a")
		assert.NoError(t, err)
		assert.Len(t, found, 2)
	})

	t.Run("returns empty slice for non-existent tenant", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		found, err := dao.FindByTenantID(ctx, "non-existent")
		assert.NoError(t, err)
		assert.Empty(t, found)
	})
}

func TestQuicBaaSDAO_FindExpired(t *testing.T) {
	t.Run("finds expired credentials", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		now := time.Now()

		// Expired credential
		expired := &EABCredential{
			ID:        1,
			KeyID:     "expired",
			ExpiresAt: now.Add(-time.Hour).Unix(),
			ProfileID: 1,
			TenantID:  "t",
		}
		err := dao.Save(ctx, expired)
		require.NoError(t, err)

		// Valid credential
		valid := &EABCredential{
			ID:        2,
			KeyID:     "valid",
			ExpiresAt: now.Add(time.Hour).Unix(),
			ProfileID: 1,
			TenantID:  "t",
		}
		err = dao.Save(ctx, valid)
		require.NoError(t, err)

		// No expiration
		noExpiry := &EABCredential{
			ID:        3,
			KeyID:     "no-expiry",
			ExpiresAt: 0,
			ProfileID: 1,
			TenantID:  "t",
		}
		err = dao.Save(ctx, noExpiry)
		require.NoError(t, err)

		found, err := dao.FindExpired(ctx, now)
		assert.NoError(t, err)
		assert.Len(t, found, 1)
		assert.Equal(t, "expired", found[0].KeyID)
	})
}

func TestQuicBaaSDAO_DeleteExpired(t *testing.T) {
	t.Run("deletes expired credentials", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		now := time.Now()

		// Expired credentials
		for i := 1; i <= 3; i++ {
			entity := &EABCredential{
				ID:        uint64(i),
				KeyID:     "expired",
				ExpiresAt: now.Add(-time.Hour).Unix(),
				ProfileID: 1,
				TenantID:  "t",
			}
			err := dao.Save(ctx, entity)
			require.NoError(t, err)
		}

		// Valid credential
		valid := &EABCredential{
			ID:        4,
			KeyID:     "valid",
			ExpiresAt: now.Add(time.Hour).Unix(),
			ProfileID: 1,
			TenantID:  "t",
		}
		err := dao.Save(ctx, valid)
		require.NoError(t, err)

		deleted, err := dao.DeleteExpired(ctx, now)
		assert.NoError(t, err)
		assert.Equal(t, 3, deleted)

		count, _ := dao.Count(ctx)
		assert.Equal(t, 1, count)
	})
}

func TestQuicBaaSDAO_Page(t *testing.T) {
	t.Run("returns paginated results", func(t *testing.T) {
		dao, _ := testDAO(t)
		ctx := context.Background()

		for i := 1; i <= 10; i++ {
			entity := &EABCredential{
				ID:        uint64(i),
				KeyID:     "key",
				ProfileID: 1,
				TenantID:  "t",
			}
			err := dao.Save(ctx, entity)
			require.NoError(t, err)
		}

		result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 5})
		assert.NoError(t, err)
		assert.Len(t, result.Entities, 5)
		assert.Equal(t, 10, result.Total)
		assert.True(t, result.HasMore)
	})
}
