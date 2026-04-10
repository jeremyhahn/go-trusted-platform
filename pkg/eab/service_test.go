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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testService(t *testing.T) (*DefaultService, *quicbaas.MockStorage) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	dao := NewQuicBaaSDAO(mockStorage, logger)
	service := NewService(dao, logger)
	return service, mockStorage
}

func TestNewService(t *testing.T) {
	service, _ := testService(t)
	assert.NotNil(t, service)
	assert.NotNil(t, service.dao)
	assert.NotNil(t, service.logger)
}

func TestService_Generate(t *testing.T) {
	t.Run("generates credential successfully", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		params := GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
			ExpiresIn: time.Hour,
		}

		cred, err := service.Generate(ctx, params)
		assert.NoError(t, err)
		assert.NotNil(t, cred)
		assert.NotZero(t, cred.ID)
		assert.NotEmpty(t, cred.KeyID)
		assert.Len(t, cred.HMACKey, DefaultHMACKeyLength)
		assert.Equal(t, params.ProfileID, cred.ProfileID)
		assert.Equal(t, params.TenantID, cred.TenantID)
		assert.Equal(t, StatusActive, cred.Status)
		assert.False(t, cred.ExpiresAt.IsZero())
	})

	t.Run("generates credential with custom HMAC key length", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		params := GenerateParams{
			ProfileID:  100,
			TenantID:   "tenant-1",
			HMACKeyLen: 64,
		}

		cred, err := service.Generate(ctx, params)
		assert.NoError(t, err)
		assert.Len(t, cred.HMACKey, 64)
	})

	t.Run("generates credential without expiration", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		params := GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
			ExpiresIn: 0,
		}

		cred, err := service.Generate(ctx, params)
		assert.NoError(t, err)
		assert.True(t, cred.ExpiresAt.IsZero())
	})

	t.Run("returns error for invalid params", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		params := GenerateParams{
			ProfileID: 0, // Invalid
			TenantID:  "tenant-1",
		}

		_, err := service.Generate(ctx, params)
		assert.Error(t, err)
		var profileErr ErrInvalidProfileID
		assert.ErrorAs(t, err, &profileErr)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		service, mockStorage := testService(t)
		ctx := context.Background()

		mockStorage.PutError = errors.New("storage error")

		params := GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		}

		_, err := service.Generate(ctx, params)
		assert.Error(t, err)
	})
}

func TestService_Get(t *testing.T) {
	t.Run("retrieves credential by ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		retrieved, err := service.Get(ctx, created.ID)
		assert.NoError(t, err)
		assert.Equal(t, created.KeyID, retrieved.KeyID)
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.Get(ctx, 0)
		assert.Error(t, err)
		var invalidErr ErrInvalidCredential
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("returns error for non-existent ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.Get(ctx, 999)
		assert.Error(t, err)
		var notFoundErr ErrCredentialNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		service, mockStorage := testService(t)
		ctx := context.Background()

		mockStorage.GetError = errors.New("storage error")

		_, err := service.Get(ctx, 123)
		assert.Error(t, err)
	})
}

func TestService_GetByKeyID(t *testing.T) {
	t.Run("retrieves credential by KeyID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		retrieved, err := service.GetByKeyID(ctx, created.KeyID)
		assert.NoError(t, err)
		assert.Equal(t, created.ID, retrieved.ID)
	})

	t.Run("returns error for empty KeyID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.GetByKeyID(ctx, "")
		assert.Error(t, err)
		var invalidErr ErrInvalidCredential
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("returns error for non-existent KeyID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.GetByKeyID(ctx, "non-existent")
		assert.Error(t, err)
		var notFoundErr ErrCredentialNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		service, mockStorage := testService(t)
		ctx := context.Background()

		mockStorage.ListError = errors.New("storage error")

		_, err := service.GetByKeyID(ctx, "key-123")
		assert.Error(t, err)
	})
}

func TestService_Revoke(t *testing.T) {
	t.Run("revokes credential successfully", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		err = service.Revoke(ctx, created.ID)
		assert.NoError(t, err)

		retrieved, err := service.Get(ctx, created.ID)
		assert.NoError(t, err)
		assert.Equal(t, StatusRevoked, retrieved.Status)
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		err := service.Revoke(ctx, 0)
		assert.Error(t, err)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		err := service.Revoke(ctx, 999)
		assert.Error(t, err)
		var notFoundErr ErrCredentialNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})
}

func TestService_MarkUsed(t *testing.T) {
	t.Run("marks credential as used", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		err = service.MarkUsed(ctx, created.ID)
		assert.NoError(t, err)

		retrieved, err := service.Get(ctx, created.ID)
		assert.NoError(t, err)
		assert.Equal(t, StatusUsed, retrieved.Status)
		assert.False(t, retrieved.UsedAt.IsZero())
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		err := service.MarkUsed(ctx, 0)
		assert.Error(t, err)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		err := service.MarkUsed(ctx, 999)
		assert.Error(t, err)
	})
}

func TestService_Validate(t *testing.T) {
	t.Run("validates active credential", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
			ExpiresIn: time.Hour,
		})
		require.NoError(t, err)

		validated, err := service.Validate(ctx, created.KeyID, created.HMACKey)
		assert.NoError(t, err)
		assert.Equal(t, created.ID, validated.ID)
	})

	t.Run("returns error for wrong HMAC key", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		_, err = service.Validate(ctx, created.KeyID, []byte("wrong-key"))
		assert.Error(t, err)
		var invalidErr ErrInvalidCredential
		assert.ErrorAs(t, err, &invalidErr)
	})

	t.Run("returns error for revoked credential", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		err = service.Revoke(ctx, created.ID)
		require.NoError(t, err)

		_, err = service.Validate(ctx, created.KeyID, created.HMACKey)
		assert.Error(t, err)
		var revokedErr ErrCredentialRevoked
		assert.ErrorAs(t, err, &revokedErr)
	})

	t.Run("returns error for used credential", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		err = service.MarkUsed(ctx, created.ID)
		require.NoError(t, err)

		_, err = service.Validate(ctx, created.KeyID, created.HMACKey)
		assert.Error(t, err)
		var usedErr ErrCredentialAlreadyUsed
		assert.ErrorAs(t, err, &usedErr)
	})

	t.Run("returns error for empty KeyID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.Validate(ctx, "", []byte("key"))
		assert.Error(t, err)
	})

	t.Run("returns error for empty HMAC key", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.Validate(ctx, "key-id", nil)
		assert.Error(t, err)
	})

	t.Run("returns error for non-existent KeyID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.Validate(ctx, "non-existent", []byte("key"))
		assert.Error(t, err)
		var notFoundErr ErrCredentialNotFound
		assert.ErrorAs(t, err, &notFoundErr)
	})

	t.Run("returns error for expired credential by time", func(t *testing.T) {
		ctx := context.Background()

		logger := logging.DefaultLogger()
		mockStorage := quicbaas.NewMockStorage()
		err := mockStorage.Start(ctx)
		require.NoError(t, err)
		dao := NewQuicBaaSDAO(mockStorage, logger)
		service := NewService(dao, logger)

		now := time.Now()

		// Create credential that is expired by time but status is still Active
		expiredEntity := &EABCredential{
			ID:        1,
			KeyID:     "expired-by-time",
			HMACKey:   []byte("secret-key"),
			ProfileID: 100,
			TenantID:  "tenant",
			ExpiresAt: now.Add(-time.Hour).Unix(),
			Status:    uint8(StatusActive),
			CreatedAt: now.Add(-2 * time.Hour).Unix(),
		}
		err = dao.Save(ctx, expiredEntity)
		require.NoError(t, err)

		_, err = service.Validate(ctx, "expired-by-time", []byte("secret-key"))
		assert.Error(t, err)
		var expiredErr ErrCredentialExpired
		assert.ErrorAs(t, err, &expiredErr)
	})

	t.Run("returns error for credential with expired status", func(t *testing.T) {
		ctx := context.Background()

		logger := logging.DefaultLogger()
		mockStorage := quicbaas.NewMockStorage()
		err := mockStorage.Start(ctx)
		require.NoError(t, err)
		dao := NewQuicBaaSDAO(mockStorage, logger)
		service := NewService(dao, logger)

		now := time.Now()

		// Create credential with StatusExpired
		expiredStatusEntity := &EABCredential{
			ID:        1,
			KeyID:     "expired-status",
			HMACKey:   []byte("secret-key"),
			ProfileID: 100,
			TenantID:  "tenant",
			ExpiresAt: now.Add(time.Hour).Unix(), // Not expired by time
			Status:    uint8(StatusExpired),
			CreatedAt: now.Unix(),
		}
		err = dao.Save(ctx, expiredStatusEntity)
		require.NoError(t, err)

		_, err = service.Validate(ctx, "expired-status", []byte("secret-key"))
		assert.Error(t, err)
		var expiredErr ErrCredentialExpired
		assert.ErrorAs(t, err, &expiredErr)
	})
}

func TestService_ListByProfile(t *testing.T) {
	t.Run("lists credentials for profile", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		for i := 0; i < 3; i++ {
			_, err := service.Generate(ctx, GenerateParams{
				ProfileID: 100,
				TenantID:  "tenant-1",
			})
			require.NoError(t, err)
		}

		_, err := service.Generate(ctx, GenerateParams{
			ProfileID: 200,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		list, err := service.ListByProfile(ctx, 100)
		assert.NoError(t, err)
		assert.Len(t, list, 3)
	})

	t.Run("returns error for zero profile ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.ListByProfile(ctx, 0)
		assert.Error(t, err)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		service, mockStorage := testService(t)
		ctx := context.Background()

		mockStorage.ListError = errors.New("storage error")

		_, err := service.ListByProfile(ctx, 100)
		assert.Error(t, err)
	})
}

func TestService_ListByTenant(t *testing.T) {
	t.Run("lists credentials for tenant", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		for i := 0; i < 2; i++ {
			_, err := service.Generate(ctx, GenerateParams{
				ProfileID: 100,
				TenantID:  "tenant-a",
			})
			require.NoError(t, err)
		}

		_, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-b",
		})
		require.NoError(t, err)

		list, err := service.ListByTenant(ctx, "tenant-a")
		assert.NoError(t, err)
		assert.Len(t, list, 2)
	})

	t.Run("returns error for empty tenant ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		_, err := service.ListByTenant(ctx, "")
		assert.Error(t, err)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		service, mockStorage := testService(t)
		ctx := context.Background()

		mockStorage.ListError = errors.New("storage error")

		_, err := service.ListByTenant(ctx, "tenant-a")
		assert.Error(t, err)
	})
}

func TestService_CleanupExpired(t *testing.T) {
	t.Run("removes expired credentials", func(t *testing.T) {
		ctx := context.Background()

		// Create a fresh service with direct DAO access for this test
		logger := logging.DefaultLogger()
		mockStorage := quicbaas.NewMockStorage()
		err := mockStorage.Start(ctx)
		require.NoError(t, err)
		dao := NewQuicBaaSDAO(mockStorage, logger)
		service := NewService(dao, logger)

		now := time.Now()

		// Create expired credential directly via DAO
		expiredEntity := &EABCredential{
			ID:        1,
			KeyID:     "expired",
			HMACKey:   []byte("secret"),
			ProfileID: 100,
			TenantID:  "tenant",
			ExpiresAt: now.Add(-time.Hour).Unix(),
			Status:    uint8(StatusActive),
			CreatedAt: now.Add(-2 * time.Hour).Unix(),
		}
		err = dao.Save(ctx, expiredEntity)
		require.NoError(t, err)

		// Create valid credential
		validEntity := &EABCredential{
			ID:        2,
			KeyID:     "valid",
			HMACKey:   []byte("secret"),
			ProfileID: 100,
			TenantID:  "tenant",
			ExpiresAt: now.Add(time.Hour).Unix(),
			Status:    uint8(StatusActive),
			CreatedAt: now.Unix(),
		}
		err = dao.Save(ctx, validEntity)
		require.NoError(t, err)

		deleted, err := service.CleanupExpired(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 1, deleted)

		count, _ := service.Count(ctx)
		assert.Equal(t, 1, count)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		service, mockStorage := testService(t)
		ctx := context.Background()

		mockStorage.ListError = errors.New("storage error")

		_, err := service.CleanupExpired(ctx)
		assert.Error(t, err)
	})
}

func TestService_Delete(t *testing.T) {
	t.Run("deletes credential successfully", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		created, err := service.Generate(ctx, GenerateParams{
			ProfileID: 100,
			TenantID:  "tenant-1",
		})
		require.NoError(t, err)

		err = service.Delete(ctx, created.ID)
		assert.NoError(t, err)

		_, err = service.Get(ctx, created.ID)
		assert.Error(t, err)
	})

	t.Run("returns error for zero ID", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		err := service.Delete(ctx, 0)
		assert.Error(t, err)
	})

	t.Run("returns error for non-existent credential", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		err := service.Delete(ctx, 999)
		assert.Error(t, err)
	})
}

func TestService_Count(t *testing.T) {
	t.Run("returns correct count", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		for i := 0; i < 5; i++ {
			_, err := service.Generate(ctx, GenerateParams{
				ProfileID: 100,
				TenantID:  "tenant-1",
			})
			require.NoError(t, err)
		}

		count, err := service.Count(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 5, count)
	})
}

func TestService_Page(t *testing.T) {
	t.Run("returns paginated results", func(t *testing.T) {
		service, _ := testService(t)
		ctx := context.Background()

		for i := 0; i < 10; i++ {
			_, err := service.Generate(ctx, GenerateParams{
				ProfileID: 100,
				TenantID:  "tenant-1",
			})
			require.NoError(t, err)
		}

		result, err := service.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 5})
		assert.NoError(t, err)
		assert.Len(t, result.Entities, 5)
		assert.Equal(t, 10, result.Total)
		assert.True(t, result.HasMore)
	})

	t.Run("returns error on storage failure", func(t *testing.T) {
		service, mockStorage := testService(t)
		ctx := context.Background()

		mockStorage.ListError = errors.New("storage error")

		_, err := service.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 5})
		assert.Error(t, err)
	})
}
