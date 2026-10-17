package kvstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGenericDAO(t *testing.T) {
	t.Run("creates with defaults", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		assert.Equal(t, "Role", dao.EntityType())
		assert.Equal(t, "Role", dao.StorageEntityType())
		assert.Equal(t, uint64(0), dao.ShardID())
		assert.Equal(t, "", dao.Partition())
	})

	t.Run("creates with options", func(t *testing.T) {
		storage := newMemoryStorage()
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
			WithRequestTimeout(5*time.Second),
			WithShard(3),
			WithPartition("tenant-abc"),
		)

		assert.Equal(t, "Role", dao.EntityType())
		assert.Equal(t, "tenant-abc/Role", dao.StorageEntityType())
		assert.Equal(t, uint64(3), dao.ShardID())
		assert.Equal(t, "tenant-abc", dao.Partition())
	})
}

func TestGenericDAO_Save(t *testing.T) {
	t.Run("saves entity with existing ID", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		role := entities.NewRole("admin")
		ctx := context.Background()

		err := dao.Save(ctx, role)
		require.NoError(t, err)
		assert.NotZero(t, role.EntityID())
	})

	t.Run("auto-generates ID when zero", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		role := &entities.Role{Name: "editor"}
		ctx := context.Background()

		err := dao.Save(ctx, role)
		require.NoError(t, err)
		assert.NotZero(t, role.EntityID())
	})

	t.Run("saves with partition prefix", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
			WithPartition("org-1"),
		)

		role := entities.NewRole("viewer")
		ctx := context.Background()

		err := dao.Save(ctx, role)
		require.NoError(t, err)

		// Verify it was stored under the partitioned entity type
		types := storage.allEntityTypes()
		assert.Contains(t, types, "org-1/Role")
	})
}

func TestGenericDAO_Get(t *testing.T) {
	t.Run("retrieves saved entity", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		role := entities.NewRole("admin")
		ctx := context.Background()

		err := dao.Save(ctx, role)
		require.NoError(t, err)

		got, err := dao.Get(ctx, role.EntityID())
		require.NoError(t, err)
		assert.Equal(t, "admin", got.Name)
		assert.Equal(t, role.EntityID(), got.EntityID())
	})

	t.Run("returns ErrNotFound for missing entity", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()
		_, err := dao.Get(ctx, 99999)
		require.Error(t, err)

		var notFound ErrNotFound
		assert.True(t, errors.As(err, &notFound))
		assert.Equal(t, "Role", notFound.EntityType)
		assert.Equal(t, uint64(99999), notFound.ID)
	})

	t.Run("returns ErrDeserializationFailed for corrupt data", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()
		// Store invalid JSON directly
		err := storage.Put(ctx, "Role", 42, []byte("{invalid-json"), 0)
		require.NoError(t, err)

		_, err = dao.Get(ctx, 42)
		require.Error(t, err)

		var deserErr ErrDeserializationFailed
		assert.True(t, errors.As(err, &deserErr))
	})
}

func TestGenericDAO_Delete(t *testing.T) {
	t.Run("deletes existing entity", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		role := entities.NewRole("admin")
		ctx := context.Background()

		err := dao.Save(ctx, role)
		require.NoError(t, err)

		err = dao.Delete(ctx, role)
		require.NoError(t, err)

		_, err = dao.Get(ctx, role.EntityID())
		require.Error(t, err)
	})

	t.Run("returns error for entity with ID 0", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		role := &entities.Role{ID: 0, Name: "invalid"}
		ctx := context.Background()

		err := dao.Delete(ctx, role)
		require.Error(t, err)

		var invalidID ErrInvalidEntityID
		assert.True(t, errors.As(err, &invalidID))
		assert.Equal(t, "Role", invalidID.EntityType)
	})
}

func TestGenericDAO_Count(t *testing.T) {
	t.Run("counts entities", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		count, err := dao.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, count)

		require.NoError(t, dao.Save(ctx, entities.NewRole("admin")))
		require.NoError(t, dao.Save(ctx, entities.NewRole("user")))
		require.NoError(t, dao.Save(ctx, entities.NewRole("editor")))

		count, err = dao.Count(ctx)
		require.NoError(t, err)
		assert.Equal(t, 3, count)
	})
}

func TestGenericDAO_Page(t *testing.T) {
	t.Run("paginates entities", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		// Save 5 roles
		for i := 0; i < 5; i++ {
			role := &entities.Role{ID: uint64(i + 1), Name: "role"}
			require.NoError(t, dao.Save(ctx, role))
		}

		// First page
		result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 2})
		require.NoError(t, err)
		assert.Len(t, result.Entities, 2)
		assert.Equal(t, 5, result.Total)
		assert.True(t, result.HasMore)
		assert.Equal(t, 1, result.Page)
		assert.Equal(t, 2, result.PageSize)

		// Last page
		result, err = dao.Page(ctx, datastore.PageQuery{Page: 3, PageSize: 2})
		require.NoError(t, err)
		assert.Len(t, result.Entities, 1)
		assert.False(t, result.HasMore)

		// Beyond last page
		result, err = dao.Page(ctx, datastore.PageQuery{Page: 10, PageSize: 2})
		require.NoError(t, err)
		assert.Empty(t, result.Entities)
		assert.False(t, result.HasMore)
	})

	t.Run("handles corrupt entity gracefully", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		// Store valid and invalid entries
		role := entities.NewRole("valid")
		require.NoError(t, dao.Save(ctx, role))
		require.NoError(t, storage.Put(ctx, "Role", 999, []byte("{bad-json"), 0))

		result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
		require.NoError(t, err)
		// Only the valid one should be deserialized
		assert.Len(t, result.Entities, 1)
	})
}

// TestGenericDAO_PageZeroQuery pins the paging inputs that panicked the
// daemon's MCP DeviceList (page 0, size 100 sliced at [-100:]): a page
// below one reads the first page and a size below one uses the default.
func TestGenericDAO_PageZeroQuery(t *testing.T) {
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	dao := NewGenericDAO[*entities.Role](
		storage, "Role", func() *entities.Role { return &entities.Role{} }, logging.DefaultLogger(),
	)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		require.NoError(t, dao.Save(ctx, &entities.Role{ID: uint64(i + 1), Name: "role"}))
	}

	result, err := dao.Page(ctx, datastore.PageQuery{PageSize: 100})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 3)
	assert.Equal(t, datastore.FirstPage, result.Page)

	result, err = dao.Page(ctx, datastore.PageQuery{Page: -2, PageSize: 0})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 3)
	assert.Equal(t, datastore.DefaultPageSize, result.PageSize)
}

func TestGenericDAO_ForEachPage(t *testing.T) {
	t.Run("iterates all pages", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		for i := 0; i < 5; i++ {
			role := &entities.Role{ID: uint64(i + 1), Name: "role"}
			require.NoError(t, dao.Save(ctx, role))
		}

		var totalEntities int
		err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 2}, func(result datastore.PageResult[*entities.Role]) error {
			totalEntities += len(result.Entities)
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, 5, totalEntities)
	})

	t.Run("stops on ErrStopIteration", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		for i := 0; i < 5; i++ {
			role := &entities.Role{ID: uint64(i + 1), Name: "role"}
			require.NoError(t, dao.Save(ctx, role))
		}

		pagesProcessed := 0
		err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 2}, func(result datastore.PageResult[*entities.Role]) error {
			pagesProcessed++
			return datastore.ErrStopIteration
		})
		require.NoError(t, err)
		assert.Equal(t, 1, pagesProcessed)
	})

	t.Run("returns callback error", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		role := &entities.Role{ID: 1, Name: "role"}
		require.NoError(t, dao.Save(ctx, role))

		callbackErr := errors.New("callback failure")
		err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 10}, func(result datastore.PageResult[*entities.Role]) error {
			return callbackErr
		})
		assert.ErrorIs(t, err, callbackErr)
	})

	t.Run("defaults page to 1 when zero", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		role := &entities.Role{ID: 1, Name: "role"}
		require.NoError(t, dao.Save(ctx, role))

		called := false
		err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 0, PageSize: 10}, func(result datastore.PageResult[*entities.Role]) error {
			called = true
			assert.Len(t, result.Entities, 1)
			return nil
		})
		require.NoError(t, err)
		assert.True(t, called)
	})

	t.Run("no entities does not call callback", func(t *testing.T) {
		storage := newMemoryStorage()
		require.NoError(t, storage.Start(context.Background()))
		logger := logging.DefaultLogger()

		dao := NewGenericDAO[*entities.Role](
			storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
		)

		ctx := context.Background()

		called := false
		err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 10}, func(result datastore.PageResult[*entities.Role]) error {
			called = true
			return nil
		})
		require.NoError(t, err)
		assert.False(t, called)
	})
}

func TestGenericDAO_SaveSerializationError(t *testing.T) {
	storage := newMemoryStorage()
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewGenericDAO[*entities.Blob](
		storage, "Blob", func() *entities.Blob { return &entities.Blob{} }, logger,
	)

	ctx := context.Background()

	blob := &entities.Blob{ID: 1}
	blob.SetEntity(make(chan int)) // channels can't be JSON marshaled

	err := dao.Save(ctx, blob)
	require.Error(t, err)

	var serErr ErrSerializationFailed
	assert.True(t, errors.As(err, &serErr))
}

func TestWithRequestTimeout(t *testing.T) {
	cfg := &daoConfig{}
	opt := WithRequestTimeout(10 * time.Second)
	opt(cfg)
	assert.Equal(t, 10*time.Second, cfg.requestTimeout)
}

func TestWithShard(t *testing.T) {
	cfg := &daoConfig{}
	opt := WithShard(5)
	opt(cfg)
	assert.Equal(t, uint64(5), cfg.shardID)
}

func TestWithPartition(t *testing.T) {
	cfg := &daoConfig{}
	opt := WithPartition("my-partition")
	opt(cfg)
	assert.Equal(t, "my-partition", cfg.partition)
}

// errorStorage is a Storage implementation that returns errors for testing.
type errorStorage struct {
	memoryStorage
	errOnList bool
}

func (e *errorStorage) List(ctx context.Context, entityType string, pageSize uint64, pageToken string, shardID uint64) ([]*service.Entity, string, error) {
	if e.errOnList {
		return nil, "", errors.New("list failed")
	}
	return e.memoryStorage.List(ctx, entityType, pageSize, pageToken, shardID)
}

func TestGenericDAO_CountWithStorageError(t *testing.T) {
	storage := &errorStorage{
		memoryStorage: *newMemoryStorage(),
		errOnList:     true,
	}
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewGenericDAO[*entities.Role](
		storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
	)

	ctx := context.Background()
	_, err := dao.Count(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list failed")
}

func TestGenericDAO_PageWithStorageError(t *testing.T) {
	storage := &errorStorage{
		memoryStorage: *newMemoryStorage(),
		errOnList:     true,
	}
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewGenericDAO[*entities.Role](
		storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
	)

	ctx := context.Background()
	_, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
	assert.Error(t, err)
}

func TestGenericDAO_ForEachPageWithStorageError(t *testing.T) {
	storage := &errorStorage{
		memoryStorage: *newMemoryStorage(),
		errOnList:     true,
	}
	require.NoError(t, storage.Start(context.Background()))
	logger := logging.DefaultLogger()

	dao := NewGenericDAO[*entities.Role](
		storage, "Role", func() *entities.Role { return &entities.Role{} }, logger,
	)

	ctx := context.Background()
	err := dao.ForEachPage(ctx, datastore.PageQuery{Page: 1, PageSize: 10}, func(result datastore.PageResult[*entities.Role]) error {
		return nil
	})
	assert.Error(t, err)
}
