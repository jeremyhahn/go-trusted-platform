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
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRole implements entities.KeyValueEntity for testing
type TestRole struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
}

func (r *TestRole) EntityID() uint64      { return r.ID }
func (r *TestRole) SetEntityID(id uint64) { r.ID = id }

func newTestLogger(t *testing.T) *logging.Logger {
	return logging.DefaultLogger()
}

func setupMockDAO(t *testing.T) (*GenericDAO[*TestRole], *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	return newMockRoleDAO(t, mock), mock
}

// newMockRoleDAO builds a TestRole DAO on an existing store, so a test can
// open a second DAO instance over the data the first one wrote.
func newMockRoleDAO(t *testing.T, mock *MockStorage) *GenericDAO[*TestRole] {
	return NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		newTestLogger(t),
		WithRequestTimeout(5*time.Second),
	)
}

// === Save Tests ===

func TestGenericDAO_Save_NewEntity_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	role := &TestRole{Name: "admin"}
	assert.Zero(t, role.ID)
	err := dao.Save(ctx, role)

	require.NoError(t, err)
	assert.NotZero(t, role.ID, "ID should be auto-generated")
	assert.Equal(t, 1, mock.Count("TestRole"), "entity should be stored")

	// The auto-assigned ID is the key the entity is stored under.
	retrieved, err := dao.Get(ctx, role.ID)
	require.NoError(t, err)
	assert.Equal(t, role.ID, retrieved.ID)
	assert.Equal(t, "admin", retrieved.Name)
}

func TestGenericDAO_Save_ExistingEntity_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	role := &TestRole{ID: 12345, Name: "admin"}
	err := dao.Save(ctx, role)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), role.ID, "ID should be preserved")

	// Update the entity
	role.Name = "superadmin"
	err = dao.Save(ctx, role)

	require.NoError(t, err)
	assert.Equal(t, 1, mock.Count("TestRole"), "should update, not create new")
}

func TestGenericDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	role := &TestRole{Name: "admin"}
	err := dao.Save(ctx, role)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestGenericDAO_Save_ServerNotStarted_Mock(t *testing.T) {
	mock := NewMockStorage()
	logger := newTestLogger(t)
	dao := NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		logger,
	)

	ctx := context.Background()
	role := &TestRole{Name: "admin"}
	err := dao.Save(ctx, role)

	require.Error(t, err)
	var notStartedErr ErrServerNotStarted
	assert.ErrorAs(t, err, &notStartedErr)
}

// === Get Tests ===

func TestGenericDAO_Get_Success_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save an entity first
	role := &TestRole{ID: 12345, Name: "admin"}
	require.NoError(t, dao.Save(ctx, role))

	// Retrieve it
	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), retrieved.ID)
	assert.Equal(t, "admin", retrieved.Name)
}

func TestGenericDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, uint64(99999), notFoundErr.ID)
}

func TestGenericDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	mock.GetError = errors.New("disk failure")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk failure")
}

// === Delete Tests ===

func TestGenericDAO_Delete_Success_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save and then delete
	role := &TestRole{ID: 12345, Name: "admin"}
	require.NoError(t, dao.Save(ctx, role))
	assert.Equal(t, 1, mock.Count("TestRole"))

	err := dao.Delete(ctx, role)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count("TestRole"))
}

func TestGenericDAO_Delete_ZeroID_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	role := &TestRole{ID: 0, Name: "admin"}
	err := dao.Delete(ctx, role)

	require.Error(t, err)
	var invalidIDErr ErrInvalidEntityID
	assert.ErrorAs(t, err, &invalidIDErr)
}

func TestGenericDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("permission denied")

	ctx := context.Background()
	role := &TestRole{ID: 12345, Name: "admin"}
	err := dao.Delete(ctx, role)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

// === Count Tests ===

func TestGenericDAO_Count_Empty_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestGenericDAO_Count_WithEntities_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save multiple entities
	for i := 1; i <= 5; i++ {
		role := &TestRole{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestGenericDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("connection reset")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")
}

// === Page Tests ===

func TestGenericDAO_Page_FirstPage_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save multiple entities
	for i := 1; i <= 10; i++ {
		role := &TestRole{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 3, len(result.Entities))
	assert.True(t, result.HasMore)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 3, result.PageSize)
	assert.Equal(t, 10, result.Total)
}

func TestGenericDAO_Page_MiddlePage_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := 1; i <= 10; i++ {
		require.NoError(t, dao.Save(ctx, &TestRole{ID: uint64(i), Name: "role"}))
	}

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 2, PageSize: 3})

	require.NoError(t, err)
	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, 2, result.Page)
	assert.True(t, result.HasMore)
}

func TestGenericDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save 5 entities
	for i := 1; i <= 5; i++ {
		role := &TestRole{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 3}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestGenericDAO_Page_BeyondLastPage_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save 3 entities
	for i := 1; i <= 3; i++ {
		role := &TestRole{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	query := datastore.PageQuery{Page: 10, PageSize: 3}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Empty(t, result.Entities)
	assert.False(t, result.HasMore)
}

func TestGenericDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("timeout")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 10}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

// === ForEachPage Tests ===

func TestGenericDAO_ForEachPage_Success_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save 10 entities
	for i := 1; i <= 10; i++ {
		role := &TestRole{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	var allEntities []*TestRole
	pageCount := 0
	processor := func(result datastore.PageResult[*TestRole]) error {
		pageCount++
		allEntities = append(allEntities, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 4, pageCount, "10 entities at 3 per page is 4 pages")
	assert.Equal(t, 10, len(allEntities))
}

func TestGenericDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save some entities
	for i := 1; i <= 5; i++ {
		role := &TestRole{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	processorErr := errors.New("processing failed")
	processor := func(result datastore.PageResult[*TestRole]) error {
		return processorErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 10}
	err := dao.ForEachPage(ctx, query, processor)

	require.Error(t, err)
	assert.Equal(t, processorErr, err)
}

func TestGenericDAO_ForEachPage_InvalidStartPage_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save some entities
	for i := 1; i <= 3; i++ {
		role := &TestRole{ID: uint64(i), Name: "role"}
		require.NoError(t, dao.Save(ctx, role))
	}

	var pageCount int
	processor := func(result datastore.PageResult[*TestRole]) error {
		pageCount++
		return nil
	}

	// Page 0 should be treated as page 1
	query := datastore.PageQuery{Page: 0, PageSize: 10}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 1, pageCount)
}

// === EntityType Tests ===

func TestGenericDAO_EntityType_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	assert.Equal(t, "TestRole", dao.EntityType())
}

// === WithRequestTimeout Tests ===

func TestWithRequestTimeout_Mock(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := newTestLogger(t)
	customTimeout := 10 * time.Second

	dao := NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		logger,
		WithRequestTimeout(customTimeout),
	)

	assert.Equal(t, customTimeout, dao.requestTimeout)
}

func TestDefaultRequestTimeout_Mock(t *testing.T) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := newTestLogger(t)

	dao := NewGenericDAO[*TestRole](
		mock,
		"TestRole",
		func() *TestRole { return &TestRole{} },
		logger,
	)

	assert.Equal(t, DefaultRequestTimeout, dao.requestTimeout)
}

func TestGenericDAO_SecondInstanceReadsSavedEntities_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	roles := []*TestRole{{Name: "role-1"}, {Name: "role-2"}, {Name: "role-3"}}
	for _, role := range roles {
		require.NoError(t, dao.Save(ctx, role))
	}

	// A DAO opened later over the same store sees everything the first wrote.
	dao2 := newMockRoleDAO(t, mock)
	for _, role := range roles {
		retrieved, err := dao2.Get(ctx, role.ID)
		require.NoError(t, err)
		assert.Equal(t, role.Name, retrieved.Name)
	}
}

func TestGenericDAO_ConcurrentSaveAndGet_Mock(t *testing.T) {
	dao, mock := setupMockDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	const seeded, workers = 5, 10
	seeds := make([]*TestRole, seeded)
	for i := range seeds {
		seeds[i] = &TestRole{Name: fmt.Sprintf("seed-%d", i)}
		require.NoError(t, dao.Save(ctx, seeds[i]))
	}

	// Each worker saves a new auto-ID entity while another reads a seed.
	errs := make(chan error, 2*workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(2)
		go func(idx int) {
			defer wg.Done()
			errs <- dao.Save(ctx, &TestRole{Name: fmt.Sprintf("worker-%d", idx)})
		}(i)
		go func(seed *TestRole) {
			defer wg.Done()
			retrieved, err := dao.Get(ctx, seed.ID)
			if err == nil && retrieved.Name != seed.Name {
				err = errSeedMismatch{want: seed.Name, got: retrieved.Name}
			}
			errs <- err
		}(seeds[i%seeded])
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, seeded+workers)
}

// errSeedMismatch reports a concurrent read that returned another entity.
type errSeedMismatch struct{ want, got string }

func (e errSeedMismatch) Error() string {
	return fmt.Sprintf("read %q, want %q", e.got, e.want)
}
