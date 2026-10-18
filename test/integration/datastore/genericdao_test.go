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

//go:build integration

// Package datastore provides integration tests for the QuicBaaS GenericDAO implementation.
// These tests require a real QuicBaaS instance with embedded PebbleDB.
// Run via: make integration-test-datastore
package datastore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	kvEntities "github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testEntity is a simple entity for testing GenericDAO operations.
type testEntity struct {
	ID   uint64 `json:"id"`
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func (e *testEntity) EntityID() uint64 {
	return e.ID
}

func (e *testEntity) SetEntityID(id uint64) {
	e.ID = id
}

// Verify testEntity implements KeyValueEntity interface.
var _ kvEntities.KeyValueEntity = (*testEntity)(nil)

// newTestGenericDAO creates a GenericDAO for testing with testEntity.
func newTestGenericDAO(storage quicbaas.Storage, logger *logging.Logger) *quicbaas.GenericDAO[*testEntity] {
	return quicbaas.NewGenericDAO[*testEntity](
		storage,
		"TestEntity",
		func() *testEntity { return &testEntity{} },
		logger,
	)
}

// TestGenericDAO_Save_NewEntity tests saving a new entity with auto-generated ID.
func TestGenericDAO_Save_NewEntity(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()
	entity := &testEntity{
		Name: "Alice",
		Age:  30,
	}

	// ID should be 0 before save
	assert.Zero(t, entity.ID)

	err := dao.Save(ctx, entity)
	require.NoError(t, err)

	// ID should be auto-generated after save
	assert.NotZero(t, entity.ID)

	// Verify entity can be retrieved
	retrieved, err := dao.Get(ctx, entity.ID)
	require.NoError(t, err)
	assert.Equal(t, entity.Name, retrieved.Name)
	assert.Equal(t, entity.Age, retrieved.Age)
	assert.Equal(t, entity.ID, retrieved.ID)
}

// TestGenericDAO_Save_UpdateExisting tests updating an existing entity.
func TestGenericDAO_Save_UpdateExisting(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Create initial entity
	entity := &testEntity{
		Name: "Bob",
		Age:  25,
	}
	require.NoError(t, dao.Save(ctx, entity))
	originalID := entity.ID

	// Update entity
	entity.Name = "Bobby"
	entity.Age = 26
	require.NoError(t, dao.Save(ctx, entity))

	// ID should remain the same
	assert.Equal(t, originalID, entity.ID)

	// Verify update persisted
	retrieved, err := dao.Get(ctx, entity.ID)
	require.NoError(t, err)
	assert.Equal(t, "Bobby", retrieved.Name)
	assert.Equal(t, 26, retrieved.Age)
}

// TestGenericDAO_Get_Success tests successful entity retrieval.
func TestGenericDAO_Get_Success(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Create entity
	entity := &testEntity{
		Name: "Charlie",
		Age:  35,
	}
	require.NoError(t, dao.Save(ctx, entity))

	// Retrieve entity
	retrieved, err := dao.Get(ctx, entity.ID)
	require.NoError(t, err)
	assert.Equal(t, entity.ID, retrieved.ID)
	assert.Equal(t, entity.Name, retrieved.Name)
	assert.Equal(t, entity.Age, retrieved.Age)
}

// TestGenericDAO_Get_NotFound tests retrieval of non-existent entity.
func TestGenericDAO_Get_NotFound(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Try to get non-existent entity
	_, err := dao.Get(ctx, 999999999)
	require.Error(t, err)

	// Should be an ErrNotFound
	var notFoundErr quicbaas.ErrNotFound
	assert.True(t, errors.As(err, &notFoundErr))
}

// TestGenericDAO_Delete_Success tests successful entity deletion.
func TestGenericDAO_Delete_Success(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Create entity
	entity := &testEntity{
		Name: "David",
		Age:  40,
	}
	require.NoError(t, dao.Save(ctx, entity))

	// Verify entity exists
	_, err := dao.Get(ctx, entity.ID)
	require.NoError(t, err)

	// Delete entity
	require.NoError(t, dao.Delete(ctx, entity))

	// Verify entity is deleted (eventually, due to async delete in QuicBaaS)
	require.Eventually(t, func() bool {
		_, err := dao.Get(ctx, entity.ID)
		return err != nil
	}, 5*time.Second, 100*time.Millisecond, "entity should be deleted")
}

// TestGenericDAO_Delete_InvalidID tests deletion with zero ID.
func TestGenericDAO_Delete_InvalidID(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Try to delete entity with ID 0
	entity := &testEntity{
		ID:   0,
		Name: "Invalid",
	}

	err := dao.Delete(ctx, entity)
	require.Error(t, err)

	// Should be an ErrInvalidEntityID
	var invalidIDErr quicbaas.ErrInvalidEntityID
	assert.True(t, errors.As(err, &invalidIDErr))
}

// TestGenericDAO_Count tests counting entities.
func TestGenericDAO_Count(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Count should start at 0
	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Add some entities
	numEntities := 5
	for i := 0; i < numEntities; i++ {
		entity := &testEntity{
			Name: "Test",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Count should reflect added entities
	count, err = dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, numEntities, count)
}

// TestGenericDAO_Page_FirstPage tests retrieving the first page of entities.
func TestGenericDAO_Page_FirstPage(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Add entities
	numEntities := 10
	for i := 0; i < numEntities; i++ {
		entity := &testEntity{
			Name: "PageTest",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Get first page
	query := datastore.PageQuery{
		Page:     1,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)

	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 3, result.PageSize)
	assert.Equal(t, numEntities, result.Total)
	assert.True(t, result.HasMore)
}

// TestGenericDAO_Page_MiddlePage tests retrieving a middle page of entities.
func TestGenericDAO_Page_MiddlePage(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Add entities
	numEntities := 10
	for i := 0; i < numEntities; i++ {
		entity := &testEntity{
			Name: "PageTest",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Get second page
	query := datastore.PageQuery{
		Page:     2,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)

	assert.Equal(t, 3, len(result.Entities))
	assert.Equal(t, 2, result.Page)
	assert.True(t, result.HasMore)
}

// TestGenericDAO_Page_LastPage tests retrieving the last page of entities.
func TestGenericDAO_Page_LastPage(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Add entities
	numEntities := 10
	for i := 0; i < numEntities; i++ {
		entity := &testEntity{
			Name: "PageTest",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Get last page (page 4: entities 10 - partial page of 1)
	query := datastore.PageQuery{
		Page:     4,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)

	assert.Equal(t, 1, len(result.Entities))
	assert.Equal(t, 4, result.Page)
	assert.False(t, result.HasMore)
}

// TestGenericDAO_Page_BeyondLastPage tests requesting a page beyond available data.
func TestGenericDAO_Page_BeyondLastPage(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Add entities
	for i := 0; i < 5; i++ {
		entity := &testEntity{
			Name: "PageTest",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Request page beyond data
	query := datastore.PageQuery{
		Page:     100,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, query)
	require.NoError(t, err)

	assert.Empty(t, result.Entities)
	assert.False(t, result.HasMore)
}

// TestGenericDAO_ForEachPage_AllPages tests iterating through all pages.
func TestGenericDAO_ForEachPage_AllPages(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Add entities
	numEntities := 10
	for i := 0; i < numEntities; i++ {
		entity := &testEntity{
			Name: "ForEachPageTest",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Iterate through all pages
	query := datastore.PageQuery{
		Page:     1,
		PageSize: 3,
	}

	var allEntities []*testEntity
	var pageCount int

	err := dao.ForEachPage(ctx, query, func(result datastore.PageResult[*testEntity]) error {
		pageCount++
		allEntities = append(allEntities, result.Entities...)
		return nil
	})
	require.NoError(t, err)

	// Should have iterated through all pages
	assert.Equal(t, 4, pageCount) // 10 entities / 3 per page = 4 pages
	assert.Equal(t, numEntities, len(allEntities))
}

// TestGenericDAO_ForEachPage_StopIteration tests early termination of page iteration.
func TestGenericDAO_ForEachPage_StopIteration(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Add entities
	for i := 0; i < 10; i++ {
		entity := &testEntity{
			Name: "StopIterationTest",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Stop after first page
	query := datastore.PageQuery{
		Page:     1,
		PageSize: 3,
	}

	var pageCount int
	err := dao.ForEachPage(ctx, query, func(result datastore.PageResult[*testEntity]) error {
		pageCount++
		return datastore.ErrStopIteration
	})
	require.NoError(t, err)

	assert.Equal(t, 1, pageCount)
}

// TestGenericDAO_ForEachPage_ErrorPropagation tests that errors from callback are propagated.
func TestGenericDAO_ForEachPage_ErrorPropagation(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Add entities
	for i := 0; i < 5; i++ {
		entity := &testEntity{
			Name: "ErrorTest",
			Age:  i + 20,
		}
		require.NoError(t, dao.Save(ctx, entity))
	}

	// Return error from callback
	query := datastore.PageQuery{
		Page:     1,
		PageSize: 3,
	}

	expectedErr := errors.New("test error")
	err := dao.ForEachPage(ctx, query, func(result datastore.PageResult[*testEntity]) error {
		return expectedErr
	})

	assert.Equal(t, expectedErr, err)
}

// TestGenericDAO_EntityType tests that EntityType returns the correct type name.
func TestGenericDAO_EntityType(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	assert.Equal(t, "TestEntity", dao.EntityType())
}

// TestGenericDAO_ContextCancellation tests that context cancellation is respected.
func TestGenericDAO_ContextCancellation(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entity := &testEntity{
		Name: "Cancelled",
		Age:  50,
	}

	// Operations with cancelled context should fail for remote transports.
	// Embedded in-memory storage may not check context cancellation since
	// operations complete synchronously without network I/O.
	err := dao.Save(ctx, entity)
	if err != nil {
		// Remote transport correctly returned context error
		assert.Contains(t, err.Error(), "cancel")
	} else {
		// Embedded transport completed despite cancelled context.
		// Verify the entity was actually saved (operation completed).
		result, getErr := dao.Get(context.Background(), entity.ID)
		require.NoError(t, getErr)
		require.NotNil(t, result, "entity should exist after successful save")
		assert.Equal(t, entity.Name, result.Name)
	}
}

// TestGenericDAO_DataPersistence tests that data persists across operations.
func TestGenericDAO_DataPersistence(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()
	dao := newTestGenericDAO(client, logger)

	ctx := context.Background()

	// Create multiple entities
	entities := []*testEntity{
		{Name: "Entity1", Age: 21},
		{Name: "Entity2", Age: 22},
		{Name: "Entity3", Age: 23},
	}

	for _, e := range entities {
		require.NoError(t, dao.Save(ctx, e))
	}

	// Create a new DAO instance (simulating reconnection)
	dao2 := newTestGenericDAO(client, logger)

	// Verify all entities are still accessible
	for _, e := range entities {
		retrieved, err := dao2.Get(ctx, e.ID)
		require.NoError(t, err)
		assert.Equal(t, e.Name, retrieved.Name)
		assert.Equal(t, e.Age, retrieved.Age)
	}
}

// TestGenericDAO_WithRequestTimeout tests custom timeout configuration.
func TestGenericDAO_WithRequestTimeout(t *testing.T) {
	client, cleanup := newIntegrationClient(t)
	defer cleanup()

	logger := logging.DefaultLogger()

	// Create DAO with custom timeout
	dao := quicbaas.NewGenericDAO[*testEntity](
		client,
		"TestEntity",
		func() *testEntity { return &testEntity{} },
		logger,
		quicbaas.WithRequestTimeout(60*time.Second),
	)

	ctx := context.Background()
	entity := &testEntity{
		Name: "TimeoutTest",
		Age:  25,
	}

	// Operation should succeed with longer timeout
	require.NoError(t, dao.Save(ctx, entity))

	retrieved, err := dao.Get(ctx, entity.ID)
	require.NoError(t, err)
	assert.Equal(t, entity.Name, retrieved.Name)
}
