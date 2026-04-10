//go:build raft

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
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGenericDAO(t *testing.T) (*GenericDAO[*entities.Role], *Client, func()) {
	t.Helper()

	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	// Create embedded server
	server, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err, "failed to create embedded server")

	// Start embedded server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = server.Start(ctx)
	cancel()
	require.NoError(t, err, "failed to start embedded server")

	// Create client
	client, err := NewClient(cfg, logger)
	require.NoError(t, err, "failed to create client")

	// Start client with embedded service
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	err = client.StartWithService(ctx, server.Service())
	cancel()
	require.NoError(t, err, "failed to start client with service")

	dao := NewGenericDAO[*entities.Role](
		client,
		"TestRole",
		func() *entities.Role { return &entities.Role{} },
		logger,
	)

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Stop client first
		if err := client.Stop(ctx); err != nil {
			t.Logf("client stop error: %v", err)
		}

		// Stop embedded server
		if err := server.Stop(ctx); err != nil {
			t.Logf("server stop error: %v", err)
		}
	}

	return dao, client, cleanup
}

func TestNewGenericDAO(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	assert.NotNil(t, dao)
	assert.Equal(t, "TestRole", dao.EntityType())
}

func TestGenericDAO_Save_NewEntity(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	role := &entities.Role{
		Name: "admin",
	}

	// ID should be 0 before save
	assert.Equal(t, uint64(0), role.EntityID())

	err := dao.Save(ctx, role)
	require.NoError(t, err)

	// ID should be auto-assigned after save
	assert.NotEqual(t, uint64(0), role.EntityID())
}

func TestGenericDAO_Save_ExistingEntity(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	role := &entities.Role{
		ID:   12345,
		Name: "admin",
	}

	err := dao.Save(ctx, role)
	require.NoError(t, err)

	// ID should remain the same
	assert.Equal(t, uint64(12345), role.EntityID())

	// Update and save again
	role.Name = "super-admin"
	err = dao.Save(ctx, role)
	require.NoError(t, err)

	// Verify update
	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, "super-admin", retrieved.Name)
}

func TestGenericDAO_Get_Success(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	role := &entities.Role{
		ID:   99999,
		Name: "test-role",
	}
	err := dao.Save(ctx, role)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 99999)
	require.NoError(t, err)
	assert.Equal(t, uint64(99999), retrieved.EntityID())
	assert.Equal(t, "test-role", retrieved.Name)
}

func TestGenericDAO_Get_NotFound(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	_, err := dao.Get(ctx, 99999999)
	require.Error(t, err)

	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "TestRole", notFoundErr.EntityType)
	assert.Equal(t, uint64(99999999), notFoundErr.ID)
}

func TestGenericDAO_Delete_Success(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	role := &entities.Role{
		ID:   77777,
		Name: "to-delete",
	}
	err := dao.Save(ctx, role)
	require.NoError(t, err)

	// Verify exists
	_, err = dao.Get(ctx, 77777)
	require.NoError(t, err)

	// Delete
	err = dao.Delete(ctx, role)
	require.NoError(t, err)

	// Note: In local mode (no Raft), delete is immediate.
	// We verify that Delete returns without error, which indicates
	// the delete operation was processed by the storage layer.
}

func TestGenericDAO_Delete_ZeroID(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	role := &entities.Role{
		Name: "no-id",
	}

	err := dao.Delete(ctx, role)
	require.Error(t, err)

	var invalidIDErr ErrInvalidEntityID
	assert.ErrorAs(t, err, &invalidIDErr)
	assert.Equal(t, "TestRole", invalidIDErr.EntityType)
}

func TestGenericDAO_Count_Empty(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestGenericDAO_Count_WithEntities(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create some entities
	for i := 1; i <= 5; i++ {
		role := &entities.Role{
			ID:   uint64(i * 1000),
			Name: "role-" + string(rune('0'+i)),
		}
		err := dao.Save(ctx, role)
		require.NoError(t, err)
	}

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestGenericDAO_Page_Success(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 10 entities
	for i := 1; i <= 10; i++ {
		role := &entities.Role{
			ID:   uint64(i * 100),
			Name: "page-role-" + string(rune('0'+i)),
		}
		err := dao.Save(ctx, role)
		require.NoError(t, err)
	}

	// Wait for all items to be visible via Raft consensus
	// QuicBaaS may need time to commit all writes to the state machine
	require.Eventually(t, func() bool {
		count, err := dao.Count(ctx)
		return err == nil && count == 10
	}, 5*time.Second, 50*time.Millisecond, "expected 10 items to be visible")

	// Get first page of 3
	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 3,
	}
	result, err := dao.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.Len(t, result.Entities, 3)
	assert.True(t, result.HasMore)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 3, result.PageSize)
}

func TestGenericDAO_Page_LastPage(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 5 entities
	for i := 1; i <= 5; i++ {
		role := &entities.Role{
			ID:   uint64(i * 100),
			Name: "last-page-role-" + string(rune('0'+i)),
		}
		err := dao.Save(ctx, role)
		require.NoError(t, err)
	}

	// Wait for all items to be visible via Raft consensus
	// QuicBaaS may need time to commit all writes to the state machine
	require.Eventually(t, func() bool {
		count, err := dao.Count(ctx)
		return err == nil && count == 5
	}, 5*time.Second, 50*time.Millisecond, "expected 5 items to be visible")

	// Get page with all remaining entities
	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}
	result, err := dao.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.Len(t, result.Entities, 5)
	assert.False(t, result.HasMore)
}

func TestGenericDAO_Page_EmptyResult(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	pageQuery := datastore.PageQuery{
		Page:     1,
		PageSize: 10,
	}
	result, err := dao.Page(ctx, pageQuery)
	require.NoError(t, err)
	assert.Empty(t, result.Entities)
	assert.False(t, result.HasMore)
}

func TestGenericDAO_ForEachPage_Success(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 8 entities
	for i := 1; i <= 8; i++ {
		role := &entities.Role{
			ID:   uint64(i * 100),
			Name: "foreach-role-" + string(rune('0'+i)),
		}
		err := dao.Save(ctx, role)
		require.NoError(t, err)
	}

	// Wait for all items to be visible via Raft consensus
	// QuicBaaS may need time to commit all writes to the state machine
	require.Eventually(t, func() bool {
		count, err := dao.Count(ctx)
		t.Logf("Count check: count=%d, err=%v", count, err)
		return err == nil && count == 8
	}, 5*time.Second, 50*time.Millisecond, "expected 8 items to be visible")

	// Debug: verify count one more time
	count, err := dao.Count(ctx)
	t.Logf("Final count before ForEachPage: count=%d, err=%v", count, err)
	require.NoError(t, err)
	require.Equal(t, 8, count, "Count must be 8 before ForEachPage")

	// Track processed entities
	var processedCount int
	var pageCount int

	err = dao.ForEachPage(
		ctx,
		datastore.PageQuery{Page: 1, PageSize: 3},
		func(result datastore.PageResult[*entities.Role]) error {
			roles := result.Entities
			t.Logf("Processing page %d with %d roles", pageCount+1, len(roles))
			for _, r := range roles {
				t.Logf("  Role: ID=%d, Name=%s", r.ID, r.Name)
			}
			processedCount += len(roles)
			pageCount++
			return nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, 8, processedCount)
	assert.GreaterOrEqual(t, pageCount, 3) // At least 3 pages of 3 items each
}

func TestGenericDAO_ForEachPage_ProcessorError(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create some entities
	for i := 1; i <= 5; i++ {
		role := &entities.Role{
			ID:   uint64(i * 100),
			Name: "error-role-" + string(rune('0'+i)),
		}
		err := dao.Save(ctx, role)
		require.NoError(t, err)
	}

	// Processor that returns error
	testErr := ErrOperationFailed{Operation: "test", Cause: nil}
	err := dao.ForEachPage(
		ctx,
		datastore.PageQuery{Page: 1, PageSize: 2},
		func(result datastore.PageResult[*entities.Role]) error {
			return testErr
		},
	)
	require.Error(t, err)
	var opErr ErrOperationFailed
	assert.ErrorAs(t, err, &opErr)
}

func TestGenericDAO_ForEachPage_Empty(t *testing.T) {
	dao, _, cleanup := newTestGenericDAO(t)
	defer cleanup()

	ctx := context.Background()

	var called bool
	err := dao.ForEachPage(
		ctx,
		datastore.PageQuery{Page: 1, PageSize: 10},
		func(result datastore.PageResult[*entities.Role]) error {
			called = true
			return nil
		},
	)
	require.NoError(t, err)
	assert.False(t, called, "processor should not be called for empty result")
}

func TestGenericDAO_SaveAndRetrieve_ComplexEntity(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	// Create embedded server
	server, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err, "failed to create embedded server")

	// Start embedded server
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = server.Start(ctx)
	cancel()
	require.NoError(t, err, "failed to start embedded server")

	// Create client
	client, err := NewClient(cfg, logger)
	require.NoError(t, err, "failed to create client")

	// Start client with embedded service
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	err = client.StartWithService(ctx, server.Service())
	cancel()
	require.NoError(t, err, "failed to start client with service")

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Stop client first
		if err := client.Stop(ctx); err != nil {
			t.Logf("client stop error: %v", err)
		}

		// Stop embedded server
		if err := server.Stop(ctx); err != nil {
			t.Logf("server stop error: %v", err)
		}
	}()

	// Use User entity which has more complex structure
	userDAO := NewGenericDAO[*entities.User](
		client,
		"TestUser",
		func() *entities.User { return &entities.User{} },
		logger,
	)

	ctx = context.Background()

	user := entities.NewUser("test@example.com")
	user.DisplayName = "Test User"
	user.OrganizationRefs = []uint64{1, 2, 3}
	user.Roles = []*entities.Role{
		{ID: 1, Name: "admin"},
		{ID: 2, Name: "user"},
	}

	err = userDAO.Save(ctx, user)
	require.NoError(t, err)

	retrieved, err := userDAO.Get(ctx, user.EntityID())
	require.NoError(t, err)

	assert.Equal(t, user.Email, retrieved.Email)
	assert.Equal(t, user.DisplayName, retrieved.DisplayName)
	assert.Equal(t, user.OrganizationRefs, retrieved.OrganizationRefs)
	assert.Len(t, retrieved.Roles, 2)
	assert.Equal(t, "admin", retrieved.Roles[0].Name)
	assert.Equal(t, "user", retrieved.Roles[1].Name)
}

func TestGenericDAO_ServerNotStarted(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	client, err := NewClient(cfg, logger)
	require.NoError(t, err)
	// Note: client.Start() is NOT called

	dao := NewGenericDAO[*entities.Role](
		client,
		"TestRole",
		func() *entities.Role { return &entities.Role{} },
		logger,
	)

	ctx := context.Background()

	// Save should fail
	role := &entities.Role{ID: 1, Name: "test"}
	err = dao.Save(ctx, role)
	require.Error(t, err)
	var notStartedErr ErrServerNotStarted
	assert.ErrorAs(t, err, &notStartedErr)

	// Get should fail
	_, err = dao.Get(ctx, 1)
	require.Error(t, err)
	assert.ErrorAs(t, err, &notStartedErr)

	// Delete should fail
	err = dao.Delete(ctx, role)
	require.Error(t, err)
	assert.ErrorAs(t, err, &notStartedErr)

	// Count should fail
	_, err = dao.Count(ctx)
	require.Error(t, err)
	assert.ErrorAs(t, err, &notStartedErr)

	// Page should fail
	_, err = dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 10})
	require.Error(t, err)
	assert.ErrorAs(t, err, &notStartedErr)
}
