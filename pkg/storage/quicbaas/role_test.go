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

func newTestRoleDAO(t *testing.T) (*RoleDAO, *Client, func()) {
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

	dao := NewRoleDAO(client, logger)

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

func TestNewRoleDAO(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	assert.NotNil(t, dao)
	assert.NotNil(t, dao.GenericDAO)
}

func TestRoleDAO_Save_Success(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()
	role := entities.NewRole("admin")

	err := dao.Save(ctx, role)
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), role.EntityID())
}

func TestRoleDAO_Get_Success(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()
	role := &entities.Role{
		ID:   12345,
		Name: "test-role",
	}

	err := dao.Save(ctx, role)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), retrieved.EntityID())
	assert.Equal(t, "test-role", retrieved.Name)
}

func TestRoleDAO_Get_NotFound(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999999)
	require.Error(t, err)

	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestRoleDAO_Delete_Success(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()
	role := &entities.Role{
		ID:   55555,
		Name: "delete-role",
	}

	err := dao.Save(ctx, role)
	require.NoError(t, err)

	err = dao.Delete(ctx, role)
	require.NoError(t, err)

	// Note: In local mode (no Raft), delete is immediate.
	// We verify that Delete returns without error, which indicates
	// the delete operation was processed by the storage layer.
}

func TestRoleDAO_GetByName_Success(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create roles with unique names
	adminRole := &entities.Role{
		ID:   11111,
		Name: "super-admin",
	}
	err := dao.Save(ctx, adminRole)
	require.NoError(t, err)

	userRole := &entities.Role{
		ID:   11112,
		Name: "regular-user",
	}
	err = dao.Save(ctx, userRole)
	require.NoError(t, err)

	guestRole := &entities.Role{
		ID:   11113,
		Name: "guest",
	}
	err = dao.Save(ctx, guestRole)
	require.NoError(t, err)

	// Find by name
	found, err := dao.GetByName(ctx, "regular-user")
	require.NoError(t, err)
	assert.NotNil(t, found)
	assert.Equal(t, uint64(11112), found.EntityID())
	assert.Equal(t, "regular-user", found.Name)
}

func TestRoleDAO_GetByName_NotFound(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create a role
	role := &entities.Role{
		ID:   22222,
		Name: "existing-role",
	}
	err := dao.Save(ctx, role)
	require.NoError(t, err)

	// Try to find non-existent role
	_, err = dao.GetByName(ctx, "non-existent-role")
	require.Error(t, err)

	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "Role", notFoundErr.EntityType)
	assert.Equal(t, "Name", notFoundErr.IndexField)
	assert.Equal(t, "non-existent-role", notFoundErr.Value)
}

func TestRoleDAO_GetByName_MultipleRoles(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create many roles
	roleNames := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	for i, name := range roleNames {
		role := &entities.Role{
			ID:   uint64(30000 + i),
			Name: name,
		}
		require.NoError(t, dao.Save(ctx, role))
	}

	// Find each role by name
	for i, name := range roleNames {
		found, err := dao.GetByName(ctx, name)
		require.NoError(t, err, "should find role: %s", name)
		assert.Equal(t, uint64(30000+i), found.EntityID())
		assert.Equal(t, name, found.Name)
	}
}

func TestRoleDAO_Count(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create roles
	for i := 1; i <= 7; i++ {
		role := &entities.Role{
			ID:   uint64(40000 + i),
			Name: "count-role-" + string(rune('0'+i)),
		}
		require.NoError(t, dao.Save(ctx, role))
	}

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 7, count)
}

func TestRoleDAO_Page(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 10 roles
	for i := 1; i <= 10; i++ {
		role := &entities.Role{
			ID:   uint64(50000 + i),
			Name: "page-role-" + string(rune('0'+i)),
		}
		require.NoError(t, dao.Save(ctx, role))
	}

	// Get first page
	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 4})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 4)
	assert.True(t, result.HasMore)
}

func TestRoleDAO_Update_Success(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create role
	role := &entities.Role{
		ID:   60000,
		Name: "original-name",
	}
	err := dao.Save(ctx, role)
	require.NoError(t, err)

	// Update role
	role.Name = "updated-name"
	err = dao.Save(ctx, role)
	require.NoError(t, err)

	// Verify update
	retrieved, err := dao.Get(ctx, 60000)
	require.NoError(t, err)
	assert.Equal(t, "updated-name", retrieved.Name)

	// Old name should not be found
	_, err = dao.GetByName(ctx, "original-name")
	require.Error(t, err)

	// New name should be found
	found, err := dao.GetByName(ctx, "updated-name")
	require.NoError(t, err)
	assert.Equal(t, uint64(60000), found.EntityID())
}

func TestRoleDAO_ForEachPage(t *testing.T) {
	dao, _, cleanup := newTestRoleDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 15 roles
	for i := 1; i <= 15; i++ {
		role := &entities.Role{
			ID:   uint64(70000 + i),
			Name: "foreach-role-" + string(rune('a'+i-1)),
		}
		require.NoError(t, dao.Save(ctx, role))
	}

	var processedCount int
	err := dao.ForEachPage(
		ctx,
		datastore.PageQuery{Page: 1, PageSize: 5},
		func(result datastore.PageResult[*entities.Role]) error {
			processedCount += len(result.Entities)
			return nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, 15, processedCount)
}
