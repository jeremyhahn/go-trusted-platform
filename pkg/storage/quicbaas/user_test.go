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

func newTestUserDAO(t *testing.T) (*UserDAO, *Client, func()) {
	t.Helper()

	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	// Create embedded server
	server, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err, "failed to create embedded server")

	// Start embedded server
	// context.Background(), deliberately (#270): a deadline here bounds
	// nothing and can only manufacture a false failure. The embedded
	// server's Start takes no context — it runs first boot synchronously and
	// the context is consulted only afterwards — and StartWithService
	// ignores its context entirely. So a deadline cannot interrupt slow
	// startup; it can only report a startup that already SUCCEEDED as a
	// failure when the machine was loaded, which is exactly what happened.
	// go test -timeout is the backstop for a genuine hang, and it prints a
	// goroutine dump, which says WHERE it hung rather than only that it did.
	err = server.Start(context.Background())
	require.NoError(t, err, "failed to start embedded server")

	// Create client
	client, err := NewClient(cfg, logger)
	require.NoError(t, err, "failed to create client")

	// Start client with embedded service
	err = client.StartWithService(context.Background(), server.Service())
	require.NoError(t, err, "failed to start client with service")

	dao := NewUserDAO(client, logger)

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

func TestNewUserDAO(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	assert.NotNil(t, dao)
	assert.NotNil(t, dao.GenericDAO)
}

func TestUserDAO_Save_NewUser(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	user := entities.NewUser("test@example.com")
	user.DisplayName = "Test User"

	err := dao.Save(ctx, user)
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), user.EntityID())
}

func TestUserDAO_Save_WithExistingID(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	user := &entities.User{
		ID:          12345,
		Email:       "existing@example.com",
		DisplayName: "Existing User",
	}

	err := dao.Save(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), user.EntityID())
}

func TestUserDAO_Get_Success(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	user := &entities.User{
		ID:          99999,
		Email:       "get@example.com",
		DisplayName: "Get Test User",
		ServiceRefs: []uint64{1, 2, 3},
	}

	err := dao.Save(ctx, user)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 99999)
	require.NoError(t, err)
	assert.Equal(t, uint64(99999), retrieved.EntityID())
	assert.Equal(t, "get@example.com", retrieved.Email)
	assert.Equal(t, "Get Test User", retrieved.DisplayName)
	assert.Equal(t, []uint64{1, 2, 3}, retrieved.ServiceRefs)
}

func TestUserDAO_Get_NotFound(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	_, err := dao.Get(ctx, 88888888)
	require.Error(t, err)

	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestUserDAO_Delete_Success(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	user := &entities.User{
		ID:    77777,
		Email: "delete@example.com",
	}

	err := dao.Save(ctx, user)
	require.NoError(t, err)

	err = dao.Delete(ctx, user)
	require.NoError(t, err)

	// Note: In local mode (no Raft), delete is immediate.
	// We verify that Delete returns without error, which indicates
	// the delete operation was processed by the storage layer.
}

func TestUserDAO_Save_WithRoles(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	user := entities.NewUser("roles@example.com")
	user.ID = 66666
	user.AddRole(&entities.Role{ID: 1, Name: "admin"})
	user.AddRole(&entities.Role{ID: 2, Name: "editor"})

	err := dao.Save(ctx, user)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 66666)
	require.NoError(t, err)

	assert.Len(t, retrieved.Roles, 2)
	assert.True(t, retrieved.HasRole("admin"))
	assert.True(t, retrieved.HasRole("editor"))
	assert.False(t, retrieved.HasRole("viewer"))
}

func TestUserDAO_Update_Success(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	user := &entities.User{
		ID:          55555,
		Email:       "original@example.com",
		DisplayName: "Original Name",
	}

	err := dao.Save(ctx, user)
	require.NoError(t, err)

	// Update
	user.DisplayName = "Updated Name"
	user.Email = "updated@example.com"
	err = dao.Save(ctx, user)
	require.NoError(t, err)

	// Verify update
	retrieved, err := dao.Get(ctx, 55555)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrieved.DisplayName)
	assert.Equal(t, "updated@example.com", retrieved.Email)
}

func TestUserDAO_Count(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create users
	for i := 1; i <= 5; i++ {
		user := &entities.User{
			ID:    uint64(40000 + i),
			Email: "count" + string(rune('0'+i)) + "@example.com",
		}
		require.NoError(t, dao.Save(ctx, user))
	}

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestUserDAO_Page(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 10 users
	for i := 1; i <= 10; i++ {
		user := &entities.User{
			ID:    uint64(30000 + i),
			Email: "page" + string(rune('0'+i)) + "@example.com",
		}
		require.NoError(t, dao.Save(ctx, user))
	}

	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 3})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 3)
	assert.True(t, result.HasMore)
}

func TestUserDAO_ForEachPage(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 12 users
	for i := 1; i <= 12; i++ {
		user := &entities.User{
			ID:    uint64(20000 + i),
			Email: "foreach" + string(rune('a'+i-1)) + "@example.com",
		}
		require.NoError(t, dao.Save(ctx, user))
	}

	var processedCount int
	err := dao.ForEachPage(
		ctx,
		datastore.PageQuery{Page: 1, PageSize: 4},
		func(result datastore.PageResult[*entities.User]) error {
			processedCount += len(result.Entities)
			return nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, 12, processedCount)
}

func TestUserDAO_ComplexUser(t *testing.T) {
	dao, _, cleanup := newTestUserDAO(t)
	defer cleanup()

	ctx := context.Background()
	user := entities.NewUser("complex@example.com")
	user.ID = 11111
	user.DisplayName = "Complex User"
	user.Password = "hashedpassword123"
	user.ServiceRefs = []uint64{1000, 2000}
	user.AddRole(&entities.Role{ID: 1, Name: "admin"})

	err := dao.Save(ctx, user)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 11111)
	require.NoError(t, err)

	assert.Equal(t, "complex@example.com", retrieved.Email)
	assert.Equal(t, "Complex User", retrieved.DisplayName)
	assert.Equal(t, "hashedpassword123", retrieved.Password)
	assert.Equal(t, []uint64{1000, 2000}, retrieved.ServiceRefs)
	assert.True(t, retrieved.HasRole("admin"))
}
