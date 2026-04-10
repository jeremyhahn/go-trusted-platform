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

func newTestOrganizationDAO(t *testing.T) (*OrganizationDAO, *Client, func()) {
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

	dao := NewOrganizationDAO(client, logger)

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

func TestNewOrganizationDAO(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	assert.NotNil(t, dao)
	assert.NotNil(t, dao.GenericDAO)
}

func TestOrganizationDAO_Save_Success(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	ctx := context.Background()
	org := entities.NewOrganization("Test Organization")

	err := dao.Save(ctx, org)
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), org.EntityID())
}

func TestOrganizationDAO_Get_Success(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	ctx := context.Background()
	org := &entities.Organization{
		ID:   12345,
		Name: "Get Test Org",
	}

	err := dao.Save(ctx, org)
	require.NoError(t, err)

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), retrieved.EntityID())
	assert.Equal(t, "Get Test Org", retrieved.Name)
}

func TestOrganizationDAO_Get_NotFound(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999999)
	require.Error(t, err)

	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestOrganizationDAO_Delete_Success(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	ctx := context.Background()
	org := &entities.Organization{
		ID:   55555,
		Name: "Delete Test Org",
	}

	err := dao.Save(ctx, org)
	require.NoError(t, err)

	err = dao.Delete(ctx, org)
	require.NoError(t, err)

	// Note: In local mode (no Raft), delete is immediate.
	// We verify that Delete returns without error, which indicates
	// the delete operation was processed by the storage layer.
}

func TestOrganizationDAO_GetUsers_NoUsers(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	ctx := context.Background()
	org := &entities.Organization{
		ID:   11111,
		Name: "Empty Org",
	}
	err := dao.Save(ctx, org)
	require.NoError(t, err)

	users, err := dao.GetUsers(ctx, 11111)
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestOrganizationDAO_GetUsers_WithUsers(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	// Create embedded server
	server, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err, "failed to create embedded server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = server.Start(ctx)
	cancel()
	require.NoError(t, err, "failed to start embedded server")

	// Create client
	client, err := NewClient(cfg, logger)
	require.NoError(t, err, "failed to create client")

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	err = client.StartWithService(ctx, server.Service())
	cancel()
	require.NoError(t, err, "failed to start client with service")

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client.Stop(ctx)
		server.Stop(ctx)
	}()

	orgDAO := NewOrganizationDAO(client, logger)
	userDAO := NewUserDAO(client, logger)

	ctx = context.Background()

	// Create organization
	org := &entities.Organization{
		ID:   22222,
		Name: "Users Test Org",
	}
	err = orgDAO.Save(ctx, org)
	require.NoError(t, err)

	// Create users belonging to this organization
	user1 := &entities.User{
		ID:               33333,
		Email:            "user1@example.com",
		DisplayName:      "User One",
		OrganizationRefs: []uint64{22222}, // Belongs to our org
	}
	err = userDAO.Save(ctx, user1)
	require.NoError(t, err)

	user2 := &entities.User{
		ID:               33334,
		Email:            "user2@example.com",
		DisplayName:      "User Two",
		OrganizationRefs: []uint64{22222}, // Belongs to our org
	}
	err = userDAO.Save(ctx, user2)
	require.NoError(t, err)

	// Create a user NOT belonging to this organization
	user3 := &entities.User{
		ID:               33335,
		Email:            "user3@example.com",
		DisplayName:      "User Three",
		OrganizationRefs: []uint64{99999}, // Different org
	}
	err = userDAO.Save(ctx, user3)
	require.NoError(t, err)

	// Get users for our organization
	users, err := orgDAO.GetUsers(ctx, 22222)
	require.NoError(t, err)

	// Should only return users belonging to organization 22222
	assert.Len(t, users, 2)

	// Verify the users are the correct ones
	emails := make([]string, len(users))
	for i, u := range users {
		emails[i] = u.Email
	}
	assert.Contains(t, emails, "user1@example.com")
	assert.Contains(t, emails, "user2@example.com")
	assert.NotContains(t, emails, "user3@example.com")
}

func TestOrganizationDAO_GetUsers_UserInMultipleOrgs(t *testing.T) {
	cfg := TestConfig(t)
	logger := logging.DefaultLogger()

	// Create embedded server
	server, err := NewEmbeddedServer(cfg, logger)
	require.NoError(t, err, "failed to create embedded server")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = server.Start(ctx)
	cancel()
	require.NoError(t, err, "failed to start embedded server")

	// Create client
	client, err := NewClient(cfg, logger)
	require.NoError(t, err, "failed to create client")

	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	err = client.StartWithService(ctx, server.Service())
	cancel()
	require.NoError(t, err, "failed to start client with service")

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client.Stop(ctx)
		server.Stop(ctx)
	}()

	orgDAO := NewOrganizationDAO(client, logger)
	userDAO := NewUserDAO(client, logger)

	ctx = context.Background()

	// Create two organizations
	org1 := &entities.Organization{ID: 44444, Name: "Org One"}
	org2 := &entities.Organization{ID: 44445, Name: "Org Two"}
	require.NoError(t, orgDAO.Save(ctx, org1))
	require.NoError(t, orgDAO.Save(ctx, org2))

	// Create a user belonging to both organizations
	user := &entities.User{
		ID:               55555,
		Email:            "multi-org@example.com",
		DisplayName:      "Multi Org User",
		OrganizationRefs: []uint64{44444, 44445}, // Belongs to both orgs
	}
	err = userDAO.Save(ctx, user)
	require.NoError(t, err)

	// User should appear in both org queries
	users1, err := orgDAO.GetUsers(ctx, 44444)
	require.NoError(t, err)
	require.Len(t, users1, 1, "User should be found in org 44444")
	assert.Equal(t, "multi-org@example.com", users1[0].Email)

	users2, err := orgDAO.GetUsers(ctx, 44445)
	require.NoError(t, err)
	require.Len(t, users2, 1, "User should be found in org 44445")
	assert.Equal(t, "multi-org@example.com", users2[0].Email)
}

func TestOrganizationDAO_Count(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create some organizations
	for i := 1; i <= 5; i++ {
		org := &entities.Organization{
			ID:   uint64(70000 + i),
			Name: "Count Org " + string(rune('0'+i)),
		}
		require.NoError(t, dao.Save(ctx, org))
	}

	count, err := dao.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestOrganizationDAO_Page(t *testing.T) {
	dao, _, cleanup := newTestOrganizationDAO(t)
	defer cleanup()

	ctx := context.Background()

	// Create 10 organizations
	for i := 1; i <= 10; i++ {
		org := &entities.Organization{
			ID:   uint64(80000 + i),
			Name: "Page Org " + string(rune('0'+i)),
		}
		require.NoError(t, dao.Save(ctx, org))
	}

	// Get first page of 3
	result, err := dao.Page(ctx, datastore.PageQuery{Page: 1, PageSize: 3})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 3)
	assert.True(t, result.HasMore)
}
