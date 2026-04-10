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
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupMockOrganizationDAO(t *testing.T) (*OrganizationDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewOrganizationDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func TestOrganizationDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	org := &entities.Organization{Name: "TestOrg"}
	err := dao.Save(ctx, org)

	require.NoError(t, err)
	assert.NotZero(t, org.ID)
	assert.Equal(t, 1, mock.Count(entityTypeOrganization))
}

func TestOrganizationDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Save and retrieve
	org := &entities.Organization{ID: 12345, Name: "TestOrg"}
	require.NoError(t, dao.Save(ctx, org))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "TestOrg", retrieved.Name)
}

func TestOrganizationDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	org := &entities.Organization{ID: 12345, Name: "TestOrg"}
	require.NoError(t, dao.Save(ctx, org))
	assert.Equal(t, 1, mock.Count(entityTypeOrganization))

	err := dao.Delete(ctx, org)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeOrganization))
}

func TestOrganizationDAO_GetUsers_Empty_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	users, err := dao.GetUsers(ctx, 12345)

	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestOrganizationDAO_GetUsers_WithUsers_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Create organization
	org := &entities.Organization{ID: 12345, Name: "TestOrg"}
	require.NoError(t, dao.Save(ctx, org))

	// Create users with organization reference
	user1 := entities.NewUser("user1@test.com")
	user1.ID = 1
	user1.OrganizationRefs = []uint64{12345}
	user1Data, _ := json.Marshal(user1)
	mock.SetData("User", 1, user1Data)

	user2 := entities.NewUser("user2@test.com")
	user2.ID = 2
	user2.OrganizationRefs = []uint64{12345}
	user2Data, _ := json.Marshal(user2)
	mock.SetData("User", 2, user2Data)

	// User in different org
	user3 := entities.NewUser("user3@test.com")
	user3.ID = 3
	user3.OrganizationRefs = []uint64{99999}
	user3Data, _ := json.Marshal(user3)
	mock.SetData("User", 3, user3Data)

	users, err := dao.GetUsers(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, 2, len(users))
}

func TestOrganizationDAO_GetUsers_MultipleOrgs_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// User belongs to multiple orgs
	user := entities.NewUser("multi@test.com")
	user.ID = 1
	user.OrganizationRefs = []uint64{12345, 67890}
	userData, _ := json.Marshal(user)
	mock.SetData("User", 1, userData)

	// Should find user for both orgs
	users1, err := dao.GetUsers(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, 1, len(users1))

	users2, err := dao.GetUsers(ctx, 67890)
	require.NoError(t, err)
	assert.Equal(t, 1, len(users2))
}

func TestOrganizationDAO_GetUsers_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage error")

	ctx := context.Background()
	_, err := dao.GetUsers(ctx, 12345)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage error")
}

func TestOrganizationDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Add organizations
	for i := 1; i <= 3; i++ {
		org := &entities.Organization{ID: uint64(i), Name: "Org"}
		require.NoError(t, dao.Save(ctx, org))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestOrganizationDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockOrganizationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Add organizations
	for i := 1; i <= 10; i++ {
		org := &entities.Organization{ID: uint64(i), Name: "Org"}
		require.NoError(t, dao.Save(ctx, org))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}
