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

func setupMockInvitationDAO(t *testing.T) (*InvitationDAO, *MockStorage) {
	mock := NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))

	logger := logging.DefaultLogger()
	dao := NewInvitationDAO(mock, logger, WithRequestTimeout(5*time.Second))

	return dao, mock
}

func createTestInvitation(t *testing.T, id uint64, tenantID, email, token string, status entities.InvitationStatus) *entities.Invitation {
	return &entities.Invitation{
		ID:          id,
		Token:       token,
		TenantID:    tenantID,
		Email:       email,
		Role:        "member",
		Status:      status,
		InvitedByID: 999,
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		CreatedAt:   time.Now(),
	}
}

func TestInvitationDAO_Save_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation, err := entities.NewInvitation("tenant-123", "user@example.com", "member", 999, 24*time.Hour)
	require.NoError(t, err)

	err = dao.Save(ctx, invitation)

	require.NoError(t, err)
	assert.NotZero(t, invitation.ID)
	assert.Equal(t, 1, mock.Count(entityTypeInvitation))
}

func TestInvitationDAO_Save_WithExistingID_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "test-token-123", entities.InvitationStatusPending)

	err := dao.Save(ctx, invitation)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), invitation.ID)
	assert.Equal(t, 1, mock.Count(entityTypeInvitation))
}

func TestInvitationDAO_Get_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "test-token-123", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	retrieved, err := dao.Get(ctx, 12345)

	require.NoError(t, err)
	assert.Equal(t, "user@example.com", retrieved.Email)
	assert.Equal(t, "tenant-123", retrieved.TenantID)
	assert.Equal(t, "test-token-123", retrieved.Token)
	assert.Equal(t, entities.InvitationStatusPending, retrieved.Status)
}

func TestInvitationDAO_Get_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	_, err := dao.Get(ctx, 99999)

	require.Error(t, err)
	var notFoundErr ErrNotFound
	assert.ErrorAs(t, err, &notFoundErr)
}

func TestInvitationDAO_Delete_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "test-token-123", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))
	assert.Equal(t, 1, mock.Count(entityTypeInvitation))

	err := dao.Delete(ctx, invitation)

	require.NoError(t, err)
	assert.Equal(t, 0, mock.Count(entityTypeInvitation))
}

func TestInvitationDAO_GetByToken_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	token := "unique-secure-token-abc123"
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", token, entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	retrieved, err := dao.GetByToken(ctx, token)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), retrieved.ID)
	assert.Equal(t, token, retrieved.Token)
	assert.Equal(t, "user@example.com", retrieved.Email)
}

func TestInvitationDAO_GetByToken_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "existing-token", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	// Force fallback to scan path so it validates the actual token value
	mock.QueryError = errors.New("secondary index not available")

	_, err := dao.GetByToken(ctx, "nonexistent-token")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "Token", notFoundErr.IndexField)
}

func TestInvitationDAO_GetByToken_NotFound_EmptyStorage_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	// Force fallback to scan path - no data exists
	mock.QueryError = errors.New("secondary index not available")

	_, err := dao.GetByToken(ctx, "nonexistent-token")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "Token", notFoundErr.IndexField)
}

func TestInvitationDAO_GetByToken_QueryFallback_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	token := "unique-secure-token-xyz789"
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", token, entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	// Force query to fail so it falls back to scan
	mock.QueryError = errors.New("secondary index not available")

	retrieved, err := dao.GetByToken(ctx, token)

	require.NoError(t, err)
	assert.Equal(t, token, retrieved.Token)
}

func TestInvitationDAO_GetByEmail_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	email := "invited@example.com"
	invitation := createTestInvitation(t, 12345, "tenant-123", email, "test-token", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	retrieved, err := dao.GetByEmail(ctx, email)

	require.NoError(t, err)
	assert.Equal(t, uint64(12345), retrieved.ID)
	assert.Equal(t, email, retrieved.Email)
	assert.Equal(t, "tenant-123", retrieved.TenantID)
}

func TestInvitationDAO_GetByEmail_NotFound_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "existing@example.com", "test-token", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	// Force fallback to scan path so it validates the actual email value
	mock.QueryError = errors.New("secondary index not available")

	_, err := dao.GetByEmail(ctx, "nonexistent@example.com")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "Email", notFoundErr.IndexField)
}

func TestInvitationDAO_GetByEmail_NotFound_EmptyStorage_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	// Force fallback to scan path - no data exists
	mock.QueryError = errors.New("secondary index not available")

	_, err := dao.GetByEmail(ctx, "nonexistent@example.com")

	require.Error(t, err)
	var notFoundErr ErrNotFoundByIndex
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, "Email", notFoundErr.IndexField)
}

func TestInvitationDAO_GetByEmail_QueryFallback_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	email := "fallback@example.com"
	invitation := createTestInvitation(t, 12345, "tenant-123", email, "test-token", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	// Force query to fail so it falls back to scan
	mock.QueryError = errors.New("secondary index not available")

	retrieved, err := dao.GetByEmail(ctx, email)

	require.NoError(t, err)
	assert.Equal(t, email, retrieved.Email)
}

func TestInvitationDAO_GetByTenant_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tenantID := "tenant-abc"

	// Create invitations for the target tenant
	inv1 := createTestInvitation(t, 1, tenantID, "user1@example.com", "token1", entities.InvitationStatusPending)
	inv2 := createTestInvitation(t, 2, tenantID, "user2@example.com", "token2", entities.InvitationStatusAccepted)
	inv3 := createTestInvitation(t, 3, tenantID, "user3@example.com", "token3", entities.InvitationStatusPending)

	// Create invitation for a different tenant
	inv4 := createTestInvitation(t, 4, "other-tenant", "other@example.com", "token4", entities.InvitationStatusPending)

	require.NoError(t, dao.Save(ctx, inv1))
	require.NoError(t, dao.Save(ctx, inv2))
	require.NoError(t, dao.Save(ctx, inv3))
	require.NoError(t, dao.Save(ctx, inv4))

	invitations, err := dao.GetByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, invitations, 3)

	emails := make(map[string]bool)
	for _, inv := range invitations {
		emails[inv.Email] = true
		assert.Equal(t, tenantID, inv.TenantID)
	}
	assert.True(t, emails["user1@example.com"])
	assert.True(t, emails["user2@example.com"])
	assert.True(t, emails["user3@example.com"])
}

func TestInvitationDAO_GetByTenant_Empty_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Create invitations for a different tenant
	inv1 := createTestInvitation(t, 1, "other-tenant", "other@example.com", "token1", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, inv1))

	invitations, err := dao.GetByTenant(ctx, "nonexistent-tenant")

	require.NoError(t, err)
	assert.Empty(t, invitations)
}

func TestInvitationDAO_GetByTenant_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.GetByTenant(ctx, "tenant-123")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestInvitationDAO_GetPendingByTenant_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tenantID := "tenant-abc"

	// Create pending invitations
	inv1 := createTestInvitation(t, 1, tenantID, "pending1@example.com", "token1", entities.InvitationStatusPending)
	inv2 := createTestInvitation(t, 2, tenantID, "pending2@example.com", "token2", entities.InvitationStatusPending)

	// Create accepted invitation (should not be returned)
	inv3 := createTestInvitation(t, 3, tenantID, "accepted@example.com", "token3", entities.InvitationStatusAccepted)

	// Create expired invitation (should not be returned)
	inv4 := createTestInvitation(t, 4, tenantID, "expired@example.com", "token4", entities.InvitationStatusExpired)

	// Create pending invitation for different tenant (should not be returned)
	inv5 := createTestInvitation(t, 5, "other-tenant", "other@example.com", "token5", entities.InvitationStatusPending)

	require.NoError(t, dao.Save(ctx, inv1))
	require.NoError(t, dao.Save(ctx, inv2))
	require.NoError(t, dao.Save(ctx, inv3))
	require.NoError(t, dao.Save(ctx, inv4))
	require.NoError(t, dao.Save(ctx, inv5))

	invitations, err := dao.GetPendingByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, invitations, 2)

	for _, inv := range invitations {
		assert.Equal(t, tenantID, inv.TenantID)
		assert.Equal(t, entities.InvitationStatusPending, inv.Status)
	}
}

func TestInvitationDAO_GetPendingByTenant_Empty_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tenantID := "tenant-abc"

	// Create only accepted invitations for the tenant
	inv1 := createTestInvitation(t, 1, tenantID, "accepted@example.com", "token1", entities.InvitationStatusAccepted)
	inv2 := createTestInvitation(t, 2, tenantID, "expired@example.com", "token2", entities.InvitationStatusExpired)
	require.NoError(t, dao.Save(ctx, inv1))
	require.NoError(t, dao.Save(ctx, inv2))

	invitations, err := dao.GetPendingByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Empty(t, invitations)
}

func TestInvitationDAO_GetPendingByTenant_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.GetPendingByTenant(ctx, "tenant-123")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestInvitationDAO_Count_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := uint64(1); i <= 5; i++ {
		inv := createTestInvitation(t, i, "tenant-123", "user@example.com", "token-"+string(rune('0'+i)), entities.InvitationStatusPending)
		require.NoError(t, dao.Save(ctx, inv))
	}

	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 5, count)
}

func TestInvitationDAO_Count_Empty_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	count, err := dao.Count(ctx)

	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestInvitationDAO_Count_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Count(ctx)

	require.Error(t, err)
}

func TestInvitationDAO_Page_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := uint64(1); i <= 10; i++ {
		inv := createTestInvitation(t, i, "tenant-123", "user@example.com", "token-"+string(rune('a'+i)), entities.InvitationStatusPending)
		require.NoError(t, dao.Save(ctx, inv))
	}

	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 5, len(result.Entities))
	assert.True(t, result.HasMore)
}

func TestInvitationDAO_Page_LastPage_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := uint64(1); i <= 7; i++ {
		inv := createTestInvitation(t, i, "tenant-123", "user@example.com", "token-"+string(rune('a'+i)), entities.InvitationStatusPending)
		require.NoError(t, dao.Save(ctx, inv))
	}

	query := datastore.PageQuery{Page: 2, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Equal(t, 2, len(result.Entities))
	assert.False(t, result.HasMore)
}

func TestInvitationDAO_Page_EmptyResult_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	result, err := dao.Page(ctx, query)

	require.NoError(t, err)
	assert.Empty(t, result.Entities)
	assert.False(t, result.HasMore)
}

func TestInvitationDAO_Page_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	mock.ListError = errors.New("storage unavailable")

	ctx := context.Background()
	query := datastore.PageQuery{Page: 1, PageSize: 5}
	_, err := dao.Page(ctx, query)

	require.Error(t, err)
}

func TestInvitationDAO_Save_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	mock.PutError = errors.New("storage unavailable")

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "test-token", entities.InvitationStatusPending)
	err := dao.Save(ctx, invitation)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestInvitationDAO_Get_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	// First save an invitation
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "test-token", entities.InvitationStatusPending)
	data, _ := json.Marshal(invitation)
	mock.SetData(entityTypeInvitation, 12345, data)

	// Then set error for Get
	mock.GetError = errors.New("storage unavailable")

	ctx := context.Background()
	_, err := dao.Get(ctx, 12345)

	require.Error(t, err)
}

func TestInvitationDAO_Delete_StorageError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	mock.DeleteError = errors.New("storage unavailable")

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "test-token", entities.InvitationStatusPending)
	err := dao.Delete(ctx, invitation)

	require.Error(t, err)
}

func TestInvitationDAO_Update_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", "test-token", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	// Update invitation status
	invitation.Status = entities.InvitationStatusAccepted
	now := time.Now()
	invitation.AcceptedAt = &now
	require.NoError(t, dao.Save(ctx, invitation))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)
	assert.Equal(t, entities.InvitationStatusAccepted, retrieved.Status)
	assert.NotNil(t, retrieved.AcceptedAt)
}

func TestInvitationDAO_ForEachPage_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := uint64(1); i <= 8; i++ {
		inv := createTestInvitation(t, i, "tenant-123", "user@example.com", "token-"+string(rune('a'+i)), entities.InvitationStatusPending)
		require.NoError(t, dao.Save(ctx, inv))
	}

	var allInvitations []*entities.Invitation
	processor := func(result datastore.PageResult[*entities.Invitation]) error {
		allInvitations = append(allInvitations, result.Entities...)
		return nil
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.NoError(t, err)
	assert.Equal(t, 8, len(allInvitations))
}

func TestInvitationDAO_ForEachPage_ProcessorError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	for i := uint64(1); i <= 5; i++ {
		inv := createTestInvitation(t, i, "tenant-123", "user@example.com", "token-"+string(rune('a'+i)), entities.InvitationStatusPending)
		require.NoError(t, dao.Save(ctx, inv))
	}

	expectedErr := errors.New("processor error")
	processor := func(result datastore.PageResult[*entities.Invitation]) error {
		return expectedErr
	}

	query := datastore.PageQuery{Page: 1, PageSize: 3}
	err := dao.ForEachPage(ctx, query, processor)

	require.ErrorIs(t, err, expectedErr)
}

func TestInvitationDAO_ComplexInvitation_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	invitation := &entities.Invitation{
		ID:          12345,
		Token:       "complex-secure-token-xyz",
		TenantID:    "tenant-complex",
		Email:       "complex@example.com",
		Role:        "admin",
		Status:      entities.InvitationStatusPending,
		InvitedByID: 999,
		ExpiresAt:   time.Now().Add(48 * time.Hour),
		CreatedAt:   time.Now(),
	}

	require.NoError(t, dao.Save(ctx, invitation))

	retrieved, err := dao.Get(ctx, 12345)
	require.NoError(t, err)

	assert.Equal(t, "complex@example.com", retrieved.Email)
	assert.Equal(t, "tenant-complex", retrieved.TenantID)
	assert.Equal(t, "complex-secure-token-xyz", retrieved.Token)
	assert.Equal(t, "admin", retrieved.Role)
	assert.Equal(t, uint64(999), retrieved.InvitedByID)
	assert.Equal(t, entities.InvitationStatusPending, retrieved.Status)
}

func TestInvitationDAO_GetByToken_EmptyQueryResult_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	token := "unique-token-for-empty-query"
	invitation := createTestInvitation(t, 12345, "tenant-123", "user@example.com", token, entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	// MockStorage.Query returns all entities for the type, but we can test the fallback path
	// by checking that the method works correctly even with the scan fallback
	retrieved, err := dao.GetByToken(ctx, token)

	require.NoError(t, err)
	assert.Equal(t, token, retrieved.Token)
}

func TestInvitationDAO_GetByEmail_EmptyQueryResult_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	email := "unique@example.com"
	invitation := createTestInvitation(t, 12345, "tenant-123", email, "test-token", entities.InvitationStatusPending)
	require.NoError(t, dao.Save(ctx, invitation))

	retrieved, err := dao.GetByEmail(ctx, email)

	require.NoError(t, err)
	assert.Equal(t, email, retrieved.Email)
}

func TestInvitationDAO_GetByTenant_MultiplePages_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tenantID := "tenant-large"

	// Create many invitations to potentially trigger pagination
	for i := uint64(1); i <= 15; i++ {
		inv := createTestInvitation(t, i, tenantID, "user@example.com", "token-"+string(rune('a'+i)), entities.InvitationStatusPending)
		require.NoError(t, dao.Save(ctx, inv))
	}

	invitations, err := dao.GetByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, invitations, 15)
}

func TestInvitationDAO_GetPendingByTenant_AllStatuses_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()
	tenantID := "tenant-statuses"

	// Create invitations with all possible statuses
	pending := createTestInvitation(t, 1, tenantID, "pending@example.com", "token1", entities.InvitationStatusPending)
	accepted := createTestInvitation(t, 2, tenantID, "accepted@example.com", "token2", entities.InvitationStatusAccepted)
	expired := createTestInvitation(t, 3, tenantID, "expired@example.com", "token3", entities.InvitationStatusExpired)
	revoked := createTestInvitation(t, 4, tenantID, "revoked@example.com", "token4", entities.InvitationStatusRevoked)

	require.NoError(t, dao.Save(ctx, pending))
	require.NoError(t, dao.Save(ctx, accepted))
	require.NoError(t, dao.Save(ctx, expired))
	require.NoError(t, dao.Save(ctx, revoked))

	invitations, err := dao.GetPendingByTenant(ctx, tenantID)

	require.NoError(t, err)
	assert.Len(t, invitations, 1)
	assert.Equal(t, "pending@example.com", invitations[0].Email)
	assert.Equal(t, entities.InvitationStatusPending, invitations[0].Status)
}

func TestInvitationDAO_GetByToken_StorageListError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Force query to fail so it falls back to scan
	mock.QueryError = errors.New("secondary index not available")
	// Then make the scan fail too
	mock.ListError = errors.New("storage unavailable")

	_, err := dao.GetByToken(ctx, "some-token")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}

func TestInvitationDAO_GetByEmail_StorageListError_Mock(t *testing.T) {
	dao, mock := setupMockInvitationDAO(t)
	defer mock.Stop(context.Background())

	ctx := context.Background()

	// Force query to fail so it falls back to scan
	mock.QueryError = errors.New("secondary index not available")
	// Then make the scan fail too
	mock.ListError = errors.New("storage unavailable")

	_, err := dao.GetByEmail(ctx, "user@example.com")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage unavailable")
}
