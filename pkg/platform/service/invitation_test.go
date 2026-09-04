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

package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockInvitationDAO implements datastore.InvitationDAO for testing.
type MockInvitationDAO struct {
	mock.Mock
}

func (m *MockInvitationDAO) Save(ctx context.Context, invitation *entities.Invitation) error {
	args := m.Called(ctx, invitation)
	return args.Error(0)
}

func (m *MockInvitationDAO) Get(ctx context.Context, id uint64) (*entities.Invitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationDAO) Delete(ctx context.Context, invitation *entities.Invitation) error {
	args := m.Called(ctx, invitation)
	return args.Error(0)
}

func (m *MockInvitationDAO) GetByToken(ctx context.Context, token string) (*entities.Invitation, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationDAO) GetByEmail(ctx context.Context, email string) (*entities.Invitation, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationDAO) GetByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Invitation), args.Error(1)
}

func (m *MockInvitationDAO) GetPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Invitation), args.Error(1)
}

func (m *MockInvitationDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockInvitationDAO) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Invitation], error) {
	args := m.Called(ctx, pageQuery)
	return args.Get(0).(datastore.PageResult[*entities.Invitation]), args.Error(1)
}

func (m *MockInvitationDAO) ForEachPage(ctx context.Context, pageQuery datastore.PageQuery, fn datastore.PagerFunc[*entities.Invitation]) error {
	args := m.Called(ctx, pageQuery, fn)
	return args.Error(0)
}

// MockUserDAO implements datastore.UserDAO for testing.
type MockUserDAO struct {
	mock.Mock
}

func (m *MockUserDAO) Save(ctx context.Context, user *entities.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserDAO) Get(ctx context.Context, id uint64) (*entities.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *MockUserDAO) Delete(ctx context.Context, user *entities.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserDAO) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *MockUserDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockUserDAO) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.User], error) {
	args := m.Called(ctx, pageQuery)
	return args.Get(0).(datastore.PageResult[*entities.User]), args.Error(1)
}

func (m *MockUserDAO) ForEachPage(ctx context.Context, pageQuery datastore.PageQuery, fn datastore.PagerFunc[*entities.User]) error {
	args := m.Called(ctx, pageQuery, fn)
	return args.Error(0)
}

// TestNewInvitationService verifies the constructor creates a valid service.
func TestNewInvitationService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)

	require.NotNil(t, service)
	assert.IsType(t, &InvitationService{}, service)

	// Verify default expiry is set
	assert.Equal(t, DefaultInvitationExpiry, service.defaultExpiry)
}

// TestNewInvitationServiceWithExpiry verifies custom expiry configuration.
func TestNewInvitationServiceWithExpiry(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	t.Run("CustomExpiry", func(t *testing.T) {
		customExpiry := 14 * 24 * time.Hour
		service := NewInvitationServiceWithExpiry(logger, mockInvDAO, mockUserDAO, customExpiry)

		require.NotNil(t, service)
		assert.Equal(t, customExpiry, service.defaultExpiry)
	})

	t.Run("ZeroExpiryFallsBackToDefault", func(t *testing.T) {
		service := NewInvitationServiceWithExpiry(logger, mockInvDAO, mockUserDAO, 0)

		require.NotNil(t, service)
		assert.Equal(t, DefaultInvitationExpiry, service.defaultExpiry)
	})

	t.Run("NegativeExpiryFallsBackToDefault", func(t *testing.T) {
		service := NewInvitationServiceWithExpiry(logger, mockInvDAO, mockUserDAO, -5*time.Hour)

		require.NotNil(t, service)
		assert.Equal(t, DefaultInvitationExpiry, service.defaultExpiry)
	})
}

// TestInvitationService_Create_Success verifies successful invitation creation.
func TestInvitationService_Create_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	email := "newuser@example.com"
	role := "member"
	invitedByID := uint64(1)

	// Mock user check - no user exists with this email
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			result := datastore.PageResult[*entities.User]{
				Entities: []*entities.User{},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.Create(ctx, &CreateInvitationRequest{
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		InvitedByID: invitedByID,
	})

	require.NoError(t, err)
	require.NotNil(t, invitation)
	assert.Equal(t, tenantID, invitation.TenantID)
	assert.Equal(t, email, invitation.Email)
	assert.Equal(t, role, invitation.Role)
	assert.Equal(t, invitedByID, invitation.InvitedByID)
	assert.Equal(t, entities.InvitationStatusPending, invitation.Status)
	assert.NotEmpty(t, invitation.Token)
	assert.False(t, invitation.ExpiresAt.IsZero())
	mockInvDAO.AssertExpectations(t)
	mockUserDAO.AssertExpectations(t)
}

// TestInvitationService_Create_DAOError verifies error handling when DAO save fails.
func TestInvitationService_Create_DAOError(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	email := "newuser@example.com"
	role := "member"
	invitedByID := uint64(1)

	// Mock user check - no user exists with this email
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			result := datastore.PageResult[*entities.User]{
				Entities: []*entities.User{},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	expectedErr := errors.New("database connection failed")
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.Create(ctx, &CreateInvitationRequest{
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		InvitedByID: invitedByID,
	})

	require.Error(t, err)
	assert.Nil(t, invitation)
	var saveFailed ErrInvitationSaveFailed
	assert.True(t, errors.As(err, &saveFailed))
	assert.Equal(t, expectedErr, saveFailed.Cause)
	mockInvDAO.AssertExpectations(t)
	mockUserDAO.AssertExpectations(t)
}

// TestInvitationService_Create_EmailAlreadyRegistered verifies error when email exists.
func TestInvitationService_Create_EmailAlreadyRegistered(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	email := "existing@example.com"
	role := "member"
	invitedByID := uint64(1)

	// Mock user check - user already exists with this email in tenant
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			result := datastore.PageResult[*entities.User]{
				Entities: []*entities.User{
					{ID: 1, Email: email, TenantID: tenantID},
				},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(datastore.ErrStopIteration)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.Create(ctx, &CreateInvitationRequest{
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		InvitedByID: invitedByID,
	})

	require.Error(t, err)
	assert.Nil(t, invitation)
	var alreadyRegistered ErrEmailAlreadyRegistered
	assert.True(t, errors.As(err, &alreadyRegistered))
	assert.Equal(t, email, alreadyRegistered.Email)
	assert.Equal(t, tenantID, alreadyRegistered.TenantID)
	mockUserDAO.AssertExpectations(t)
}

// TestInvitationService_Create_InvalidRequest verifies validation errors.
func TestInvitationService_Create_InvalidRequest(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)

	t.Run("NilRequest", func(t *testing.T) {
		invitation, err := service.Create(ctx, nil)
		require.Error(t, err)
		assert.Nil(t, invitation)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})

	t.Run("EmptyTenantID", func(t *testing.T) {
		invitation, err := service.Create(ctx, &CreateInvitationRequest{
			Email:       "test@example.com",
			Role:        "member",
			InvitedByID: 1,
		})
		require.Error(t, err)
		assert.Nil(t, invitation)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})

	t.Run("EmptyEmail", func(t *testing.T) {
		invitation, err := service.Create(ctx, &CreateInvitationRequest{
			TenantID:    "tenant-123",
			Role:        "member",
			InvitedByID: 1,
		})
		require.Error(t, err)
		assert.Nil(t, invitation)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})

	t.Run("EmptyRole", func(t *testing.T) {
		invitation, err := service.Create(ctx, &CreateInvitationRequest{
			TenantID:    "tenant-123",
			Email:       "test@example.com",
			InvitedByID: 1,
		})
		require.Error(t, err)
		assert.Nil(t, invitation)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})

	t.Run("ZeroInvitedByID", func(t *testing.T) {
		invitation, err := service.Create(ctx, &CreateInvitationRequest{
			TenantID: "tenant-123",
			Email:    "test@example.com",
			Role:     "member",
		})
		require.Error(t, err)
		assert.Nil(t, invitation)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})
}

// TestInvitationService_GetByToken_Success verifies successful token lookup.
func TestInvitationService_GetByToken_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "valid-token-123"
	expectedInvitation := &entities.Invitation{
		ID:        1,
		Token:     token,
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	mockInvDAO.On("GetByToken", ctx, token).Return(expectedInvitation, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.GetByToken(ctx, token)

	require.NoError(t, err)
	require.NotNil(t, invitation)
	assert.Equal(t, expectedInvitation.ID, invitation.ID)
	assert.Equal(t, token, invitation.Token)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_GetByToken_NotFound verifies error when token not found.
func TestInvitationService_GetByToken_NotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "nonexistent-token"
	mockInvDAO.On("GetByToken", ctx, token).Return(nil, datastore.ErrRecordNotFound)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.GetByToken(ctx, token)

	require.Error(t, err)
	assert.Nil(t, invitation)
	var notFound ErrInvitationNotFound
	assert.True(t, errors.As(err, &notFound))
	assert.Equal(t, token, notFound.Token)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_GetByToken_Expired verifies error when invitation expired.
func TestInvitationService_GetByToken_Expired(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "expired-token"
	expiredInvitation := &entities.Invitation{
		ID:        1,
		Token:     token,
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(-24 * time.Hour), // Expired
	}

	mockInvDAO.On("GetByToken", ctx, token).Return(expiredInvitation, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.GetByToken(ctx, token)

	require.Error(t, err)
	assert.Nil(t, invitation)
	var expired ErrInvitationExpired
	assert.True(t, errors.As(err, &expired))
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_GetByToken_EmptyToken verifies error for empty token.
func TestInvitationService_GetByToken_EmptyToken(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.GetByToken(ctx, "")

	require.Error(t, err)
	assert.Nil(t, invitation)
	var invalid ErrInvalidInvitation
	assert.True(t, errors.As(err, &invalid))
}

// TestInvitationService_GetByID_Success verifies successful ID lookup.
func TestInvitationService_GetByID_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(1)
	expectedInvitation := &entities.Invitation{
		ID:       invitationID,
		Token:    "some-token",
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Role:     "member",
		Status:   entities.InvitationStatusPending,
	}

	mockInvDAO.On("Get", ctx, invitationID).Return(expectedInvitation, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.GetByID(ctx, invitationID)

	require.NoError(t, err)
	require.NotNil(t, invitation)
	assert.Equal(t, invitationID, invitation.ID)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_GetByID_NotFound verifies error when ID not found.
func TestInvitationService_GetByID_NotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(999)
	mockInvDAO.On("Get", ctx, invitationID).Return(nil, datastore.ErrRecordNotFound)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.GetByID(ctx, invitationID)

	require.Error(t, err)
	assert.Nil(t, invitation)
	var notFound ErrInvitationNotFound
	assert.True(t, errors.As(err, &notFound))
	assert.Equal(t, invitationID, notFound.ID)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_GetByID_ZeroID verifies error for zero ID.
func TestInvitationService_GetByID_ZeroID(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.GetByID(ctx, 0)

	require.Error(t, err)
	assert.Nil(t, invitation)
	var invalid ErrInvalidInvitation
	assert.True(t, errors.As(err, &invalid))
}

// TestInvitationService_Accept_Success verifies successful invitation acceptance.
func TestInvitationService_Accept_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "valid-token-123"
	userID := uint64(42)
	pendingInvitation := &entities.Invitation{
		ID:        1,
		Token:     token,
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour), // Not expired
	}

	mockInvDAO.On("GetByToken", ctx, token).Return(pendingInvitation, nil)
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Accept(ctx, token, userID)

	require.NoError(t, err)
	assert.Equal(t, entities.InvitationStatusAccepted, pendingInvitation.Status)
	assert.NotNil(t, pendingInvitation.AcceptedAt)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Accept_NotFound verifies error when invitation not found.
func TestInvitationService_Accept_NotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "nonexistent-token"
	userID := uint64(42)
	mockInvDAO.On("GetByToken", ctx, token).Return(nil, datastore.ErrRecordNotFound)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Accept(ctx, token, userID)

	require.Error(t, err)
	var notFound ErrInvitationNotFound
	assert.True(t, errors.As(err, &notFound))
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Accept_AlreadyAccepted verifies error for already accepted invitation.
func TestInvitationService_Accept_AlreadyAccepted(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "accepted-token"
	userID := uint64(42)
	acceptedInvitation := &entities.Invitation{
		ID:       1,
		Token:    token,
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Role:     "member",
		Status:   entities.InvitationStatusAccepted,
	}

	mockInvDAO.On("GetByToken", ctx, token).Return(acceptedInvitation, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Accept(ctx, token, userID)

	require.Error(t, err)
	var alreadyAccepted ErrInvitationAlreadyAccepted
	assert.True(t, errors.As(err, &alreadyAccepted))
	assert.Equal(t, token, alreadyAccepted.Token)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Accept_AlreadyRevoked verifies error for revoked invitation.
func TestInvitationService_Accept_AlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "revoked-token"
	userID := uint64(42)
	revokedInvitation := &entities.Invitation{
		ID:       1,
		Token:    token,
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Role:     "member",
		Status:   entities.InvitationStatusRevoked,
	}

	mockInvDAO.On("GetByToken", ctx, token).Return(revokedInvitation, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Accept(ctx, token, userID)

	require.Error(t, err)
	var alreadyRevoked ErrInvitationAlreadyRevoked
	assert.True(t, errors.As(err, &alreadyRevoked))
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Accept_Expired verifies error for expired invitation.
func TestInvitationService_Accept_Expired(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	t.Run("StatusAlreadyExpired", func(t *testing.T) {
		token := "expired-token"
		userID := uint64(42)
		expiredInvitation := &entities.Invitation{
			ID:        1,
			Token:     token,
			TenantID:  "tenant-123",
			Email:     "user@example.com",
			Role:      "member",
			Status:    entities.InvitationStatusExpired,
			ExpiresAt: time.Now().UTC().Add(-24 * time.Hour),
		}

		mockInvDAO.On("GetByToken", ctx, token).Return(expiredInvitation, nil)

		service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
		err := service.Accept(ctx, token, userID)

		require.Error(t, err)
		var expired ErrInvitationExpired
		assert.True(t, errors.As(err, &expired))
		mockInvDAO.AssertExpectations(t)
	})

	t.Run("PendingButTimeExpired", func(t *testing.T) {
		mockInvDAO2 := new(MockInvitationDAO)
		token := "pending-but-expired-token"
		userID := uint64(42)
		pendingExpiredInvitation := &entities.Invitation{
			ID:        2,
			Token:     token,
			TenantID:  "tenant-123",
			Email:     "user@example.com",
			Role:      "member",
			Status:    entities.InvitationStatusPending,
			ExpiresAt: time.Now().UTC().Add(-24 * time.Hour), // Expired
		}

		mockInvDAO2.On("GetByToken", ctx, token).Return(pendingExpiredInvitation, nil)
		// Service will try to update status to expired
		mockInvDAO2.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(nil)

		service := NewInvitationService(logger, mockInvDAO2, mockUserDAO)
		err := service.Accept(ctx, token, userID)

		require.Error(t, err)
		var expired ErrInvitationExpired
		assert.True(t, errors.As(err, &expired))
		mockInvDAO2.AssertExpectations(t)
	})
}

// TestInvitationService_Accept_InvalidInput verifies validation errors.
func TestInvitationService_Accept_InvalidInput(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)

	t.Run("EmptyToken", func(t *testing.T) {
		err := service.Accept(ctx, "", 42)
		require.Error(t, err)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})

	t.Run("ZeroUserID", func(t *testing.T) {
		err := service.Accept(ctx, "valid-token", 0)
		require.Error(t, err)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})
}

// TestInvitationService_Accept_SaveFails verifies error handling when save fails.
func TestInvitationService_Accept_SaveFails(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	token := "valid-token-123"
	userID := uint64(42)
	pendingInvitation := &entities.Invitation{
		ID:        1,
		Token:     token,
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	expectedErr := errors.New("database error")
	mockInvDAO.On("GetByToken", ctx, token).Return(pendingInvitation, nil)
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Accept(ctx, token, userID)

	require.Error(t, err)
	var saveFailed ErrInvitationSaveFailed
	assert.True(t, errors.As(err, &saveFailed))
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Revoke_Success verifies successful invitation revocation.
func TestInvitationService_Revoke_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(1)
	revokerID := uint64(10)
	pendingInvitation := &entities.Invitation{
		ID:       invitationID,
		Token:    "some-token",
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Role:     "member",
		Status:   entities.InvitationStatusPending,
	}

	mockInvDAO.On("Get", ctx, invitationID).Return(pendingInvitation, nil)
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Revoke(ctx, invitationID, revokerID)

	require.NoError(t, err)
	assert.Equal(t, entities.InvitationStatusRevoked, pendingInvitation.Status)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Revoke_NotFound verifies error when invitation not found.
func TestInvitationService_Revoke_NotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(999)
	revokerID := uint64(10)
	mockInvDAO.On("Get", ctx, invitationID).Return(nil, datastore.ErrRecordNotFound)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Revoke(ctx, invitationID, revokerID)

	require.Error(t, err)
	var notFound ErrInvitationNotFound
	assert.True(t, errors.As(err, &notFound))
	assert.Equal(t, invitationID, notFound.ID)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Revoke_AlreadyRevoked verifies error when already revoked.
func TestInvitationService_Revoke_AlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(1)
	revokerID := uint64(10)
	revokedInvitation := &entities.Invitation{
		ID:       invitationID,
		Token:    "some-token",
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Role:     "member",
		Status:   entities.InvitationStatusRevoked,
	}

	mockInvDAO.On("Get", ctx, invitationID).Return(revokedInvitation, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Revoke(ctx, invitationID, revokerID)

	require.Error(t, err)
	var alreadyRevoked ErrInvitationAlreadyRevoked
	assert.True(t, errors.As(err, &alreadyRevoked))
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Revoke_NotPending verifies error when revoking non-pending invitation.
func TestInvitationService_Revoke_NotPending(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)

	testCases := []struct {
		name   string
		status entities.InvitationStatus
	}{
		{"AlreadyAccepted", entities.InvitationStatusAccepted},
		{"AlreadyExpired", entities.InvitationStatusExpired},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockInvDAO := new(MockInvitationDAO)
			mockUserDAO := new(MockUserDAO)
			invitationID := uint64(1)
			revokerID := uint64(10)
			invitation := &entities.Invitation{
				ID:       invitationID,
				Token:    "some-token",
				TenantID: "tenant-123",
				Email:    "user@example.com",
				Role:     "member",
				Status:   tc.status,
			}

			mockInvDAO.On("Get", ctx, invitationID).Return(invitation, nil)

			service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
			err := service.Revoke(ctx, invitationID, revokerID)

			require.Error(t, err)
			var invalid ErrInvalidInvitation
			assert.True(t, errors.As(err, &invalid))
			mockInvDAO.AssertExpectations(t)
		})
	}
}

// TestInvitationService_Revoke_InvalidInput verifies validation errors.
func TestInvitationService_Revoke_InvalidInput(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)

	t.Run("ZeroInvitationID", func(t *testing.T) {
		err := service.Revoke(ctx, 0, 10)
		require.Error(t, err)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})

	t.Run("ZeroRevokerID", func(t *testing.T) {
		err := service.Revoke(ctx, 1, 0)
		require.Error(t, err)
		var invalid ErrInvalidInvitation
		assert.True(t, errors.As(err, &invalid))
	})
}

// TestInvitationService_Revoke_SaveFails verifies error handling when save fails.
func TestInvitationService_Revoke_SaveFails(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(1)
	revokerID := uint64(10)
	pendingInvitation := &entities.Invitation{
		ID:       invitationID,
		Token:    "some-token",
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Role:     "member",
		Status:   entities.InvitationStatusPending,
	}

	expectedErr := errors.New("database error")
	mockInvDAO.On("Get", ctx, invitationID).Return(pendingInvitation, nil)
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Revoke(ctx, invitationID, revokerID)

	require.Error(t, err)
	var saveFailed ErrInvitationSaveFailed
	assert.True(t, errors.As(err, &saveFailed))
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_ListByTenant_Success verifies listing all invitations for a tenant.
func TestInvitationService_ListByTenant_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	expectedInvitations := []*entities.Invitation{
		{ID: 1, TenantID: tenantID, Email: "user1@example.com", Status: entities.InvitationStatusPending},
		{ID: 2, TenantID: tenantID, Email: "user2@example.com", Status: entities.InvitationStatusAccepted},
		{ID: 3, TenantID: tenantID, Email: "user3@example.com", Status: entities.InvitationStatusRevoked},
	}

	mockInvDAO.On("GetByTenant", ctx, tenantID).Return(expectedInvitations, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitations, err := service.ListByTenant(ctx, tenantID)

	require.NoError(t, err)
	require.NotNil(t, invitations)
	assert.Len(t, invitations, 3)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_ListByTenant_EmptyTenantID verifies error for empty tenant ID.
func TestInvitationService_ListByTenant_EmptyTenantID(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitations, err := service.ListByTenant(ctx, "")

	require.Error(t, err)
	assert.Nil(t, invitations)
	var invalid ErrInvalidInvitation
	assert.True(t, errors.As(err, &invalid))
}

// TestInvitationService_ListPendingByTenant_Success verifies listing pending invitations.
func TestInvitationService_ListPendingByTenant_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	expectedInvitations := []*entities.Invitation{
		{ID: 1, TenantID: tenantID, Email: "user1@example.com", Status: entities.InvitationStatusPending},
		{ID: 4, TenantID: tenantID, Email: "user4@example.com", Status: entities.InvitationStatusPending},
	}

	mockInvDAO.On("GetPendingByTenant", ctx, tenantID).Return(expectedInvitations, nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitations, err := service.ListPendingByTenant(ctx, tenantID)

	require.NoError(t, err)
	require.NotNil(t, invitations)
	assert.Len(t, invitations, 2)
	for _, inv := range invitations {
		assert.Equal(t, entities.InvitationStatusPending, inv.Status)
	}
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_ListPendingByTenant_EmptyTenantID verifies error for empty tenant ID.
func TestInvitationService_ListPendingByTenant_EmptyTenantID(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitations, err := service.ListPendingByTenant(ctx, "")

	require.Error(t, err)
	assert.Nil(t, invitations)
	var invalid ErrInvalidInvitation
	assert.True(t, errors.As(err, &invalid))
}

// TestInvitationService_CleanupExpired_Success verifies expired invitations are marked.
func TestInvitationService_CleanupExpired_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	expiredInvitation := &entities.Invitation{
		ID:        1,
		Token:     "expired-token",
		TenantID:  "tenant-123",
		Email:     "user1@example.com",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(-24 * time.Hour), // Expired
	}

	notExpiredInvitation := &entities.Invitation{
		ID:        2,
		Token:     "valid-token",
		TenantID:  "tenant-123",
		Email:     "user2@example.com",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour), // Not expired
	}

	alreadyAcceptedInvitation := &entities.Invitation{
		ID:        3,
		Token:     "accepted-token",
		TenantID:  "tenant-123",
		Email:     "user3@example.com",
		Status:    entities.InvitationStatusAccepted,
		ExpiresAt: time.Now().UTC().Add(-48 * time.Hour), // Would be expired but already accepted
	}

	// Set up ForEachPage to call the callback with our test data
	mockInvDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.Invitation])
			result := datastore.PageResult[*entities.Invitation]{
				Entities: []*entities.Invitation{expiredInvitation, notExpiredInvitation, alreadyAcceptedInvitation},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	// Only the expired pending invitation should be saved
	mockInvDAO.On("Save", ctx, expiredInvitation).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	count, err := service.CleanupExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, entities.InvitationStatusExpired, expiredInvitation.Status)
	// The not-expired one should still be pending
	assert.Equal(t, entities.InvitationStatusPending, notExpiredInvitation.Status)
	// The accepted one should remain accepted
	assert.Equal(t, entities.InvitationStatusAccepted, alreadyAcceptedInvitation.Status)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_CleanupExpired_NoExpiredInvitations verifies no changes when nothing expired.
func TestInvitationService_CleanupExpired_NoExpiredInvitations(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	validInvitation := &entities.Invitation{
		ID:        1,
		Token:     "valid-token",
		TenantID:  "tenant-123",
		Email:     "user1@example.com",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}

	mockInvDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.Invitation])
			result := datastore.PageResult[*entities.Invitation]{
				Entities: []*entities.Invitation{validInvitation},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	count, err := service.CleanupExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Equal(t, entities.InvitationStatusPending, validInvitation.Status)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_CleanupExpired_DAOError verifies error handling during cleanup.
func TestInvitationService_CleanupExpired_DAOError(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	expectedErr := errors.New("database error during pagination")
	mockInvDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Return(expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	count, err := service.CleanupExpired(ctx)

	require.Error(t, err)
	assert.Equal(t, 0, count)
	// Error is returned directly, not wrapped
	assert.Equal(t, expectedErr, err)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Delete_Success verifies successful invitation deletion.
func TestInvitationService_Delete_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(1)
	invitation := &entities.Invitation{
		ID:       invitationID,
		Token:    "some-token",
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Role:     "member",
		Status:   entities.InvitationStatusPending,
	}

	mockInvDAO.On("Get", ctx, invitationID).Return(invitation, nil)
	mockInvDAO.On("Delete", ctx, invitation).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Delete(ctx, invitationID)

	require.NoError(t, err)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Delete_NotFound verifies error when invitation not found.
func TestInvitationService_Delete_NotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(999)
	mockInvDAO.On("Get", ctx, invitationID).Return(nil, datastore.ErrRecordNotFound)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Delete(ctx, invitationID)

	require.Error(t, err)
	var notFound ErrInvitationNotFound
	assert.True(t, errors.As(err, &notFound))
	assert.Equal(t, invitationID, notFound.ID)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Delete_ZeroID verifies error for zero ID.
func TestInvitationService_Delete_ZeroID(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Delete(ctx, 0)

	require.Error(t, err)
	var invalid ErrInvalidInvitation
	assert.True(t, errors.As(err, &invalid))
}

// TestInvitationService_ErrInvitationSaveFailed_Error verifies error message formatting.
func TestInvitationService_ErrInvitationSaveFailed_Error(t *testing.T) {
	t.Run("WithCause", func(t *testing.T) {
		cause := errors.New("database error")
		err := ErrInvitationSaveFailed{Cause: cause}
		assert.Equal(t, "invitation save failed: database error", err.Error())
	})

	t.Run("WithoutCause", func(t *testing.T) {
		err := ErrInvitationSaveFailed{}
		assert.Equal(t, "invitation save failed", err.Error())
	})
}

// TestInvitationService_ErrInvitationSaveFailed_Unwrap verifies error unwrapping.
func TestInvitationService_ErrInvitationSaveFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := ErrInvitationSaveFailed{Cause: cause}
	assert.Equal(t, cause, err.Unwrap())
}

// TestInvitationService_ErrEmailAlreadyRegistered_Error verifies error message formatting.
func TestInvitationService_ErrEmailAlreadyRegistered_Error(t *testing.T) {
	err := ErrEmailAlreadyRegistered{Email: "test@example.com", TenantID: "tenant-123"}
	assert.Contains(t, err.Error(), "test@example.com")
	assert.Contains(t, err.Error(), "tenant-123")
}

// TestInvitationService_ErrInvalidInvitationStatus_Error verifies error message formatting.
func TestInvitationService_ErrInvalidInvitationStatus_Error(t *testing.T) {
	err := ErrInvalidInvitationStatus{Status: "unknown"}
	assert.Contains(t, err.Error(), "unknown")
}

// TestInvitationService_ErrInvitationAlreadyRevoked_Error verifies error message formatting.
func TestInvitationService_ErrInvitationAlreadyRevoked_Error(t *testing.T) {
	t.Run("WithToken", func(t *testing.T) {
		err := ErrInvitationAlreadyRevoked{Token: "test-token"}
		assert.Contains(t, err.Error(), "test-token")
	})

	t.Run("WithID", func(t *testing.T) {
		err := ErrInvitationAlreadyRevoked{ID: 123}
		assert.Contains(t, err.Error(), "123")
	})
}

// TestErrorTypes_Error verifies all error type Error() methods
func TestErrorTypes_Error(t *testing.T) {
	t.Run("ErrInvitationNotFound_WithToken", func(t *testing.T) {
		err := ErrInvitationNotFound{Token: "abc123"}
		assert.Equal(t, "invitation not found: token=abc123", err.Error())
	})

	t.Run("ErrInvitationNotFound_WithID", func(t *testing.T) {
		err := ErrInvitationNotFound{ID: 42}
		assert.Equal(t, "invitation not found: id=42", err.Error())
	})

	t.Run("ErrInvitationExpired", func(t *testing.T) {
		err := ErrInvitationExpired{Token: "expired-abc"}
		assert.Equal(t, "invitation expired: token=expired-abc", err.Error())
	})

	t.Run("ErrInvitationAlreadyAccepted", func(t *testing.T) {
		err := ErrInvitationAlreadyAccepted{Token: "accepted-abc"}
		assert.Equal(t, "invitation already accepted: token=accepted-abc", err.Error())
	})

	t.Run("ErrInvitationRevoked", func(t *testing.T) {
		err := ErrInvitationRevoked{Token: "revoked-abc"}
		assert.Equal(t, "invitation has been revoked: token=revoked-abc", err.Error())
	})

	t.Run("ErrInvalidInvitation", func(t *testing.T) {
		err := ErrInvalidInvitation{Reason: "test reason"}
		assert.Equal(t, "invalid invitation: test reason", err.Error())
	})
}

// TestInvitationService_ListByTenant_DAOError verifies error handling when DAO fails
func TestInvitationService_ListByTenant_DAOError(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	expectedErr := errors.New("database error")
	mockInvDAO.On("GetByTenant", ctx, tenantID).Return(nil, expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitations, err := service.ListByTenant(ctx, tenantID)

	require.Error(t, err)
	assert.Nil(t, invitations)
	// Error is returned directly, not wrapped
	assert.Equal(t, expectedErr, err)

	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_ListPendingByTenant_DAOError verifies error handling when DAO fails
func TestInvitationService_ListPendingByTenant_DAOError(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	expectedErr := errors.New("database error")
	mockInvDAO.On("GetPendingByTenant", ctx, tenantID).Return(nil, expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitations, err := service.ListPendingByTenant(ctx, tenantID)

	require.Error(t, err)
	assert.Nil(t, invitations)
	// Error is returned directly, not wrapped
	assert.Equal(t, expectedErr, err)

	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Delete_DAODeleteError verifies error handling when delete fails
func TestInvitationService_Delete_DAODeleteError(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	invitationID := uint64(1)
	invitation := &entities.Invitation{
		ID:       invitationID,
		Token:    "some-token",
		TenantID: "tenant-123",
		Email:    "user@example.com",
		Status:   entities.InvitationStatusPending,
	}

	expectedErr := errors.New("delete failed")
	mockInvDAO.On("Get", ctx, invitationID).Return(invitation, nil)
	mockInvDAO.On("Delete", ctx, invitation).Return(expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	err := service.Delete(ctx, invitationID)

	require.Error(t, err)
	var saveFailed ErrInvitationSaveFailed
	assert.ErrorAs(t, err, &saveFailed)
	assert.Equal(t, expectedErr, saveFailed.Cause)
	mockInvDAO.AssertExpectations(t)
}

// TestInvitationService_Create_UserCheckError verifies error handling when user check fails
func TestInvitationService_Create_UserCheckError(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	tenantID := "tenant-123"
	email := "newuser@example.com"
	role := "member"
	invitedByID := uint64(1)

	expectedErr := errors.New("database error during user check")
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).Return(expectedErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.Create(ctx, &CreateInvitationRequest{
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		InvitedByID: invitedByID,
	})

	require.Error(t, err)
	assert.Nil(t, invitation)
	// Error is returned directly, not wrapped
	assert.Equal(t, expectedErr, err)

	mockUserDAO.AssertExpectations(t)
}

// TestInvitationService_CleanupExpired_SaveError verifies partial success when save fails
func TestInvitationService_CleanupExpired_SaveError(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)

	expiredInvitation := &entities.Invitation{
		ID:        1,
		Token:     "expired-token",
		TenantID:  "tenant-123",
		Email:     "user1@example.com",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: time.Now().UTC().Add(-24 * time.Hour), // Expired
	}

	mockInvDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.Invitation])
			result := datastore.PageResult[*entities.Invitation]{
				Entities: []*entities.Invitation{expiredInvitation},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			}
			_ = fn(result)
		}).Return(nil)

	// Save fails for the expired invitation
	saveErr := errors.New("save failed")
	mockInvDAO.On("Save", ctx, expiredInvitation).Return(saveErr)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	count, err := service.CleanupExpired(ctx)

	// Should still succeed but count should be 0 since save failed
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	mockInvDAO.AssertExpectations(t)
}
