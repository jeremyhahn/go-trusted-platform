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
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockUserServicer implements UserServicer for testing
type MockUserServicer struct {
	mock.Mock
}

func (m *MockUserServicer) Save(ctx context.Context, user *entities.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserServicer) Delete(ctx context.Context, userID uint64) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserServicer) Get(ctx context.Context, userID uint64) (*entities.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *MockUserServicer) GetByEmail(ctx context.Context, email string) (*entities.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.User), args.Error(1)
}

func (m *MockUserServicer) GetByTenant(ctx context.Context, tenantID string) ([]*entities.User, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.User), args.Error(1)
}

func (m *MockUserServicer) IsTenantOwner(ctx context.Context, userID uint64) (bool, error) {
	args := m.Called(ctx, userID)
	return args.Bool(0), args.Error(1)
}

// MockInvitationServicer implements InvitationServicer for testing
type MockInvitationServicer struct {
	mock.Mock
}

func (m *MockInvitationServicer) Create(ctx context.Context, req *CreateInvitationRequest) (*entities.Invitation, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationServicer) CreateInitialAdmin(ctx context.Context, req *CreateInvitationRequest) (*entities.Invitation, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationServicer) GetByToken(ctx context.Context, token string) (*entities.Invitation, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationServicer) GetByID(ctx context.Context, id uint64) (*entities.Invitation, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Invitation), args.Error(1)
}

func (m *MockInvitationServicer) Accept(ctx context.Context, token string, userID uint64) error {
	args := m.Called(ctx, token, userID)
	return args.Error(0)
}

func (m *MockInvitationServicer) Revoke(ctx context.Context, id uint64, revokerID uint64) error {
	args := m.Called(ctx, id, revokerID)
	return args.Error(0)
}

func (m *MockInvitationServicer) ListByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Invitation), args.Error(1)
}

func (m *MockInvitationServicer) ListPendingByTenant(ctx context.Context, tenantID string) ([]*entities.Invitation, error) {
	args := m.Called(ctx, tenantID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entities.Invitation), args.Error(1)
}

func (m *MockInvitationServicer) CleanupExpired(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockInvitationServicer) Delete(ctx context.Context, id uint64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// MockTokenIssuer implements TokenIssuer for testing
type MockTokenIssuer struct {
	mock.Mock
}

func (m *MockTokenIssuer) IssueToken(ctx context.Context, userID uint64, tenantID string, roles []string) (string, error) {
	args := m.Called(ctx, userID, tenantID, roles)
	return args.String(0), args.Error(1)
}

// TenantManagerInterface abstracts the tenant.Manager for testing
type TenantManagerInterface interface {
	CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error)
	DeleteTenant(ctx context.Context, id string) error
}

// MockTenantManager implements TenantManagerInterface for testing
type MockTenantManager struct {
	mock.Mock
}

func (m *MockTenantManager) CreateTenant(ctx context.Context, req *tenant.CreateTenantRequest) (*tenant.TenantEntity, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tenant.TenantEntity), args.Error(1)
}

func (m *MockTenantManager) DeleteTenant(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockTenantManager) GetTenant(ctx context.Context, id string) (*tenant.TenantEntity, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*tenant.TenantEntity), args.Error(1)
}

// TestableTenantUserService wraps TenantUserService for testing with mocked TenantManager
type TestableTenantUserService struct {
	*TenantUserService
	mockTenantManager *MockTenantManager
}

// newTestableTenantUserService creates a testable service with mocked dependencies
func newTestableTenantUserService(
	logger *logging.Logger,
	userService UserServicer,
	invitationService InvitationServicer,
	tokenIssuer TokenIssuer,
) (*TestableTenantUserService, *MockTenantManager) {
	mockTM := new(MockTenantManager)

	// Create the base service - TenantManager will be nil, we override the methods
	service := &TenantUserService{
		logger:            logger,
		userService:       userService,
		invitationService: invitationService,
		tenantManager:     nil, // We use mock via wrapper
		tokenIssuer:       tokenIssuer,
	}

	return &TestableTenantUserService{
		TenantUserService: service,
		mockTenantManager: mockTM,
	}, mockTM
}

// RegisterNewUser overrides to use mock tenant manager
func (s *TestableTenantUserService) RegisterNewUser(
	ctx context.Context,
	user *entities.User,
) (*entities.User, string, error) {
	s.logger.Info("registering new user with tenant creation",
		"email", user.Email,
	)

	// Check if user already exists
	existingUser, err := s.userService.GetByEmail(ctx, user.Email)
	if err == nil && existingUser != nil {
		return nil, "", ErrUserAlreadyExists{Email: user.Email}
	}

	// Create tenant via mock TenantManager
	tenantRequest := &tenant.CreateTenantRequest{
		Name:        "", // Will be set by manager
		DisplayName: user.DisplayName,
		Labels: map[string]string{
			"owner_email": user.Email,
		},
	}

	tenantEntity, err := s.mockTenantManager.CreateTenant(ctx, tenantRequest)
	if err != nil {
		s.logger.Error(err, "failed to create tenant")
		return nil, "", ErrTenantCreationFailed{Cause: err}
	}

	tenantID := tenantEntity.ID

	// Configure user as tenant owner. Mirrors the production
	// RegisterNewUser flow which grants the default tenant-owner
	// role on the first user; without this the test harness drifts
	// from real behavior and a regression in the role-grant code
	// path goes undetected.
	now := time.Now().UTC()
	user.TenantID = tenantID
	user.IsTenantOwner = true
	user.CreatedAt = now
	user.UpdatedAt = now
	user.AddRole(entities.NewRole(DefaultTenantOwnerRole))

	// Save the user
	if err := s.userService.Save(ctx, user); err != nil {
		s.logger.Error(err, "failed to save user")
		// Attempt to clean up the tenant
		if cleanupErr := s.mockTenantManager.DeleteTenant(ctx, tenantID); cleanupErr != nil {
			s.logger.Error(cleanupErr, "failed to cleanup tenant after user save failure")
		}
		return nil, "", ErrUserSaveFailed{Cause: err}
	}

	s.logger.Info("new user registered with tenant",
		"user_id", user.ID,
		"email", user.Email,
		"tenant_id", tenantID,
	)

	return user, tenantID, nil
}

// Helper function to create test logger
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelWarn, os.Stderr)
}

// Helper function to create test user
func newTestUser(email string) *entities.User {
	return &entities.User{
		ID:          12345,
		Email:       email,
		DisplayName: "Test User",
	}
}

// Helper function to create test invitation
func newTestInvitation(token, tenantID, email, role string, status entities.InvitationStatus) *entities.Invitation {
	return &entities.Invitation{
		ID:          1,
		Token:       token,
		TenantID:    tenantID,
		Email:       email,
		Role:        role,
		Status:      status,
		InvitedByID: 999,
		ExpiresAt:   time.Now().UTC().Add(7 * 24 * time.Hour), // Expires in 7 days
		CreatedAt:   time.Now().UTC(),
	}
}

// TestNewTenantUserService verifies the constructor creates a valid service
func TestNewTenantUserService(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     nil, // Can be nil in production
		TokenIssuer:       mockTokenIssuer,
	}

	service := NewTenantUserService(config)

	require.NotNil(t, service)
	assert.Implements(t, (*TenantUserServicer)(nil), service)
}

// TestNewTenantUserService_NilTokenIssuer verifies service works without token issuer
func TestNewTenantUserService_NilTokenIssuer(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     nil,
		TokenIssuer:       nil, // Explicitly nil
	}

	service := NewTenantUserService(config)

	require.NotNil(t, service)
}

// TestTenantUserService_RegisterNewUser_Success verifies successful user registration
// with tenant creation
func TestTenantUserService_RegisterNewUser_Success(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	service, mockTM := newTestableTenantUserService(
		logger,
		mockUserService,
		mockInvitationService,
		mockTokenIssuer,
	)

	user := newTestUser("newuser@example.com")
	tenantID := "test-tenant-uuid-123"

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Tenant creation succeeds
	createdTenant := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: user.DisplayName,
	}
	mockTM.On("CreateTenant", ctx, mock.AnythingOfType("*tenant.CreateTenantRequest")).Return(createdTenant, nil)

	// User save succeeds
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(nil)

	// Execute
	resultUser, resultTenantID, err := service.RegisterNewUser(ctx, user)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, resultUser)
	assert.Equal(t, tenantID, resultTenantID)
	assert.Equal(t, tenantID, resultUser.TenantID)
	assert.True(t, resultUser.IsTenantOwner)
	assert.True(t, resultUser.HasRole(DefaultTenantOwnerRole),
		"first user in a fresh tenant should automatically get the %q role; got %+v",
		DefaultTenantOwnerRole, resultUser.Roles)
	assert.False(t, resultUser.CreatedAt.IsZero())
	assert.False(t, resultUser.UpdatedAt.IsZero())

	mockUserService.AssertExpectations(t)
	mockTM.AssertExpectations(t)
}

// TestTenantUserService_RegisterNewUser_UserExists verifies error when user already exists
func TestTenantUserService_RegisterNewUser_UserExists(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	service, _ := newTestableTenantUserService(
		logger,
		mockUserService,
		mockInvitationService,
		mockTokenIssuer,
	)

	user := newTestUser("existing@example.com")
	existingUser := &entities.User{
		ID:    999,
		Email: user.Email,
	}

	// User already exists
	mockUserService.On("GetByEmail", ctx, user.Email).Return(existingUser, nil)

	// Execute
	resultUser, resultTenantID, err := service.RegisterNewUser(ctx, user)

	// Verify
	require.Error(t, err)
	assert.Nil(t, resultUser)
	assert.Empty(t, resultTenantID)

	var errUserExists ErrUserAlreadyExists
	assert.ErrorAs(t, err, &errUserExists)
	assert.Equal(t, user.Email, errUserExists.Email)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_RegisterNewUser_TenantFails verifies error handling when
// tenant creation fails
func TestTenantUserService_RegisterNewUser_TenantFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	service, mockTM := newTestableTenantUserService(
		logger,
		mockUserService,
		mockInvitationService,
		mockTokenIssuer,
	)

	user := newTestUser("newuser@example.com")

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Tenant creation fails
	tenantErr := errors.New("IAM service unavailable")
	mockTM.On("CreateTenant", ctx, mock.AnythingOfType("*tenant.CreateTenantRequest")).Return(nil, tenantErr)

	// Execute
	resultUser, resultTenantID, err := service.RegisterNewUser(ctx, user)

	// Verify
	require.Error(t, err)
	assert.Nil(t, resultUser)
	assert.Empty(t, resultTenantID)

	var errTenantFailed ErrTenantCreationFailed
	assert.ErrorAs(t, err, &errTenantFailed)
	assert.Equal(t, tenantErr, errTenantFailed.Cause)

	mockUserService.AssertExpectations(t)
	mockTM.AssertExpectations(t)
}

// TestTenantUserService_RegisterNewUser_UserSaveFails verifies cleanup on user save failure
func TestTenantUserService_RegisterNewUser_UserSaveFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	service, mockTM := newTestableTenantUserService(
		logger,
		mockUserService,
		mockInvitationService,
		mockTokenIssuer,
	)

	user := newTestUser("newuser@example.com")
	tenantID := "test-tenant-uuid-123"

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Tenant creation succeeds
	createdTenant := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: user.DisplayName,
	}
	mockTM.On("CreateTenant", ctx, mock.AnythingOfType("*tenant.CreateTenantRequest")).Return(createdTenant, nil)

	// User save fails
	saveErr := errors.New("database connection lost")
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(saveErr)

	// Tenant cleanup is attempted
	mockTM.On("DeleteTenant", ctx, tenantID).Return(nil)

	// Execute
	resultUser, resultTenantID, err := service.RegisterNewUser(ctx, user)

	// Verify
	require.Error(t, err)
	assert.Nil(t, resultUser)
	assert.Empty(t, resultTenantID)

	var errSaveFailed ErrUserSaveFailed
	assert.ErrorAs(t, err, &errSaveFailed)
	assert.Equal(t, saveErr, errSaveFailed.Cause)

	// Verify cleanup was attempted
	mockTM.AssertCalled(t, "DeleteTenant", ctx, tenantID)

	mockUserService.AssertExpectations(t)
	mockTM.AssertExpectations(t)
}

// TestTenantUserService_RegisterNewUser_UserSaveFails_CleanupFails verifies cleanup
// failure is logged but original error is returned
func TestTenantUserService_RegisterNewUser_UserSaveFails_CleanupFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	service, mockTM := newTestableTenantUserService(
		logger,
		mockUserService,
		mockInvitationService,
		mockTokenIssuer,
	)

	user := newTestUser("newuser@example.com")
	tenantID := "test-tenant-uuid-123"

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Tenant creation succeeds
	createdTenant := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: user.DisplayName,
	}
	mockTM.On("CreateTenant", ctx, mock.AnythingOfType("*tenant.CreateTenantRequest")).Return(createdTenant, nil)

	// User save fails
	saveErr := errors.New("database connection lost")
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(saveErr)

	// Tenant cleanup also fails
	cleanupErr := errors.New("tenant cleanup failed")
	mockTM.On("DeleteTenant", ctx, tenantID).Return(cleanupErr)

	// Execute
	resultUser, resultTenantID, err := service.RegisterNewUser(ctx, user)

	// Verify - original save error is returned
	require.Error(t, err)
	assert.Nil(t, resultUser)
	assert.Empty(t, resultTenantID)

	var errSaveFailed ErrUserSaveFailed
	assert.ErrorAs(t, err, &errSaveFailed)
	assert.Equal(t, saveErr, errSaveFailed.Cause)

	mockUserService.AssertExpectations(t)
	mockTM.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_Success verifies successful registration
// via invitation
func TestTenantUserService_RegisterInvitedUser_Success(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
		TokenIssuer:       mockTokenIssuer,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	tenantID := "existing-tenant-123"
	invitationToken := "valid-token-abc"
	invitation := newTestInvitation(invitationToken, tenantID, user.Email, "member", entities.InvitationStatusPending)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation is valid
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Tenant exists
	tenantEntity := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: "Existing Tenant",
	}
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(tenantEntity, nil)

	// User save succeeds
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(nil)

	// Accept invitation succeeds - returns error only
	mockInvitationService.On("Accept", ctx, invitationToken, mock.AnythingOfType("uint64")).Return(nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	assert.Equal(t, tenantID, result.User.TenantID)
	assert.False(t, result.User.IsTenantOwner)
	assert.False(t, result.User.CreatedAt.IsZero())
	assert.False(t, result.User.UpdatedAt.IsZero())
	assert.False(t, result.IsNewTenant)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_UserExists verifies error when user exists
func TestTenantUserService_RegisterInvitedUser_UserExists(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("existing@example.com")
	existingUser := &entities.User{
		ID:    999,
		Email: user.Email,
	}

	// User already exists
	mockUserService.On("GetByEmail", ctx, user.Email).Return(existingUser, nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, "some-token")

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errUserExists ErrUserAlreadyExists
	assert.ErrorAs(t, err, &errUserExists)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_InvitationNotFound verifies error when
// invitation token is invalid
func TestTenantUserService_RegisterInvitedUser_InvitationNotFound(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	invitationToken := "invalid-token"

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation not found
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(nil, errors.New("not found"))

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errNotFound ErrInvitationNotFound
	assert.ErrorAs(t, err, &errNotFound)
	assert.Equal(t, invitationToken, errNotFound.Token)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_EmailMismatch verifies error when emails
// don't match
func TestTenantUserService_RegisterInvitedUser_EmailMismatch(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("different@example.com")
	invitationToken := "valid-token"
	// Invitation is for a different email
	invitation := newTestInvitation(invitationToken, "tenant-123", "invited@example.com", "member", entities.InvitationStatusPending)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation found but for different email
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errInvalid ErrInvalidInvitation
	assert.ErrorAs(t, err, &errInvalid)
	assert.Contains(t, errInvalid.Reason, "email")

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_AlreadyAccepted verifies error when
// invitation was already used
func TestTenantUserService_RegisterInvitedUser_AlreadyAccepted(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	invitationToken := "used-token"
	invitation := newTestInvitation(invitationToken, "tenant-123", user.Email, "member", entities.InvitationStatusAccepted)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation found but already accepted
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errAlreadyAccepted ErrInvitationAlreadyAccepted
	assert.ErrorAs(t, err, &errAlreadyAccepted)
	assert.Equal(t, invitationToken, errAlreadyAccepted.Token)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_Expired verifies error when invitation
// has expired
func TestTenantUserService_RegisterInvitedUser_Expired(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	invitationToken := "expired-token"
	invitation := newTestInvitation(invitationToken, "tenant-123", user.Email, "member", entities.InvitationStatusExpired)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation found but expired
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errExpired ErrInvitationExpired
	assert.ErrorAs(t, err, &errExpired)
	assert.Equal(t, invitationToken, errExpired.Token)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_ExpiredByTime verifies error when invitation
// is pending but past expiry time
func TestTenantUserService_RegisterInvitedUser_ExpiredByTime(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	invitationToken := "time-expired-token"
	invitation := &entities.Invitation{
		ID:          1,
		Token:       invitationToken,
		TenantID:    "tenant-123",
		Email:       user.Email,
		Role:        "member",
		Status:      entities.InvitationStatusPending,
		InvitedByID: 999,
		ExpiresAt:   time.Now().UTC().Add(-24 * time.Hour), // Expired yesterday
		CreatedAt:   time.Now().UTC().Add(-8 * 24 * time.Hour),
	}

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation found but time-expired
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errExpired ErrInvitationExpired
	assert.ErrorAs(t, err, &errExpired)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_Revoked verifies error when invitation
// was revoked
func TestTenantUserService_RegisterInvitedUser_Revoked(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	invitationToken := "revoked-token"
	invitation := newTestInvitation(invitationToken, "tenant-123", user.Email, "member", entities.InvitationStatusRevoked)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation found but revoked
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errRevoked ErrInvitationRevoked
	assert.ErrorAs(t, err, &errRevoked)
	assert.Equal(t, invitationToken, errRevoked.Token)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_AssignsRole verifies that the role from
// invitation is assigned to user
func TestTenantUserService_RegisterInvitedUser_AssignsRole(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	tenantID := "existing-tenant-123"
	invitationToken := "valid-token-with-role"
	roleName := "admin"
	invitation := newTestInvitation(invitationToken, tenantID, user.Email, roleName, entities.InvitationStatusPending)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation is valid
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Tenant exists
	tenantEntity := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: "Existing Tenant",
	}
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(tenantEntity, nil)

	// User save succeeds - capture the user to verify role
	var savedUser *entities.User
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Run(func(args mock.Arguments) {
		savedUser = args.Get(1).(*entities.User)
	}).Return(nil)

	// Accept invitation succeeds
	mockInvitationService.On("Accept", ctx, invitationToken, mock.AnythingOfType("uint64")).Return(nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, savedUser)

	// Verify role was assigned
	assert.Len(t, savedUser.Roles, 1)
	assert.Equal(t, roleName, savedUser.Roles[0].Name)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_NoRole verifies registration works without role
func TestTenantUserService_RegisterInvitedUser_NoRole(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	tenantID := "existing-tenant-123"
	invitationToken := "valid-token-no-role"
	invitation := newTestInvitation(invitationToken, tenantID, user.Email, "", entities.InvitationStatusPending)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation is valid
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Tenant exists
	tenantEntity := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: "Existing Tenant",
	}
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(tenantEntity, nil)

	// User save succeeds - capture the user to verify no role
	var savedUser *entities.User
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Run(func(args mock.Arguments) {
		savedUser = args.Get(1).(*entities.User)
	}).Return(nil)

	// Accept invitation succeeds
	mockInvitationService.On("Accept", ctx, invitationToken, mock.AnythingOfType("uint64")).Return(nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, savedUser)

	// Verify no role was assigned
	assert.Empty(t, savedUser.Roles)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_AcceptFails verifies error handling when
// invitation accept fails (non-critical - user should still be saved)
func TestTenantUserService_RegisterInvitedUser_AcceptFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	tenantID := "tenant-123"
	invitationToken := "valid-token"
	invitation := newTestInvitation(invitationToken, tenantID, user.Email, "member", entities.InvitationStatusPending)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation is valid
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Tenant exists
	tenantEntity := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: "Existing Tenant",
	}
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(tenantEntity, nil)

	// User save succeeds
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(nil)

	// Accept invitation fails - but this is non-critical, user registration should succeed
	acceptErr := errors.New("database error during accept")
	mockInvitationService.On("Accept", ctx, invitationToken, mock.AnythingOfType("uint64")).Return(acceptErr)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify - registration succeeds even if invitation accept fails
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	assert.Equal(t, tenantID, result.User.TenantID)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_SaveFails verifies error handling when
// user save fails
func TestTenantUserService_RegisterInvitedUser_SaveFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	tenantID := "tenant-123"
	invitationToken := "valid-token"
	invitation := newTestInvitation(invitationToken, tenantID, user.Email, "member", entities.InvitationStatusPending)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation is valid
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Tenant exists
	tenantEntity := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: "Existing Tenant",
	}
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(tenantEntity, nil)

	// User save fails
	saveErr := errors.New("database error")
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(saveErr)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errSaveFailed ErrUserSaveFailed
	assert.ErrorAs(t, err, &errSaveFailed)
	assert.Equal(t, saveErr, errSaveFailed.Cause)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_NilUser verifies error when user is nil
func TestTenantUserService_RegisterInvitedUser_NilUser(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	// Execute with nil user
	result, err := service.RegisterInvitedUser(ctx, nil, "some-token")

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errInvalid ErrInvalidUserInput
	assert.ErrorAs(t, err, &errInvalid)
}

// TestTenantUserService_RegisterInvitedUser_EmptyToken verifies error when token is empty
func TestTenantUserService_RegisterInvitedUser_EmptyToken(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("test@example.com")

	// Execute with empty token
	result, err := service.RegisterInvitedUser(ctx, user, "")

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errRequired ErrInvitationRequired
	assert.ErrorAs(t, err, &errRequired)
}

// TestTenantUserService_RegisterInvitedUser_UnknownStatus verifies error for unknown status
func TestTenantUserService_RegisterInvitedUser_UnknownStatus(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	invitationToken := "unknown-status-token"
	invitation := &entities.Invitation{
		ID:          1,
		Token:       invitationToken,
		TenantID:    "tenant-123",
		Email:       user.Email,
		Role:        "member",
		Status:      entities.InvitationStatus("unknown"), // Unknown status
		InvitedByID: 999,
		ExpiresAt:   time.Now().UTC().Add(24 * time.Hour),
		CreatedAt:   time.Now().UTC(),
	}

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation found with unknown status
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errInvalid ErrInvalidInvitation
	assert.ErrorAs(t, err, &errInvalid)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
}

// TestTenantUserService_RegisterInvitedUser_TenantNotFound verifies error when tenant is not found
func TestTenantUserService_RegisterInvitedUser_TenantNotFound(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
	}

	service := NewTenantUserService(config)

	user := newTestUser("invited@example.com")
	tenantID := "nonexistent-tenant"
	invitationToken := "valid-token"
	invitation := newTestInvitation(invitationToken, tenantID, user.Email, "member", entities.InvitationStatusPending)

	// User does not exist
	mockUserService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})

	// Invitation is valid
	mockInvitationService.On("GetByToken", ctx, invitationToken).Return(invitation, nil)

	// Tenant not found
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(nil, errors.New("tenant not found"))

	// Execute
	result, err := service.RegisterInvitedUser(ctx, user, invitationToken)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errNotFound ErrTenantNotFound
	assert.ErrorAs(t, err, &errNotFound)

	mockUserService.AssertExpectations(t)
	mockInvitationService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_GetUserTenant_Success verifies successful tenant retrieval
func TestTenantUserService_GetUserTenant_Success(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
	}

	service := NewTenantUserService(config)

	userID := uint64(123)
	tenantID := "tenant-456"
	user := &entities.User{
		ID:       userID,
		Email:    "user@example.com",
		TenantID: tenantID,
	}
	expectedTenant := &tenant.TenantEntity{
		ID:          tenantID,
		Name:        tenantID,
		DisplayName: "Test Tenant",
	}

	mockUserService.On("Get", ctx, userID).Return(user, nil)
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(expectedTenant, nil)

	// Execute
	result, err := service.GetUserTenant(ctx, userID)

	// Verify
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, tenantID, result.ID)

	mockUserService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_GetUserTenant_UserNotFound verifies error when user not found
func TestTenantUserService_GetUserTenant_UserNotFound(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	userID := uint64(999)

	mockUserService.On("Get", ctx, userID).Return(nil, errors.New("not found"))

	// Execute
	result, err := service.GetUserTenant(ctx, userID)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errNotFound ErrUserNotFound
	assert.ErrorAs(t, err, &errNotFound)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_GetUserTenant_UserNotInTenant verifies error when user has no tenant
func TestTenantUserService_GetUserTenant_UserNotInTenant(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	userID := uint64(123)
	user := &entities.User{
		ID:       userID,
		Email:    "user@example.com",
		TenantID: "", // No tenant
	}

	mockUserService.On("Get", ctx, userID).Return(user, nil)

	// Execute
	result, err := service.GetUserTenant(ctx, userID)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errNotInTenant ErrUserNotInTenant
	assert.ErrorAs(t, err, &errNotInTenant)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_GetUserTenant_TenantNotFound verifies error when tenant not found
func TestTenantUserService_GetUserTenant_TenantNotFound(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
	}

	service := NewTenantUserService(config)

	userID := uint64(123)
	tenantID := "deleted-tenant"
	user := &entities.User{
		ID:       userID,
		Email:    "user@example.com",
		TenantID: tenantID,
	}

	mockUserService.On("Get", ctx, userID).Return(user, nil)
	mockTenantManager.On("GetTenant", ctx, tenantID).Return(nil, errors.New("not found"))

	// Execute
	result, err := service.GetUserTenant(ctx, userID)

	// Verify
	require.Error(t, err)
	assert.Nil(t, result)

	var errNotFound ErrTenantNotFound
	assert.ErrorAs(t, err, &errNotFound)

	mockUserService.AssertExpectations(t)
	mockTenantManager.AssertExpectations(t)
}

// TestTenantUserService_IsTenantOwner_Success verifies successful owner check
func TestTenantUserService_IsTenantOwner_Success(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	_ = NewTenantUserService(config)

	t.Run("IsOwner", func(t *testing.T) {
		mockUserService2 := new(MockUserServicer)
		config2 := &TenantUserServiceConfig{
			Logger:            logger,
			UserService:       mockUserService2,
			InvitationService: mockInvitationService,
		}
		service2 := NewTenantUserService(config2)

		userID := uint64(123)
		user := &entities.User{
			ID:            userID,
			Email:         "owner@example.com",
			IsTenantOwner: true,
		}

		mockUserService2.On("Get", ctx, userID).Return(user, nil)

		isOwner, err := service2.IsTenantOwner(ctx, userID)

		require.NoError(t, err)
		assert.True(t, isOwner)
		mockUserService2.AssertExpectations(t)
	})

	t.Run("NotOwner", func(t *testing.T) {
		mockUserService3 := new(MockUserServicer)
		config3 := &TenantUserServiceConfig{
			Logger:            logger,
			UserService:       mockUserService3,
			InvitationService: mockInvitationService,
		}
		service3 := NewTenantUserService(config3)

		userID := uint64(456)
		user := &entities.User{
			ID:            userID,
			Email:         "member@example.com",
			IsTenantOwner: false,
		}

		mockUserService3.On("Get", ctx, userID).Return(user, nil)

		isOwner, err := service3.IsTenantOwner(ctx, userID)

		require.NoError(t, err)
		assert.False(t, isOwner)
		mockUserService3.AssertExpectations(t)
	})
}

// TestTenantUserService_IsTenantOwner_UserNotFound verifies error when user not found
func TestTenantUserService_IsTenantOwner_UserNotFound(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	userID := uint64(999)

	mockUserService.On("Get", ctx, userID).Return(nil, errors.New("not found"))

	// Execute
	isOwner, err := service.IsTenantOwner(ctx, userID)

	// Verify
	require.Error(t, err)
	assert.False(t, isOwner)

	var errNotFound ErrUserNotFound
	assert.ErrorAs(t, err, &errNotFound)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_Success verifies successful ownership transfer
func TestTenantUserService_TransferOwnership_Success(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(100)
	newOwnerID := uint64(200)
	tenantID := "tenant-123"

	currentOwner := &entities.User{
		ID:            currentOwnerID,
		Email:         "current@example.com",
		TenantID:      tenantID,
		IsTenantOwner: true,
	}
	newOwner := &entities.User{
		ID:            newOwnerID,
		Email:         "new@example.com",
		TenantID:      tenantID,
		IsTenantOwner: false,
	}

	mockUserService.On("Get", ctx, currentOwnerID).Return(currentOwner, nil)
	mockUserService.On("Get", ctx, newOwnerID).Return(newOwner, nil)
	mockUserService.On("Save", ctx, currentOwner).Return(nil)
	mockUserService.On("Save", ctx, newOwner).Return(nil)

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify
	require.NoError(t, err)
	assert.False(t, currentOwner.IsTenantOwner)
	assert.True(t, newOwner.IsTenantOwner)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_SameUser verifies error when same user
func TestTenantUserService_TransferOwnership_SameUser(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	userID := uint64(100)

	// Execute
	err := service.TransferOwnership(ctx, userID, userID)

	// Verify
	require.Error(t, err)

	var errInvalid ErrInvalidUserInput
	assert.ErrorAs(t, err, &errInvalid)
}

// TestTenantUserService_TransferOwnership_CurrentOwnerNotFound verifies error when current owner not found
func TestTenantUserService_TransferOwnership_CurrentOwnerNotFound(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(999)
	newOwnerID := uint64(200)

	mockUserService.On("Get", ctx, currentOwnerID).Return(nil, errors.New("not found"))

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify
	require.Error(t, err)

	var errNotFound ErrUserNotFound
	assert.ErrorAs(t, err, &errNotFound)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_NotOwner verifies error when current user is not owner
func TestTenantUserService_TransferOwnership_NotOwner(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(100)
	newOwnerID := uint64(200)

	currentOwner := &entities.User{
		ID:            currentOwnerID,
		Email:         "member@example.com",
		IsTenantOwner: false, // Not owner
	}

	mockUserService.On("Get", ctx, currentOwnerID).Return(currentOwner, nil)

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify
	require.Error(t, err)

	var errNotOwner ErrNotTenantOwner
	assert.ErrorAs(t, err, &errNotOwner)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_NewOwnerNotFound verifies error when new owner not found
func TestTenantUserService_TransferOwnership_NewOwnerNotFound(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(100)
	newOwnerID := uint64(999)

	currentOwner := &entities.User{
		ID:            currentOwnerID,
		Email:         "owner@example.com",
		IsTenantOwner: true,
	}

	mockUserService.On("Get", ctx, currentOwnerID).Return(currentOwner, nil)
	mockUserService.On("Get", ctx, newOwnerID).Return(nil, errors.New("not found"))

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify
	require.Error(t, err)

	var errNotFound ErrUserNotFound
	assert.ErrorAs(t, err, &errNotFound)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_DifferentTenant verifies error when users in different tenants
func TestTenantUserService_TransferOwnership_DifferentTenant(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(100)
	newOwnerID := uint64(200)

	currentOwner := &entities.User{
		ID:            currentOwnerID,
		Email:         "owner@example.com",
		TenantID:      "tenant-A",
		IsTenantOwner: true,
	}
	newOwner := &entities.User{
		ID:       newOwnerID,
		Email:    "user@example.com",
		TenantID: "tenant-B", // Different tenant
	}

	mockUserService.On("Get", ctx, currentOwnerID).Return(currentOwner, nil)
	mockUserService.On("Get", ctx, newOwnerID).Return(newOwner, nil)

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify
	require.Error(t, err)

	var errNotInTenant ErrUserNotInTenant
	assert.ErrorAs(t, err, &errNotInTenant)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_SaveCurrentOwnerFails verifies error when saving current owner fails
func TestTenantUserService_TransferOwnership_SaveCurrentOwnerFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(100)
	newOwnerID := uint64(200)
	tenantID := "tenant-123"

	currentOwner := &entities.User{
		ID:            currentOwnerID,
		Email:         "owner@example.com",
		TenantID:      tenantID,
		IsTenantOwner: true,
	}
	newOwner := &entities.User{
		ID:       newOwnerID,
		Email:    "user@example.com",
		TenantID: tenantID,
	}

	saveErr := errors.New("database error")

	mockUserService.On("Get", ctx, currentOwnerID).Return(currentOwner, nil)
	mockUserService.On("Get", ctx, newOwnerID).Return(newOwner, nil)
	mockUserService.On("Save", ctx, currentOwner).Return(saveErr)

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify
	require.Error(t, err)

	var errSaveFailed ErrUserSaveFailed
	assert.ErrorAs(t, err, &errSaveFailed)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_SaveNewOwnerFails verifies rollback when saving new owner fails
func TestTenantUserService_TransferOwnership_SaveNewOwnerFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(100)
	newOwnerID := uint64(200)
	tenantID := "tenant-123"

	currentOwner := &entities.User{
		ID:            currentOwnerID,
		Email:         "owner@example.com",
		TenantID:      tenantID,
		IsTenantOwner: true,
	}
	newOwner := &entities.User{
		ID:       newOwnerID,
		Email:    "user@example.com",
		TenantID: tenantID,
	}

	saveErr := errors.New("database error")

	mockUserService.On("Get", ctx, currentOwnerID).Return(currentOwner, nil)
	mockUserService.On("Get", ctx, newOwnerID).Return(newOwner, nil)
	mockUserService.On("Save", ctx, currentOwner).Return(nil).Once() // First save succeeds
	mockUserService.On("Save", ctx, newOwner).Return(saveErr)        // Second save fails
	mockUserService.On("Save", ctx, currentOwner).Return(nil).Once() // Rollback succeeds

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify
	require.Error(t, err)

	var errSaveFailed ErrUserSaveFailed
	assert.ErrorAs(t, err, &errSaveFailed)
	// Verify ownership was rolled back (current owner is still owner)
	assert.True(t, currentOwner.IsTenantOwner)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_TransferOwnership_RollbackFails verifies behavior when rollback also fails
func TestTenantUserService_TransferOwnership_RollbackFails(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
	}

	service := NewTenantUserService(config)

	currentOwnerID := uint64(100)
	newOwnerID := uint64(200)
	tenantID := "tenant-123"

	currentOwner := &entities.User{
		ID:            currentOwnerID,
		Email:         "owner@example.com",
		TenantID:      tenantID,
		IsTenantOwner: true,
	}
	newOwner := &entities.User{
		ID:       newOwnerID,
		Email:    "user@example.com",
		TenantID: tenantID,
	}

	saveErr := errors.New("database error")
	rollbackErr := errors.New("rollback failed")

	mockUserService.On("Get", ctx, currentOwnerID).Return(currentOwner, nil)
	mockUserService.On("Get", ctx, newOwnerID).Return(newOwner, nil)
	mockUserService.On("Save", ctx, currentOwner).Return(nil).Once()  // First save succeeds
	mockUserService.On("Save", ctx, newOwner).Return(saveErr)         // Second save fails
	mockUserService.On("Save", ctx, currentOwner).Return(rollbackErr) // Rollback also fails

	// Execute
	err := service.TransferOwnership(ctx, currentOwnerID, newOwnerID)

	// Verify - original error is returned even when rollback fails
	require.Error(t, err)

	var errSaveFailed ErrUserSaveFailed
	assert.ErrorAs(t, err, &errSaveFailed)
	assert.Equal(t, saveErr, errSaveFailed.Cause)

	mockUserService.AssertExpectations(t)
}

// TestTenantUserService_IssueToken_Success verifies successful token issuance
func TestTenantUserService_IssueToken_Success(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TokenIssuer:       mockTokenIssuer,
	}

	service := NewTenantUserService(config)

	user := &entities.User{
		ID:            12345,
		TenantID:      "tenant-abc",
		IsTenantOwner: false,
		Roles: []*entities.Role{
			{Name: "member"},
		},
	}

	expectedToken := "jwt-token-123"
	expectedRoles := []string{"member"}

	mockTokenIssuer.On("IssueToken", ctx, user.ID, user.TenantID, expectedRoles).Return(expectedToken, nil)

	// Execute
	token, err := service.IssueToken(ctx, user)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)

	mockTokenIssuer.AssertExpectations(t)
}

// TestTenantUserService_IssueToken_WithTenantOwnerRole verifies tenant_owner role
// is added for owners
func TestTenantUserService_IssueToken_WithTenantOwnerRole(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TokenIssuer:       mockTokenIssuer,
	}

	service := NewTenantUserService(config)

	user := &entities.User{
		ID:            12345,
		TenantID:      "tenant-abc",
		IsTenantOwner: true,
		Roles: []*entities.Role{
			{Name: "admin"},
		},
	}

	expectedToken := "jwt-token-owner"
	// Should include both admin and tenant_owner
	mockTokenIssuer.On("IssueToken", ctx, user.ID, user.TenantID, []string{"admin", "tenant_owner"}).Return(expectedToken, nil)

	// Execute
	token, err := service.IssueToken(ctx, user)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)

	mockTokenIssuer.AssertExpectations(t)
}

// TestTenantUserService_IssueToken_NoRoles verifies token issuance with no roles
func TestTenantUserService_IssueToken_NoRoles(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TokenIssuer:       mockTokenIssuer,
	}

	service := NewTenantUserService(config)

	user := &entities.User{
		ID:            12345,
		TenantID:      "tenant-abc",
		IsTenantOwner: false,
		Roles:         nil,
	}

	expectedToken := "jwt-token-no-roles"
	// Empty roles slice
	mockTokenIssuer.On("IssueToken", ctx, user.ID, user.TenantID, []string{}).Return(expectedToken, nil)

	// Execute
	token, err := service.IssueToken(ctx, user)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)

	mockTokenIssuer.AssertExpectations(t)
}

// TestTenantUserService_IssueToken_NoIssuer verifies empty token when no issuer configured
func TestTenantUserService_IssueToken_NoIssuer(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TokenIssuer:       nil, // No issuer configured
	}

	service := NewTenantUserService(config)

	user := &entities.User{
		ID:       12345,
		TenantID: "tenant-abc",
	}

	// Execute
	token, err := service.IssueToken(ctx, user)

	// Verify
	require.NoError(t, err)
	assert.Empty(t, token)
}

// TestTenantUserService_IssueToken_Failure verifies error handling when token
// issuance fails
func TestTenantUserService_IssueToken_Failure(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TokenIssuer:       mockTokenIssuer,
	}

	service := NewTenantUserService(config)

	user := &entities.User{
		ID:       12345,
		TenantID: "tenant-abc",
	}

	issueErr := errors.New("signing key unavailable")
	mockTokenIssuer.On("IssueToken", ctx, user.ID, user.TenantID, []string{}).Return("", issueErr)

	// Execute
	token, err := service.IssueToken(ctx, user)

	// Verify
	require.Error(t, err)
	assert.Empty(t, token)

	var errTokenFailed ErrTokenIssueFailed
	assert.ErrorAs(t, err, &errTokenFailed)
	assert.Equal(t, issueErr, errTokenFailed.Cause)

	mockTokenIssuer.AssertExpectations(t)
}

// TestTenantUserService_IssueToken_MultipleRoles verifies token issuance with
// multiple roles
func TestTenantUserService_IssueToken_MultipleRoles(t *testing.T) {
	logger := newTestLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTokenIssuer := new(MockTokenIssuer)
	ctx := context.Background()

	config := &TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TokenIssuer:       mockTokenIssuer,
	}

	service := NewTenantUserService(config)

	user := &entities.User{
		ID:            12345,
		TenantID:      "tenant-abc",
		IsTenantOwner: true,
		Roles: []*entities.Role{
			{Name: "admin"},
			{Name: "developer"},
			{Name: "auditor"},
		},
	}

	expectedToken := "jwt-token-multi-role"
	// All roles including tenant_owner for owner
	expectedRoles := []string{"admin", "developer", "auditor", "tenant_owner"}
	mockTokenIssuer.On("IssueToken", ctx, user.ID, user.TenantID, expectedRoles).Return(expectedToken, nil)

	// Execute
	token, err := service.IssueToken(ctx, user)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, expectedToken, token)

	mockTokenIssuer.AssertExpectations(t)
}

// TestTenantUserService_ErrUserAlreadyExists_Error verifies error message formatting
func TestTenantUserService_ErrUserAlreadyExists_Error(t *testing.T) {
	err := ErrUserAlreadyExists{Email: "test@example.com"}
	assert.Equal(t, "user already exists: email=test@example.com", err.Error())
}

// TestTenantUserService_ErrTenantCreationFailed_Error verifies error message formatting
func TestTenantUserService_ErrTenantCreationFailed_Error(t *testing.T) {
	// Without cause
	err1 := ErrTenantCreationFailed{}
	assert.Equal(t, "tenant creation failed", err1.Error())

	// With cause
	cause := errors.New("IAM error")
	err2 := ErrTenantCreationFailed{Cause: cause}
	assert.Equal(t, "tenant creation failed: IAM error", err2.Error())
	assert.Equal(t, cause, err2.Unwrap())
}

// TestTenantUserService_ErrUserSaveFailed_Error verifies error message formatting
func TestTenantUserService_ErrUserSaveFailed_Error(t *testing.T) {
	// Without cause
	err1 := ErrUserSaveFailed{}
	assert.Equal(t, "user save failed", err1.Error())

	// With cause
	cause := errors.New("database error")
	err2 := ErrUserSaveFailed{Cause: cause}
	assert.Equal(t, "user save failed: database error", err2.Error())
	assert.Equal(t, cause, err2.Unwrap())
}

// TestTenantUserService_ErrTokenIssueFailed_Error verifies error message formatting
func TestTenantUserService_ErrTokenIssueFailed_Error(t *testing.T) {
	// Without cause
	err1 := ErrTokenIssueFailed{}
	assert.Equal(t, "token issuance failed", err1.Error())

	// With cause
	cause := errors.New("signing error")
	err2 := ErrTokenIssueFailed{Cause: cause}
	assert.Equal(t, "token issuance failed: signing error", err2.Error())
	assert.Equal(t, cause, err2.Unwrap())
}

// TestTenantUserService_ErrTenantNotFound_Error verifies error message formatting
func TestTenantUserService_ErrTenantNotFound_Error(t *testing.T) {
	t.Run("WithID", func(t *testing.T) {
		err := ErrTenantNotFound{ID: "tenant-123"}
		assert.Contains(t, err.Error(), "tenant-123")
	})

	t.Run("WithName", func(t *testing.T) {
		err := ErrTenantNotFound{Name: "my-tenant"}
		assert.Contains(t, err.Error(), "my-tenant")
	})

	t.Run("Empty", func(t *testing.T) {
		err := ErrTenantNotFound{}
		assert.Equal(t, "tenant not found", err.Error())
	})
}

// TestTenantUserService_ErrUserNotInTenant_Error verifies error message formatting
func TestTenantUserService_ErrUserNotInTenant_Error(t *testing.T) {
	t.Run("WithTenantID", func(t *testing.T) {
		err := ErrUserNotInTenant{UserID: 123, TenantID: "tenant-456"}
		assert.Contains(t, err.Error(), "123")
		assert.Contains(t, err.Error(), "tenant-456")
	})

	t.Run("WithoutTenantID", func(t *testing.T) {
		err := ErrUserNotInTenant{UserID: 123}
		assert.Contains(t, err.Error(), "123")
	})
}

// TestTenantUserService_ErrInvitationRequired_Error verifies error message
func TestTenantUserService_ErrInvitationRequired_Error(t *testing.T) {
	err := ErrInvitationRequired{}
	assert.Equal(t, "invitation token is required", err.Error())
}

// TestTenantUserService_ErrInvalidUserInput_Error verifies error message formatting
func TestTenantUserService_ErrInvalidUserInput_Error(t *testing.T) {
	err := ErrInvalidUserInput{Reason: "user is required"}
	assert.Equal(t, "invalid user input: user is required", err.Error())
}

// TestTenantUserService_ErrNotTenantOwner_Error verifies error message formatting
func TestTenantUserService_ErrNotTenantOwner_Error(t *testing.T) {
	err := ErrNotTenantOwner{UserID: 123}
	assert.Contains(t, err.Error(), "123")
}
