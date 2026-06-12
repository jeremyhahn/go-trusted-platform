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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockRegistrationDAO implements datastore.RegistrationDAO for testing
type MockRegistrationDAO struct {
	mock.Mock
}

func (m *MockRegistrationDAO) Save(ctx context.Context, reg *entities.Registration) error {
	args := m.Called(ctx, reg)
	return args.Error(0)
}

func (m *MockRegistrationDAO) Get(ctx context.Context, id uint64) (*entities.Registration, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entities.Registration), args.Error(1)
}

func (m *MockRegistrationDAO) Delete(ctx context.Context, reg *entities.Registration) error {
	args := m.Called(ctx, reg)
	return args.Error(0)
}

func (m *MockRegistrationDAO) Count(ctx context.Context) (int, error) {
	args := m.Called(ctx)
	return args.Int(0), args.Error(1)
}

func (m *MockRegistrationDAO) Page(ctx context.Context, pageQuery datastore.PageQuery) (datastore.PageResult[*entities.Registration], error) {
	args := m.Called(ctx, pageQuery)
	return args.Get(0).(datastore.PageResult[*entities.Registration]), args.Error(1)
}

func (m *MockRegistrationDAO) ForEachPage(ctx context.Context, pageQuery datastore.PageQuery, procFunc datastore.PagerFunc[*entities.Registration]) error {
	args := m.Called(ctx, pageQuery, procFunc)
	return args.Error(0)
}

func TestNewRegistrationService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	service := NewRegistrationService(logger, mockDAO)

	require.NotNil(t, service)
	assert.IsType(t, &Registration{}, service)
}

func TestRegistration_Create_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	registration := &entities.Registration{
		ID:    1,
		Email: "newuser@example.com",
	}

	mockDAO.On("Save", mock.Anything, registration).Return(nil)

	service := NewRegistrationService(logger, mockDAO)
	err := service.Create(ctx, registration)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}

func TestRegistration_Create_Error(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	registration := &entities.Registration{
		ID:    1,
		Email: "newuser@example.com",
	}

	expectedErr := errors.New("database error")
	mockDAO.On("Save", mock.Anything, registration).Return(expectedErr)

	service := NewRegistrationService(logger, mockDAO)
	err := service.Create(ctx, registration)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockDAO.AssertExpectations(t)
}

func TestRegistration_Get_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	session := NewSession()
	registrationID := uint64(123)

	expectedRegistration := &entities.Registration{
		ID:    registrationID,
		Email: "test@example.com",
	}

	mockDAO.On("Get", mock.Anything, registrationID).Return(expectedRegistration, nil)

	service := NewRegistrationService(logger, mockDAO)
	registration, err := service.Get(ctx, session, registrationID)

	require.NoError(t, err)
	require.NotNil(t, registration)
	assert.Equal(t, registrationID, registration.ID)
	assert.Equal(t, "test@example.com", registration.Email)
	mockDAO.AssertExpectations(t)
}

func TestRegistration_Get_NotFound(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	session := NewSession()
	registrationID := uint64(999)

	expectedErr := ErrRegistrationNotFound
	mockDAO.On("Get", mock.Anything, registrationID).Return(nil, expectedErr)

	service := NewRegistrationService(logger, mockDAO)
	registration, err := service.Get(ctx, session, registrationID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, registration)
	mockDAO.AssertExpectations(t)
}

func TestRegistration_Get_Error(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	session := NewSession()
	registrationID := uint64(123)

	expectedErr := errors.New("database connection error")
	mockDAO.On("Get", mock.Anything, registrationID).Return(nil, expectedErr)

	service := NewRegistrationService(logger, mockDAO)
	registration, err := service.Get(ctx, session, registrationID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, registration)
	mockDAO.AssertExpectations(t)
}

func TestRegistration_Delete_Success(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	session := NewSession()
	registrationID := uint64(456)

	mockDAO.On("Delete", mock.Anything, &entities.Registration{ID: registrationID}).Return(nil)

	service := NewRegistrationService(logger, mockDAO)
	err := service.Delete(ctx, session, registrationID)

	require.NoError(t, err)
	mockDAO.AssertExpectations(t)
}

func TestRegistration_Delete_Error(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	session := NewSession()
	registrationID := uint64(456)

	expectedErr := errors.New("deletion failed")
	mockDAO.On("Delete", mock.Anything, &entities.Registration{ID: registrationID}).Return(expectedErr)

	service := NewRegistrationService(logger, mockDAO)
	err := service.Delete(ctx, session, registrationID)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	mockDAO.AssertExpectations(t)
}

func TestErrRegistrationNotFound(t *testing.T) {
	assert.Equal(t, "registration not found", ErrRegistrationNotFound.Error())
}

func TestRegistration_FullWorkflow(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	service := NewRegistrationService(logger, mockDAO)
	session := NewSession()

	// Create registration
	registration := &entities.Registration{
		ID:    100,
		Email: "workflow@example.com",
	}

	mockDAO.On("Save", mock.Anything, registration).Return(nil)
	err := service.Create(ctx, registration)
	require.NoError(t, err)

	// Get registration
	mockDAO.On("Get", mock.Anything, registration.ID).Return(registration, nil).Once()
	fetchedReg, err := service.Get(ctx, session, registration.ID)
	require.NoError(t, err)
	assert.Equal(t, registration.Email, fetchedReg.Email)

	// Delete registration
	mockDAO.On("Delete", mock.Anything, &entities.Registration{ID: registration.ID}).Return(nil)
	err = service.Delete(ctx, session, registration.ID)
	require.NoError(t, err)

	// Verify deletion - use Once() since we have another Get call with same args
	mockDAO.On("Get", mock.Anything, registration.ID).Return(nil, ErrRegistrationNotFound).Once()
	fetchedReg, err = service.Get(ctx, session, registration.ID)
	assert.Error(t, err)
	assert.Nil(t, fetchedReg)

	mockDAO.AssertExpectations(t)
}

func TestRegistration_CreateMultiple(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	service := NewRegistrationService(logger, mockDAO)

	registrations := []*entities.Registration{
		{ID: 1, Email: "user1@example.com"},
		{ID: 2, Email: "user2@example.com"},
		{ID: 3, Email: "user3@example.com"},
	}

	for _, reg := range registrations {
		mockDAO.On("Save", mock.Anything, reg).Return(nil).Once()
		err := service.Create(ctx, reg)
		require.NoError(t, err)
	}

	mockDAO.AssertExpectations(t)
}

func TestRegistration_GetWithDifferentSessions(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockDAO := new(MockRegistrationDAO)

	service := NewRegistrationService(logger, mockDAO)
	registrationID := uint64(777)

	registration := &entities.Registration{
		ID:    registrationID,
		Email: "session@example.com",
	}

	// Test with system session
	systemSession := NewSession()
	mockDAO.On("Get", mock.Anything, registrationID).Return(registration, nil).Once()
	result, err := service.Get(ctx, systemSession, registrationID)
	require.NoError(t, err)
	assert.Equal(t, registration.Email, result.Email)

	// Test with user session
	user := &entities.User{ID: 1, Email: "user@example.com"}
	userSession := CreateSession(logger, 0, nil, user)
	mockDAO.On("Get", mock.Anything, registrationID).Return(registration, nil).Once()
	result, err = service.Get(ctx, userSession, registrationID)
	require.NoError(t, err)
	assert.Equal(t, registration.Email, result.Email)

	mockDAO.AssertExpectations(t)
}
