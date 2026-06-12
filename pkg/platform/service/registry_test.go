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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/serializer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockDatastoreFactory implements datastore.Factory for testing
type MockDatastoreFactory struct {
	mock.Mock
}

func (m *MockDatastoreFactory) UserDAO() (datastore.UserDAO, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(datastore.UserDAO), args.Error(1)
}

func (m *MockDatastoreFactory) RegistrationDAO() (datastore.RegistrationDAO, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(datastore.RegistrationDAO), args.Error(1)
}

func (m *MockDatastoreFactory) InvitationDAO() (datastore.InvitationDAO, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(datastore.InvitationDAO), args.Error(1)
}

func (m *MockDatastoreFactory) RoleDAO() (datastore.RoleDAO, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(datastore.RoleDAO), args.Error(1)
}

func (m *MockDatastoreFactory) WebAuthnDAO() (datastore.WebAuthnDAO, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(datastore.WebAuthnDAO), args.Error(1)
}

func (m *MockDatastoreFactory) SerializerType() serializer.SerializerType {
	args := m.Called()
	return args.Get(0).(serializer.SerializerType)
}

func TestNewRegistry_Success(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)

	require.NoError(t, err)
	require.NotNil(t, registry)
	mockFactory.AssertExpectations(t)
}

func TestNewRegistry_RegistrationDAOError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)

	expectedErr := errors.New("registration dao error")
	mockFactory.On("RegistrationDAO").Return(nil, expectedErr)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, registry)
	mockFactory.AssertExpectations(t)
}

func TestNewRegistry_RoleDAOError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)

	expectedErr := errors.New("role dao error")
	mockFactory.On("RoleDAO").Return(nil, expectedErr)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, registry)
	mockFactory.AssertExpectations(t)
}

func TestNewRegistry_UserDAOError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)

	expectedErr := errors.New("user dao error")
	mockFactory.On("UserDAO").Return(nil, expectedErr)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, registry)
	mockFactory.AssertExpectations(t)
}

func TestNewRegistry_WebAuthnDAOError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)

	expectedErr := errors.New("webauthn dao error")
	mockFactory.On("WebAuthnDAO").Return(nil, expectedErr)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, registry)
	mockFactory.AssertExpectations(t)
}

func TestRegistry_DeviceService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	deviceService := &device.Service{}

	registry, err := NewRegistry(logger, deviceService, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.DeviceService()
	assert.Equal(t, deviceService, result)
}

func TestRegistry_DeviceService_Nil(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.DeviceService()
	assert.Nil(t, result)
}

func TestRegistry_DNSService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	dnsService := &dns.Service{}

	registry, err := NewRegistry(logger, nil, nil, nil, dnsService, mockFactory)
	require.NoError(t, err)

	result := registry.DNSService()
	assert.Equal(t, dnsService, result)
}

func TestRegistry_DNSService_Nil(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.DNSService()
	assert.Nil(t, result)
}

func TestRegistry_UserService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.UserService()
	require.NotNil(t, result)
	assert.IsType(t, &User{}, result)
}

func TestRegistry_RegistrationService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.RegistrationService()
	require.NotNil(t, result)
	assert.IsType(t, &Registration{}, result)
}

func TestRegistry_WebAuthnSessionService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.WebAuthnSessionService()
	require.NotNil(t, result)
	assert.IsType(t, &WebAuthnSessionService{}, result)
}

func TestRegistry_AllServices(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	deviceService := &device.Service{}
	dnsService := &dns.Service{}

	registry, err := NewRegistry(logger, deviceService, nil, nil, dnsService, mockFactory)
	require.NoError(t, err)

	// Verify all services are accessible
	assert.Equal(t, deviceService, registry.DeviceService())
	assert.Equal(t, dnsService, registry.DNSService())
	assert.NotNil(t, registry.UserService())
	assert.NotNil(t, registry.RegistrationService())
	assert.NotNil(t, registry.WebAuthnSessionService())
}

func TestRegistry_ServicesAreReusable(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// Call each getter multiple times and verify same instance
	userService1 := registry.UserService()
	userService2 := registry.UserService()
	assert.Same(t, userService1, userService2)

	regService1 := registry.RegistrationService()
	regService2 := registry.RegistrationService()
	assert.Same(t, regService1, regService2)

	webAuthnService1 := registry.WebAuthnSessionService()
	webAuthnService2 := registry.WebAuthnSessionService()
	assert.Same(t, webAuthnService1, webAuthnService2)
}

func TestRegistry_ProfileService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	profileService := &device.ProfileService{}

	registry, err := NewRegistry(logger, nil, profileService, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.ProfileService()
	assert.Equal(t, profileService, result)
}

func TestRegistry_ProfileService_Nil(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.ProfileService()
	assert.Nil(t, result)
}

func TestRegistry_Struct(t *testing.T) {
	registry := &Registry{}

	assert.Nil(t, registry.deviceService)
	assert.Nil(t, registry.profileService)
	assert.Nil(t, registry.dnsService)
	assert.Nil(t, registry.userService)
	assert.Nil(t, registry.registrationService)
	assert.Nil(t, registry.webAuthnSessionService)
}

func TestRegistry_WithMockedUserService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// Test that the user service can be used
	userService := registry.UserService()
	require.NotNil(t, userService)

	// Setup mock expectations for user service operations
	user := &entities.User{ID: 1, Email: "test@example.com"}
	mockUserDAO.On("Save", mock.Anything, user).Return(nil)

	// Use the service
	err = userService.Save(context.Background(), user)
	require.NoError(t, err)
	mockUserDAO.AssertExpectations(t)
}

// TestRegistry_InvitationService verifies InvitationService getter returns the service
func TestRegistry_InvitationService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.InvitationService()
	require.NotNil(t, result)
	assert.IsType(t, &InvitationService{}, result)
	mockFactory.AssertExpectations(t)
}

// TestRegistry_InvitationService_NilWhenDAOFails verifies InvitationService is nil
// when DAO returns an error
func TestRegistry_InvitationService_NilWhenDAOFails(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	// InvitationDAO returns error
	mockFactory.On("InvitationDAO").Return(nil, errors.New("invitation dao not available"))

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	result := registry.InvitationService()
	assert.Nil(t, result)
	mockFactory.AssertExpectations(t)
}

// TestRegistry_TenantUserService verifies TenantUserService getter returns nil by default
// since it requires TenantManager which is not provided in basic NewRegistry
func TestRegistry_TenantUserService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// TenantUserService should be nil when TenantManager is not provided
	result := registry.TenantUserService()
	assert.Nil(t, result)
	mockFactory.AssertExpectations(t)
}

// TestRegistry_SetTenantUserService verifies setting the TenantUserService after initialization
func TestRegistry_SetTenantUserService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// Initially nil
	assert.Nil(t, registry.TenantUserService())

	// Create a mock tenant user service
	mockTenantUserService := &TenantUserService{}
	registry.SetTenantUserService(mockTenantUserService)

	// Should return the set service
	result := registry.TenantUserService()
	require.NotNil(t, result)
	assert.Equal(t, mockTenantUserService, result)
	mockFactory.AssertExpectations(t)
}

// TestRegistry_SetTenantUserService_Nil verifies setting nil TenantUserService
func TestRegistry_SetTenantUserService_Nil(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// Set a service first
	mockTenantUserService := &TenantUserService{}
	registry.SetTenantUserService(mockTenantUserService)
	require.NotNil(t, registry.TenantUserService())

	// Set nil to clear
	registry.SetTenantUserService(nil)
	assert.Nil(t, registry.TenantUserService())
	mockFactory.AssertExpectations(t)
}

// TestRegistry_SetInvitationService verifies setting the InvitationService after initialization
func TestRegistry_SetInvitationService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	// InvitationDAO returns error so initial service is nil
	mockFactory.On("InvitationDAO").Return(nil, errors.New("not available"))

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// Initially nil due to DAO error
	assert.Nil(t, registry.InvitationService())

	// Create a mock invitation service
	mockInvitationService := &InvitationService{}
	registry.SetInvitationService(mockInvitationService)

	// Should return the set service
	result := registry.InvitationService()
	require.NotNil(t, result)
	assert.Equal(t, mockInvitationService, result)
	mockFactory.AssertExpectations(t)
}

// TestRegistry_SetInvitationService_Nil verifies setting nil InvitationService
func TestRegistry_SetInvitationService_Nil(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// Initially has service
	require.NotNil(t, registry.InvitationService())

	// Set nil to clear
	registry.SetInvitationService(nil)
	assert.Nil(t, registry.InvitationService())
	mockFactory.AssertExpectations(t)
}

// TestRegistry_SetInvitationService_Replace verifies replacing the InvitationService
func TestRegistry_SetInvitationService_Replace(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockFactory := new(MockDatastoreFactory)
	mockRegDAO := new(MockRegistrationDAO)
	mockRoleDAO := new(MockRoleDAO)
	mockUserDAO := new(MockUserDAO)
	mockWebAuthnDAO := new(MockWebAuthnDAO)
	mockInvitationDAO := new(MockInvitationDAO)

	mockFactory.On("RegistrationDAO").Return(mockRegDAO, nil)
	mockFactory.On("RoleDAO").Return(mockRoleDAO, nil)
	mockFactory.On("UserDAO").Return(mockUserDAO, nil)
	mockFactory.On("WebAuthnDAO").Return(mockWebAuthnDAO, nil)
	mockFactory.On("InvitationDAO").Return(mockInvitationDAO, nil)

	registry, err := NewRegistry(logger, nil, nil, nil, nil, mockFactory)
	require.NoError(t, err)

	// Get original service
	original := registry.InvitationService()
	require.NotNil(t, original)

	// Replace with new service
	newService := &InvitationService{}
	registry.SetInvitationService(newService)

	// Should return new service
	result := registry.InvitationService()
	require.NotNil(t, result)
	assert.Equal(t, newService, result)
	assert.NotSame(t, original, result)
	mockFactory.AssertExpectations(t)
}
