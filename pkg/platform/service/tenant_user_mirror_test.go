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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// mirroredUser records one MirrorUser call.
type mirroredUser struct {
	TenantID string
	Email    string
	Roles    []string
}

// fakeIAMMirror records MirrorUser calls and fails for the emails in failFor.
type fakeIAMMirror struct {
	mu      sync.Mutex
	calls   []mirroredUser
	failFor map[string]error
}

func (f *fakeIAMMirror) MirrorUser(_ context.Context, tenantID, email, _ string, roles []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, mirroredUser{TenantID: tenantID, Email: email, Roles: roles})
	return f.failFor[email]
}

// newMirroredRegistration wires a real TenantUserService over mocks with the
// given mirror, and primes the mocks for a registration that reaches the
// mirror step.
func newMirroredRegistration(
	t *testing.T,
	mirror IAMUserMirror,
	user *entities.User,
	tenantID string,
) (*TenantUserService, *MockUserServicer, *MockTenantManager) {
	t.Helper()
	ctx := context.Background()
	userService := new(MockUserServicer)
	tenantManager := new(MockTenantManager)

	svc := NewTenantUserService(&TenantUserServiceConfig{
		Logger:            newTestLogger(),
		UserService:       userService,
		InvitationService: new(MockInvitationServicer),
		TenantManager:     tenantManager,
		TokenIssuer:       new(MockTokenIssuer),
		IAMMirror:         mirror,
	}).(*TenantUserService)

	userService.On("GetByEmail", ctx, user.Email).Return(nil, ErrUserNotFound{Email: user.Email})
	tenantManager.On("CreateTenant", ctx, mock.AnythingOfType("*tenant.CreateTenantRequest")).
		Return(&tenant.TenantEntity{ID: tenantID, Name: tenantID}, nil)
	userService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(nil)

	return svc, userService, tenantManager
}

func TestRegisterNewUser_MirrorsOwnerWithOwnerRole(t *testing.T) {
	mirror := &fakeIAMMirror{}
	user := newTestUser("owner@example.com")
	svc, userService, tenantManager := newMirroredRegistration(t, mirror, user, "tenant-1")

	result, err := svc.RegisterNewUser(context.Background(), user)
	require.NoError(t, err)

	assert.Equal(t, "tenant-1", result.Tenant.ID)
	require.Len(t, mirror.calls, 1)
	assert.Equal(t, mirroredUser{TenantID: "tenant-1", Email: user.Email, Roles: []string{DefaultTenantOwnerRole}}, mirror.calls[0])
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	tenantManager.AssertNotCalled(t, "DeleteTenant", mock.Anything, mock.Anything)
}

func TestRegisterNewUser_MirrorFailureRollsBackRegistration(t *testing.T) {
	ctx := context.Background()
	user := newTestUser("owner@example.com")
	mirrorErr := errors.New("iam.role: not_found")
	mirror := &fakeIAMMirror{failFor: map[string]error{user.Email: mirrorErr}}
	svc, userService, tenantManager := newMirroredRegistration(t, mirror, user, "tenant-1")
	userService.On("Delete", ctx, user.ID).Return(nil)
	tenantManager.On("DeleteTenant", ctx, "tenant-1").Return(nil)

	result, err := svc.RegisterNewUser(ctx, user)

	assert.Nil(t, result)
	var mirrorFailed ErrIAMMirrorFailed
	require.ErrorAs(t, err, &mirrorFailed)
	assert.Equal(t, "tenant-1", mirrorFailed.TenantID)
	assert.ErrorIs(t, err, mirrorErr)
	userService.AssertCalled(t, "Delete", ctx, user.ID)
	tenantManager.AssertCalled(t, "DeleteTenant", ctx, "tenant-1")
}

func TestRegisterNewUser_MirrorFailureCleanupErrorsKeepTypedError(t *testing.T) {
	ctx := context.Background()
	user := newTestUser("owner@example.com")
	mirror := &fakeIAMMirror{failFor: map[string]error{user.Email: errors.New("iam unavailable")}}
	svc, userService, tenantManager := newMirroredRegistration(t, mirror, user, "tenant-1")
	userService.On("Delete", ctx, user.ID).Return(errors.New("store unavailable"))
	tenantManager.On("DeleteTenant", ctx, "tenant-1").Return(errors.New("iam unavailable"))

	_, err := svc.RegisterNewUser(ctx, user)

	var mirrorFailed ErrIAMMirrorFailed
	assert.ErrorAs(t, err, &mirrorFailed, "a failed cleanup must not mask the mirror failure")
}

func TestIAMMirrorRoles(t *testing.T) {
	assert.Equal(t, []string{DefaultTenantOwnerRole}, iamMirrorRoles(&entities.User{IsTenantOwner: true}))
	assert.Nil(t, iamMirrorRoles(&entities.User{IsTenantOwner: false}))
}

func TestErrIAMMirrorFailed(t *testing.T) {
	cause := errors.New("role not found")
	err := ErrIAMMirrorFailed{Email: "a@example.com", TenantID: "t1", Cause: cause}

	assert.Equal(t, "failed to mirror user a@example.com into IAM tenant t1: role not found", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}
