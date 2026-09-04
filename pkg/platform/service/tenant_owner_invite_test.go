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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// redeemInvitation runs the redemption path against an invitation and returns
// the user it produced.
func redeemInvitation(t *testing.T, invitation *entities.Invitation) *entities.User {
	t.Helper()

	logger := logging.DefaultLogger()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	service := NewTenantUserService(&TenantUserServiceConfig{
		Logger:            logger,
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
		TokenIssuer:       new(MockTokenIssuer),
	})

	user := newTestUser(invitation.Email)
	mockUserService.On("GetByEmail", ctx, user.Email).
		Return(nil, ErrUserNotFound{Email: user.Email})
	mockInvitationService.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)
	mockTenantManager.On("GetTenant", ctx, invitation.TenantID).Return(&tenant.TenantEntity{
		ID:   invitation.TenantID,
		Name: invitation.TenantID,
	}, nil)
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(nil)
	mockInvitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).
		Return(nil)

	result, err := service.RegisterInvitedUser(ctx, user, invitation.Token)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.User)
	return result.User
}

// TestRegisterInvitedUser_OwnershipComesFromTheInvitation is the #158
// behaviour. RegisterInvitedUser hardcoded IsTenantOwner = false, so the
// owner-enrollment half of the 2026-09-01 ruling could not be expressed at
// all — every redemption produced a non-owner regardless of intent.
func TestRegisterInvitedUser_OwnershipComesFromTheInvitation(t *testing.T) {
	invitation, err := entities.NewInitialAdminInvitation(
		"tenant-a", "owner@example.test", "admin", 999, 7*24*time.Hour)
	require.NoError(t, err)

	user := redeemInvitation(t, invitation)

	assert.True(t, user.IsTenantOwner,
		"redeeming the initial-admin invitation did not make the redeemer the tenant owner")
	assert.Equal(t, "tenant-a", user.TenantID)
}

// TestRegisterInvitedUser_OrdinaryInvitationsDoNotConferOwnership is the
// control, and the one that must never regress: the common path stays
// non-owner. Without it the test above would pass against a change that
// simply made everyone an owner.
func TestRegisterInvitedUser_OrdinaryInvitationsDoNotConferOwnership(t *testing.T) {
	invitation, err := entities.NewInvitation(
		"tenant-a", "member@example.test", "member", 999, 7*24*time.Hour)
	require.NoError(t, err)

	assert.False(t, redeemInvitation(t, invitation).IsTenantOwner)
}

// TestRegisterInvitedUser_AnAdminRoleAloneDoesNotConferOwnership is the
// distinction the marker exists for. A tenant's SECOND administrator holds
// the same role as its first and must not own the tenant — if ownership were
// inferred from the role, every admin invitation would be an ownership grant.
func TestRegisterInvitedUser_AnAdminRoleAloneDoesNotConferOwnership(t *testing.T) {
	invitation, err := entities.NewInvitation(
		"tenant-a", "second-admin@example.test", "admin", 999, 7*24*time.Hour)
	require.NoError(t, err)

	user := redeemInvitation(t, invitation)

	assert.True(t, user.HasRole("admin"), "the admin role should still be granted")
	assert.False(t, user.IsTenantOwner,
		"an admin-role invitation conferred tenant ownership")
}

// TestInvitationServicer_DoesNotExposeOwnerMinting guards the narrowing that
// keeps CreateInitialAdmin off InvitationServicer.
//
// Every holder of an InvitationServicer serves tenant-scoped callers -- the
// gRPC service and MCP tool provider in pkg/api/daemon, the WebAuthn handler,
// TenantUserService. Widening the interface would hand owner-minting to all of
// them at once, and the MCP provider in particular is one dispatch entry away
// from exposing it as a tool. Ownership must be conferred only by a call site
// that names *InvitationService.CreateInitialAdmin directly.
//
// This is a design decision a comment alone cannot hold: adding the method to
// the interface compiles, passes every other test, and silently widens the
// capability. So assert it.
func TestInvitationServicer_DoesNotExposeOwnerMinting(t *testing.T) {
	iface := reflect.TypeOf((*InvitationServicer)(nil)).Elem()

	if _, found := iface.MethodByName("CreateInitialAdmin"); found {
		t.Fatal("CreateInitialAdmin is on InvitationServicer: every tenant-scoped " +
			"holder of that interface can now mint a tenant owner. Keep it on " +
			"*InvitationService and give the consumer its own one-method interface.")
	}

	// The control: an ordinary Create IS on the interface, so a typo in the
	// method name above cannot make this test pass vacuously.
	if _, found := iface.MethodByName("Create"); !found {
		t.Fatal("Create is missing from InvitationServicer; this test is not " +
			"looking at the interface it thinks it is")
	}
}

// TestInvitationService_StillOffersOwnerMinting is the converse: the capability
// must exist on the concrete type. Without this, deleting CreateInitialAdmin
// outright would satisfy the test above.
func TestInvitationService_StillOffersOwnerMinting(t *testing.T) {
	concrete := reflect.TypeOf((*InvitationService)(nil))

	if _, found := concrete.MethodByName("CreateInitialAdmin"); !found {
		t.Fatal("*InvitationService.CreateInitialAdmin is gone; nothing can " +
			"confer tenant ownership on an invitation any more")
	}
}

// noExistingUser wires the duplicate-email pre-check to report an empty tenant,
// which is the only thing the create path needs from the user DAO.
func noExistingUser(ctx context.Context, mockUserDAO *MockUserDAO) {
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.User])
			_ = fn(datastore.PageResult[*entities.User]{
				Entities: []*entities.User{},
				Page:     1,
				PageSize: 100,
				HasMore:  false,
			})
		}).Return(nil)
}

// TestInvitationService_CreateInitialAdmin_PersistsTheMarker asserts the marker
// reaches the DAO, not merely the returned struct.
//
// The returned value is not the interesting one: redemption reads the
// invitation back from storage, so an implementation that set InitialAdmin on
// the value it returned and saved an unmarked entity would satisfy a
// return-value assertion and still produce a non-owner on redemption. Capture
// what Save actually received.
//
// It also asserts a SINGLE save. The first implementation created an ordinary
// invitation and marked it in a second write; a failure between the two left a
// redeemable ordinary invitation behind while the caller saw an error.
func TestInvitationService_CreateInitialAdmin_PersistsTheMarker(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)
	noExistingUser(ctx, mockUserDAO)

	var saved []*entities.Invitation
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).
		Run(func(args mock.Arguments) {
			saved = append(saved, args.Get(1).(*entities.Invitation))
		}).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.CreateInitialAdmin(ctx, &CreateInvitationRequest{
		TenantID:    "tenant-123",
		Email:       "first-admin@example.com",
		Role:        "admin",
		InvitedByID: 1,
	})

	require.NoError(t, err)
	require.NotNil(t, invitation)
	assert.True(t, invitation.InitialAdmin, "returned invitation must carry the marker")

	require.Len(t, saved, 1, "the invitation must be persisted in one write, "+
		"or a failed second write leaves an ordinary invitation redeemable")
	assert.True(t, saved[0].InitialAdmin,
		"the PERSISTED invitation must carry the marker; redemption reads it back from storage")

	mockInvDAO.AssertExpectations(t)
	mockUserDAO.AssertExpectations(t)
}

// TestInvitationService_Create_DoesNotSetTheMarker is the control: the ordinary
// path must persist an unmarked invitation. Without it, an implementation that
// marked every invitation would pass the test above.
func TestInvitationService_Create_DoesNotSetTheMarker(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)
	noExistingUser(ctx, mockUserDAO)

	var saved *entities.Invitation
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).
		Run(func(args mock.Arguments) {
			saved = args.Get(1).(*entities.Invitation)
		}).Return(nil)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.Create(ctx, &CreateInvitationRequest{
		TenantID:    "tenant-123",
		Email:       "member@example.com",
		Role:        "admin",
		InvitedByID: 1,
	})

	require.NoError(t, err)
	require.NotNil(t, invitation)
	assert.False(t, invitation.InitialAdmin)
	require.NotNil(t, saved)
	assert.False(t, saved.InitialAdmin,
		"an ordinary invitation must never be persisted as an owner invitation, "+
			"whatever role it carries")
}

// TestInvitationService_CreateInitialAdmin_SaveFails verifies the error path:
// a failed write must surface as ErrInvitationSaveFailed and return nothing,
// so no caller treats a dropped invitation as a provisioned tenant admin.
func TestInvitationService_CreateInitialAdmin_SaveFails(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)
	noExistingUser(ctx, mockUserDAO)

	cause := errors.New("database connection failed")
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(cause)

	service := NewInvitationService(logger, mockInvDAO, mockUserDAO)
	invitation, err := service.CreateInitialAdmin(ctx, &CreateInvitationRequest{
		TenantID:    "tenant-123",
		Email:       "first-admin@example.com",
		Role:        "admin",
		InvitedByID: 1,
	})

	require.Error(t, err)
	assert.Nil(t, invitation)
	var saveFailed ErrInvitationSaveFailed
	require.True(t, errors.As(err, &saveFailed))
	assert.Equal(t, cause, saveFailed.Cause)
	mockInvDAO.AssertExpectations(t)
	mockUserDAO.AssertExpectations(t)
}

// TestInvitationService_CreateInitialAdmin_RejectsInvalidRequests verifies the
// owner path applies the same validation as the ordinary one -- it must not
// become a way around the checks by virtue of being a different method.
func TestInvitationService_CreateInitialAdmin_RejectsInvalidRequests(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)

	cases := map[string]*CreateInvitationRequest{
		"nil request": nil,
		"no tenant":   {Email: "a@example.com", Role: "admin", InvitedByID: 1},
		"no email":    {TenantID: "tenant-123", Role: "admin", InvitedByID: 1},
		"no role":     {TenantID: "tenant-123", Email: "a@example.com", InvitedByID: 1},
		"no inviter":  {TenantID: "tenant-123", Email: "a@example.com", Role: "admin"},
	}

	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			mockInvDAO := new(MockInvitationDAO)
			mockUserDAO := new(MockUserDAO)
			service := NewInvitationService(logger, mockInvDAO, mockUserDAO)

			invitation, err := service.CreateInitialAdmin(context.Background(), req)

			require.Error(t, err)
			assert.Nil(t, invitation)
			var invalid ErrInvalidInvitation
			assert.True(t, errors.As(err, &invalid))
			mockInvDAO.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
		})
	}
}
