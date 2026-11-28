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
		"tenant-a", "owner@example.test", "admin", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)

	user := redeemInvitation(t, invitation)

	assert.True(t, user.IsTenantOwner,
		"redeeming the initial-admin invitation did not make the redeemer the tenant owner")
	assert.Equal(t, "tenant-a", user.TenantID)
}

// newMirroredInvitedRegistration wires a TenantUserService whose IAM mirror
// is the given recorder, with the mocks an owner-invitation redemption needs
// up to and including the user save (#2362).
func newMirroredInvitedRegistration(
	t *testing.T, mirror IAMUserMirror, invitation *entities.Invitation,
) (TenantUserServicer, *MockUserServicer, *MockInvitationServicer) {
	t.Helper()
	mockUserService := new(MockUserServicer)
	mockInvitationService := new(MockInvitationServicer)
	mockTenantManager := new(MockTenantManager)
	ctx := context.Background()

	svc := NewTenantUserService(&TenantUserServiceConfig{
		Logger:            logging.DefaultLogger(),
		UserService:       mockUserService,
		InvitationService: mockInvitationService,
		TenantManager:     mockTenantManager,
		TokenIssuer:       new(MockTokenIssuer),
		IAMMirror:         mirror,
	})
	mockUserService.On("GetByEmail", ctx, invitation.Email).
		Return(nil, ErrUserNotFound{Email: invitation.Email})
	mockInvitationService.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)
	mockTenantManager.On("GetTenant", ctx, invitation.TenantID).Return(&tenant.TenantEntity{
		ID:   invitation.TenantID,
		Name: invitation.TenantID,
	}, nil)
	mockUserService.On("Save", ctx, mock.AnythingOfType("*entities.User")).Return(nil)
	return svc, mockUserService, mockInvitationService
}

// TestRegisterInvitedUser_MirrorsInvitedOwnerIntoIAM: an owner who redeems
// the initial-admin invitation is mirrored into the tenant's IAM store with
// the owner role, as a self-registered owner is (#2362).
func TestRegisterInvitedUser_MirrorsInvitedOwnerIntoIAM(t *testing.T) {
	invitation, err := entities.NewInitialAdminInvitation(
		"tenant-a", "owner@example.test", DefaultTenantOwnerRole, 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	mirror := &fakeIAMMirror{}
	svc, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)
	invitationService.On("Accept", context.Background(), invitation.Token, mock.AnythingOfType("uint64")).
		Return(nil)

	_, err = svc.RegisterInvitedUser(context.Background(), newTestUser(invitation.Email), invitation.Token)
	require.NoError(t, err)

	require.Len(t, mirror.calls, 1)
	assert.Equal(t, mirroredUser{
		TenantID: "tenant-a", Email: invitation.Email, Roles: []string{DefaultTenantOwnerRole},
	}, mirror.calls[0])
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	invitationService.AssertCalled(t, "Accept", context.Background(), invitation.Token, mock.AnythingOfType("uint64"))
}

// An ordinary invitation carries a listed IAM role that the mirror must
// keep: a roleless IAM user would consume the invitation without the access
// it grants (#2362).
func TestRegisterInvitedUser_MirrorsOrdinaryInviteeWithInvitationRole(t *testing.T) {
	cases := []struct {
		name  string
		role  string
		roles []string
	}{
		{name: "admin", role: "admin", roles: []string{"admin"}},
		{name: "viewer", role: "viewer", roles: []string{"viewer"}},
		{name: "no role", role: "", roles: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invitation, err := entities.NewInvitation(
				"tenant-a", "member@example.test", tc.role, 999, 7*24*time.Hour, time.Now())
			require.NoError(t, err)
			mirror := &fakeIAMMirror{}
			svc, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)
			invitationService.On("Accept", context.Background(), invitation.Token, mock.AnythingOfType("uint64")).
				Return(nil)

			result, err := svc.RegisterInvitedUser(context.Background(), newTestUser(invitation.Email), invitation.Token)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, result.User)
			assert.False(t, result.User.IsTenantOwner)

			require.Len(t, mirror.calls, 1)
			assert.Equal(t, mirroredUser{
				TenantID: "tenant-a", Email: invitation.Email, Roles: tc.roles,
			}, mirror.calls[0])
			userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
		})
	}
}

// TestRegisterInvitedUser_MirrorFailureLeavesInvitationPending: when the IAM
// mirror refuses the invited owner, the saved user is deleted, the
// invitation is not accepted, and the typed mirror error is returned (#2362).
func TestRegisterInvitedUser_MirrorFailureLeavesInvitationPending(t *testing.T) {
	invitation, err := entities.NewInitialAdminInvitation(
		"tenant-a", "owner@example.test", DefaultTenantOwnerRole, 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	mirror := &fakeIAMMirror{failFor: map[string]error{invitation.Email: assert.AnError}}
	svc, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)
	userService.On("Delete", mock.Anything, mock.AnythingOfType("uint64")).Return(nil)

	_, err = svc.RegisterInvitedUser(context.Background(), newTestUser(invitation.Email), invitation.Token)
	var mirrorErr ErrIAMMirrorFailed
	require.ErrorAs(t, err, &mirrorErr)
	assert.Equal(t, "tenant-a", mirrorErr.TenantID)

	userService.AssertCalled(t, "Delete", mock.Anything, mock.AnythingOfType("uint64"))
	invitationService.AssertNotCalled(t, "Accept", mock.Anything, mock.Anything, mock.Anything)
}

// TestRegisterInvitedUser_AcceptFailureKeepsTheSavedUser: whatever Accept
// answers, this redemption cannot tell whether another one committed the
// same email-derived user and IAM identity, so the saved user and the mirror
// are kept and the error is returned (Tenant ruling, Codex #2362 round 16).
func TestRegisterInvitedUser_AcceptFailureKeepsTheSavedUser(t *testing.T) {
	cases := []struct {
		name   string
		err    func(token string) error
		target func() any
	}{
		{
			name:   "revoked during mirroring",
			err:    func(token string) error { return ErrInvitationAlreadyRevoked{Token: token} },
			target: func() any { return new(ErrInvitationAlreadyRevoked) },
		},
		{
			name:   "expired during mirroring",
			err:    func(token string) error { return ErrInvitationExpired{Token: token} },
			target: func() any { return new(ErrInvitationExpired) },
		},
		{
			name:   "not found during mirroring",
			err:    func(token string) error { return ErrInvitationNotFound{Token: token} },
			target: func() any { return new(ErrInvitationNotFound) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			invitation, err := entities.NewInvitation(
				"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
			require.NoError(t, err)
			mirror := &fakeIAMMirror{}
			svc, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)
			invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).
				Return(tc.err(invitation.Token))
			userService.On("Delete", mock.Anything, mock.AnythingOfType("uint64")).Return(nil).Maybe()

			result, err := svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
			assert.Nil(t, result)
			require.ErrorAs(t, err, tc.target())
			assert.Len(t, mirror.calls, 1)
			assert.Empty(t, mirror.undone, "an Accept failure undid the IAM mirror")
			userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
		})
	}
}

// gatedIAMMirror holds its first MirrorUser or MirrorInvitedUser call inside
// the mirror until the test releases it, so a second registration or
// redemption can be started while the first is mid-mirror.
type gatedIAMMirror struct {
	fakeIAMMirror
	entered chan struct{}
	release chan struct{}
	gated   bool
}

// hold blocks the first mirror call until the test closes release.
func (g *gatedIAMMirror) hold() {
	g.mu.Lock()
	first := !g.gated
	g.gated = true
	g.mu.Unlock()
	if first {
		close(g.entered)
		<-g.release
	}
}

func (g *gatedIAMMirror) MirrorInvitedUser(
	ctx context.Context, tenantID, email, displayName string, roles []string,
) (func(context.Context) error, error) {
	undo, err := g.fakeIAMMirror.MirrorInvitedUser(ctx, tenantID, email, displayName, roles)
	g.hold()
	return undo, err
}

func (g *gatedIAMMirror) MirrorUser(
	ctx context.Context, tenantID, email, displayName string, roles []string,
) error {
	err := g.fakeIAMMirror.MirrorUser(ctx, tenantID, email, displayName, roles)
	g.hold()
	return err
}

// TestRegisterInvitedUser_ConcurrentRedemptionNeverDeletesTheWinner: two
// redemptions of one email derive one user ID. Without a claim the second
// could save, mirror and accept while the first is mirroring, and the
// first's AlreadyAccepted rollback would delete the second's committed user
// and IAM identity. The gate makes the overlap deterministic: B starts only
// once A is inside the mirror (#2362).
func TestRegisterInvitedUser_ConcurrentRedemptionNeverDeletesTheWinner(t *testing.T) {
	ctx := context.Background()
	invitation, err := entities.NewInvitation(
		"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	mirror := &gatedIAMMirror{entered: make(chan struct{}), release: make(chan struct{})}
	svc, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).Return(nil).Once()
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).
		Return(ErrInvitationAlreadyAccepted{Token: invitation.Token})
	userService.On("Delete", ctx, mock.AnythingOfType("uint64")).Return(nil)

	type outcome struct {
		result *RegisterResult
		err    error
	}
	doneA := make(chan outcome, 1)
	go func() {
		result, err := svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
		doneA <- outcome{result, err}
	}()
	<-mirror.entered

	resultB, errB := svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
	close(mirror.release)
	a := <-doneA

	require.NoError(t, a.err)
	assert.NotNil(t, a.result)
	require.ErrorAs(t, errB, new(ErrInvitationRedemptionInProgress))
	assert.Nil(t, resultB)
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	userService.AssertNumberOfCalls(t, "Save", 1)
	invitationService.AssertNumberOfCalls(t, "Accept", 1)
	assert.Len(t, mirror.calls, 1)
	assert.Empty(t, mirror.undone)
}

// TestRegisterInvitedUser_AcrossServicesAnAcceptLoserKeepsTheWinner:
// claimRedemption is in-process, so two platformd instances sharing the
// stores can both save the email-derived user ID. When B accepts while A is
// mirroring, A's Accept answers AlreadyAccepted and A must not delete B's
// committed user or undo the IAM identity B's registration uses (Codex
// #2362).
func TestRegisterInvitedUser_AcrossServicesAnAcceptLoserKeepsTheWinner(t *testing.T) {
	ctx := context.Background()
	invitation, err := entities.NewInvitation(
		"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	mirror := &gatedIAMMirror{entered: make(chan struct{}), release: make(chan struct{})}
	svcA, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)

	// A second platformd over the same user store, invitation store and IAM.
	tenantManagerB := new(MockTenantManager)
	tenantManagerB.On("GetTenant", ctx, invitation.TenantID).Return(&tenant.TenantEntity{
		ID:   invitation.TenantID,
		Name: invitation.TenantID,
	}, nil)
	svcB := NewTenantUserService(&TenantUserServiceConfig{
		Logger:            logging.DefaultLogger(),
		UserService:       userService,
		InvitationService: invitationService,
		TenantManager:     tenantManagerB,
		TokenIssuer:       new(MockTokenIssuer),
		IAMMirror:         mirror,
	})

	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).Return(nil).Once()
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).
		Return(ErrInvitationAlreadyAccepted{Token: invitation.Token})
	userService.On("Delete", mock.Anything, mock.AnythingOfType("uint64")).Return(nil)

	type outcome struct {
		result *RegisterResult
		err    error
	}
	doneA := make(chan outcome, 1)
	go func() {
		result, err := svcA.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
		doneA <- outcome{result, err}
	}()
	<-mirror.entered

	resultB, errB := svcB.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
	close(mirror.release)
	a := <-doneA

	require.NoError(t, errB, "B wins the invitation")
	assert.NotNil(t, resultB)
	require.ErrorAs(t, a.err, new(ErrInvitationAlreadyAccepted))
	assert.Nil(t, a.result)
	// A Delete here is the Accept loser deleting the winner's user.
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	assert.Empty(t, mirror.undone, "the Accept loser undid the IAM identity the winner uses")
	userService.AssertNumberOfCalls(t, "Save", 2)
	invitationService.AssertNumberOfCalls(t, "Accept", 2)
	assert.Len(t, mirror.calls, 2)
}

// TestRegisterInvitedUser_AcrossServicesANotFoundAcceptKeepsTheWinner: as the
// AlreadyAccepted case above, but A's Accept answers ErrInvitationNotFound (a
// canceled or failed lookup). A cannot tell whether B committed, so it must
// not delete B's user or undo B's IAM identity (Codex #2362 round 16).
func TestRegisterInvitedUser_AcrossServicesANotFoundAcceptKeepsTheWinner(t *testing.T) {
	ctx := context.Background()
	invitation, err := entities.NewInvitation(
		"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	mirror := &gatedIAMMirror{entered: make(chan struct{}), release: make(chan struct{})}
	svcA, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)

	// A second platformd over the same user store, invitation store and IAM.
	tenantManagerB := new(MockTenantManager)
	tenantManagerB.On("GetTenant", ctx, invitation.TenantID).Return(&tenant.TenantEntity{
		ID:   invitation.TenantID,
		Name: invitation.TenantID,
	}, nil)
	svcB := NewTenantUserService(&TenantUserServiceConfig{
		Logger:            logging.DefaultLogger(),
		UserService:       userService,
		InvitationService: invitationService,
		TenantManager:     tenantManagerB,
		TokenIssuer:       new(MockTokenIssuer),
		IAMMirror:         mirror,
	})

	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).Return(nil).Once()
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).
		Return(ErrInvitationNotFound{Token: invitation.Token})
	userService.On("Delete", mock.Anything, mock.AnythingOfType("uint64")).Return(nil).Maybe()

	type outcome struct {
		result *RegisterResult
		err    error
	}
	doneA := make(chan outcome, 1)
	go func() {
		result, err := svcA.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
		doneA <- outcome{result, err}
	}()
	<-mirror.entered

	resultB, errB := svcB.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
	close(mirror.release)
	a := <-doneA

	require.NoError(t, errB, "B wins the invitation")
	assert.NotNil(t, resultB)
	require.ErrorAs(t, a.err, new(ErrInvitationNotFound))
	assert.Nil(t, a.result)
	// A Delete here is the Accept loser deleting the winner's user.
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	assert.Empty(t, mirror.undone, "the Accept loser undid the IAM identity the winner uses")
	userService.AssertNumberOfCalls(t, "Save", 2)
	invitationService.AssertNumberOfCalls(t, "Accept", 2)
	assert.Len(t, mirror.calls, 2)
}

// TestRegisterInvitedUser_ARetryAfterAFailedAcceptCompletes: a failed Accept
// keeps the saved user, and a retry of the same invitation completes the
// redemption instead of being refused as an existing user (Tenant ruling,
// Codex #2362 round 16).
func TestRegisterInvitedUser_ARetryAfterAFailedAcceptCompletes(t *testing.T) {
	ctx := context.Background()
	invitation, err := entities.NewInvitation(
		"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	mirror := &fakeIAMMirror{}

	userService := new(MockUserServicer)
	invitationService := new(MockInvitationServicer)
	tenantManager := new(MockTenantManager)
	svc := NewTenantUserService(&TenantUserServiceConfig{
		Logger:            logging.DefaultLogger(),
		UserService:       userService,
		InvitationService: invitationService,
		TenantManager:     tenantManager,
		TokenIssuer:       new(MockTokenIssuer),
		IAMMirror:         mirror,
	})

	leftover := new(entities.User)
	userService.On("GetByEmail", ctx, invitation.Email).
		Return(nil, ErrUserNotFound{Email: invitation.Email}).Once()
	userService.On("GetByEmail", ctx, invitation.Email).Return(leftover, nil)
	invitationService.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)
	tenantManager.On("GetTenant", ctx, invitation.TenantID).Return(&tenant.TenantEntity{
		ID:   invitation.TenantID,
		Name: invitation.TenantID,
	}, nil)
	userService.On("Save", ctx, mock.AnythingOfType("*entities.User")).
		Run(func(args mock.Arguments) { *leftover = *args.Get(1).(*entities.User) }).
		Return(nil)
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).
		Return(context.DeadlineExceeded).Once()
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).Return(nil)
	userService.On("Delete", mock.Anything, mock.Anything).Return(nil).Maybe()

	_, err = svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	// A Delete here is a failed Accept deleting the saved user.
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	assert.Empty(t, mirror.undone)

	result, err := svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
	require.NoError(t, err, "the retry completes the redemption")
	assert.NotNil(t, result)
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	assert.Empty(t, mirror.undone)
	userService.AssertNumberOfCalls(t, "Save", 2)
	invitationService.AssertNumberOfCalls(t, "Accept", 2)
	assert.Len(t, mirror.calls, 2)
}

// TestRegisterInvitedUser_AnExistingUserIsStillRefused: only an unaccepted
// redemption's own record lets a retry through. Another tenant's user, a
// user with no tenant, and the user of an accepted invitation are refused
// with ErrUserAlreadyExists and nothing is saved (#2362).
func TestRegisterInvitedUser_AnExistingUserIsStillRefused(t *testing.T) {
	cases := []struct {
		name     string
		existing *entities.User
		status   entities.InvitationStatus
	}{
		{
			name:     "another tenant's user",
			existing: &entities.User{ID: 7, Email: "member@example.test", TenantID: "tenant-b", CreatedAt: time.Now()},
			status:   entities.InvitationStatusPending,
		},
		{
			name:     "no tenant",
			existing: &entities.User{ID: 7, Email: "member@example.test", TenantID: "", CreatedAt: time.Now()},
			status:   entities.InvitationStatusPending,
		},
		{
			name:     "accepted invitation",
			existing: &entities.User{ID: 7, Email: "member@example.test", TenantID: "tenant-a", CreatedAt: time.Now()},
			status:   entities.InvitationStatusAccepted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			invitation, err := entities.NewInvitation(
				"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
			require.NoError(t, err)
			invitation.Status = tc.status

			userService := new(MockUserServicer)
			invitationService := new(MockInvitationServicer)
			svc := NewTenantUserService(&TenantUserServiceConfig{
				Logger:            logging.DefaultLogger(),
				UserService:       userService,
				InvitationService: invitationService,
				TenantManager:     new(MockTenantManager),
				TokenIssuer:       new(MockTokenIssuer),
				IAMMirror:         &fakeIAMMirror{},
			})
			userService.On("GetByEmail", ctx, invitation.Email).Return(tc.existing, nil)
			invitationService.On("GetByToken", ctx, invitation.Token).Return(invitation, nil).Maybe()

			result, err := svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
			require.ErrorAs(t, err, new(ErrUserAlreadyExists))
			assert.Nil(t, result)
			userService.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
		})
	}
}

// redemptionBindingFixture is one TenantUserService over mocks whose user
// store holds the single user Save writes, as the retry test's store does.
type redemptionBindingFixture struct {
	svc               TenantUserServicer
	userService       *MockUserServicer
	invitationService *MockInvitationServicer
	mirror            *fakeIAMMirror
	saved             *entities.User
}

// newRedemptionBindingFixture serves the given invitations by token. The
// first GetByEmail finds no user; every later one returns the user Save
// last wrote.
func newRedemptionBindingFixture(t *testing.T, ctx context.Context, invitations ...*entities.Invitation) *redemptionBindingFixture {
	t.Helper()
	f := &redemptionBindingFixture{
		userService:       new(MockUserServicer),
		invitationService: new(MockInvitationServicer),
		mirror:            &fakeIAMMirror{},
		saved:             new(entities.User),
	}
	tenantManager := new(MockTenantManager)
	f.svc = NewTenantUserService(&TenantUserServiceConfig{
		Logger:            logging.DefaultLogger(),
		UserService:       f.userService,
		InvitationService: f.invitationService,
		TenantManager:     tenantManager,
		TokenIssuer:       new(MockTokenIssuer),
		IAMMirror:         f.mirror,
	})
	email := invitations[0].Email
	f.userService.On("GetByEmail", ctx, email).
		Return(nil, ErrUserNotFound{Email: email}).Once()
	f.userService.On("GetByEmail", ctx, email).Return(f.saved, nil)
	for _, inv := range invitations {
		f.invitationService.On("GetByToken", ctx, inv.Token).Return(inv, nil).Maybe()
	}
	tenantManager.On("GetTenant", ctx, "tenant-a").Return(&tenant.TenantEntity{
		ID:   "tenant-a",
		Name: "tenant-a",
	}, nil).Maybe()
	f.userService.On("Save", ctx, mock.AnythingOfType("*entities.User")).
		Run(func(args mock.Arguments) { *f.saved = *args.Get(1).(*entities.User) }).
		Return(nil).Maybe()
	f.userService.On("Delete", mock.Anything, mock.Anything).Return(nil).Maybe()
	return f
}

// acceptedOn marks inv accepted when its Accept succeeds, as the
// invitation store does.
func acceptedOn(inv *entities.Invitation) func(mock.Arguments) {
	return func(mock.Arguments) { inv.Status = entities.InvitationStatusAccepted }
}

// acceptCalls counts the Accept calls made with token.
func acceptCalls(m *MockInvitationServicer, token string) int {
	n := 0
	for _, c := range m.Calls {
		if c.Method == "Accept" && c.Arguments.String(1) == token {
			n++
		}
	}
	return n
}

// TestRegisterInvitedUser_AnotherPendingInvitationCannotOverwriteARedeemedUser
// pins Codex round 17 P1 on #2362: two pending invitations for one email
// both predate the registration; once B is redeemed, redeeming A must not
// pass as a retry and overwrite the user B saved.
func TestRegisterInvitedUser_AnotherPendingInvitationCannotOverwriteARedeemedUser(t *testing.T) {
	ctx := context.Background()
	created := time.Now().Add(-time.Hour)
	invA, err := entities.NewInvitation("tenant-a", "member@example.test", "admin", 999, 7*24*time.Hour, created)
	require.NoError(t, err)
	invA.InitialAdmin = true
	invB, err := entities.NewInvitation("tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, created)
	require.NoError(t, err)
	require.NotEqual(t, invA.ID, invB.ID)

	f := newRedemptionBindingFixture(t, ctx, invA, invB)
	f.invitationService.On("Accept", ctx, invB.Token, mock.AnythingOfType("uint64")).
		Run(acceptedOn(invB)).Return(nil)
	f.invitationService.On("Accept", ctx, invA.Token, mock.AnythingOfType("uint64")).
		Run(acceptedOn(invA)).Return(nil).Maybe()

	_, err = f.svc.RegisterInvitedUser(ctx, newTestUser(invB.Email), invB.Token)
	require.NoError(t, err)

	result, err := f.svc.RegisterInvitedUser(ctx, newTestUser(invA.Email), invA.Token)
	require.ErrorAs(t, err, new(ErrUserAlreadyExists), "invitation A did not save this user")
	assert.Nil(t, result)
	f.userService.AssertNumberOfCalls(t, "Save", 1)
	assert.Zero(t, acceptCalls(f.invitationService, invA.Token), "A is never accepted")
	assert.Equal(t, "tenant-a", f.saved.TenantID)
	assert.False(t, f.saved.IsTenantOwner, "A's owner grant never reaches B's user")
	assert.True(t, f.saved.HasRole("viewer"))
	assert.False(t, f.saved.HasRole("admin"))
}

// TestRegisterInvitedUser_AFailedRedemptionIsRetryableOnlyByItsOwnInvitation
// pins that the user a failed Accept of A kept is A's retry only: another
// pending invitation B for the same email is refused, and A's own retry
// still completes.
func TestRegisterInvitedUser_AFailedRedemptionIsRetryableOnlyByItsOwnInvitation(t *testing.T) {
	ctx := context.Background()
	created := time.Now().Add(-time.Hour)
	invA, err := entities.NewInvitation("tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, created)
	require.NoError(t, err)
	invB, err := entities.NewInvitation("tenant-a", "member@example.test", "admin", 999, 7*24*time.Hour, created)
	require.NoError(t, err)

	f := newRedemptionBindingFixture(t, ctx, invA, invB)
	f.invitationService.On("Accept", ctx, invA.Token, mock.AnythingOfType("uint64")).
		Return(context.DeadlineExceeded).Once()
	f.invitationService.On("Accept", ctx, invA.Token, mock.AnythingOfType("uint64")).
		Run(acceptedOn(invA)).Return(nil)
	f.invitationService.On("Accept", ctx, invB.Token, mock.AnythingOfType("uint64")).
		Run(acceptedOn(invB)).Return(nil).Maybe()

	_, err = f.svc.RegisterInvitedUser(ctx, newTestUser(invA.Email), invA.Token)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	result, err := f.svc.RegisterInvitedUser(ctx, newTestUser(invB.Email), invB.Token)
	require.ErrorAs(t, err, new(ErrUserAlreadyExists), "B is not A's unfinished redemption")
	assert.Nil(t, result)
	f.userService.AssertNumberOfCalls(t, "Save", 1)
	assert.Zero(t, acceptCalls(f.invitationService, invB.Token))

	result, err = f.svc.RegisterInvitedUser(ctx, newTestUser(invA.Email), invA.Token)
	require.NoError(t, err, "A's own retry completes")
	assert.NotNil(t, result)
	f.userService.AssertNumberOfCalls(t, "Save", 2)
	assert.Equal(t, 2, acceptCalls(f.invitationService, invA.Token))
	f.userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
}

// TestRegisterInvitedUser_AUserWithNoOriginatingInvitationIsRefused pins
// that a user no invitation redemption saved (self-registered, or saved
// before #2362 recorded the invitation) is never taken for a retry.
func TestRegisterInvitedUser_AUserWithNoOriginatingInvitationIsRefused(t *testing.T) {
	ctx := context.Background()
	inv, err := entities.NewInvitation("tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now().Add(-time.Hour))
	require.NoError(t, err)

	f := newRedemptionBindingFixture(t, ctx, inv)
	*f.saved = entities.User{ID: 7, Email: inv.Email, TenantID: "tenant-a", CreatedAt: time.Now()}
	// The fixture's first lookup finds no user; this one exists already.
	_, _ = f.userService.GetByEmail(ctx, inv.Email)
	f.invitationService.On("Accept", ctx, inv.Token, mock.AnythingOfType("uint64")).Return(nil).Maybe()

	result, err := f.svc.RegisterInvitedUser(ctx, newTestUser(inv.Email), inv.Token)
	require.ErrorAs(t, err, new(ErrUserAlreadyExists))
	assert.Nil(t, result)
	f.userService.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
}

// cancelingIAMMirror cancels the request right after its IAM write, and
// records the context the returned undo runs on: whether it was already
// canceled and whether it carries a deadline.
type cancelingIAMMirror struct {
	fakeIAMMirror
	cancel          context.CancelFunc
	undoRan         bool
	undoCtxErr      error
	undoHasDeadline bool
}

func (c *cancelingIAMMirror) MirrorInvitedUser(
	ctx context.Context, tenantID, email, displayName string, roles []string,
) (func(context.Context) error, error) {
	undo, err := c.fakeIAMMirror.MirrorInvitedUser(ctx, tenantID, email, displayName, roles)
	c.cancel()
	if err != nil {
		return nil, err
	}
	return func(uctx context.Context) error {
		c.undoRan = true
		c.undoCtxErr = uctx.Err()
		_, c.undoHasDeadline = uctx.Deadline()
		return undo(uctx)
	}, nil
}

// TestRegisterInvitedUser_RollbackOutlivesACanceledRequest: a request
// canceled during a failed IAM mirror must still delete the saved user, on a
// bounded context the cancel does not reach. An Accept failure rolls nothing
// back (TestRegisterInvitedUser_AcceptFailureKeepsTheSavedUser) (#2362).
func TestRegisterInvitedUser_RollbackOutlivesACanceledRequest(t *testing.T) {
	cases := []struct {
		name      string
		mirrorErr error
	}{
		{"mirror failed", context.Canceled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			invitation, err := entities.NewInvitation(
				"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
			require.NoError(t, err)
			mirror := &cancelingIAMMirror{cancel: cancel}
			if tc.mirrorErr != nil {
				mirror.failFor = map[string]error{invitation.Email: tc.mirrorErr}
			}

			userService := new(MockUserServicer)
			invitationService := new(MockInvitationServicer)
			tenantManager := new(MockTenantManager)
			svc := NewTenantUserService(&TenantUserServiceConfig{
				Logger:            logging.DefaultLogger(),
				UserService:       userService,
				InvitationService: invitationService,
				TenantManager:     tenantManager,
				TokenIssuer:       new(MockTokenIssuer),
				IAMMirror:         mirror,
			})
			userService.On("GetByEmail", mock.Anything, invitation.Email).
				Return(nil, ErrUserNotFound{Email: invitation.Email})
			invitationService.On("GetByToken", mock.Anything, invitation.Token).Return(invitation, nil)
			tenantManager.On("GetTenant", mock.Anything, "tenant-a").
				Return(&tenant.TenantEntity{ID: "tenant-a", Name: "tenant-a"}, nil)
			userService.On("Save", mock.Anything, mock.AnythingOfType("*entities.User")).Return(nil)
			invitationService.On("Accept", mock.Anything, invitation.Token, mock.AnythingOfType("uint64")).
				Return(context.Canceled)
			deleteCtxErr := errors.New("Delete not called")
			var deleteHasDeadline bool
			userService.On("Delete", mock.Anything, mock.AnythingOfType("uint64")).
				Run(func(args mock.Arguments) {
					dctx := args.Get(0).(context.Context)
					deleteCtxErr = dctx.Err()
					_, deleteHasDeadline = dctx.Deadline()
				}).Return(nil)

			result, err := svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)

			assert.Nil(t, result)
			require.Error(t, err)
			assert.NoError(t, deleteCtxErr,
				"the saved user is deleted on a context the request's cancel does not reach")
			assert.True(t, deleteHasDeadline, "the rollback context is bounded")
		})
	}
}

// TestRegisterNewUser_RefusedWhileARedemptionOfTheEmailRuns: the
// self-registered and the invited user share one email-derived ID; without a
// shared claim B saves and finishes while A is mirroring, and A's Accept
// refusal then deletes B's committed user (#2362).
func TestRegisterNewUser_RefusedWhileARedemptionOfTheEmailRuns(t *testing.T) {
	ctx := context.Background()
	invitation, err := entities.NewInvitation(
		"tenant-a", "member@example.test", "viewer", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	mirror := &gatedIAMMirror{entered: make(chan struct{}), release: make(chan struct{})}
	svc, userService, invitationService := newMirroredInvitedRegistration(t, mirror, invitation)
	tenantManager := svc.(*TenantUserService).tenantManager.(*MockTenantManager)
	tenantManager.On("CreateTenant", ctx, mock.AnythingOfType("*tenant.CreateTenantRequest")).
		Return(&tenant.TenantEntity{ID: "tenant-b", Name: "tenant-b"}, nil)
	tenantManager.On("DeleteTenant", mock.Anything, mock.Anything).Return(nil)
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).
		Return(ErrInvitationExpired{Token: invitation.Token})
	userService.On("Delete", mock.Anything, mock.AnythingOfType("uint64")).Return(nil).Maybe()

	doneA := make(chan error, 1)
	go func() {
		_, err := svc.RegisterInvitedUser(ctx, newTestUser(invitation.Email), invitation.Token)
		doneA <- err
	}()
	<-mirror.entered

	resultB, errB := svc.RegisterNewUser(ctx, newTestUser(invitation.Email))
	close(mirror.release)
	errA := <-doneA

	require.ErrorAs(t, errB, new(ErrInvitationRedemptionInProgress),
		"a self-registration of an email under redemption is refused")
	assert.Nil(t, resultB)
	require.ErrorAs(t, errA, new(ErrInvitationExpired))
	tenantManager.AssertNotCalled(t, "CreateTenant", mock.Anything, mock.Anything)
	userService.AssertNumberOfCalls(t, "Save", 1)
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	assert.Len(t, mirror.calls, 1)
}

// TestRegisterInvitedUser_RefusedWhileASelfRegistrationOfTheEmailRuns is the
// converse: a redemption of an email whose self-registration is mid-mirror is
// refused, so it can neither accept nor roll back over the registered user
// (#2362).
func TestRegisterInvitedUser_RefusedWhileASelfRegistrationOfTheEmailRuns(t *testing.T) {
	ctx := context.Background()
	user := newTestUser("owner@example.com")
	mirror := &gatedIAMMirror{entered: make(chan struct{}), release: make(chan struct{})}
	svc, userService, tenantManager := newMirroredRegistration(t, mirror, user, "tenant-1")
	invitationService := svc.invitationService.(*MockInvitationServicer)
	invitation, err := entities.NewInvitation(
		"tenant-a", user.Email, "viewer", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)
	invitationService.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)
	tenantManager.On("GetTenant", ctx, "tenant-a").
		Return(&tenant.TenantEntity{ID: "tenant-a", Name: "tenant-a"}, nil)
	invitationService.On("Accept", ctx, invitation.Token, mock.AnythingOfType("uint64")).Return(nil)

	doneA := make(chan error, 1)
	go func() {
		_, err := svc.RegisterNewUser(ctx, user)
		doneA <- err
	}()
	<-mirror.entered

	resultB, errB := svc.RegisterInvitedUser(ctx, newTestUser(user.Email), invitation.Token)
	close(mirror.release)
	errA := <-doneA

	require.NoError(t, errA)
	require.ErrorAs(t, errB, new(ErrInvitationRedemptionInProgress))
	assert.Nil(t, resultB)
	invitationService.AssertNotCalled(t, "Accept", mock.Anything, mock.Anything, mock.Anything)
	userService.AssertNumberOfCalls(t, "Save", 1)
	userService.AssertNotCalled(t, "Delete", mock.Anything, mock.Anything)
	tenantManager.AssertNotCalled(t, "DeleteTenant", mock.Anything, mock.Anything)
	assert.Len(t, mirror.calls, 1)
}

// TestRegisterInvitedUser_OrdinaryInvitationsDoNotConferOwnership is the
// control, and the one that must never regress: the common path stays
// non-owner. Without it the test above would pass against a change that
// simply made everyone an owner.
func TestRegisterInvitedUser_OrdinaryInvitationsDoNotConferOwnership(t *testing.T) {
	invitation, err := entities.NewInvitation(
		"tenant-a", "member@example.test", "member", 999, 7*24*time.Hour, time.Now())
	require.NoError(t, err)

	assert.False(t, redeemInvitation(t, invitation).IsTenantOwner)
}

// TestRegisterInvitedUser_AnAdminRoleAloneDoesNotConferOwnership is the
// distinction the marker exists for. A tenant's SECOND administrator holds
// the same role as its first and must not own the tenant — if ownership were
// inferred from the role, every admin invitation would be an ownership grant.
func TestRegisterInvitedUser_AnAdminRoleAloneDoesNotConferOwnership(t *testing.T) {
	invitation, err := entities.NewInvitation(
		"tenant-a", "second-admin@example.test", "admin", 999, 7*24*time.Hour, time.Now())
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
	service.SetRoleLister(listedRoles("admin", "member", "viewer"))
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
