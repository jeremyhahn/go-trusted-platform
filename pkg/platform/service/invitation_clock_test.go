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

// The tests in this file drive InvitationService from a fixed clock. Each one
// places the service's "now" relative to an invitation's expiry, so expiry is
// asserted at the boundary rather than a day either side of the wall clock.

// fixedInvitationClock is an invitationClock that always reports the same
// instant.
type fixedInvitationClock struct{ now time.Time }

func (c fixedInvitationClock) Now() time.Time { return c.now }

// clockNow is the instant the fixed clock reports, chosen far from the
// wall clock so a test that silently fell back to time.Now() would fail.
var clockNow = time.Date(2031, time.July, 4, 12, 0, 0, 0, time.UTC)

// newClockedInvitationService builds an InvitationService whose clock reports at.
func newClockedInvitationService(invDAO *MockInvitationDAO, userDAO *MockUserDAO, at time.Time) *InvitationService {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)
	service := NewInvitationService(logger, invDAO, userDAO)
	service.clk = fixedInvitationClock{now: at}
	return service
}

// pendingInvitationExpiringAt returns a pending invitation that expires at expiresAt.
func pendingInvitationExpiringAt(expiresAt time.Time) *entities.Invitation {
	return &entities.Invitation{
		ID:        7,
		Token:     "clock-token",
		TenantID:  "tenant-123",
		Email:     "user@example.com",
		Role:      "member",
		Status:    entities.InvitationStatusPending,
		ExpiresAt: expiresAt,
	}
}

func TestInvitationService_DefaultsToRealClock(t *testing.T) {
	logger := logging.NewLogger(slog.LevelWarn, os.Stderr)

	assert.IsType(t, realInvitationClock{}, NewInvitationService(logger, nil, nil).clk)
	assert.IsType(t, realInvitationClock{}, NewInvitationServiceWithExpiry(logger, nil, nil, time.Hour).clk)
}

func TestRealInvitationClock_Now(t *testing.T) {
	before := time.Now()
	got := realInvitationClock{}.Now()
	after := time.Now()

	assert.False(t, got.Before(before))
	assert.False(t, got.After(after))
}

func TestInvitationService_Create_StampsServiceClock(t *testing.T) {
	ctx := context.Background()
	mockInvDAO := new(MockInvitationDAO)
	mockUserDAO := new(MockUserDAO)
	mockUserDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).Return(nil)
	mockInvDAO.On("Save", ctx, mock.AnythingOfType("*entities.Invitation")).Return(nil)

	service := newClockedInvitationService(mockInvDAO, mockUserDAO, clockNow)
	invitation, err := service.Create(ctx, &CreateInvitationRequest{
		TenantID:    "tenant-123",
		Email:       "new@example.com",
		Role:        "member",
		InvitedByID: 1,
		ExpiresIn:   48 * time.Hour,
	})

	require.NoError(t, err)
	assert.Equal(t, clockNow, invitation.CreatedAt)
	assert.Equal(t, clockNow, invitation.UpdatedAt)
	assert.Equal(t, clockNow.Add(48*time.Hour), invitation.ExpiresAt)
}

func TestInvitationService_GetByToken_DecidedByServiceClock(t *testing.T) {
	ctx := context.Background()

	t.Run("valid at the instant it expires", func(t *testing.T) {
		mockInvDAO := new(MockInvitationDAO)
		invitation := pendingInvitationExpiringAt(clockNow)
		mockInvDAO.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)

		got, err := newClockedInvitationService(mockInvDAO, new(MockUserDAO), clockNow).
			GetByToken(ctx, invitation.Token)

		require.NoError(t, err)
		assert.Same(t, invitation, got)
	})

	t.Run("expired one nanosecond later", func(t *testing.T) {
		mockInvDAO := new(MockInvitationDAO)
		invitation := pendingInvitationExpiringAt(clockNow)
		mockInvDAO.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)

		_, err := newClockedInvitationService(mockInvDAO, new(MockUserDAO), clockNow.Add(time.Nanosecond)).
			GetByToken(ctx, invitation.Token)

		assert.ErrorIs(t, err, ErrInvitationExpired{Token: invitation.Token})
	})
}

func TestInvitationService_Accept_StampsServiceClock(t *testing.T) {
	ctx := context.Background()
	mockInvDAO := new(MockInvitationDAO)
	invitation := pendingInvitationExpiringAt(clockNow)
	mockInvDAO.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)
	mockInvDAO.On("Save", ctx, invitation).Return(nil)

	err := newClockedInvitationService(mockInvDAO, new(MockUserDAO), clockNow).
		Accept(ctx, invitation.Token, 42)

	require.NoError(t, err)
	assert.Equal(t, entities.InvitationStatusAccepted, invitation.Status)
	require.NotNil(t, invitation.AcceptedAt)
	assert.Equal(t, clockNow, *invitation.AcceptedAt)
	assert.Equal(t, clockNow, invitation.UpdatedAt)
}

func TestInvitationService_Accept_ExpiredStampsServiceClock(t *testing.T) {
	ctx := context.Background()
	mockInvDAO := new(MockInvitationDAO)
	invitation := pendingInvitationExpiringAt(clockNow)
	mockInvDAO.On("GetByToken", ctx, invitation.Token).Return(invitation, nil)
	mockInvDAO.On("Save", ctx, invitation).Return(nil)
	later := clockNow.Add(time.Nanosecond)

	err := newClockedInvitationService(mockInvDAO, new(MockUserDAO), later).
		Accept(ctx, invitation.Token, 42)

	assert.ErrorIs(t, err, ErrInvitationExpired{Token: invitation.Token})
	assert.Equal(t, entities.InvitationStatusExpired, invitation.Status)
	assert.Equal(t, later, invitation.UpdatedAt)
	assert.Nil(t, invitation.AcceptedAt)
	mockInvDAO.AssertExpectations(t)
}

func TestInvitationService_Revoke_StampsServiceClock(t *testing.T) {
	ctx := context.Background()
	mockInvDAO := new(MockInvitationDAO)
	invitation := pendingInvitationExpiringAt(clockNow.Add(time.Hour))
	mockInvDAO.On("Get", ctx, invitation.ID).Return(invitation, nil)
	mockInvDAO.On("Save", ctx, invitation).Return(nil)

	err := newClockedInvitationService(mockInvDAO, new(MockUserDAO), clockNow).
		Revoke(ctx, invitation.ID, 10)

	require.NoError(t, err)
	assert.Equal(t, entities.InvitationStatusRevoked, invitation.Status)
	assert.Equal(t, clockNow, invitation.UpdatedAt)
}

func TestInvitationService_CleanupExpired_UsesOneCutoff(t *testing.T) {
	ctx := context.Background()
	mockInvDAO := new(MockInvitationDAO)
	atCutoff := pendingInvitationExpiringAt(clockNow)
	pastCutoff := pendingInvitationExpiringAt(clockNow.Add(-time.Nanosecond))
	pastCutoff.ID = 8

	pages := [][]*entities.Invitation{{atCutoff}, {pastCutoff}}
	mockInvDAO.On("ForEachPage", ctx, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			fn := args.Get(2).(datastore.PagerFunc[*entities.Invitation])
			for i, page := range pages {
				require.NoError(t, fn(datastore.PageResult[*entities.Invitation]{
					Entities: page,
					Page:     i + 1,
					PageSize: 1,
					HasMore:  i < len(pages)-1,
				}))
			}
		}).Return(nil)
	mockInvDAO.On("Save", ctx, pastCutoff).Return(nil)

	count, err := newClockedInvitationService(mockInvDAO, new(MockUserDAO), clockNow).CleanupExpired(ctx)

	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, entities.InvitationStatusPending, atCutoff.Status)
	assert.Equal(t, entities.InvitationStatusExpired, pastCutoff.Status)
	assert.Equal(t, clockNow, pastCutoff.UpdatedAt)
	mockInvDAO.AssertExpectations(t)
}
