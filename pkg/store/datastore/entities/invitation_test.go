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

package entities

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNow is the instant every test in this file passes as now. Invitation
// takes time as a parameter (#311), so expiry and the timestamps it stamps are
// asserted exactly, not against a window around the wall clock.
var testNow = time.Date(2026, time.March, 14, 15, 9, 26, 0, time.UTC)

func TestNewInvitation(t *testing.T) {
	t.Run("Create new invitation with valid inputs", func(t *testing.T) {
		tenantID := "tenant-123"
		email := "user@example.com"
		role := "member"
		invitedByID := uint64(12345)
		expiresDuration := 72 * time.Hour

		invitation, err := NewInvitation(tenantID, email, role, invitedByID, expiresDuration, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.NotZero(t, invitation.ID)
		assert.NotEmpty(t, invitation.Token)
		assert.Equal(t, tenantID, invitation.TenantID)
		assert.Equal(t, email, invitation.Email)
		assert.Equal(t, role, invitation.Role)
		assert.Equal(t, InvitationStatusPending, invitation.Status)
		assert.Equal(t, invitedByID, invitation.InvitedByID)
		assert.Equal(t, testNow.Add(expiresDuration), invitation.ExpiresAt)
		assert.Nil(t, invitation.AcceptedAt)
	})

	t.Run("Create invitation with empty email", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "", "member", 1, time.Hour, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Empty(t, invitation.Email)
		assert.NotEmpty(t, invitation.Token)
	})

	t.Run("Create invitation with empty tenant ID", func(t *testing.T) {
		invitation, err := NewInvitation("", "user@example.com", "member", 1, time.Hour, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Empty(t, invitation.TenantID)
	})

	t.Run("Create invitation with empty role", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "", 1, time.Hour, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Empty(t, invitation.Role)
	})

	t.Run("Create invitation with zero invitedByID", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 0, time.Hour, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Zero(t, invitation.InvitedByID)
	})

	t.Run("Create invitation with negative duration (already expired)", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, -24*time.Hour, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.True(t, invitation.IsExpired(testNow))
	})

	t.Run("CreatedAt and UpdatedAt are the given instant", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Equal(t, testNow, invitation.CreatedAt)
		assert.Equal(t, testNow, invitation.UpdatedAt)
	})

	t.Run("Timestamps are stored in UTC whatever the caller's zone", func(t *testing.T) {
		local := testNow.In(time.FixedZone("UTC-5", -5*60*60))

		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, local)

		require.NoError(t, err)
		assert.Equal(t, time.UTC, invitation.CreatedAt.Location())
		assert.Equal(t, time.UTC, invitation.ExpiresAt.Location())
		assert.True(t, invitation.CreatedAt.Equal(testNow))
	})

	t.Run("Token is base64url encoded", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		// Base64url encoding of 32 bytes should be 44 characters (with padding)
		assert.Len(t, invitation.Token, 44)
	})
}

func TestNewInvitation_GeneratesUniqueTokens(t *testing.T) {
	t.Run("Different invitations have unique tokens", func(t *testing.T) {
		tokenSet := make(map[string]struct{})
		const numInvitations = 100

		for i := 0; i < numInvitations; i++ {
			invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, 72*time.Hour, testNow)
			require.NoError(t, err)
			require.NotNil(t, invitation)

			_, exists := tokenSet[invitation.Token]
			assert.False(t, exists, "Duplicate token found: %s", invitation.Token)
			tokenSet[invitation.Token] = struct{}{}
		}

		assert.Len(t, tokenSet, numInvitations)
	})

	t.Run("Different invitations have unique IDs", func(t *testing.T) {
		idSet := make(map[uint64]struct{})
		const numInvitations = 100

		for i := 0; i < numInvitations; i++ {
			invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, 72*time.Hour, testNow)
			require.NoError(t, err)
			require.NotNil(t, invitation)

			_, exists := idSet[invitation.ID]
			assert.False(t, exists, "Duplicate ID found: %d", invitation.ID)
			idSet[invitation.ID] = struct{}{}
		}

		assert.Len(t, idSet, numInvitations)
	})

	t.Run("Same inputs produce different tokens", func(t *testing.T) {
		tenantID := "tenant-123"
		email := "user@example.com"
		role := "member"
		invitedByID := uint64(1)
		expiresDuration := 72 * time.Hour

		inv1, err1 := NewInvitation(tenantID, email, role, invitedByID, expiresDuration, testNow)
		inv2, err2 := NewInvitation(tenantID, email, role, invitedByID, expiresDuration, testNow)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, inv1.Token, inv2.Token)
		assert.NotEqual(t, inv1.ID, inv2.ID)
	})
}

func TestInvitation_EntityID(t *testing.T) {
	t.Run("EntityID returns the invitation ID", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		entityID := invitation.EntityID()
		assert.Equal(t, invitation.ID, entityID)
		assert.NotZero(t, entityID)
	})

	t.Run("SetEntityID updates the invitation ID", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		originalID := invitation.ID
		newID := uint64(99999)
		invitation.SetEntityID(newID)

		assert.NotEqual(t, originalID, invitation.ID)
		assert.Equal(t, newID, invitation.ID)
		assert.Equal(t, newID, invitation.EntityID())
	})

	t.Run("SetEntityID to zero", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.SetEntityID(0)
		assert.Zero(t, invitation.ID)
		assert.Zero(t, invitation.EntityID())
	})

	t.Run("Invitation implements KeyValueEntity interface", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		var entity KeyValueEntity = invitation

		id := entity.EntityID()
		assert.NotZero(t, id)

		newID := uint64(12345)
		entity.SetEntityID(newID)
		assert.Equal(t, newID, entity.EntityID())
	})
}

func TestInvitation_IsExpired(t *testing.T) {
	newInvitation := func(t *testing.T) *Invitation {
		t.Helper()
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)
		return invitation
	}

	t.Run("Not expired before its expiry", func(t *testing.T) {
		invitation := newInvitation(t)

		assert.False(t, invitation.IsExpired(testNow))
		assert.False(t, invitation.IsExpired(invitation.ExpiresAt.Add(-time.Nanosecond)))
	})

	t.Run("Still valid at the exact instant it expires", func(t *testing.T) {
		invitation := newInvitation(t)

		assert.False(t, invitation.IsExpired(invitation.ExpiresAt))
	})

	t.Run("Expired one nanosecond after its expiry", func(t *testing.T) {
		invitation := newInvitation(t)

		assert.True(t, invitation.IsExpired(invitation.ExpiresAt.Add(time.Nanosecond)))
	})

	t.Run("Answer depends on when you ask, not when it was loaded", func(t *testing.T) {
		// A zero-value invitation is what the datastore reconstitutes before
		// decoding into it: it never runs NewInvitation, and must still answer.
		invitation := &Invitation{ExpiresAt: testNow}

		assert.False(t, invitation.IsExpired(testNow.Add(-365*24*time.Hour)))
		assert.True(t, invitation.IsExpired(testNow.Add(365*24*time.Hour)))
	})

	t.Run("Zone of now does not change the answer", func(t *testing.T) {
		invitation := newInvitation(t)
		east := time.FixedZone("UTC+9", 9*60*60)

		assert.False(t, invitation.IsExpired(invitation.ExpiresAt.In(east)))
		assert.True(t, invitation.IsExpired(invitation.ExpiresAt.Add(time.Second).In(east)))
	})

	t.Run("Invitation with zero expiry is expired", func(t *testing.T) {
		invitation := newInvitation(t)
		invitation.ExpiresAt = time.Time{}

		assert.True(t, invitation.IsExpired(testNow))
	})

	t.Run("Zero now fails closed", func(t *testing.T) {
		// A zero now is a caller that never read the clock. Since the zero
		// time precedes every expiry, answering literally would make every
		// invitation valid forever; an invitation is a credential, so it is
		// treated as expired instead.
		invitation := newInvitation(t)

		assert.True(t, invitation.IsExpired(time.Time{}))
		assert.False(t, invitation.CanAccept(time.Time{}))
	})
}

func TestInvitation_IsPending(t *testing.T) {
	t.Run("New invitation is pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		assert.Equal(t, InvitationStatusPending, invitation.Status)
	})

	t.Run("Accepted invitation is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = InvitationStatusAccepted
		assert.False(t, invitation.IsPending())
	})

	t.Run("Expired invitation is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = InvitationStatusExpired
		assert.False(t, invitation.IsPending())
	})

	t.Run("Revoked invitation is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = InvitationStatusRevoked
		assert.False(t, invitation.IsPending())
	})

	t.Run("Invitation with empty status is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = ""
		assert.False(t, invitation.IsPending())
	})

	t.Run("Invitation with invalid status is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = InvitationStatus("invalid")
		assert.False(t, invitation.IsPending())
	})
}

func TestInvitation_CanAccept(t *testing.T) {
	t.Run("Pending non-expired invitation can be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept(testNow))
	})

	t.Run("Pending expired invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, -time.Hour, testNow)
		require.NoError(t, err)

		assert.False(t, invitation.CanAccept(testNow))
	})

	t.Run("The same pending invitation stops being acceptable once now passes its expiry", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept(invitation.ExpiresAt))
		assert.False(t, invitation.CanAccept(invitation.ExpiresAt.Add(time.Nanosecond)))
		assert.Equal(t, InvitationStatusPending, invitation.Status, "asking does not mutate")
	})

	t.Run("Accepted invitation cannot be accepted again", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Accept(testNow)
		assert.False(t, invitation.CanAccept(testNow))
	})

	t.Run("Revoked invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Revoke(testNow)
		assert.False(t, invitation.CanAccept(testNow))
	})

	t.Run("Expired status invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Expire(testNow)
		assert.False(t, invitation.CanAccept(testNow))
	})

	t.Run("Non-pending non-expired invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = InvitationStatusAccepted
		assert.False(t, invitation.CanAccept(testNow))
	})
}

func TestInvitation_Accept(t *testing.T) {
	t.Run("Accept changes status to accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.Equal(t, InvitationStatusPending, invitation.Status)
		assert.Nil(t, invitation.AcceptedAt)

		invitation.Accept(testNow)

		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)
	})

	t.Run("Accept stamps AcceptedAt and UpdatedAt with the given instant", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)
		acceptedAt := testNow.Add(10 * time.Minute)

		invitation.Accept(acceptedAt)

		require.NotNil(t, invitation.AcceptedAt)
		assert.Equal(t, acceptedAt, *invitation.AcceptedAt)
		assert.Equal(t, acceptedAt, invitation.UpdatedAt)
		assert.Equal(t, testNow, invitation.CreatedAt)
	})

	t.Run("Accept stores UTC whatever the caller's zone", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Accept(testNow.In(time.FixedZone("UTC+2", 2*60*60)))

		require.NotNil(t, invitation.AcceptedAt)
		assert.Equal(t, testNow, *invitation.AcceptedAt)
		assert.Equal(t, testNow, invitation.UpdatedAt)
	})

	t.Run("Accept on already accepted invitation updates AcceptedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)
		later := testNow.Add(time.Millisecond)

		invitation.Accept(testNow)
		firstAcceptedAt := invitation.AcceptedAt
		invitation.Accept(later)

		assert.Equal(t, testNow, *firstAcceptedAt, "the first stamp is not overwritten in place")
		assert.Equal(t, later, *invitation.AcceptedAt)
		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
	})

	t.Run("Accept on expired status invitation changes to accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = InvitationStatusExpired
		invitation.Accept(testNow)

		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)
	})

	t.Run("Accept on revoked status invitation changes to accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		invitation.Status = InvitationStatusRevoked
		invitation.Accept(testNow)

		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)
	})

	t.Run("IsPending returns false after Accept", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		invitation.Accept(testNow)
		assert.False(t, invitation.IsPending())
	})
}

func TestInvitation_Revoke(t *testing.T) {
	t.Run("Revoke changes status to revoked", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.Equal(t, InvitationStatusPending, invitation.Status)
		invitation.Revoke(testNow)
		assert.Equal(t, InvitationStatusRevoked, invitation.Status)
	})

	t.Run("Revoke stamps UpdatedAt with the given instant", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)
		revokedAt := testNow.Add(5 * time.Minute)

		invitation.Revoke(revokedAt.In(time.FixedZone("UTC-3", -3*60*60)))

		assert.Equal(t, revokedAt, invitation.UpdatedAt)
		assert.Nil(t, invitation.AcceptedAt)
	})

	t.Run("IsPending returns false after Revoke", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		invitation.Revoke(testNow)
		assert.False(t, invitation.IsPending())
	})

	t.Run("CanAccept returns false after Revoke", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept(testNow))
		invitation.Revoke(testNow)
		assert.False(t, invitation.CanAccept(testNow))
	})

	t.Run("Revoke on already revoked invitation updates UpdatedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		later := testNow.Add(time.Millisecond)

		invitation.Revoke(testNow)
		invitation.Revoke(later)

		assert.Equal(t, later, invitation.UpdatedAt)
		assert.Equal(t, InvitationStatusRevoked, invitation.Status)
	})
}

func TestInvitation_Expire(t *testing.T) {
	t.Run("Expire changes status to expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.Equal(t, InvitationStatusPending, invitation.Status)
		invitation.Expire(testNow)
		assert.Equal(t, InvitationStatusExpired, invitation.Status)
	})

	t.Run("Expire stamps UpdatedAt with the given instant", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)
		expiredAt := invitation.ExpiresAt.Add(time.Second)

		invitation.Expire(expiredAt)

		assert.Equal(t, expiredAt, invitation.UpdatedAt)
		assert.Equal(t, testNow, invitation.CreatedAt)
	})

	t.Run("IsPending returns false after Expire", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		invitation.Expire(testNow)
		assert.False(t, invitation.IsPending())
	})

	t.Run("CanAccept returns false after Expire", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept(testNow))
		invitation.Expire(testNow)
		assert.False(t, invitation.CanAccept(testNow))
	})
}

func TestInvitation_GenerateToken(t *testing.T) {
	t.Run("GenerateToken creates new token", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		originalToken := invitation.Token
		originalID := invitation.ID

		err = invitation.GenerateToken(testNow)
		require.NoError(t, err)

		assert.NotEqual(t, originalToken, invitation.Token)
		assert.NotEqual(t, originalID, invitation.ID)
		assert.Len(t, invitation.Token, 44)
	})

	t.Run("GenerateToken stamps UpdatedAt with the given instant", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)
		reissuedAt := testNow.Add(time.Hour)

		err = invitation.GenerateToken(reissuedAt)
		require.NoError(t, err)

		assert.Equal(t, reissuedAt, invitation.UpdatedAt)
		assert.Equal(t, testNow, invitation.CreatedAt)
	})

	t.Run("GenerateToken generates unique tokens", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		tokenSet := make(map[string]struct{})
		tokenSet[invitation.Token] = struct{}{}

		for i := 0; i < 50; i++ {
			err = invitation.GenerateToken(testNow)
			require.NoError(t, err)

			_, exists := tokenSet[invitation.Token]
			assert.False(t, exists, "Duplicate token found: %s", invitation.Token)
			tokenSet[invitation.Token] = struct{}{}
		}
	})

	t.Run("GenerateToken preserves other fields", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		originalTenantID := invitation.TenantID
		originalEmail := invitation.Email
		originalRole := invitation.Role
		originalStatus := invitation.Status
		originalInvitedByID := invitation.InvitedByID
		originalExpiresAt := invitation.ExpiresAt
		originalCreatedAt := invitation.CreatedAt

		err = invitation.GenerateToken(testNow)
		require.NoError(t, err)

		assert.Equal(t, originalTenantID, invitation.TenantID)
		assert.Equal(t, originalEmail, invitation.Email)
		assert.Equal(t, originalRole, invitation.Role)
		assert.Equal(t, originalStatus, invitation.Status)
		assert.Equal(t, originalInvitedByID, invitation.InvitedByID)
		assert.Equal(t, originalExpiresAt, invitation.ExpiresAt)
		assert.Equal(t, originalCreatedAt, invitation.CreatedAt)
	})
}

func TestInvitationStatus_Constants(t *testing.T) {
	t.Run("Pending status has correct value", func(t *testing.T) {
		assert.Equal(t, InvitationStatus("pending"), InvitationStatusPending)
	})

	t.Run("Accepted status has correct value", func(t *testing.T) {
		assert.Equal(t, InvitationStatus("accepted"), InvitationStatusAccepted)
	})

	t.Run("Expired status has correct value", func(t *testing.T) {
		assert.Equal(t, InvitationStatus("expired"), InvitationStatusExpired)
	})

	t.Run("Revoked status has correct value", func(t *testing.T) {
		assert.Equal(t, InvitationStatus("revoked"), InvitationStatusRevoked)
	})

	t.Run("Status constants are unique", func(t *testing.T) {
		statuses := []InvitationStatus{
			InvitationStatusPending,
			InvitationStatusAccepted,
			InvitationStatusExpired,
			InvitationStatusRevoked,
		}

		seen := make(map[InvitationStatus]struct{})
		for _, status := range statuses {
			_, exists := seen[status]
			assert.False(t, exists, "Duplicate status value: %s", status)
			seen[status] = struct{}{}
		}

		assert.Len(t, seen, 4)
	})

	t.Run("Status values are non-empty strings", func(t *testing.T) {
		assert.NotEmpty(t, string(InvitationStatusPending))
		assert.NotEmpty(t, string(InvitationStatusAccepted))
		assert.NotEmpty(t, string(InvitationStatusExpired))
		assert.NotEmpty(t, string(InvitationStatusRevoked))
	})
}

func TestErrTokenGeneration(t *testing.T) {
	t.Run("Error message without cause", func(t *testing.T) {
		err := ErrTokenGeneration{}
		assert.Equal(t, "invitation: failed to generate secure token", err.Error())
	})

	t.Run("Error message with cause", func(t *testing.T) {
		cause := errors.New("random source unavailable")
		err := ErrTokenGeneration{Cause: cause}
		assert.Equal(t, "invitation: failed to generate secure token: random source unavailable", err.Error())
	})

	t.Run("Unwrap returns nil when no cause", func(t *testing.T) {
		err := ErrTokenGeneration{}
		assert.Nil(t, err.Unwrap())
	})

	t.Run("Unwrap returns the cause error", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrTokenGeneration{Cause: cause}
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("Error can be checked with errors.Is", func(t *testing.T) {
		cause := errors.New("specific error")
		err := ErrTokenGeneration{Cause: cause}

		assert.True(t, errors.Is(err, cause))
	})

	t.Run("Error implements error interface", func(t *testing.T) {
		var err error = ErrTokenGeneration{Cause: errors.New("test")}
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "failed to generate secure token")
	})

	t.Run("Nested error unwrapping", func(t *testing.T) {
		innerErr := errors.New("inner error")
		wrappedErr := ErrTokenGeneration{Cause: innerErr}

		assert.True(t, errors.Is(wrappedErr, innerErr))
		assert.Equal(t, innerErr, errors.Unwrap(wrappedErr))
	})
}

func TestInvitation_CompleteWorkflow(t *testing.T) {
	t.Run("Full invitation lifecycle", func(t *testing.T) {
		// Create invitation
		tenantID := "tenant-acme"
		email := "newuser@example.com"
		role := "admin"
		invitedByID := uint64(1001)
		expiresDuration := 72 * time.Hour

		invitation, err := NewInvitation(tenantID, email, role, invitedByID, expiresDuration, testNow)
		require.NoError(t, err)
		require.NotNil(t, invitation)

		// Verify initial state
		assert.True(t, invitation.IsPending())
		assert.False(t, invitation.IsExpired(testNow))
		assert.True(t, invitation.CanAccept(testNow))
		assert.Nil(t, invitation.AcceptedAt)

		// Verify all fields are populated
		assert.NotZero(t, invitation.ID)
		assert.NotEmpty(t, invitation.Token)
		assert.Equal(t, tenantID, invitation.TenantID)
		assert.Equal(t, email, invitation.Email)
		assert.Equal(t, role, invitation.Role)
		assert.Equal(t, invitedByID, invitation.InvitedByID)
		assert.False(t, invitation.ExpiresAt.IsZero())
		assert.False(t, invitation.CreatedAt.IsZero())
		assert.False(t, invitation.UpdatedAt.IsZero())

		// Accept the invitation
		invitation.Accept(testNow)

		// Verify accepted state
		assert.False(t, invitation.IsPending())
		assert.False(t, invitation.CanAccept(testNow))
		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)

		// Other fields should remain unchanged
		assert.Equal(t, tenantID, invitation.TenantID)
		assert.Equal(t, email, invitation.Email)
		assert.Equal(t, role, invitation.Role)
	})

	t.Run("Revocation workflow", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept(testNow))

		invitation.Revoke(testNow)

		assert.False(t, invitation.IsPending())
		assert.False(t, invitation.CanAccept(testNow))
		assert.Equal(t, InvitationStatusRevoked, invitation.Status)
	})

	t.Run("Token regeneration workflow", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour, testNow)
		require.NoError(t, err)

		originalToken := invitation.Token

		err = invitation.GenerateToken(testNow)
		require.NoError(t, err)

		assert.NotEqual(t, originalToken, invitation.Token)
		assert.True(t, invitation.CanAccept(testNow))
	})
}
