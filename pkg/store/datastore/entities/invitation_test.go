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

func TestNewInvitation(t *testing.T) {
	t.Run("Create new invitation with valid inputs", func(t *testing.T) {
		tenantID := "tenant-123"
		email := "user@example.com"
		role := "member"
		invitedByID := uint64(12345)
		expiresDuration := 72 * time.Hour

		before := time.Now().UTC()
		invitation, err := NewInvitation(tenantID, email, role, invitedByID, expiresDuration)
		after := time.Now().UTC()

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.NotZero(t, invitation.ID)
		assert.NotEmpty(t, invitation.Token)
		assert.Equal(t, tenantID, invitation.TenantID)
		assert.Equal(t, email, invitation.Email)
		assert.Equal(t, role, invitation.Role)
		assert.Equal(t, InvitationStatusPending, invitation.Status)
		assert.Equal(t, invitedByID, invitation.InvitedByID)
		assert.True(t, invitation.ExpiresAt.After(before.Add(expiresDuration-time.Second)))
		assert.True(t, invitation.ExpiresAt.Before(after.Add(expiresDuration+time.Second)))
		assert.False(t, invitation.CreatedAt.IsZero())
		assert.False(t, invitation.UpdatedAt.IsZero())
		assert.Nil(t, invitation.AcceptedAt)
	})

	t.Run("Create invitation with empty email", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "", "member", 1, time.Hour)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Empty(t, invitation.Email)
		assert.NotEmpty(t, invitation.Token)
	})

	t.Run("Create invitation with empty tenant ID", func(t *testing.T) {
		invitation, err := NewInvitation("", "user@example.com", "member", 1, time.Hour)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Empty(t, invitation.TenantID)
	})

	t.Run("Create invitation with empty role", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "", 1, time.Hour)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Empty(t, invitation.Role)
	})

	t.Run("Create invitation with zero invitedByID", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 0, time.Hour)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.Zero(t, invitation.InvitedByID)
	})

	t.Run("Create invitation with negative duration (already expired)", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, -24*time.Hour)

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.True(t, invitation.IsExpired())
	})

	t.Run("CreatedAt and UpdatedAt are set to current UTC time", func(t *testing.T) {
		before := time.Now().UTC()
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		after := time.Now().UTC()

		require.NoError(t, err)
		require.NotNil(t, invitation)
		assert.True(t, invitation.CreatedAt.Equal(before) || invitation.CreatedAt.After(before))
		assert.True(t, invitation.CreatedAt.Equal(after) || invitation.CreatedAt.Before(after))
		assert.True(t, invitation.UpdatedAt.Equal(before) || invitation.UpdatedAt.After(before))
		assert.True(t, invitation.UpdatedAt.Equal(after) || invitation.UpdatedAt.Before(after))
		assert.Equal(t, invitation.CreatedAt, invitation.UpdatedAt)
	})

	t.Run("Token is base64url encoded", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)

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
			invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, 72*time.Hour)
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
			invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, 72*time.Hour)
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

		inv1, err1 := NewInvitation(tenantID, email, role, invitedByID, expiresDuration)
		inv2, err2 := NewInvitation(tenantID, email, role, invitedByID, expiresDuration)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, inv1.Token, inv2.Token)
		assert.NotEqual(t, inv1.ID, inv2.ID)
	})
}

func TestInvitation_EntityID(t *testing.T) {
	t.Run("EntityID returns the invitation ID", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		entityID := invitation.EntityID()
		assert.Equal(t, invitation.ID, entityID)
		assert.NotZero(t, entityID)
	})

	t.Run("SetEntityID updates the invitation ID", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalID := invitation.ID
		newID := uint64(99999)
		invitation.SetEntityID(newID)

		assert.NotEqual(t, originalID, invitation.ID)
		assert.Equal(t, newID, invitation.ID)
		assert.Equal(t, newID, invitation.EntityID())
	})

	t.Run("SetEntityID to zero", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.SetEntityID(0)
		assert.Zero(t, invitation.ID)
		assert.Zero(t, invitation.EntityID())
	})

	t.Run("Invitation implements KeyValueEntity interface", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
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
	t.Run("Invitation with future expiration is not expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, 72*time.Hour)
		require.NoError(t, err)

		assert.False(t, invitation.IsExpired())
	})

	t.Run("Invitation with past expiration is expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, -1*time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.IsExpired())
	})

	t.Run("Invitation expiring in 1 second is not expired yet", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Second)
		require.NoError(t, err)

		assert.False(t, invitation.IsExpired())
	})

	t.Run("Invitation that expired 1 second ago is expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, -1*time.Second)
		require.NoError(t, err)

		assert.True(t, invitation.IsExpired())
	})

	t.Run("Invitation with zero time is expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)
		invitation.ExpiresAt = time.Time{}

		assert.True(t, invitation.IsExpired())
	})

	t.Run("Invitation expiring far in the future is not expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, 365*24*time.Hour)
		require.NoError(t, err)

		assert.False(t, invitation.IsExpired())
	})

	t.Run("Invitation that expired long ago is expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, -365*24*time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.IsExpired())
	})
}

func TestInvitation_IsPending(t *testing.T) {
	t.Run("New invitation is pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		assert.Equal(t, InvitationStatusPending, invitation.Status)
	})

	t.Run("Accepted invitation is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = InvitationStatusAccepted
		assert.False(t, invitation.IsPending())
	})

	t.Run("Expired invitation is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = InvitationStatusExpired
		assert.False(t, invitation.IsPending())
	})

	t.Run("Revoked invitation is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = InvitationStatusRevoked
		assert.False(t, invitation.IsPending())
	})

	t.Run("Invitation with empty status is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = ""
		assert.False(t, invitation.IsPending())
	})

	t.Run("Invitation with invalid status is not pending", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = InvitationStatus("invalid")
		assert.False(t, invitation.IsPending())
	})
}

func TestInvitation_CanAccept(t *testing.T) {
	t.Run("Pending non-expired invitation can be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept())
	})

	t.Run("Pending expired invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, -time.Hour)
		require.NoError(t, err)

		assert.False(t, invitation.CanAccept())
	})

	t.Run("Accepted invitation cannot be accepted again", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Accept()
		assert.False(t, invitation.CanAccept())
	})

	t.Run("Revoked invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Revoke()
		assert.False(t, invitation.CanAccept())
	})

	t.Run("Expired status invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Expire()
		assert.False(t, invitation.CanAccept())
	})

	t.Run("Non-pending non-expired invitation cannot be accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = InvitationStatusAccepted
		assert.False(t, invitation.CanAccept())
	})
}

func TestInvitation_Accept(t *testing.T) {
	t.Run("Accept changes status to accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.Equal(t, InvitationStatusPending, invitation.Status)
		assert.Nil(t, invitation.AcceptedAt)

		invitation.Accept()

		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)
	})

	t.Run("Accept sets AcceptedAt to current UTC time", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		before := time.Now().UTC()
		invitation.Accept()
		after := time.Now().UTC()

		require.NotNil(t, invitation.AcceptedAt)
		assert.True(t, invitation.AcceptedAt.Equal(before) || invitation.AcceptedAt.After(before))
		assert.True(t, invitation.AcceptedAt.Equal(after) || invitation.AcceptedAt.Before(after))
	})

	t.Run("Accept updates UpdatedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalUpdatedAt := invitation.UpdatedAt

		before := time.Now().UTC()
		invitation.Accept()
		after := time.Now().UTC()

		assert.True(t, invitation.UpdatedAt.Equal(originalUpdatedAt) || invitation.UpdatedAt.After(originalUpdatedAt))
		assert.True(t, invitation.UpdatedAt.Equal(before) || invitation.UpdatedAt.After(before))
		assert.True(t, invitation.UpdatedAt.Equal(after) || invitation.UpdatedAt.Before(after))
	})

	t.Run("Accept on already accepted invitation updates AcceptedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Accept()
		firstAcceptedAt := *invitation.AcceptedAt

		// Ensure some time passes
		time.Sleep(1 * time.Millisecond)

		invitation.Accept()
		secondAcceptedAt := *invitation.AcceptedAt

		assert.True(t, secondAcceptedAt.After(firstAcceptedAt) || secondAcceptedAt.Equal(firstAcceptedAt))
		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
	})

	t.Run("Accept on expired status invitation changes to accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = InvitationStatusExpired
		invitation.Accept()

		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)
	})

	t.Run("Accept on revoked status invitation changes to accepted", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Status = InvitationStatusRevoked
		invitation.Accept()

		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)
	})

	t.Run("IsPending returns false after Accept", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		invitation.Accept()
		assert.False(t, invitation.IsPending())
	})
}

func TestInvitation_Revoke(t *testing.T) {
	t.Run("Revoke changes status to revoked", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.Equal(t, InvitationStatusPending, invitation.Status)
		invitation.Revoke()
		assert.Equal(t, InvitationStatusRevoked, invitation.Status)
	})

	t.Run("Revoke updates UpdatedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalUpdatedAt := invitation.UpdatedAt

		before := time.Now().UTC()
		invitation.Revoke()
		after := time.Now().UTC()

		assert.True(t, invitation.UpdatedAt.Equal(originalUpdatedAt) || invitation.UpdatedAt.After(originalUpdatedAt))
		assert.True(t, invitation.UpdatedAt.Equal(before) || invitation.UpdatedAt.After(before))
		assert.True(t, invitation.UpdatedAt.Equal(after) || invitation.UpdatedAt.Before(after))
	})

	t.Run("IsPending returns false after Revoke", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		invitation.Revoke()
		assert.False(t, invitation.IsPending())
	})

	t.Run("CanAccept returns false after Revoke", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept())
		invitation.Revoke()
		assert.False(t, invitation.CanAccept())
	})

	t.Run("Revoke on already revoked invitation updates UpdatedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		invitation.Revoke()
		firstUpdatedAt := invitation.UpdatedAt

		time.Sleep(1 * time.Millisecond)
		invitation.Revoke()

		assert.True(t, invitation.UpdatedAt.After(firstUpdatedAt) || invitation.UpdatedAt.Equal(firstUpdatedAt))
	})
}

func TestInvitation_Expire(t *testing.T) {
	t.Run("Expire changes status to expired", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.Equal(t, InvitationStatusPending, invitation.Status)
		invitation.Expire()
		assert.Equal(t, InvitationStatusExpired, invitation.Status)
	})

	t.Run("Expire updates UpdatedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalUpdatedAt := invitation.UpdatedAt

		before := time.Now().UTC()
		invitation.Expire()
		after := time.Now().UTC()

		assert.True(t, invitation.UpdatedAt.Equal(originalUpdatedAt) || invitation.UpdatedAt.After(originalUpdatedAt))
		assert.True(t, invitation.UpdatedAt.Equal(before) || invitation.UpdatedAt.After(before))
		assert.True(t, invitation.UpdatedAt.Equal(after) || invitation.UpdatedAt.Before(after))
	})

	t.Run("IsPending returns false after Expire", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.IsPending())
		invitation.Expire()
		assert.False(t, invitation.IsPending())
	})

	t.Run("CanAccept returns false after Expire", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept())
		invitation.Expire()
		assert.False(t, invitation.CanAccept())
	})
}

func TestInvitation_GenerateToken(t *testing.T) {
	t.Run("GenerateToken creates new token", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalToken := invitation.Token
		originalID := invitation.ID

		err = invitation.GenerateToken()
		require.NoError(t, err)

		assert.NotEqual(t, originalToken, invitation.Token)
		assert.NotEqual(t, originalID, invitation.ID)
		assert.Len(t, invitation.Token, 44)
	})

	t.Run("GenerateToken updates UpdatedAt", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalUpdatedAt := invitation.UpdatedAt

		before := time.Now().UTC()
		err = invitation.GenerateToken()
		require.NoError(t, err)
		after := time.Now().UTC()

		assert.True(t, invitation.UpdatedAt.Equal(originalUpdatedAt) || invitation.UpdatedAt.After(originalUpdatedAt))
		assert.True(t, invitation.UpdatedAt.Equal(before) || invitation.UpdatedAt.After(before))
		assert.True(t, invitation.UpdatedAt.Equal(after) || invitation.UpdatedAt.Before(after))
	})

	t.Run("GenerateToken generates unique tokens", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		tokenSet := make(map[string]struct{})
		tokenSet[invitation.Token] = struct{}{}

		for i := 0; i < 50; i++ {
			err = invitation.GenerateToken()
			require.NoError(t, err)

			_, exists := tokenSet[invitation.Token]
			assert.False(t, exists, "Duplicate token found: %s", invitation.Token)
			tokenSet[invitation.Token] = struct{}{}
		}
	})

	t.Run("GenerateToken preserves other fields", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalTenantID := invitation.TenantID
		originalEmail := invitation.Email
		originalRole := invitation.Role
		originalStatus := invitation.Status
		originalInvitedByID := invitation.InvitedByID
		originalExpiresAt := invitation.ExpiresAt
		originalCreatedAt := invitation.CreatedAt

		err = invitation.GenerateToken()
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

		invitation, err := NewInvitation(tenantID, email, role, invitedByID, expiresDuration)
		require.NoError(t, err)
		require.NotNil(t, invitation)

		// Verify initial state
		assert.True(t, invitation.IsPending())
		assert.False(t, invitation.IsExpired())
		assert.True(t, invitation.CanAccept())
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
		invitation.Accept()

		// Verify accepted state
		assert.False(t, invitation.IsPending())
		assert.False(t, invitation.CanAccept())
		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.NotNil(t, invitation.AcceptedAt)

		// Other fields should remain unchanged
		assert.Equal(t, tenantID, invitation.TenantID)
		assert.Equal(t, email, invitation.Email)
		assert.Equal(t, role, invitation.Role)
	})

	t.Run("Revocation workflow", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		assert.True(t, invitation.CanAccept())

		invitation.Revoke()

		assert.False(t, invitation.IsPending())
		assert.False(t, invitation.CanAccept())
		assert.Equal(t, InvitationStatusRevoked, invitation.Status)
	})

	t.Run("Token regeneration workflow", func(t *testing.T) {
		invitation, err := NewInvitation("tenant-123", "user@example.com", "member", 1, time.Hour)
		require.NoError(t, err)

		originalToken := invitation.Token

		err = invitation.GenerateToken()
		require.NoError(t, err)

		assert.NotEqual(t, originalToken, invitation.Token)
		assert.True(t, invitation.CanAccept())
	})
}

func TestInvitation_StructFields(t *testing.T) {
	t.Run("All struct fields can be set and read", func(t *testing.T) {
		now := time.Now().UTC()
		acceptedAt := now.Add(time.Hour)

		invitation := &Invitation{
			ID:          12345,
			Token:       "test-token-value",
			TenantID:    "tenant-xyz",
			Email:       "test@example.com",
			Role:        "viewer",
			Status:      InvitationStatusAccepted,
			InvitedByID: 67890,
			ExpiresAt:   now.Add(24 * time.Hour),
			CreatedAt:   now,
			UpdatedAt:   now.Add(time.Minute),
			AcceptedAt:  &acceptedAt,
		}

		assert.Equal(t, uint64(12345), invitation.ID)
		assert.Equal(t, "test-token-value", invitation.Token)
		assert.Equal(t, "tenant-xyz", invitation.TenantID)
		assert.Equal(t, "test@example.com", invitation.Email)
		assert.Equal(t, "viewer", invitation.Role)
		assert.Equal(t, InvitationStatusAccepted, invitation.Status)
		assert.Equal(t, uint64(67890), invitation.InvitedByID)
		assert.Equal(t, now.Add(24*time.Hour), invitation.ExpiresAt)
		assert.Equal(t, now, invitation.CreatedAt)
		assert.Equal(t, now.Add(time.Minute), invitation.UpdatedAt)
		assert.NotNil(t, invitation.AcceptedAt)
		assert.Equal(t, acceptedAt, *invitation.AcceptedAt)
	})

	t.Run("Zero value struct is valid", func(t *testing.T) {
		invitation := &Invitation{}

		assert.Zero(t, invitation.ID)
		assert.Empty(t, invitation.Token)
		assert.Empty(t, invitation.TenantID)
		assert.Empty(t, invitation.Email)
		assert.Empty(t, invitation.Role)
		assert.Empty(t, invitation.Status)
		assert.Zero(t, invitation.InvitedByID)
		assert.True(t, invitation.ExpiresAt.IsZero())
		assert.True(t, invitation.CreatedAt.IsZero())
		assert.True(t, invitation.UpdatedAt.IsZero())
		assert.Nil(t, invitation.AcceptedAt)
	})
}
