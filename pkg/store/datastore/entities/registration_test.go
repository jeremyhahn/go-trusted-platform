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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistration(t *testing.T) {
	t.Run("Create new registration", func(t *testing.T) {
		email := "user@example.com"
		reg := NewRegistration(email)

		require.NotNil(t, reg)
		assert.Equal(t, email, reg.Email)
		assert.Equal(t, util.NewID([]byte(email)), reg.ID)
		assert.Empty(t, reg.Password)
		assert.Zero(t, reg.OrgID)
		assert.Empty(t, reg.OrgName)
		assert.Nil(t, reg.SessionData)
	})

	t.Run("Create registration with empty email", func(t *testing.T) {
		reg := NewRegistration("")

		require.NotNil(t, reg)
		assert.Equal(t, "", reg.Email)
		assert.Equal(t, util.NewID([]byte("")), reg.ID)
	})

	t.Run("Same email generates same ID", func(t *testing.T) {
		email := "test@example.com"
		reg1 := NewRegistration(email)
		reg2 := NewRegistration(email)

		assert.Equal(t, reg1.ID, reg2.ID)
	})

	t.Run("Different emails generate different IDs", func(t *testing.T) {
		reg1 := NewRegistration("user1@example.com")
		reg2 := NewRegistration("user2@example.com")

		assert.NotEqual(t, reg1.ID, reg2.ID)
	})
}

func TestRegistration_EntityID(t *testing.T) {
	email := "test@example.com"
	reg := NewRegistration(email)

	expectedID := util.NewID([]byte(email))
	assert.Equal(t, expectedID, reg.EntityID())
}

func TestRegistration_SetEntityID(t *testing.T) {
	reg := NewRegistration("test@example.com")
	originalID := reg.ID

	newID := uint64(99999)
	reg.SetEntityID(newID)

	assert.NotEqual(t, originalID, reg.ID)
	assert.Equal(t, newID, reg.ID)
	assert.Equal(t, newID, reg.EntityID())
}

func TestRegistration_KeyValueEntity(t *testing.T) {
	// Test that Registration implements KeyValueEntity interface
	var entity KeyValueEntity = NewRegistration("test@example.com")

	id := entity.EntityID()
	assert.NotZero(t, id)

	newID := uint64(12345)
	entity.SetEntityID(newID)
	assert.Equal(t, newID, entity.EntityID())
}

func TestRegistration_Fields(t *testing.T) {
	t.Run("Set all fields", func(t *testing.T) {
		reg := NewRegistration("test@example.com")

		reg.Password = "hashed_password_123"
		reg.OrgID = uint64(5678)
		reg.OrgName = "Test Organization"
		reg.SessionData = []byte("session_data_bytes")

		assert.Equal(t, "test@example.com", reg.Email)
		assert.Equal(t, "hashed_password_123", reg.Password)
		assert.Equal(t, uint64(5678), reg.OrgID)
		assert.Equal(t, "Test Organization", reg.OrgName)
		assert.Equal(t, []byte("session_data_bytes"), reg.SessionData)
	})

	t.Run("Modify fields after creation", func(t *testing.T) {
		reg := NewRegistration("test@example.com")

		// Initially empty
		assert.Empty(t, reg.Password)
		assert.Zero(t, reg.OrgID)
		assert.Empty(t, reg.OrgName)

		// Set values
		reg.Password = "new_password"
		reg.OrgID = uint64(1234)
		reg.OrgName = "New Org"

		assert.Equal(t, "new_password", reg.Password)
		assert.Equal(t, uint64(1234), reg.OrgID)
		assert.Equal(t, "New Org", reg.OrgName)
	})
}

func TestRegistration_SessionData(t *testing.T) {
	t.Run("Set session data", func(t *testing.T) {
		reg := NewRegistration("test@example.com")

		sessionData := []byte("encrypted_session_data")
		reg.SessionData = sessionData

		assert.Equal(t, sessionData, reg.SessionData)
	})

	t.Run("Empty session data", func(t *testing.T) {
		reg := NewRegistration("test@example.com")

		assert.Nil(t, reg.SessionData)

		reg.SessionData = []byte{}
		assert.NotNil(t, reg.SessionData)
		assert.Empty(t, reg.SessionData)
	})
}

func TestRegistration_UniqueIDs(t *testing.T) {
	// Test that different emails produce unique IDs
	emails := []string{
		"user1@example.com",
		"user2@example.com",
		"admin@example.com",
		"test@test.com",
		"demo@demo.org",
	}

	ids := make(map[uint64]bool)
	for _, email := range emails {
		reg := NewRegistration(email)
		// Ensure no duplicate IDs
		assert.False(t, ids[reg.ID], "Duplicate ID found for email: %s", email)
		ids[reg.ID] = true
	}

	assert.Len(t, ids, len(emails))
}
