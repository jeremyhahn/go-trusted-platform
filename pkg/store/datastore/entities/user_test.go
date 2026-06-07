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

func TestNewUser(t *testing.T) {
	t.Run("Create new user", func(t *testing.T) {
		email := "user@example.com"
		user := NewUser(email)

		require.NotNil(t, user)
		assert.Equal(t, email, user.Email)
		assert.Equal(t, util.NewID([]byte(email)), user.ID)
		assert.NotNil(t, user.Roles)
		assert.Empty(t, user.Roles)
		assert.Empty(t, user.DisplayName)
		assert.Empty(t, user.Password)
		assert.Empty(t, user.OrganizationRefs)
		assert.Empty(t, user.ServiceRefs)
	})

	t.Run("Create user with empty email", func(t *testing.T) {
		user := NewUser("")

		require.NotNil(t, user)
		assert.Equal(t, "", user.Email)
	})

	t.Run("Same email generates same ID", func(t *testing.T) {
		email := "test@example.com"
		user1 := NewUser(email)
		user2 := NewUser(email)

		assert.Equal(t, user1.ID, user2.ID)
	})

	t.Run("Different emails generate different IDs", func(t *testing.T) {
		user1 := NewUser("user1@example.com")
		user2 := NewUser("user2@example.com")

		assert.NotEqual(t, user1.ID, user2.ID)
	})
}

func TestUser_SetEntityID(t *testing.T) {
	user := NewUser("test@example.com")
	originalID := user.ID

	newID := uint64(99999)
	user.SetEntityID(newID)

	assert.NotEqual(t, originalID, user.ID)
	assert.Equal(t, newID, user.ID)
	assert.Equal(t, newID, user.EntityID())
}

func TestUser_EntityID(t *testing.T) {
	email := "test@example.com"
	user := NewUser(email)

	expectedID := util.NewID([]byte(email))
	assert.Equal(t, expectedID, user.EntityID())
}

func TestUser_AddRole(t *testing.T) {
	user := NewUser("test@example.com")

	assert.Empty(t, user.Roles)

	role1 := NewRole("admin")
	user.AddRole(role1)

	assert.Len(t, user.Roles, 1)
	assert.Equal(t, "admin", user.Roles[0].Name)

	role2 := NewRole("user")
	user.AddRole(role2)

	assert.Len(t, user.Roles, 2)
	assert.Equal(t, "user", user.Roles[1].Name)
}

func TestUser_HasRole(t *testing.T) {
	user := NewUser("test@example.com")

	// No roles initially
	assert.False(t, user.HasRole("admin"))
	assert.False(t, user.HasRole("user"))

	// Add admin role
	adminRole := NewRole("admin")
	user.AddRole(adminRole)

	assert.True(t, user.HasRole("admin"))
	assert.False(t, user.HasRole("user"))

	// Add user role
	userRole := NewRole("user")
	user.AddRole(userRole)

	assert.True(t, user.HasRole("admin"))
	assert.True(t, user.HasRole("user"))
	assert.False(t, user.HasRole("guest"))
}

func TestUser_KeyValueEntity(t *testing.T) {
	// Test that User implements KeyValueEntity interface
	var entity KeyValueEntity = NewUser("test@example.com")

	id := entity.EntityID()
	assert.NotZero(t, id)

	newID := uint64(12345)
	entity.SetEntityID(newID)
	assert.Equal(t, newID, entity.EntityID())
}

func TestUser_OrganizationRefs(t *testing.T) {
	user := NewUser("test@example.com")

	assert.Empty(t, user.OrganizationRefs)

	user.OrganizationRefs = []uint64{1, 2, 3}
	assert.Len(t, user.OrganizationRefs, 3)
	assert.Contains(t, user.OrganizationRefs, uint64(1))
	assert.Contains(t, user.OrganizationRefs, uint64(2))
	assert.Contains(t, user.OrganizationRefs, uint64(3))
}

func TestUser_ServiceRefs(t *testing.T) {
	user := NewUser("test@example.com")

	assert.Empty(t, user.ServiceRefs)

	user.ServiceRefs = []uint64{10, 20, 30}
	assert.Len(t, user.ServiceRefs, 3)
	assert.Contains(t, user.ServiceRefs, uint64(10))
	assert.Contains(t, user.ServiceRefs, uint64(20))
	assert.Contains(t, user.ServiceRefs, uint64(30))
}

func TestUser_CompleteUserProfile(t *testing.T) {
	// Test a fully populated user
	user := NewUser("admin@example.com")

	user.DisplayName = "System Administrator"
	user.Password = "hashed_password"
	user.OrganizationRefs = []uint64{1, 2}
	user.ServiceRefs = []uint64{10, 20, 30}

	// Add roles
	user.AddRole(NewRole("admin"))
	user.AddRole(NewRole("superuser"))

	// Verify all fields
	assert.Equal(t, "admin@example.com", user.Email)
	assert.Equal(t, "System Administrator", user.DisplayName)
	assert.Equal(t, "hashed_password", user.Password)
	assert.Len(t, user.OrganizationRefs, 2)
	assert.Len(t, user.ServiceRefs, 3)
	assert.Len(t, user.Roles, 2)
	assert.True(t, user.HasRole("admin"))
	assert.True(t, user.HasRole("superuser"))
	assert.False(t, user.HasRole("guest"))
}
