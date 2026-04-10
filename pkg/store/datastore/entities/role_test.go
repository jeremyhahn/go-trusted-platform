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

func TestNewRole(t *testing.T) {
	t.Run("Create new role", func(t *testing.T) {
		name := "admin"
		role := NewRole(name)

		require.NotNil(t, role)
		assert.Equal(t, name, role.Name)
		assert.Equal(t, util.NewID([]byte(name)), role.ID)
	})

	t.Run("Create role with empty name", func(t *testing.T) {
		role := NewRole("")

		require.NotNil(t, role)
		assert.Equal(t, "", role.Name)
		assert.Equal(t, util.NewID([]byte("")), role.ID)
	})

	t.Run("Same name generates same ID", func(t *testing.T) {
		name := "user"
		role1 := NewRole(name)
		role2 := NewRole(name)

		assert.Equal(t, role1.ID, role2.ID)
	})

	t.Run("Different names generate different IDs", func(t *testing.T) {
		role1 := NewRole("admin")
		role2 := NewRole("user")

		assert.NotEqual(t, role1.ID, role2.ID)
	})
}

func TestRole_SetEntityID(t *testing.T) {
	role := NewRole("admin")
	originalID := role.ID

	newID := uint64(99999)
	role.SetEntityID(newID)

	assert.NotEqual(t, originalID, role.ID)
	assert.Equal(t, newID, role.ID)
	assert.Equal(t, newID, role.EntityID())
}

func TestRole_EntityID(t *testing.T) {
	name := "moderator"
	role := NewRole(name)

	expectedID := util.NewID([]byte(name))
	assert.Equal(t, expectedID, role.EntityID())
}

func TestRole_KeyValueEntity(t *testing.T) {
	// Test that Role implements KeyValueEntity interface
	var entity KeyValueEntity = NewRole("admin")

	id := entity.EntityID()
	assert.NotZero(t, id)

	newID := uint64(12345)
	entity.SetEntityID(newID)
	assert.Equal(t, newID, entity.EntityID())
}

func TestRole_CommonRoles(t *testing.T) {
	// Test common role names
	commonRoles := []string{
		"admin",
		"user",
		"guest",
		"moderator",
		"superuser",
	}

	for _, name := range commonRoles {
		role := NewRole(name)
		require.NotNil(t, role)
		assert.Equal(t, name, role.Name)
		assert.NotZero(t, role.ID)
	}
}

func TestRole_UniqueIDs(t *testing.T) {
	// Test that different role names produce unique IDs
	names := []string{
		"admin",
		"user",
		"guest",
		"moderator",
		"superuser",
		"developer",
		"tester",
	}

	ids := make(map[uint64]bool)
	for _, name := range names {
		role := NewRole(name)
		// Ensure no duplicate IDs
		assert.False(t, ids[role.ID], "Duplicate ID found for role: %s", name)
		ids[role.ID] = true
	}

	assert.Len(t, ids, len(names))
}
