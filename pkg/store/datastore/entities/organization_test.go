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

func TestNewOrganization(t *testing.T) {
	t.Run("Create new organization", func(t *testing.T) {
		name := "Acme Corporation"
		org := NewOrganization(name)

		require.NotNil(t, org)
		assert.Equal(t, name, org.Name)
		assert.Equal(t, util.NewID([]byte(name)), org.ID)
	})

	t.Run("Create organization with empty name", func(t *testing.T) {
		org := NewOrganization("")

		require.NotNil(t, org)
		assert.Equal(t, "", org.Name)
		assert.Equal(t, util.NewID([]byte("")), org.ID)
	})

	t.Run("Same name generates same ID", func(t *testing.T) {
		name := "Test Org"
		org1 := NewOrganization(name)
		org2 := NewOrganization(name)

		assert.Equal(t, org1.ID, org2.ID)
	})

	t.Run("Different names generate different IDs", func(t *testing.T) {
		org1 := NewOrganization("Org 1")
		org2 := NewOrganization("Org 2")

		assert.NotEqual(t, org1.ID, org2.ID)
	})
}

func TestOrganization_SetEntityID(t *testing.T) {
	org := NewOrganization("Test Org")
	originalID := org.ID

	newID := uint64(99999)
	org.SetEntityID(newID)

	assert.NotEqual(t, originalID, org.ID)
	assert.Equal(t, newID, org.ID)
	assert.Equal(t, newID, org.EntityID())
}

func TestOrganization_EntityID(t *testing.T) {
	name := "Test Organization"
	org := NewOrganization(name)

	expectedID := util.NewID([]byte(name))
	assert.Equal(t, expectedID, org.EntityID())
}

func TestOrganization_KeyValueEntity(t *testing.T) {
	// Test that Organization implements KeyValueEntity interface
	var entity KeyValueEntity = NewOrganization("Test Org")

	id := entity.EntityID()
	assert.NotZero(t, id)

	newID := uint64(12345)
	entity.SetEntityID(newID)
	assert.Equal(t, newID, entity.EntityID())
}

func TestOrganization_UniqueIDs(t *testing.T) {
	// Test that different organization names produce unique IDs
	names := []string{
		"Org A",
		"Org B",
		"Org C",
		"Organization Alpha",
		"Organization Beta",
	}

	ids := make(map[uint64]bool)
	for _, name := range names {
		org := NewOrganization(name)
		// Ensure no duplicate IDs
		assert.False(t, ids[org.ID], "Duplicate ID found for organization: %s", name)
		ids[org.ID] = true
	}

	assert.Len(t, ids, len(names))
}
