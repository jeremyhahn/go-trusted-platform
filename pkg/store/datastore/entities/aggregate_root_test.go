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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAggregateRoot(t *testing.T) {
	t.Run("Create aggregate root with references", func(t *testing.T) {
		root := NewUser("root@test.com")
		refs := []KeyValueEntity{
			NewRole("admin"),
			NewRole("user"),
		}

		aggregate, err := NewAggregateRoot(root, "organization", refs, "roles")
		require.NoError(t, err)
		assert.NotNil(t, aggregate)
		assert.Equal(t, root, aggregate.Root)
		assert.Equal(t, "organization", aggregate.RootPartition)
		assert.Equal(t, refs, aggregate.References)
		assert.Equal(t, "roles", aggregate.ReferencePartition)
	})

	t.Run("Create aggregate root with empty references", func(t *testing.T) {
		root := NewUser("root@test.com")
		refs := []KeyValueEntity{}

		aggregate, err := NewAggregateRoot(root, "organization", refs, "roles")
		assert.ErrorIs(t, err, ErrEmptyReferencesSlice)
		assert.Nil(t, aggregate)
	})

	t.Run("Create aggregate root with nil references", func(t *testing.T) {
		root := NewUser("root@test.com")

		aggregate, err := NewAggregateRoot(root, "organization", nil, "roles")
		assert.ErrorIs(t, err, ErrEmptyReferencesSlice)
		assert.Nil(t, aggregate)
	})
}

func TestAggregateRoot_Partition(t *testing.T) {
	t.Run("Get partition", func(t *testing.T) {
		root := NewUser("root@test.com")
		refs := []KeyValueEntity{
			NewRole("admin"),
		}

		aggregate, err := NewAggregateRoot(root, "organization", refs, "roles")
		require.NoError(t, err)

		partition := aggregate.Partition()
		assert.Equal(t, "organization_roles", partition)
	})

	t.Run("Get partition with empty root partition", func(t *testing.T) {
		root := NewUser("root@test.com")
		refs := []KeyValueEntity{
			NewRole("admin"),
		}

		aggregate, err := NewAggregateRoot(root, "", refs, "roles")
		require.NoError(t, err)

		partition := aggregate.Partition()
		assert.Equal(t, "_roles", partition)
	})

	t.Run("Get partition with empty reference partition", func(t *testing.T) {
		root := NewUser("root@test.com")
		refs := []KeyValueEntity{
			NewRole("admin"),
		}

		aggregate, err := NewAggregateRoot(root, "organization", refs, "")
		require.NoError(t, err)

		partition := aggregate.Partition()
		assert.Equal(t, "organization_", partition)
	})
}

func TestAggregateRoot_EntityIDs(t *testing.T) {
	t.Run("Get entity IDs", func(t *testing.T) {
		root := NewUser("root@test.com")
		role1 := NewRole("admin")
		role2 := NewRole("user")
		role3 := NewRole("guest")
		refs := []KeyValueEntity{role1, role2, role3}

		aggregate, err := NewAggregateRoot(root, "organization", refs, "roles")
		require.NoError(t, err)

		ids := aggregate.EntityIDs()
		require.Len(t, ids, 3)
		assert.Contains(t, ids, role1.EntityID())
		assert.Contains(t, ids, role2.EntityID())
		assert.Contains(t, ids, role3.EntityID())
	})

	t.Run("Get entity IDs with single reference", func(t *testing.T) {
		root := NewUser("root@test.com")
		role := NewRole("admin")
		refs := []KeyValueEntity{role}

		aggregate, err := NewAggregateRoot(root, "organization", refs, "roles")
		require.NoError(t, err)

		ids := aggregate.EntityIDs()
		require.Len(t, ids, 1)
		assert.Equal(t, role.EntityID(), ids[0])
	})

	t.Run("Entity IDs maintain order", func(t *testing.T) {
		root := NewUser("root@test.com")
		role1 := NewRole("admin")
		role2 := NewRole("user")
		refs := []KeyValueEntity{role1, role2}

		aggregate, err := NewAggregateRoot(root, "organization", refs, "roles")
		require.NoError(t, err)

		ids := aggregate.EntityIDs()
		require.Len(t, ids, 2)
		assert.Equal(t, role1.EntityID(), ids[0])
		assert.Equal(t, role2.EntityID(), ids[1])
	})
}
