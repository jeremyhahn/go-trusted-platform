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

func TestNewReference(t *testing.T) {
	t.Run("Create new reference", func(t *testing.T) {
		name := "test-index"
		referenceID := uint64(12345)
		referencedValue := []byte("indexed-value")

		ref := NewReference(name, referenceID, referencedValue)

		require.NotNil(t, ref)

		// Cast to concrete type to access fields
		concreteRef, ok := ref.(*Reference)
		require.True(t, ok)

		assert.Equal(t, name, concreteRef.Name())
		assert.Equal(t, referenceID, concreteRef.RefID())
		assert.Equal(t, util.NewID(referencedValue), concreteRef.ID)
	})

	t.Run("Reference with empty name", func(t *testing.T) {
		ref := NewReference("", uint64(123), []byte("value"))

		require.NotNil(t, ref)
		concreteRef := ref.(*Reference)
		assert.Equal(t, "", concreteRef.Name())
	})

	t.Run("Reference with zero ID", func(t *testing.T) {
		ref := NewReference("test", uint64(0), []byte("value"))

		require.NotNil(t, ref)
		concreteRef := ref.(*Reference)
		assert.Equal(t, uint64(0), concreteRef.RefID())
	})

	t.Run("Same referenced value generates same ID", func(t *testing.T) {
		value := []byte("same-value")
		ref1 := NewReference("ref1", uint64(1), value)
		ref2 := NewReference("ref2", uint64(2), value)

		// Even with different names and reference IDs, the ID should be the same
		// because it's derived from the referenced value
		assert.Equal(t, ref1.EntityID(), ref2.EntityID())
	})

	t.Run("Different referenced values generate different IDs", func(t *testing.T) {
		ref1 := NewReference("ref", uint64(1), []byte("value1"))
		ref2 := NewReference("ref", uint64(1), []byte("value2"))

		assert.NotEqual(t, ref1.EntityID(), ref2.EntityID())
	})
}

func TestReference_SetEntityID(t *testing.T) {
	ref := NewReference("test", uint64(123), []byte("value"))
	concreteRef := ref.(*Reference)

	originalID := concreteRef.ID

	newID := uint64(99999)
	ref.SetEntityID(newID)

	assert.NotEqual(t, originalID, concreteRef.ID)
	assert.Equal(t, newID, concreteRef.ID)
	assert.Equal(t, newID, ref.EntityID())
}

func TestReference_EntityID(t *testing.T) {
	value := []byte("test-value")
	ref := NewReference("test", uint64(123), value)

	expectedID := util.NewID(value)
	assert.Equal(t, expectedID, ref.EntityID())
}

func TestReference_Name(t *testing.T) {
	tests := []struct {
		name    string
		refName string
	}{
		{
			name:    "Normal name",
			refName: "user-email-index",
		},
		{
			name:    "Empty name",
			refName: "",
		},
		{
			name:    "Name with special chars",
			refName: "index:test@123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := NewReference(tt.refName, uint64(1), []byte("value"))
			assert.Equal(t, tt.refName, ref.Name())
		})
	}
}

func TestReference_RefID(t *testing.T) {
	tests := []struct {
		name  string
		refID uint64
	}{
		{
			name:  "Normal ID",
			refID: uint64(12345),
		},
		{
			name:  "Zero ID",
			refID: uint64(0),
		},
		{
			name:  "Large ID",
			refID: uint64(18446744073709551615), // max uint64
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := NewReference("test", tt.refID, []byte("value"))
			assert.Equal(t, tt.refID, ref.RefID())
		})
	}
}

func TestReference_Index(t *testing.T) {
	// Test that Reference implements Index interface
	index := NewReference("test", uint64(123), []byte("value"))

	assert.Equal(t, "test", index.Name())
	assert.Equal(t, uint64(123), index.RefID())
	assert.NotZero(t, index.EntityID())
}

func TestReference_KeyValueEntity(t *testing.T) {
	// Test that Reference implements KeyValueEntity interface
	var entity KeyValueEntity = NewReference("test", uint64(123), []byte("value"))

	id := entity.EntityID()
	assert.NotZero(t, id)

	newID := uint64(54321)
	entity.SetEntityID(newID)
	assert.Equal(t, newID, entity.EntityID())
}

func TestReference_MultipleReferences(t *testing.T) {
	// Create multiple references for indexing different values
	email1 := []byte("user1@example.com")
	email2 := []byte("user2@example.com")
	email3 := []byte("user3@example.com")

	ref1 := NewReference("email-index", uint64(1001), email1)
	ref2 := NewReference("email-index", uint64(1002), email2)
	ref3 := NewReference("email-index", uint64(1003), email3)

	// All should have the same name
	assert.Equal(t, "email-index", ref1.Name())
	assert.Equal(t, "email-index", ref2.Name())
	assert.Equal(t, "email-index", ref3.Name())

	// Each should have their own reference ID
	assert.Equal(t, uint64(1001), ref1.RefID())
	assert.Equal(t, uint64(1002), ref2.RefID())
	assert.Equal(t, uint64(1003), ref3.RefID())

	// Each should have a unique entity ID based on the indexed value
	assert.NotEqual(t, ref1.EntityID(), ref2.EntityID())
	assert.NotEqual(t, ref2.EntityID(), ref3.EntityID())
	assert.NotEqual(t, ref1.EntityID(), ref3.EntityID())
}

func TestReference_IDConsistency(t *testing.T) {
	// Test that the ID is consistently generated from the referenced value
	value := []byte("consistent-value")

	// Create multiple references with the same value
	refs := make([]Index, 10)
	for i := 0; i < 10; i++ {
		refs[i] = NewReference("test", uint64(i), value)
	}

	// All should have the same EntityID
	expectedID := refs[0].EntityID()
	for i := 1; i < 10; i++ {
		assert.Equal(t, expectedID, refs[i].EntityID(),
			"Reference %d has different ID", i)
	}
}

func TestReference_AsAggregateReference(t *testing.T) {
	// Test using references in an aggregate pattern
	orgID := uint64(100)

	// Create references to users in an organization
	user1Ref := NewReference("org-users", orgID, []byte("user1@example.com"))
	user2Ref := NewReference("org-users", orgID, []byte("user2@example.com"))
	user3Ref := NewReference("org-users", orgID, []byte("user3@example.com"))

	refs := []KeyValueEntity{user1Ref, user2Ref, user3Ref}

	// All references point to the same organization
	for _, ref := range refs {
		indexRef := ref.(Index)
		assert.Equal(t, orgID, indexRef.RefID())
		assert.Equal(t, "org-users", indexRef.Name())
	}

	// But each has a unique entity ID
	ids := make(map[uint64]bool)
	for _, ref := range refs {
		id := ref.EntityID()
		assert.False(t, ids[id], "Duplicate entity ID found")
		ids[id] = true
	}
	assert.Len(t, ids, 3)
}
