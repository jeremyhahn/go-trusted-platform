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

func TestNewBlob(t *testing.T) {
	t.Run("Create new blob", func(t *testing.T) {
		id := uint64(12345)
		data := []byte("test data")

		blob := NewBlob(id, data)
		require.NotNil(t, blob)
		assert.Equal(t, id, blob.ID)
		assert.Equal(t, data, blob.Bytes)
		assert.Equal(t, blob_partition, blob.Partition())
	})

	t.Run("Create blob with nil bytes", func(t *testing.T) {
		id := uint64(12345)

		blob := NewBlob(id, nil)
		require.NotNil(t, blob)
		assert.Equal(t, id, blob.ID)
		assert.Nil(t, blob.Bytes)
	})

	t.Run("Create blob with empty bytes", func(t *testing.T) {
		id := uint64(12345)
		data := []byte{}

		blob := NewBlob(id, data)
		require.NotNil(t, blob)
		assert.Equal(t, id, blob.ID)
		assert.Empty(t, blob.Bytes)
	})
}

func TestCreateBlob(t *testing.T) {
	t.Run("Create blob with custom partition", func(t *testing.T) {
		id := uint64(12345)
		data := []byte("test data")
		partition := "custom_partition"

		blob := CreateBlob(id, data, partition)
		require.NotNil(t, blob)
		assert.Equal(t, id, blob.ID)
		assert.Equal(t, data, blob.Bytes)
		assert.Equal(t, partition, blob.Partition())
	})

	t.Run("Create blob with empty partition", func(t *testing.T) {
		id := uint64(12345)
		data := []byte("test data")

		blob := CreateBlob(id, data, "")
		require.NotNil(t, blob)
		assert.Equal(t, "", blob.Partition())
	})
}

func TestBlob_SetEntityID(t *testing.T) {
	blob := NewBlob(12345, []byte("test"))

	newID := uint64(67890)
	blob.SetEntityID(newID)

	assert.Equal(t, newID, blob.ID)
	assert.Equal(t, newID, blob.EntityID())
}

func TestBlob_EntityID(t *testing.T) {
	id := uint64(12345)
	blob := NewBlob(id, []byte("test"))

	assert.Equal(t, id, blob.EntityID())
}

func TestBlob_SetEntity(t *testing.T) {
	blob := NewBlob(12345, []byte("test"))

	type TestEntity struct {
		Name  string
		Value int
	}

	entity := &TestEntity{
		Name:  "test",
		Value: 42,
	}

	blob.SetEntity(entity)
	assert.Equal(t, entity, blob.Entity)

	retrievedEntity, ok := blob.Entity.(*TestEntity)
	require.True(t, ok)
	assert.Equal(t, "test", retrievedEntity.Name)
	assert.Equal(t, 42, retrievedEntity.Value)
}

func TestBlob_SetPartition(t *testing.T) {
	blob := NewBlob(12345, []byte("test"))

	newPartition := "new_partition"
	blob.SetPartition(newPartition)

	assert.Equal(t, newPartition, blob.Partition())
}

func TestBlob_Partition(t *testing.T) {
	t.Run("Default partition", func(t *testing.T) {
		blob := NewBlob(12345, []byte("test"))
		assert.Equal(t, blob_partition, blob.Partition())
	})

	t.Run("Custom partition", func(t *testing.T) {
		blob := CreateBlob(12345, []byte("test"), "custom")
		assert.Equal(t, "custom", blob.Partition())
	})

	t.Run("Modified partition", func(t *testing.T) {
		blob := NewBlob(12345, []byte("test"))
		blob.SetPartition("modified")
		assert.Equal(t, "modified", blob.Partition())
	})
}

func TestBlob_LargeData(t *testing.T) {
	// Test with larger blob data
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	blob := NewBlob(12345, largeData)
	require.NotNil(t, blob)
	assert.Equal(t, len(largeData), len(blob.Bytes))
	assert.Equal(t, largeData[0], blob.Bytes[0])
	assert.Equal(t, largeData[len(largeData)-1], blob.Bytes[len(blob.Bytes)-1])
}
