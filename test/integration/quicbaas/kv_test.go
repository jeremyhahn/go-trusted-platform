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

//go:build integration

package quicbaas_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKVService_Put tests the KV Put operation.
func TestKVService_Put(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("ValidPut", func(t *testing.T) {
		entityType := generateTestKey("kv/put/valid")
		data := []byte(`{"test": "data"}`)
		id := nextEntityID()

		resp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			ID:         id,
			Data:       data,
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, id, resp.ID)
	})

	t.Run("PutWithEmptyValue", func(t *testing.T) {
		entityType := generateTestKey("kv/put/empty")
		data := []byte{}

		resp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			Data:       data,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// Verify we can retrieve the empty value
		getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         resp.ID,
		})
		require.NoError(t, err)
		assert.True(t, getResp.Found)
		assert.Empty(t, getResp.Data)
	})

	t.Run("PutLargeValue", func(t *testing.T) {
		entityType := generateTestKey("kv/put/large")
		// Create a 1MB value
		largeData := make([]byte, 1024*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		resp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			Data:       largeData,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// Verify we can retrieve it
		getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         resp.ID,
		})
		require.NoError(t, err)
		assert.True(t, getResp.Found)
		assert.Equal(t, largeData, getResp.Data)
	})

	t.Run("PutMultipleEntities", func(t *testing.T) {
		entityType := generateTestKey("kv/put/multiple")
		data1 := []byte(`{"version": 1}`)
		data2 := []byte(`{"version": 2}`)

		// First put
		resp1, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			ID:         nextEntityID(),
			Data:       data1,
		})
		require.NoError(t, err)

		// Second put (new entity, not overwrite)
		resp2, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			ID:         nextEntityID(),
			Data:       data2,
		})
		require.NoError(t, err)

		// Both should have different IDs
		assert.NotEqual(t, resp1.ID, resp2.ID)

		// Verify each can be retrieved
		getResp1, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         resp1.ID,
		})
		require.NoError(t, err)
		assert.True(t, getResp1.Found)
		assert.Equal(t, data1, getResp1.Data)

		getResp2, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         resp2.ID,
		})
		require.NoError(t, err)
		assert.True(t, getResp2.Found)
		assert.Equal(t, data2, getResp2.Data)
	})
}

// TestKVService_Get tests the KV Get operation.
func TestKVService_Get(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("GetExistingEntity", func(t *testing.T) {
		entityType := generateTestKey("kv/get/existing")
		data := []byte(`{"message": "hello"}`)

		putResp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			Data:       data,
		})
		require.NoError(t, err)

		resp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         putResp.ID,
		})
		require.NoError(t, err)
		assert.True(t, resp.Found)
		assert.Equal(t, data, resp.Data)
	})

	t.Run("GetNonExistingEntity", func(t *testing.T) {
		entityType := generateTestKey("kv/get/nonexisting")

		resp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         999999, // Non-existing ID
		})
		assert.True(t, helpers.KVEntityAbsent(resp, err), "Get of a missing entity must report it absent, got %+v, %v", resp, err)
	})
}

// TestKVService_Delete tests the KV Delete operation.
func TestKVService_Delete(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("DeleteExistingEntity", func(t *testing.T) {
		entityType := generateTestKey("kv/delete/existing")
		data := []byte(`{"data": "to delete"}`)

		putResp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			Data:       data,
		})
		require.NoError(t, err)

		// Delete the entity
		resp, err := kv.Delete(ctx, &quicbaassdk.DeleteRequest{
			EntityType: entityType,
			ID:         putResp.ID,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// Verify deletion (with eventual consistency)
		require.Eventually(t, func() bool {
			getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
				EntityType: entityType,
				ID:         putResp.ID,
			})
			return helpers.KVEntityAbsent(getResp, err)
		}, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("DeleteNonExistingEntity", func(t *testing.T) {
		entityType := generateTestKey("kv/delete/nonexisting")

		// Deleting a non-existing entity should not error
		resp, err := kv.Delete(ctx, &quicbaassdk.DeleteRequest{
			EntityType: entityType,
			ID:         999999,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("DeleteThenRecreate", func(t *testing.T) {
		entityType := generateTestKey("kv/delete/recreate")
		data1 := []byte(`{"version": 1}`)
		data2 := []byte(`{"version": 2}`)

		// Create
		putResp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			Data:       data1,
		})
		require.NoError(t, err)

		// Delete
		_, err = kv.Delete(ctx, &quicbaassdk.DeleteRequest{
			EntityType: entityType,
			ID:         putResp.ID,
		})
		require.NoError(t, err)

		// Wait for deletion to propagate
		require.Eventually(t, func() bool {
			getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
				EntityType: entityType,
				ID:         putResp.ID,
			})
			return helpers.KVEntityAbsent(getResp, err)
		}, 5*time.Second, 100*time.Millisecond)

		// Recreate with new value (will get a new ID)
		putResp2, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			Data:       data2,
		})
		require.NoError(t, err)

		// Verify new entity
		getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         putResp2.ID,
		})
		require.NoError(t, err)
		assert.True(t, getResp.Found)
		assert.Equal(t, data2, getResp.Data)
	})
}

// TestKVService_List tests the KV List operation.
func TestKVService_List(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("ListByEntityType", func(t *testing.T) {
		entityType := generateTestKey("kv/list/type")

		// Create multiple entities with the same type
		numEntities := 10
		for i := 0; i < numEntities; i++ {
			data := []byte(`{"index": ` + string(rune('0'+i)) + `}`)
			_, err := kv.Put(ctx, &quicbaassdk.PutRequest{
				EntityType: entityType,
				ID:         nextEntityID(),
				Data:       data,
			})
			require.NoError(t, err)
		}

		// List entities by type
		resp, err := kv.List(ctx, &quicbaassdk.ListRequest{
			EntityType: entityType,
			PageSize:   100,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.GreaterOrEqual(t, len(resp.Entities), numEntities)
	})

	t.Run("ListWithPageSize", func(t *testing.T) {
		entityType := generateTestKey("kv/list/paged")

		// Create 20 entities
		for i := 0; i < 20; i++ {
			_, err := kv.Put(ctx, &quicbaassdk.PutRequest{
				EntityType: entityType,
				ID:         nextEntityID(),
				Data:       []byte(`{}`),
			})
			require.NoError(t, err)
		}

		// List with page size of 5
		resp, err := kv.List(ctx, &quicbaassdk.ListRequest{
			EntityType: entityType,
			PageSize:   5,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
		// Declared gap: go-quicbaas #1534 — flips to the success path on the pin bump that carries the fix.
		// The embedded KV List merges every page the server streams into one
		// answer, so a PageSize of 5 over 20 entities answers all 20.
		if helpers.GapEmbeddedKVListPageSize.Defect(t, "List", len(resp.Entities) == 20,
			"PageSize 5 ignored: all 20 entities", strconv.Itoa(len(resp.Entities))+" entities") {
			return
		}
		assert.LessOrEqual(t, len(resp.Entities), 5)
	})
}

// TestKVService_CRUD tests full CRUD lifecycle.
func TestKVService_CRUD(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	ctx, cancel := testContext()
	defer cancel()

	entityType := generateTestKey("kv/crud")
	createData := []byte(`{"status": "created"}`)
	updateData := []byte(`{"status": "updated"}`)

	// Create
	putResp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
		EntityType: entityType,
		Data:       createData,
	})
	require.NoError(t, err, "Create should succeed")
	entityID := putResp.ID

	// Read
	readResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
		EntityType: entityType,
		ID:         entityID,
	})
	require.NoError(t, err, "Read should succeed")
	assert.True(t, readResp.Found)
	assert.Equal(t, createData, readResp.Data)

	// Update (put with same ID)
	_, err = kv.Put(ctx, &quicbaassdk.PutRequest{
		EntityType: entityType,
		ID:         entityID,
		Data:       updateData,
	})
	require.NoError(t, err, "Update should succeed")

	// Read updated
	readResp, err = kv.Get(ctx, &quicbaassdk.GetRequest{
		EntityType: entityType,
		ID:         entityID,
	})
	require.NoError(t, err, "Read after update should succeed")
	assert.True(t, readResp.Found)
	assert.Equal(t, updateData, readResp.Data)

	// Delete
	_, err = kv.Delete(ctx, &quicbaassdk.DeleteRequest{
		EntityType: entityType,
		ID:         entityID,
	})
	require.NoError(t, err, "Delete should succeed")

	// Verify deleted
	require.Eventually(t, func() bool {
		getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         entityID,
		})
		return helpers.KVEntityAbsent(getResp, err)
	}, 5*time.Second, 100*time.Millisecond, "Entity should be deleted")
}

// TestKVService_ConcurrentPuts tests concurrent put operations.
func TestKVService_ConcurrentPuts(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	numConcurrent := 50
	entityType := generateTestKey("kv/concurrent")
	done := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(idx int) {
			ctx, cancel := testContext()
			defer cancel()

			data := []byte(`{"index": "` + string(rune('0'+idx%10)) + `"}`)

			_, err := kv.Put(ctx, &quicbaassdk.PutRequest{
				EntityType: entityType,
				Data:       data,
			})
			done <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numConcurrent; i++ {
		select {
		case err := <-done:
			assert.NoError(t, err, "Concurrent put %d should succeed", i)
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent puts")
		}
	}
}

// TestKVService_ContextCancellation tests that operations respect context cancellation.
func TestKVService_ContextCancellation(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entityType := generateTestKey("kv/cancelled")
	data := []byte(`{"test": "cancelled"}`)

	// Operations should fail with cancelled context
	_, err := kv.Put(ctx, &quicbaassdk.PutRequest{
		EntityType: entityType,
		Data:       data,
	})
	assert.Error(t, err, "Put with cancelled context should fail")

	_, err = kv.Get(ctx, &quicbaassdk.GetRequest{
		EntityType: entityType,
		ID:         1,
	})
	assert.Error(t, err, "Get with cancelled context should fail")
}

// TestKVService_Batch tests batch operations.
func TestKVService_Batch(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	batch := sdk.Batch()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("BatchPut", func(t *testing.T) {
		entityType := generateTestKey("kv/batch/put")

		ops := make([]quicbaassdk.BatchOperation, 10)
		for i := 0; i < 10; i++ {
			ops[i] = quicbaassdk.BatchOperation{
				Type:       quicbaassdk.BatchOpPut,
				EntityType: entityType,
				Key:        entityType + "/" + string(rune('a'+i)),
				Value:      []byte(`{"index": ` + string(rune('0'+i)) + `}`),
			}
		}

		resp, err := batch.Execute(ctx, &quicbaassdk.BatchRequest{
			Operations: ops,
		})
		// Declared gap: go-quicbaas #1533 — flips to the success path on the pin bump that carries the fix.
		if helpers.GapEmbeddedBatch.Unserved(t, "Execute", err) {
			return
		}
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("BatchDelete", func(t *testing.T) {
		entityType := generateTestKey("kv/batch/delete")

		// First create some keys with batch put
		keys := make([]string, 5)
		ops := make([]quicbaassdk.BatchOperation, 5)
		for i := 0; i < 5; i++ {
			keys[i] = entityType + "/" + string(rune('a'+i))
			ops[i] = quicbaassdk.BatchOperation{
				Type:       quicbaassdk.BatchOpPut,
				EntityType: entityType,
				Key:        keys[i],
				Value:      []byte(`{}`),
			}
		}
		_, err := batch.Execute(ctx, &quicbaassdk.BatchRequest{
			Operations: ops,
		})
		// Declared gap: go-quicbaas #1533 — flips to the success path on the pin bump that carries the fix.
		if helpers.GapEmbeddedBatch.Unserved(t, "Execute", err) {
			return
		}
		require.NoError(t, err)

		// Batch delete
		deleteOps := make([]quicbaassdk.BatchOperation, len(keys))
		for i, key := range keys {
			deleteOps[i] = quicbaassdk.BatchOperation{
				Type:       quicbaassdk.BatchOpDelete,
				EntityType: entityType,
				Key:        key,
			}
		}

		resp, err := batch.Execute(ctx, &quicbaassdk.BatchRequest{
			Operations: deleteOps,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

// TestKVService_Transaction tests transactional operations.
func TestKVService_Transaction(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	txn := sdk.Transaction()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("CompareAndSwap", func(t *testing.T) {
		entityType := generateTestKey("kv/txn/cas")
		key := entityType + "/testkey"
		value1 := []byte(`{"version": 1}`)
		value2 := []byte(`{"version": 2}`)

		// Create the key only if it does not exist: version 0 means absent.
		createResp, err := txn.Execute(ctx, &quicbaassdk.TxnRequest{
			Compare: []quicbaassdk.Compare{
				{Key: key, Target: quicbaassdk.CompareVersion, Result: quicbaassdk.CompareEqual, Revision: 0},
			},
			Success: []quicbaassdk.TxnOp{
				{Type: quicbaassdk.TxnOpPut, EntityType: entityType, Key: key, Value: value1},
			},
		})
		// Declared gap: go-quicbaas #1319 — flips to the success path on the pin bump that carries the fix.
		if helpers.GapEmbeddedTransaction.Mistyped(t, "Execute", err) {
			return
		}
		require.NoError(t, err)
		assert.True(t, createResp.Succeeded)

		// Swap only while the stored value is still value1.
		swapResp, err := txn.Execute(ctx, &quicbaassdk.TxnRequest{
			Compare: []quicbaassdk.Compare{
				{Key: key, Target: quicbaassdk.CompareValue, Result: quicbaassdk.CompareEqual, Value: value1},
			},
			Success: []quicbaassdk.TxnOp{
				{Type: quicbaassdk.TxnOpPut, EntityType: entityType, Key: key, Value: value2},
			},
		})
		require.NoError(t, err)
		assert.True(t, swapResp.Succeeded)

		// A second create-if-absent loses: the key exists now.
		recreateResp, err := txn.Execute(ctx, &quicbaassdk.TxnRequest{
			Compare: []quicbaassdk.Compare{
				{Key: key, Target: quicbaassdk.CompareVersion, Result: quicbaassdk.CompareEqual, Revision: 0},
			},
			Success: []quicbaassdk.TxnOp{
				{Type: quicbaassdk.TxnOpPut, EntityType: entityType, Key: key, Value: value1},
			},
		})
		require.NoError(t, err)
		assert.False(t, recreateResp.Succeeded)
	})
}
