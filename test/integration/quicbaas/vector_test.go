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
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVectorService_Upsert tests vector upsert operations.
func TestVectorService_Upsert(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	vectorClient := sdk.Vector()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("UpsertSingleVector", func(t *testing.T) {
		namespace := generateTestKey("vector/upsert/single")
		vectorID := "vec-001"
		embedding := []float32{0.1, 0.2, 0.3, 0.4, 0.5}

		resp, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
			Vector: &vector.VectorEntity{
				ID:        vectorID,
				Namespace: namespace,
				Vector:    embedding,
				Metadata:  map[string]string{"type": "test"},
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("UpsertMultipleVectors", func(t *testing.T) {
		namespace := generateTestKey("vector/upsert/multiple")

		for i := 0; i < 10; i++ {
			vectorID := "vec-" + string(rune('0'+i))
			embedding := make([]float32, 128)
			for j := range embedding {
				embedding[j] = float32(i) * 0.01 * float32(j)
			}

			resp, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
				Vector: &vector.VectorEntity{
					ID:        vectorID,
					Namespace: namespace,
					Vector:    embedding,
					Metadata:  map[string]string{"index": string(rune('0' + i))},
				},
			})
			require.NoError(t, err)
			assert.NotNil(t, resp)
		}
	})

	t.Run("UpsertWithMetadata", func(t *testing.T) {
		namespace := generateTestKey("vector/upsert/metadata")
		vectorID := "vec-metadata"
		embedding := []float32{0.5, 0.5, 0.5, 0.5, 0.5}

		metadata := map[string]string{
			"source":     "integration-test",
			"category":   "test",
			"created_at": time.Now().Format(time.RFC3339),
		}

		resp, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
			Vector: &vector.VectorEntity{
				ID:        vectorID,
				Namespace: namespace,
				Vector:    embedding,
				Metadata:  metadata,
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("UpsertHighDimensionalVector", func(t *testing.T) {
		namespace := generateTestKey("vector/upsert/highdim")
		vectorID := "vec-highdim"
		// Create a 1536-dimensional vector (common for OpenAI embeddings)
		embedding := make([]float32, 1536)
		for i := range embedding {
			embedding[i] = float32(i) * 0.001
		}

		resp, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
			Vector: &vector.VectorEntity{
				ID:        vectorID,
				Namespace: namespace,
				Vector:    embedding,
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

// TestVectorService_Search tests vector similarity search operations.
func TestVectorService_Search(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	vectorClient := sdk.Vector()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("SearchSimilarVectors", func(t *testing.T) {
		namespace := generateTestKey("vector/search/similar")

		// Insert some vectors first
		vectors := []struct {
			id     string
			vector []float32
		}{
			{id: "vec-a", vector: []float32{1.0, 0.0, 0.0, 0.0, 0.0}},
			{id: "vec-b", vector: []float32{0.9, 0.1, 0.0, 0.0, 0.0}},
			{id: "vec-c", vector: []float32{0.8, 0.2, 0.0, 0.0, 0.0}},
			{id: "vec-d", vector: []float32{0.0, 1.0, 0.0, 0.0, 0.0}},
			{id: "vec-e", vector: []float32{0.0, 0.0, 1.0, 0.0, 0.0}},
		}

		for _, v := range vectors {
			_, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
				Vector: &vector.VectorEntity{
					ID:        v.id,
					Namespace: namespace,
					Vector:    v.vector,
				},
			})
			require.NoError(t, err)
		}

		// Search for vectors similar to [1.0, 0.0, 0.0, 0.0, 0.0]
		queryVector := []float32{1.0, 0.0, 0.0, 0.0, 0.0}

		resp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
			Namespace:   namespace,
			QueryVector: queryVector,
			K:           3,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.LessOrEqual(t, len(resp.Results), 3)

		// The most similar should be vec-a (exact match)
		if len(resp.Results) > 0 {
			assert.Equal(t, "vec-a", resp.Results[0].Vector.ID)
		}
	})

	t.Run("SearchWithTopK", func(t *testing.T) {
		namespace := generateTestKey("vector/search/topk")

		// Insert 20 vectors
		for i := 0; i < 20; i++ {
			embedding := make([]float32, 8)
			for j := range embedding {
				embedding[j] = float32(i) * 0.05 * float32(j+1)
			}

			_, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
				Vector: &vector.VectorEntity{
					ID:        "vec-" + string(rune('A'+i)),
					Namespace: namespace,
					Vector:    embedding,
				},
			})
			require.NoError(t, err)
		}

		// Search with K=5
		queryVector := make([]float32, 8)
		for j := range queryVector {
			queryVector[j] = 0.5 * float32(j+1)
		}

		resp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
			Namespace:   namespace,
			QueryVector: queryVector,
			K:           5,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.LessOrEqual(t, len(resp.Results), 5)
	})

	t.Run("SearchEmptyNamespace", func(t *testing.T) {
		namespace := generateTestKey("vector/search/empty")
		queryVector := []float32{1.0, 0.0, 0.0}

		resp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
			Namespace:   namespace,
			QueryVector: queryVector,
			K:           5,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Empty(t, resp.Results)
	})
}

// TestVectorService_Delete tests vector deletion operations.
func TestVectorService_Delete(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	vectorClient := sdk.Vector()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("DeleteExistingVector", func(t *testing.T) {
		namespace := generateTestKey("vector/delete/existing")
		vectorID := "vec-to-delete"
		embedding := []float32{0.1, 0.2, 0.3}

		// Insert vector
		_, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
			Vector: &vector.VectorEntity{
				ID:        vectorID,
				Namespace: namespace,
				Vector:    embedding,
			},
		})
		require.NoError(t, err)

		// Delete vector
		_, err = vectorClient.Delete(ctx, &vector.DeleteRequest{
			Namespace: namespace,
			ID:        vectorID,
		})
		require.NoError(t, err)

		// Verify deletion - search should not find the vector
		require.Eventually(t, func() bool {
			resp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
				Namespace:   namespace,
				QueryVector: embedding,
				K:           10,
			})
			if err != nil {
				return false
			}
			for _, result := range resp.Results {
				if result.Vector.ID == vectorID {
					return false
				}
			}
			return true
		}, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("DeleteNonExistingVector", func(t *testing.T) {
		namespace := generateTestKey("vector/delete/nonexisting")
		vectorID := "nonexistent-vector"

		// Deleting a non-existing vector should not error
		_, err := vectorClient.Delete(ctx, &vector.DeleteRequest{
			Namespace: namespace,
			ID:        vectorID,
		})
		require.NoError(t, err)
	})
}

// TestVectorService_Lifecycle tests the full vector lifecycle.
func TestVectorService_Lifecycle(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	vectorClient := sdk.Vector()

	ctx, cancel := testContext()
	defer cancel()

	namespace := generateTestKey("vector/lifecycle")
	vectorID := "lifecycle-vector"
	embedding := []float32{0.5, 0.5, 0.5, 0.5}

	// Insert
	upsertResp, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
		Vector: &vector.VectorEntity{
			ID:        vectorID,
			Namespace: namespace,
			Vector:    embedding,
			Metadata:  map[string]string{"stage": "created"},
		},
	})
	require.NoError(t, err, "Upsert should succeed")
	assert.NotNil(t, upsertResp)

	// Search to verify it exists
	searchResp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
		Namespace:   namespace,
		QueryVector: embedding,
		K:           5,
	})
	require.NoError(t, err, "Search should succeed")
	assert.NotEmpty(t, searchResp.Results)

	found := false
	for _, result := range searchResp.Results {
		if result.Vector.ID == vectorID {
			found = true
			break
		}
	}
	assert.True(t, found, "Vector should be found in search results")

	// Update (re-upsert with new data)
	newEmbedding := []float32{0.6, 0.6, 0.6, 0.6}
	_, err = vectorClient.Upsert(ctx, &vector.UpsertRequest{
		Vector: &vector.VectorEntity{
			ID:        vectorID,
			Namespace: namespace,
			Vector:    newEmbedding,
			Metadata:  map[string]string{"stage": "updated"},
		},
	})
	require.NoError(t, err, "Update should succeed")

	// Delete
	_, err = vectorClient.Delete(ctx, &vector.DeleteRequest{
		Namespace: namespace,
		ID:        vectorID,
	})
	require.NoError(t, err, "Delete should succeed")
}

// TestVectorService_ConcurrentUpserts tests concurrent vector upserts.
func TestVectorService_ConcurrentUpserts(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	vectorClient := sdk.Vector()

	namespace := generateTestKey("vector/concurrent")
	numVectors := 50
	done := make(chan error, numVectors)

	for i := 0; i < numVectors; i++ {
		go func(idx int) {
			ctx, cancel := testContext()
			defer cancel()

			vectorID := "concurrent-vec-" + string(rune('A'+idx%26)) + string(rune('0'+idx%10))
			embedding := make([]float32, 64)
			for j := range embedding {
				embedding[j] = float32(idx) * 0.01 * float32(j)
			}

			_, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
				Vector: &vector.VectorEntity{
					ID:        vectorID,
					Namespace: namespace,
					Vector:    embedding,
				},
			})
			done <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numVectors; i++ {
		select {
		case err := <-done:
			assert.NoError(t, err, "Concurrent upsert %d should succeed", i)
		case <-time.After(60 * time.Second):
			t.Fatal("Timeout waiting for concurrent upserts")
		}
	}
}

// TestVectorService_DifferentDimensions tests vectors with different dimensions.
func TestVectorService_DifferentDimensions(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	vectorClient := sdk.Vector()

	ctx, cancel := testContext()
	defer cancel()

	dimensions := []int{8, 64, 128, 256, 512, 768, 1536}

	for _, dim := range dimensions {
		t.Run("Dimension"+string(rune('0'+dim%10))+string(rune('0'+(dim/10)%10)), func(t *testing.T) {
			namespace := generateTestKey("vector/dim/" + string(rune('0'+dim%10)))
			vectorID := "dim-vec"
			embedding := make([]float32, dim)
			for i := range embedding {
				embedding[i] = float32(i) * 0.001
			}

			resp, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
				Vector: &vector.VectorEntity{
					ID:        vectorID,
					Namespace: namespace,
					Vector:    embedding,
				},
			})
			require.NoError(t, err, "Upsert should succeed for dimension %d", dim)
			assert.NotNil(t, resp)

			// Verify search works
			searchResp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
				Namespace:   namespace,
				QueryVector: embedding,
				K:           1,
			})
			require.NoError(t, err, "Search should succeed for dimension %d", dim)
			assert.NotEmpty(t, searchResp.Results)
		})
	}
}
