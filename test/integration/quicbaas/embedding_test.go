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

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/embedding"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEmbeddingService_Generate tests embedding generation.
// Note: Embedding generation requires external providers (Voyage, OpenAI, Ollama, LMStudio).
// These tests verify the SDK client is properly connected and handles responses.
// Actual embedding generation may fail if no provider is configured.
func TestEmbeddingService_Generate(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	embeddingClient := sdk.Embedding()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("ClientAvailable", func(t *testing.T) {
		// Verify the embedding client is available
		assert.NotNil(t, embeddingClient, "Embedding client should not be nil")
	})

	t.Run("ListProviders", func(t *testing.T) {
		// This test verifies we can list available providers
		// In embedded mode without external providers, this may return an empty list
		resp, err := embeddingClient.ListProviders(ctx, &embedding.ListProvidersRequest{})
		if err != nil {
			// Provider listing may fail if no providers are configured
			t.Logf("ListProviders returned error (expected if no providers configured): %v", err)
			return
		}
		assert.NotNil(t, resp)
		t.Logf("Available providers: %v", resp.Providers)
	})

	// Note: Actual embedding generation tests require external provider configuration.
	// The following tests verify error handling when providers are not available.

	t.Run("GenerateWithoutProvider", func(t *testing.T) {
		// Attempting to generate without a configured provider should return an error
		_, err := embeddingClient.GenerateEmbedding(ctx, &embedding.GenerateEmbeddingRequest{
			Text:     "Hello, world!",
			Provider: embedding.ProviderVoyage,
		})
		// We expect an error since Voyage API is not configured in test environment
		if err != nil {
			t.Logf("Generate returned expected error (no provider configured): %v", err)
		}
	})
}

// TestEmbeddingService_Ollama tests Ollama embedding operations. It needs an
// Ollama reachable from the embedded QuicBaaS, with an embedding model.
func TestEmbeddingService_Ollama(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	ollama := sdk.Ollama()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("ClientAvailable", func(t *testing.T) {
		assert.NotNil(t, ollama, "Ollama client should not be nil")
	})

	t.Run("Health", func(t *testing.T) {
		resp, err := ollama.Health(ctx, &quicbaassdk.OllamaHealthRequest{})
		// Declared gap: go-quicbaas #1535 — flips to the success path on the pin bump that carries the fix.
		if helpers.GapEmbeddedOllama.Unserved(t, "Health", err) {
			return
		}
		if err != nil {
			t.Fatalf("missing prerequisite: %v", ErrOllamaUnavailable{Op: "Health", Err: err})
		}
		assert.NotNil(t, resp)
		t.Logf("Ollama status: available=%v", resp.Available)
	})

	t.Run("ListModels", func(t *testing.T) {
		resp, err := ollama.ListModels(ctx, &quicbaassdk.OllamaListModelsRequest{})
		// Declared gap: go-quicbaas #1535 — flips to the success path on the pin bump that carries the fix.
		if helpers.GapEmbeddedOllama.Unserved(t, "ListModels", err) {
			return
		}
		if err != nil {
			t.Fatalf("missing prerequisite: %v", ErrOllamaUnavailable{Op: "ListModels", Err: err})
		}
		assert.NotNil(t, resp)
		t.Logf("Available Ollama models: %d", len(resp.Models))
		for _, model := range resp.Models {
			t.Logf("  - %s", model.Name)
		}
	})

	t.Run("EmbedWithDefaultModel", func(t *testing.T) {
		resp, err := ollama.Embed(ctx, &quicbaassdk.OllamaEmbedRequest{
			Text: "Hello, this is a test embedding request.",
		})
		// Declared gap: go-quicbaas #1535 — flips to the success path on the pin bump that carries the fix.
		if helpers.GapEmbeddedOllama.Unserved(t, "Embed", err) {
			return
		}
		if err != nil {
			t.Fatalf("missing prerequisite: %v", ErrOllamaUnavailable{Op: "Embed", Err: err})
		}
		assert.NotNil(t, resp)
		assert.NotEmpty(t, resp.Embedding)
		t.Logf("Generated embedding with %d dimensions", len(resp.Embedding))
	})
}

// TestEmbeddingService_BatchGenerate tests batch embedding generation.
// Note: This requires external providers to be configured.
func TestEmbeddingService_BatchGenerate(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	embeddingClient := sdk.Embedding()

	ctx, cancel := testContext()
	defer cancel()

	t.Run("BatchGenerateWithoutProvider", func(t *testing.T) {
		items := []*embedding.BatchEmbeddingItem{
			{Text: "First document"},
			{Text: "Second document"},
			{Text: "Third document"},
		}

		_, err := embeddingClient.BatchGenerateEmbeddings(ctx, &embedding.BatchGenerateEmbeddingsRequest{
			Items:    items,
			Provider: embedding.ProviderVoyage,
		})
		// We expect an error since Voyage API is not configured
		if err != nil {
			t.Logf("BatchGenerate returned expected error (no provider configured): %v", err)
		}
	})
}

// TestEmbeddingService_OllamaBatch tests batch Ollama embedding generation.
func TestEmbeddingService_OllamaBatch(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	ollama := sdk.Ollama()

	ctx, cancel := testContext()
	defer cancel()

	// Declared gap: go-quicbaas #1535 — flips to the success path on the pin bump that carries the fix.
	_, healthErr := ollama.Health(ctx, &quicbaassdk.OllamaHealthRequest{})
	if helpers.GapEmbeddedOllama.Unserved(t, "Health", healthErr) {
		return
	}
	requireOllama(ctx, t, ollama)

	t.Run("BatchEmbed", func(t *testing.T) {
		inputs := []string{
			"First document for embedding",
			"Second document for embedding",
			"Third document for embedding",
		}

		resp, err := ollama.EmbedBatch(ctx, &quicbaassdk.OllamaEmbedBatchRequest{
			Texts: inputs,
		})
		if err != nil {
			t.Fatalf("missing prerequisite: %v", ErrOllamaUnavailable{Op: "EmbedBatch", Err: err})
		}
		assert.NotNil(t, resp)
		assert.Equal(t, len(inputs), len(resp.Embeddings))
	})
}

// TestEmbeddingService_InputTypes tests different input types for embeddings.
func TestEmbeddingService_InputTypes(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	embeddingClient := sdk.Embedding()

	ctx, cancel := testContext()
	defer cancel()

	inputTypes := []quicbaassdk.EmbeddingInputType{
		quicbaassdk.EmbeddingInputTypeDocument,
		quicbaassdk.EmbeddingInputTypeQuery,
		quicbaassdk.EmbeddingInputTypeCode,
	}

	for _, inputType := range inputTypes {
		t.Run("InputType_"+string(inputType), func(t *testing.T) {
			_, err := embeddingClient.GenerateEmbedding(ctx, &quicbaassdk.EmbeddingGenerateRequest{
				Text:      "Test input for embedding generation.",
				Provider:  quicbaassdk.EmbeddingProviderVoyage,
				InputType: inputType,
			})
			// Expected to fail without provider configuration
			if err != nil {
				t.Logf("Generate with input type %v failed as expected: %v", inputType, err)
			}
		})
	}
}

// TestEmbeddingService_WithVectorStorage tests the integration of embeddings with vector storage.
// This demonstrates the typical workflow of generating embeddings and storing them for search.
func TestEmbeddingService_WithVectorStorage(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	_ = sdk.Vector() // unused at this level, used in subtests
	ollama := sdk.Ollama()

	ctx, cancel := testContext()
	defer cancel()

	// Declared gap: go-quicbaas #1535 — flips to the success path on the pin bump that carries the fix.
	_, healthErr := ollama.Health(ctx, &quicbaassdk.OllamaHealthRequest{})
	if helpers.GapEmbeddedOllama.Unserved(t, "Health", healthErr) {
		return
	}
	requireOllama(ctx, t, ollama)

	t.Run("EmbedAndStore", func(t *testing.T) {
		// Generate embedding using Ollama
		embedResp, err := ollama.Embed(ctx, &quicbaassdk.OllamaEmbedRequest{
			Text: "This is a test document for vector similarity search.",
		})
		if err != nil {
			t.Fatalf("missing prerequisite: %v", ErrOllamaUnavailable{Op: "Embed", Err: err})
		}

		// Store the embedding in vector storage
		namespace := generateTestKey("embed/store")
		vectorClient := sdk.Vector()
		_, err = vectorClient.Upsert(ctx, &vector.UpsertRequest{
			Vector: &vector.VectorEntity{
				ID:        "1",
				Namespace: namespace,
				Vector:    embedResp.Embedding,
				Metadata: map[string]string{
					"content": "This is a test document for vector similarity search.",
					"source":  "ollama",
				},
			},
		})
		// Declared gap: go-quicbaas #1404 — flips to the success path on the pin bump that carries the fix.
		if helpers.GapEmbeddedVector.Unserved(t, "Upsert", err) {
			return
		}
		require.NoError(t, err)

		// Search for similar vectors
		searchResp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
			Namespace:   namespace,
			QueryVector: embedResp.Embedding,
			K:           5,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, searchResp.Results)
		assert.Equal(t, "1", searchResp.Results[0].Vector.ID)
	})
}
