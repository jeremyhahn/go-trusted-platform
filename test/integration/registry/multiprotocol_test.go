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

// Package registry provides multi-protocol integration tests for the trusted registry.
// These tests verify that registry operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified RegistryCommands interface.
//
// Run tests via:
//
//	make integration-test-registry
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package registry

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestRegistryMultiProtocol runs the complete registry test suite against all
// protocol adapters. Each adapter implements the RegistryCommands interface,
// enabling unified testing across CLI, REST, and future protocols (gRPC, QUIC, MCP, Socket).
func TestRegistryMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement RegistryCommands
	adapters := []RegistryCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	// Signed pushes sign with an SDK KMS key the push names; the registry
	// never creates it. Create one through the CLI for every protocol leg.
	signingKeyID := fmt.Sprintf("registry-sign-%d", time.Now().UnixNano())
	keyAdmin := NewCLIAdapter()
	require.NoError(t, keyAdmin.Setup(ctx), "CLI setup for the signing key")
	require.NoError(t, keyAdmin.GenerateSigningKey(ctx, signingKeyID), "create the signing key in the SDK KMS")
	if err := keyAdmin.Teardown(); err != nil {
		t.Logf("Warning: teardown error for the signing-key CLI: %v", err)
	}

	gate := helpers.NewAdapterGate(t, "registry", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			runRegistryProtocolTests(t, ctx, adapter, signingKeyID)
		})
	}
}

// runRegistryProtocolTests runs the complete registry test suite against a single
// protocol adapter.
func runRegistryProtocolTests(t *testing.T, ctx context.Context, cmd RegistryCommands, signingKeyID string) {
	// Generate unique test prefix for this protocol run. Every image
	// reference starts with it, and an OCI repository name is lowercase
	// (distribution-spec "Pulling manifests": [a-z0-9]+(...)*), so the
	// mixed-case transport name ("gRPC", "MCP") is lowercased here.
	prefix := fmt.Sprintf("%s-%d", strings.ToLower(cmd.Name()), time.Now().Unix())

	t.Run("ImageLifecycle", func(t *testing.T) {
		runImagePushTests(t, ctx, cmd, prefix, signingKeyID)
		runImagePullTests(t, ctx, cmd, prefix)
		runImageListTests(t, ctx, cmd, prefix)
		runImageDeleteTests(t, ctx, cmd, prefix)
		runImageInspectTests(t, ctx, cmd, prefix)
	})

	t.Run("RegistryStatus", func(t *testing.T) {
		runRegistryStatusTests(t, ctx, cmd, prefix)
	})

	t.Run("Attestation", func(t *testing.T) {
		runClientVerificationTests(t, ctx, cmd, prefix)
		runSessionManagementTests(t, ctx, cmd, prefix)
	})

	t.Run("Encryption", func(t *testing.T) {
		runImageEncryptionTests(t, ctx, cmd, prefix)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		runImageNotFoundTests(t, ctx, cmd, prefix)
		runInvalidArgumentTests(t, ctx, cmd, prefix)
	})

	t.Run("FullLifecycle", func(t *testing.T) {
		runFullImageLifecycleTests(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// Image Push Tests
// =============================================================================

func runImagePushTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix, signingKeyID string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if declaredMissing(t, testCtx, cmd, opPush) {
		return
	}

	t.Run("PushBasicImage", func(t *testing.T) {
		ref := GenerateUniqueImageRef(prefix+"-push-basic", "v1")
		layers, config := GenerateTestImage(1, 1024)

		opts := PushOptions{
			Layers:         layers,
			Config:         config,
			AllowOverwrite: false,
		}

		result, err := cmd.Push(testCtx, ref, opts)
		require.NoError(t, err, "Push should succeed for basic image")
		require.NotNil(t, result, "Push result should not be nil")
		assert.NotEmpty(t, result.Digest, "Digest should not be empty")
		assert.Equal(t, ref, result.Reference, "Reference should match")
		assert.False(t, result.Encrypted, "Image should not be encrypted")
		assert.False(t, result.Signed, "Image should not be signed")

		// Cleanup
		cleanupImage(t, testCtx, cmd, ref)
	})

	t.Run("PushImageWithMultipleLayers", func(t *testing.T) {
		ref := GenerateUniqueImageRef(prefix+"-push-layers", "v1")
		layers, config := GenerateTestImage(3, 2048)

		opts := PushOptions{
			Layers: layers,
			Config: config,
		}

		result, err := cmd.Push(testCtx, ref, opts)
		require.NoError(t, err, "Push should succeed for multi-layer image")
		require.NotNil(t, result, "Push result should not be nil")
		assert.NotEmpty(t, result.Digest, "Digest should not be empty")
		assert.Greater(t, result.Size, int64(0), "Size should be positive")

		// Cleanup
		cleanupImage(t, testCtx, cmd, ref)
	})

	t.Run("PushImageWithAnnotations", func(t *testing.T) {
		ref := GenerateUniqueImageRef(prefix+"-push-annotations", "v1")
		layers, config := GenerateTestImage(1, 512)

		opts := PushOptions{
			Layers: layers,
			Config: config,
			Annotations: map[string]string{
				"org.opencontainers.image.authors": "test@example.com",
				"org.opencontainers.image.source":  "https://github.com/test/repo",
			},
		}

		result, err := cmd.Push(testCtx, ref, opts)
		require.NoError(t, err, "Push should succeed with annotations")
		require.NotNil(t, result, "Push result should not be nil")

		// Cleanup
		cleanupImage(t, testCtx, cmd, ref)
	})

	t.Run("PushImageWithEncryption", func(t *testing.T) {
		ref := GenerateUniqueImageRef(prefix+"-push-encrypted", "v1")
		layers, config := GenerateTestImage(1, 1024)

		opts := PushOptions{
			Layers:  layers,
			Config:  config,
			Encrypt: true,
			KeyID:   "test-encryption-key-1",
		}

		result, err := cmd.Push(testCtx, ref, opts)
		require.NoError(t, err, "Push should succeed with encryption")
		require.NotNil(t, result, "Push result should not be nil")
		assert.True(t, result.Encrypted, "Image should be encrypted")

		// Cleanup
		cleanupImage(t, testCtx, cmd, ref)
	})

	t.Run("PushImageWithSigning", func(t *testing.T) {
		ref := GenerateUniqueImageRef(prefix+"-push-signed", "v1")
		layers, config := GenerateTestImage(1, 1024)

		opts := PushOptions{
			Layers:       layers,
			Config:       config,
			SignImage:    true,
			SigningKeyID: signingKeyID,
		}

		result, err := cmd.Push(testCtx, ref, opts)
		require.NoError(t, err, "Push should succeed with signing")
		require.NotNil(t, result, "Push result should not be nil")
		assert.True(t, result.Signed, "Image should be signed")

		// Cleanup
		cleanupImage(t, testCtx, cmd, ref)
	})

	t.Run("PushImageWithMissingSigningKeyIsRefused", func(t *testing.T) {
		// The registry signs only with an existing SDK KMS key: a key the
		// KMS does not hold is refused (ErrSigningKeyUnavailable), never
		// created, and nothing is stored.
		ref := GenerateUniqueImageRef(prefix+"-push-missing-key", "v1")
		layers, config := GenerateTestImage(1, 1024)

		_, err := cmd.Push(testCtx, ref, PushOptions{
			Layers:       layers,
			Config:       config,
			SignImage:    true,
			SigningKeyID: signingKeyID + "-missing",
		})
		require.Error(t, err, "Push should fail when the signing key is not in the KMS")

		_, err = cmd.Inspect(testCtx, ref)
		require.Error(t, err, "a push refused for a missing signing key must store nothing")
	})

	t.Run("PushImageOverwriteNotAllowed", func(t *testing.T) {
		ref := GenerateUniqueImageRef(prefix+"-push-no-overwrite", "v1")
		layers, config := GenerateTestImage(1, 512)

		opts := PushOptions{
			Layers:         layers,
			Config:         config,
			AllowOverwrite: false,
		}

		// First push should succeed
		_, err := cmd.Push(testCtx, ref, opts)
		require.NoError(t, err, "First push should succeed")

		// Second push without overwrite should fail
		_, err = cmd.Push(testCtx, ref, opts)
		require.Error(t, err, "Push should fail when overwrite is not allowed")

		// Cleanup
		cleanupImage(t, testCtx, cmd, ref)
	})

	t.Run("PushImageAllowOverwrite", func(t *testing.T) {
		ref := GenerateUniqueImageRef(prefix+"-push-overwrite", "v1")
		layers1, config1 := GenerateTestImage(1, 512)
		layers2, config2 := GenerateTestImage(2, 1024)

		opts1 := PushOptions{
			Layers:         layers1,
			Config:         config1,
			AllowOverwrite: true,
		}

		// First push
		result1, err := cmd.Push(testCtx, ref, opts1)
		require.NoError(t, err, "First push should succeed")
		require.NotNil(t, result1, "First push result should not be nil")

		opts2 := PushOptions{
			Layers:         layers2,
			Config:         config2,
			AllowOverwrite: true,
		}

		// Second push with overwrite should succeed
		result2, err := cmd.Push(testCtx, ref, opts2)
		require.NoError(t, err, "Second push with overwrite should succeed")
		require.NotNil(t, result2, "Second push result should not be nil")

		// Digests should be different
		assert.NotEqual(t, result1.Digest, result2.Digest, "Digests should differ after overwrite")

		// Cleanup
		cleanupImage(t, testCtx, cmd, ref)
	})
}

// =============================================================================
// Image Pull Tests
// =============================================================================

func runImagePullTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if declaredMissing(t, testCtx, cmd, opPull) {
		return
	}

	// First, push an image for pull tests
	ref := GenerateUniqueImageRef(prefix+"-pull-test", "v1")
	layers, config := GenerateTestImage(2, 1024)
	pushOpts := PushOptions{
		Layers: layers,
		Config: config,
	}
	seedImage(t, testCtx, cmd, ref, pushOpts)
	defer cleanupImage(t, testCtx, cmd, ref)

	t.Run("PullExistingImage", func(t *testing.T) {
		pullOpts := PullOptions{}

		result, err := cmd.Pull(testCtx, ref, pullOpts)
		require.NoError(t, err, "Pull should succeed for existing image")
		require.NotNil(t, result, "Pull result should not be nil")
		assert.Equal(t, ref, result.Reference, "Reference should match")
		assert.NotNil(t, result.Manifest, "Manifest should not be nil")
		assert.NotEmpty(t, result.Layers, "Layers should not be empty")
		assert.Equal(t, len(layers), len(result.Layers), "Layer count should match")
	})

	t.Run("PullImageVerifyContent", func(t *testing.T) {
		pullOpts := PullOptions{}

		result, err := cmd.Pull(testCtx, ref, pullOpts)
		require.NoError(t, err, "Pull should succeed")
		require.NotNil(t, result, "Pull result should not be nil")

		// Verify layer contents match original
		for i, originalLayer := range layers {
			assert.True(t, bytes.Equal(originalLayer.Content, result.Layers[i].Content),
				"Layer %d content should match", i)
		}
	})

	t.Run("PullImageWithVerification", func(t *testing.T) {
		pullOpts := PullOptions{
			VerifySignature: true,
		}

		result, err := cmd.Pull(testCtx, ref, pullOpts)
		require.NoError(t, err, "Pull with verification should succeed")
		require.NotNil(t, result, "Pull result should not be nil")
	})

	t.Run("PullNonexistentImageFails", func(t *testing.T) {
		nonexistentRef := GenerateUniqueImageRef(prefix+"-nonexistent", "v1")
		pullOpts := PullOptions{}

		_, err := cmd.Pull(testCtx, nonexistentRef, pullOpts)
		require.Error(t, err, "Pull should fail for nonexistent image")
	})
}

// =============================================================================
// Image List Tests
// =============================================================================

func runImageListTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if declaredMissing(t, testCtx, cmd, opList) {
		return
	}

	// Push multiple images for list tests
	imageRefs := make([]string, 3)
	for i := 0; i < 3; i++ {
		ref := GenerateUniqueImageRef(fmt.Sprintf("%s-list-%d", prefix, i), "latest")
		layers, config := GenerateTestImage(1, 512)
		opts := PushOptions{
			Layers: layers,
			Config: config,
		}
		seedImage(t, testCtx, cmd, ref, opts)
		imageRefs[i] = ref
	}

	// Cleanup at end
	defer func() {
		for _, ref := range imageRefs {
			cleanupImage(t, testCtx, cmd, ref)
		}
	}()

	t.Run("ListAllImages", func(t *testing.T) {
		listOpts := ListOptions{
			Limit: 100,
		}

		result, err := cmd.List(testCtx, listOpts)
		require.NoError(t, err, "List should succeed")
		require.NotNil(t, result, "List result should not be nil")
		assert.GreaterOrEqual(t, len(result.Images), 3, "Should have at least 3 images")
	})

	t.Run("ListImagesWithPagination", func(t *testing.T) {
		listOpts := ListOptions{
			Limit: 2,
		}

		result, err := cmd.List(testCtx, listOpts)
		require.NoError(t, err, "List should succeed with limit")
		require.NotNil(t, result, "List result should not be nil")
		assert.LessOrEqual(t, len(result.Images), 2, "Should respect limit")

		if result.HasMore {
			// Fetch next page
			nextOpts := ListOptions{
				Limit:  2,
				Cursor: result.NextCursor,
			}
			nextResult, err := cmd.List(testCtx, nextOpts)
			require.NoError(t, err, "List next page should succeed")
			require.NotNil(t, nextResult, "Next page result should not be nil")
		}
	})

	t.Run("ListImagesEmpty", func(t *testing.T) {
		// Use a prefix that doesn't match any images
		listOpts := ListOptions{
			Repository: "nonexistent-repository-xyz123",
		}

		result, err := cmd.List(testCtx, listOpts)
		require.NoError(t, err, "List should succeed even with no matches")
		require.NotNil(t, result, "List result should not be nil")
		assert.Empty(t, result.Images, "Should return empty list for no matches")
	})
}

// =============================================================================
// Image Delete Tests
// =============================================================================

func runImageDeleteTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if declaredMissing(t, testCtx, cmd, opDelete) {
		return
	}

	t.Run("DeleteExistingImage", func(t *testing.T) {
		// Push an image first
		ref := GenerateUniqueImageRef(prefix+"-delete-test", "v1")
		layers, config := GenerateTestImage(1, 512)
		pushOpts := PushOptions{
			Layers: layers,
			Config: config,
		}
		seedImage(t, testCtx, cmd, ref, pushOpts)

		// Delete the image
		deleteOpts := DeleteOptions{
			Force:        true,
			DeleteLayers: true,
		}
		result, err := cmd.Delete(testCtx, ref, deleteOpts)
		require.NoError(t, err, "Delete should succeed")
		require.NotNil(t, result, "Delete result should not be nil")
		assert.Equal(t, ref, result.Reference, "Reference should match")
		assert.False(t, result.DeletedAt.IsZero(), "DeletedAt should be set")

		// Verify image is deleted
		_, err = cmd.Inspect(testCtx, ref)
		require.Error(t, err, "Inspect should fail for deleted image")
	})

	t.Run("DeleteNonexistentImageFails", func(t *testing.T) {
		nonexistentRef := GenerateUniqueImageRef(prefix+"-delete-nonexistent", "v1")
		deleteOpts := DeleteOptions{Force: true}

		_, err := cmd.Delete(testCtx, nonexistentRef, deleteOpts)
		require.Error(t, err, "Delete should fail for nonexistent image")
	})
}

// =============================================================================
// Image Inspect Tests
// =============================================================================

func runImageInspectTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if declaredMissing(t, testCtx, cmd, opInspect) {
		return
	}

	// Push an image for inspect tests
	ref := GenerateUniqueImageRef(prefix+"-inspect-test", "v1")
	layers, config := GenerateTestImage(2, 1024)
	pushOpts := PushOptions{
		Layers: layers,
		Config: config,
		Annotations: map[string]string{
			"test.annotation": "value",
		},
	}
	seedImage(t, testCtx, cmd, ref, pushOpts)
	defer cleanupImage(t, testCtx, cmd, ref)

	t.Run("InspectExistingImage", func(t *testing.T) {
		result, err := cmd.Inspect(testCtx, ref)
		require.NoError(t, err, "Inspect should succeed")
		require.NotNil(t, result, "Inspect result should not be nil")
		assert.Equal(t, ref, result.Reference, "Reference should match")
		assert.NotNil(t, result.Manifest, "Manifest should not be nil")
		assert.NotNil(t, result.Config, "Config should not be nil")
		assert.Equal(t, 2, result.LayerCount, "Layer count should be 2")
		assert.Greater(t, result.TotalSize, int64(0), "Total size should be positive")
	})

	t.Run("InspectImageConfig", func(t *testing.T) {
		result, err := cmd.Inspect(testCtx, ref)
		require.NoError(t, err, "Inspect should succeed")
		require.NotNil(t, result.Config, "Config should not be nil")
		assert.Equal(t, "linux", result.Config.OS, "OS should be linux")
		assert.Equal(t, "amd64", result.Config.Architecture, "Architecture should be amd64")
	})

	t.Run("InspectNonexistentImageFails", func(t *testing.T) {
		nonexistentRef := GenerateUniqueImageRef(prefix+"-inspect-nonexistent", "v1")

		_, err := cmd.Inspect(testCtx, nonexistentRef)
		require.Error(t, err, "Inspect should fail for nonexistent image")
	})
}

// =============================================================================
// Registry Status Tests
// =============================================================================

func runRegistryStatusTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if declaredMissing(t, testCtx, cmd, opStatus) {
		return
	}

	t.Run("GetRegistryStatus", func(t *testing.T) {
		result, err := cmd.Status(testCtx)
		require.NoError(t, err, "Status should succeed")
		require.NotNil(t, result, "Status result should not be nil")
		assert.True(t, result.Healthy, "Registry should be healthy")
		assert.Equal(t, "running", result.Status, "Registry should be running")
		assert.NotEmpty(t, result.Version, "Version should not be empty")
		assert.Greater(t, result.Uptime, time.Duration(0), "Uptime should be positive")
		assert.NotEmpty(t, result.StorageBackend, "Storage backend should be set")
	})
}

// =============================================================================
// Client Verification Tests
// =============================================================================

func runClientVerificationTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if declaredMissing(t, testCtx, cmd, opVerifyClient) {
		return
	}

	t.Run("VerifyValidClient", func(t *testing.T) {
		clientID := fmt.Sprintf("%s-client-valid", prefix)
		evidence := GenerateMockAttestationEvidence(clientID)

		result, err := cmd.VerifyClient(testCtx, evidence)
		require.NoError(t, err, "VerifyClient should succeed for valid client")
		require.NotNil(t, result, "VerifyClient result should not be nil")
		assert.True(t, result.Verified, "Client should be verified")
		assert.Equal(t, clientID, result.ClientID, "Client ID should match")
		assert.NotEmpty(t, result.SessionID, "Session ID should be set")
		assert.False(t, result.ValidUntil.IsZero(), "ValidUntil should be set")
		assert.NotEmpty(t, result.Permissions, "Permissions should be set")

		// Cleanup session
		if err := cmd.InvalidateSession(testCtx, clientID); err != nil {
			t.Logf("Warning: failed to invalidate session %s: %v", clientID, err)
		}
	})

	t.Run("VerifyClientWithInvalidQuote", func(t *testing.T) {
		clientID := fmt.Sprintf("%s-client-invalid", prefix)
		evidence := GenerateMockAttestationEvidence(clientID)
		// Corrupt the quote
		evidence.Quote = []byte("invalid-quote-data")

		result, err := cmd.VerifyClient(testCtx, evidence)
		// The server might return an error or set Verified to false
		if err == nil {
			assert.False(t, result.Verified, "Client should not be verified with invalid quote")
			assert.NotEmpty(t, result.Reason, "Reason should be provided for verification failure")
		}
	})
}

// =============================================================================
// Session Management Tests
// =============================================================================

func runSessionManagementTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	verifyMissing := declaredMissing(t, testCtx, cmd, opVerifyClient)
	getMissing := declaredMissing(t, testCtx, cmd, opGetSession)
	invalidateMissing := declaredMissing(t, testCtx, cmd, opInvalidateSession)
	if verifyMissing || getMissing || invalidateMissing {
		return
	}

	// Create a session first
	clientID := fmt.Sprintf("%s-session-test", prefix)
	evidence := GenerateMockAttestationEvidence(clientID)
	verifyResult, err := cmd.VerifyClient(testCtx, evidence)
	if err != nil {
		t.Fatalf("Setup: VerifyClient failed; session tests need a verified client: %v", err)
	}
	require.True(t, verifyResult.Verified, "Client should be verified")

	t.Run("GetExistingSession", func(t *testing.T) {
		result, err := cmd.GetSession(testCtx, clientID)
		require.NoError(t, err, "GetSession should succeed for existing session")
		require.NotNil(t, result, "Session result should not be nil")
		assert.Equal(t, clientID, result.ClientID, "Client ID should match")
		assert.NotEmpty(t, result.SessionID, "Session ID should be set")
		assert.False(t, result.ValidUntil.IsZero(), "ValidUntil should be set")
		assert.False(t, result.CreatedAt.IsZero(), "CreatedAt should be set")
		assert.True(t, time.Now().Before(result.ValidUntil), "Session should not be expired")
	})

	t.Run("InvalidateSession", func(t *testing.T) {
		err := cmd.InvalidateSession(testCtx, clientID)
		require.NoError(t, err, "InvalidateSession should succeed")

		// Session should no longer exist
		_, err = cmd.GetSession(testCtx, clientID)
		require.Error(t, err, "GetSession should fail for invalidated session")
	})

	t.Run("GetNonexistentSessionFails", func(t *testing.T) {
		nonexistentClientID := fmt.Sprintf("%s-nonexistent-session", prefix)

		_, err := cmd.GetSession(testCtx, nonexistentClientID)
		require.Error(t, err, "GetSession should fail for nonexistent session")
	})

	t.Run("InvalidateNonexistentSessionFails", func(t *testing.T) {
		nonexistentClientID := fmt.Sprintf("%s-nonexistent-invalidate", prefix)

		err := cmd.InvalidateSession(testCtx, nonexistentClientID)
		require.Error(t, err, "InvalidateSession should fail for nonexistent session")
	})
}

// =============================================================================
// Image Encryption Tests
// =============================================================================

func runImageEncryptionTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	encryptMissing := declaredMissing(t, testCtx, cmd, opEncryptImage)
	decryptMissing := declaredMissing(t, testCtx, cmd, opDecryptImage)
	if encryptMissing || decryptMissing {
		return
	}

	// Push an unencrypted image first
	ref := GenerateUniqueImageRef(prefix+"-encrypt-test", "v1")
	layers, config := GenerateTestImage(2, 1024)
	pushOpts := PushOptions{
		Layers: layers,
		Config: config,
	}
	seedImage(t, testCtx, cmd, ref, pushOpts)
	defer cleanupImage(t, testCtx, cmd, ref)

	t.Run("EncryptExistingImage", func(t *testing.T) {
		keyID := "test-encryption-key"

		result, err := cmd.EncryptImage(testCtx, ref, keyID)
		require.NoError(t, err, "EncryptImage should succeed")
		require.NotNil(t, result, "EncryptImage result should not be nil")
		assert.Equal(t, ref, result.Reference, "Reference should match")
		assert.Equal(t, keyID, result.KeyID, "Key ID should match")
		assert.False(t, result.EncryptedAt.IsZero(), "EncryptedAt should be set")
		assert.Equal(t, 2, result.LayersEncrypted, "All layers should be encrypted")

		// Verify image is now encrypted
		inspectResult, err := cmd.Inspect(testCtx, ref)
		require.NoError(t, err, "Inspect should succeed")
		assert.True(t, inspectResult.Encrypted, "Image should be encrypted")
		assert.Equal(t, keyID, inspectResult.EncryptionKeyID, "Encryption key ID should match")
	})

	t.Run("DecryptEncryptedImage", func(t *testing.T) {
		result, err := cmd.DecryptImage(testCtx, ref)
		require.NoError(t, err, "DecryptImage should succeed")
		require.NotNil(t, result, "DecryptImage result should not be nil")
		assert.Equal(t, ref, result.Reference, "Reference should match")
		assert.NotEmpty(t, result.KeyID, "Key ID should be set")
		assert.False(t, result.DecryptedAt.IsZero(), "DecryptedAt should be set")
		assert.NotNil(t, result.Manifest, "Manifest should be returned")
		assert.NotEmpty(t, result.Layers, "Decrypted layers should be returned")
	})

	t.Run("EncryptNonexistentImageFails", func(t *testing.T) {
		nonexistentRef := GenerateUniqueImageRef(prefix+"-encrypt-nonexistent", "v1")

		_, err := cmd.EncryptImage(testCtx, nonexistentRef, "test-key")
		require.Error(t, err, "EncryptImage should fail for nonexistent image")
	})

	t.Run("DecryptNonexistentImageFails", func(t *testing.T) {
		nonexistentRef := GenerateUniqueImageRef(prefix+"-decrypt-nonexistent", "v1")

		_, err := cmd.DecryptImage(testCtx, nonexistentRef)
		require.Error(t, err, "DecryptImage should fail for nonexistent image")
	})
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func runImageNotFoundTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	nonexistentRef := GenerateUniqueImageRef(prefix+"-notfound", "v1")

	t.Run("PullNotFound", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opPull) {
			return
		}
		_, err := cmd.Pull(testCtx, nonexistentRef, PullOptions{})
		require.Error(t, err, "Pull should fail for nonexistent image")
	})

	t.Run("InspectNotFound", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opInspect) {
			return
		}
		_, err := cmd.Inspect(testCtx, nonexistentRef)
		require.Error(t, err, "Inspect should fail for nonexistent image")
	})

	t.Run("DeleteNotFound", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opDelete) {
			return
		}
		_, err := cmd.Delete(testCtx, nonexistentRef, DeleteOptions{Force: true})
		require.Error(t, err, "Delete should fail for nonexistent image")
	})

	t.Run("EncryptNotFound", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opEncryptImage) {
			return
		}
		_, err := cmd.EncryptImage(testCtx, nonexistentRef, "test-key")
		require.Error(t, err, "EncryptImage should fail for nonexistent image")
	})

	t.Run("DecryptNotFound", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opDecryptImage) {
			return
		}
		_, err := cmd.DecryptImage(testCtx, nonexistentRef)
		require.Error(t, err, "DecryptImage should fail for nonexistent image")
	})
}

func runInvalidArgumentTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	t.Run("PushEmptyReference", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opPush) {
			return
		}
		layers, config := GenerateTestImage(1, 512)
		opts := PushOptions{
			Layers: layers,
			Config: config,
		}

		_, err := cmd.Push(testCtx, "", opts)
		require.Error(t, err, "Push should fail with empty reference")
	})

	t.Run("PushNoLayers", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opPush) {
			return
		}
		ref := GenerateUniqueImageRef(prefix+"-no-layers", "v1")
		opts := PushOptions{
			Config: GenerateTestConfig(),
		}

		_, err := cmd.Push(testCtx, ref, opts)
		require.Error(t, err, "Push should fail with no layers")
	})

	t.Run("PullEmptyReference", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opPull) {
			return
		}
		_, err := cmd.Pull(testCtx, "", PullOptions{})
		require.Error(t, err, "Pull should fail with empty reference")
	})

	t.Run("InspectEmptyReference", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opInspect) {
			return
		}
		_, err := cmd.Inspect(testCtx, "")
		require.Error(t, err, "Inspect should fail with empty reference")
	})

	t.Run("DeleteEmptyReference", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opDelete) {
			return
		}
		_, err := cmd.Delete(testCtx, "", DeleteOptions{})
		require.Error(t, err, "Delete should fail with empty reference")
	})

	t.Run("EncryptEmptyKeyID", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opEncryptImage) {
			return
		}
		ref := GenerateUniqueImageRef(prefix+"-encrypt-nokey", "v1")

		_, err := cmd.EncryptImage(testCtx, ref, "")
		require.Error(t, err, "EncryptImage should fail with empty key ID")
	})

	t.Run("GetSessionEmptyClientID", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opGetSession) {
			return
		}
		_, err := cmd.GetSession(testCtx, "")
		require.Error(t, err, "GetSession should fail with empty client ID")
	})

	t.Run("InvalidateSessionEmptyClientID", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opInvalidateSession) {
			return
		}
		err := cmd.InvalidateSession(testCtx, "")
		require.Error(t, err, "InvalidateSession should fail with empty client ID")
	})
}

// =============================================================================
// Full Lifecycle Test
// =============================================================================

func runFullImageLifecycleTests(t *testing.T, ctx context.Context, cmd RegistryCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("CompleteLifecycle", func(t *testing.T) {
		if declaredMissing(t, testCtx, cmd, opInspect) {
			return
		}
		imageName := prefix + "-full-lifecycle"
		tag := "latest"
		ref := GenerateUniqueImageRef(imageName, tag)

		// Phase 1: Push image
		t.Log("=== Phase 1: Push Image ===")
		layers, config := GenerateTestImage(2, 2048)
		pushOpts := PushOptions{
			Layers: layers,
			Config: config,
			Annotations: map[string]string{
				"lifecycle.phase": "initial",
				"protocol":        cmd.Name(),
			},
		}

		pushResult := seedImage(t, testCtx, cmd, ref, pushOpts)
		assert.NotEmpty(t, pushResult.Digest, "Push digest should not be empty")
		t.Logf("Pushed image: %s (digest: %s)", ref, pushResult.Digest)

		// Phase 2: Verify image exists via Inspect
		t.Log("=== Phase 2: Inspect Image ===")
		inspectResult, err := cmd.Inspect(testCtx, ref)
		require.NoError(t, err, "Inspect should succeed")
		require.NotNil(t, inspectResult, "Inspect result should not be nil")
		assert.Equal(t, ref, inspectResult.Reference, "Reference should match")
		assert.Equal(t, 2, inspectResult.LayerCount, "Layer count should be 2")
		t.Logf("Image has %d layers, total size: %d bytes", inspectResult.LayerCount, inspectResult.TotalSize)

		// Phase 3: List images and verify our image appears
		t.Log("=== Phase 3: List Images ===")
		listResult, err := cmd.List(testCtx, ListOptions{Limit: 100})
		require.NoError(t, err, "List should succeed")
		found := false
		for _, img := range listResult.Images {
			if img.Reference == ref {
				found = true
				break
			}
		}
		assert.True(t, found, "Image should appear in list")
		t.Logf("Found image in list of %d images", len(listResult.Images))

		// Phase 4: Pull image and verify content
		t.Log("=== Phase 4: Pull Image ===")
		if !declaredMissing(t, testCtx, cmd, opPull) {
			pullResult, err := cmd.Pull(testCtx, ref, PullOptions{})
			require.NoError(t, err, "Pull should succeed")
			require.NotNil(t, pullResult, "Pull result should not be nil")
			assert.Equal(t, len(layers), len(pullResult.Layers), "Layer count should match")

			// Verify layer content matches
			for i, originalLayer := range layers {
				assert.True(t, bytes.Equal(originalLayer.Content, pullResult.Layers[i].Content),
					"Layer %d content should match", i)
			}
			t.Logf("Pulled and verified %d layers", len(pullResult.Layers))
		}

		// Phase 5: Encrypt the image
		t.Log("=== Phase 5: Encrypt Image ===")
		if !declaredMissing(t, testCtx, cmd, opEncryptImage) {
			encryptionKeyID := "lifecycle-encryption-key"
			encryptResult, err := cmd.EncryptImage(testCtx, ref, encryptionKeyID)
			require.NoError(t, err, "EncryptImage should succeed")
			require.NotNil(t, encryptResult, "Encrypt result should not be nil")
			assert.Equal(t, 2, encryptResult.LayersEncrypted, "All layers should be encrypted")
			t.Logf("Encrypted %d layers with key: %s", encryptResult.LayersEncrypted, encryptionKeyID)

			// Verify image is now encrypted
			inspectResult, err = cmd.Inspect(testCtx, ref)
			require.NoError(t, err, "Inspect should succeed after encryption")
			assert.True(t, inspectResult.Encrypted, "Image should be encrypted")
		}

		// Phase 6: Decrypt the image
		t.Log("=== Phase 6: Decrypt Image ===")
		if !declaredMissing(t, testCtx, cmd, opDecryptImage) {
			decryptResult, err := cmd.DecryptImage(testCtx, ref)
			require.NoError(t, err, "DecryptImage should succeed")
			require.NotNil(t, decryptResult, "Decrypt result should not be nil")
			assert.NotEmpty(t, decryptResult.Layers, "Decrypted layers should be returned")
			t.Logf("Decrypted image, got %d layers", len(decryptResult.Layers))
		}

		// Phase 7: Check registry status
		t.Log("=== Phase 7: Check Registry Status ===")
		statusResult, err := cmd.Status(testCtx)
		require.NoError(t, err, "Status should succeed")
		assert.True(t, statusResult.Healthy, "Registry should be healthy")
		t.Logf("Registry status: %s (uptime: %s)", statusResult.Status, statusResult.Uptime)

		// Phase 8: Delete the image
		t.Log("=== Phase 8: Delete Image ===")
		deleteOpts := DeleteOptions{
			Force:        true,
			DeleteLayers: true,
		}
		deleteResult, err := cmd.Delete(testCtx, ref, deleteOpts)
		require.NoError(t, err, "Delete should succeed")
		require.NotNil(t, deleteResult, "Delete result should not be nil")
		t.Logf("Deleted image, removed %d orphaned layers", deleteResult.LayersDeleted)

		// Verify image is gone
		_, err = cmd.Inspect(testCtx, ref)
		require.Error(t, err, "Inspect should fail for deleted image")
		t.Log("Verified image is deleted")

		t.Log("=== Full Lifecycle Test Complete ===")
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// cleanupImage attempts to delete an image, ignoring errors.
// This is used in test cleanup to ensure images don't accumulate.
func cleanupImage(t *testing.T, ctx context.Context, cmd RegistryCommands, ref string) {
	t.Helper()

	deleteOpts := DeleteOptions{
		Force:        true,
		DeleteLayers: true,
	}
	if _, err := cmd.Delete(ctx, ref, deleteOpts); err != nil {
		// Only log, don't fail - this is cleanup
		t.Logf("Warning: failed to cleanup image %s: %v", ref, err)
	}
}

// probeRef is the reference a no-surface probe passes; no transport sends it.
const probeRef = "registry-probe/no-surface:v1"

// surfaceProbes call one operation on an adapter with placeholder arguments,
// so declaredMissing can check what the adapter returns for it.
var surfaceProbes = map[string]func(context.Context, RegistryCommands) error{
	opPush: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.Push(ctx, probeRef, PushOptions{})
		return err
	},
	opPull: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.Pull(ctx, probeRef, PullOptions{})
		return err
	},
	opList: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.List(ctx, ListOptions{})
		return err
	},
	opDelete: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.Delete(ctx, probeRef, DeleteOptions{})
		return err
	},
	opInspect: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.Inspect(ctx, probeRef)
		return err
	},
	opStatus: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.Status(ctx)
		return err
	},
	opTag: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.Tag(ctx, probeRef, probeRef)
		return err
	},
	opVerifyClient: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.VerifyClient(ctx, VerifyClientOptions{ClientID: "registry-probe"})
		return err
	},
	opGetSession: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.GetSession(ctx, "registry-probe")
		return err
	},
	opInvalidateSession: func(ctx context.Context, cmd RegistryCommands) error {
		return cmd.InvalidateSession(ctx, "registry-probe")
	},
	opEncryptImage: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.EncryptImage(ctx, probeRef, "registry-probe-key")
		return err
	},
	opDecryptImage: func(ctx context.Context, cmd RegistryCommands) error {
		_, err := cmd.DecryptImage(ctx, probeRef)
		return err
	},
}

// declaredMissing reports whether cmd's transport has no server surface for
// op (see missingSurface). When it has none, the operation is called and the
// adapter must return surface.ErrNoSurface naming it, so the absence is
// asserted on every run instead of skipped. The caller returns on true.
func declaredMissing(t *testing.T, ctx context.Context, cmd RegistryCommands, op string) bool {
	t.Helper()

	reason, missing := missingSurface(cmd.Name(), op)
	if !missing {
		return false
	}
	var noSurface surface.ErrNoSurface
	require.ErrorAs(t, surfaceProbes[op](ctx, cmd), &noSurface,
		"%s %s has no server surface (%s): the adapter must say so", cmd.Name(), op, reason)
	assert.Equal(t, cmd.Name(), noSurface.Transport, "declared transport")
	assert.Equal(t, op, noSurface.Operation, "declared operation")
	t.Logf("MISSING: %s %s: %s", cmd.Name(), op, reason)
	return true
}

// seedImage pushes ref for a test that needs the image to exist. A transport
// with no push surface (MCP, docs/registry/api.md §4) seeds through gRPC,
// which serves Push, so its own read and delete calls still run.
func seedImage(t *testing.T, ctx context.Context, cmd RegistryCommands, ref string, opts PushOptions) *PushResult {
	t.Helper()

	pusher := cmd
	if _, missing := missingSurface(cmd.Name(), opPush); missing {
		seeder := NewGRPCAdapter()
		require.NoError(t, seeder.Setup(ctx), "Setup: gRPC seeder for %s", cmd.Name())
		defer func() {
			if err := seeder.Teardown(); err != nil {
				t.Logf("Warning: gRPC seeder teardown: %v", err)
			}
		}()
		pusher = seeder
	}
	result, err := pusher.Push(ctx, ref, opts)
	require.NoError(t, err, "Setup: Push should succeed")
	require.NotNil(t, result, "Setup: Push result should not be nil")
	return result
}
