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

// Package secrets provides multi-protocol integration tests for the Secrets services.
// These tests verify that Secrets operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified SecretsCommands interface.
//
// Run tests via:
//
//	make integration-test-secrets
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package secrets

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestSecretsMultiProtocol runs the complete Secrets test suite against all protocol adapters.
// Each adapter implements the SecretsCommands interface, enabling unified testing across
// CLI, REST, and future protocols (gRPC, QUIC, MCP, Socket).
func TestSecretsMultiProtocol(t *testing.T) {
	SkipIfNotIntegration(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement SecretsCommands
	adapters := []SecretsCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Skipf("Skipping %s: setup failed: %v", adapter.Name(), err)
			}
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testSecretsProtocol(t, ctx, adapter)
		})
	}
}

// testSecretsProtocol runs the complete Secrets test suite against a single protocol adapter.
func testSecretsProtocol(t *testing.T, ctx context.Context, cmd SecretsCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("BasicOperations", func(t *testing.T) {
		testStore(t, ctx, cmd, prefix)
		testGet(t, ctx, cmd, prefix)
		testList(t, ctx, cmd, prefix)
		testDelete(t, ctx, cmd, prefix)
	})

	t.Run("VersionManagement", func(t *testing.T) {
		testRotate(t, ctx, cmd, prefix)
		testVersions(t, ctx, cmd, prefix)
		testVersion(t, ctx, cmd, prefix)
		testRollback(t, ctx, cmd, prefix)
	})

	t.Run("StatusAndPolicy", func(t *testing.T) {
		testStatus(t, ctx, cmd, prefix)
		testPolicy(t, ctx, cmd, prefix)
	})

	t.Run("AdvancedOperations", func(t *testing.T) {
		testPrefix(t, ctx, cmd, prefix)
		testBinarySecrets(t, ctx, cmd, prefix)
		testLargeSecrets(t, ctx, cmd, prefix)
		testSecretMetadata(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// Basic Operations Tests
// =============================================================================

func testStore(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("StoreSimpleSecret", func(t *testing.T) {
		secretName := prefix + "-store-simple"
		secretData := []byte("super-secret-password-123")
		opts := StoreOptions{
			Name:        secretName,
			Data:        secretData,
			Description: "Multi-protocol test secret",
		}

		result, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Store should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.SecretID, "SecretID should not be empty")
		assert.Equal(t, uint64(1), result.Version, "Initial version should be 1")

		// Cleanup
		CleanupSecret(cmd, testCtx, secretName)
	})

	t.Run("StoreSecretWithDescription", func(t *testing.T) {
		secretName := prefix + "-store-desc"
		secretData := []byte("secret-with-description")
		opts := StoreOptions{
			Name:        secretName,
			Data:        secretData,
			Description: "This is a detailed description of the secret",
		}

		result, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Store should succeed with description")
		require.NotNil(t, result, "Result should not be nil")

		// Cleanup
		CleanupSecret(cmd, testCtx, secretName)
	})

	t.Run("StoreSecretWithTags", func(t *testing.T) {
		secretName := prefix + "-store-tags"
		secretData := []byte("secret-with-tags")
		opts := StoreOptions{
			Name: secretName,
			Data: secretData,
			Tags: map[string]string{
				"environment": "test",
				"team":        "platform",
			},
		}

		result, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Store should succeed with tags")
		require.NotNil(t, result, "Result should not be nil")

		// Cleanup
		CleanupSecret(cmd, testCtx, secretName)
	})

	t.Run("StoreSecretWithMetadata", func(t *testing.T) {
		secretName := prefix + "-store-metadata"
		secretData := []byte("secret-with-metadata")
		opts := StoreOptions{
			Name: secretName,
			Data: secretData,
			Metadata: map[string]string{
				"source":   "integration-test",
				"rotation": "manual",
			},
		}

		result, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Store should succeed with metadata")
		require.NotNil(t, result, "Result should not be nil")

		// Cleanup
		CleanupSecret(cmd, testCtx, secretName)
	})

	t.Run("StoreSecretEmptyNameFails", func(t *testing.T) {
		opts := StoreOptions{
			Name: "",
			Data: []byte("data"),
		}

		_, err := cmd.Store(testCtx, opts)
		require.Error(t, err, "Store should fail with empty name")
	})
}

func testGet(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret first
	secretName := prefix + "-get-test"
	secretData := []byte("secret-data-for-get")
	storeOpts := StoreOptions{
		Name:        secretName,
		Data:        secretData,
		Description: "Secret for get test",
	}
	_, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")
	defer CleanupSecret(cmd, testCtx, secretName)

	t.Run("GetExistingSecret", func(t *testing.T) {
		result, err := cmd.Get(testCtx, secretName)
		require.NoError(t, err, "Get should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, bytes.Equal(secretData, result.Data), "Secret data should match")
	})

	t.Run("GetNonexistentSecretFails", func(t *testing.T) {
		_, err := cmd.Get(testCtx, prefix+"-nonexistent-secret")
		require.Error(t, err, "Get should fail for nonexistent secret")
	})
}

func testList(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store multiple secrets
	var secretNames []string
	for i := 0; i < 3; i++ {
		secretName := fmt.Sprintf("%s-list-%d", prefix, i)
		secretNames = append(secretNames, secretName)
		opts := StoreOptions{
			Name: secretName,
			Data: []byte(fmt.Sprintf("secret-data-%d", i)),
		}
		_, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Setup: Store should succeed")
	}
	defer CleanupSecrets(cmd, testCtx, secretNames)

	t.Run("ListSecrets", func(t *testing.T) {
		result, err := cmd.List(testCtx, ListOptions{Limit: 100})
		require.NoError(t, err, "List should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Secrets), 3, "Should have at least 3 secrets")
	})

	t.Run("ListSecretsWithPagination", func(t *testing.T) {
		result, err := cmd.List(testCtx, ListOptions{Limit: 2})
		require.NoError(t, err, "List should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Secrets)), int32(2), "Should respect limit")
	})
}

func testDelete(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret for deletion
	secretName := prefix + "-delete-test"
	storeOpts := StoreOptions{
		Name: secretName,
		Data: []byte("delete-me"),
	}
	_, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")

	t.Run("DeleteSecret", func(t *testing.T) {
		result, err := cmd.Delete(testCtx, secretName, true)
		require.NoError(t, err, "Delete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Deleted, "Secret should be deleted")
	})

	t.Run("VerifySecretIsDeleted", func(t *testing.T) {
		_, err := cmd.Get(testCtx, secretName)
		require.Error(t, err, "Get should fail for deleted secret")
	})

	t.Run("DeleteNonexistentSecretFails", func(t *testing.T) {
		_, err := cmd.Delete(testCtx, prefix+"-nonexistent-delete", false)
		require.Error(t, err, "Delete should fail for nonexistent secret")
	})
}

// =============================================================================
// Version Management Tests
// =============================================================================

func testRotate(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret first
	secretName := prefix + "-rotate-test"
	originalData := []byte("original-secret-data")
	storeOpts := StoreOptions{
		Name: secretName,
		Data: originalData,
	}
	storeResult, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")
	originalVersion := storeResult.Version
	defer CleanupSecret(cmd, testCtx, secretName)

	t.Run("RotateSecret", func(t *testing.T) {
		newData := []byte("new-rotated-secret-data")

		result, err := cmd.Rotate(testCtx, secretName, newData)
		require.NoError(t, err, "Rotate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, originalVersion, result.OldVersion, "OldVersion should match original")
		assert.Greater(t, result.NewVersion, result.OldVersion, "NewVersion should be greater")
	})

	t.Run("VerifyRotatedSecret", func(t *testing.T) {
		result, err := cmd.Get(testCtx, secretName)
		require.NoError(t, err, "Get should succeed")
		assert.True(t, bytes.Equal([]byte("new-rotated-secret-data"), result.Data), "Secret data should be rotated")
	})

	t.Run("RotateNonexistentSecretFails", func(t *testing.T) {
		_, err := cmd.Rotate(testCtx, prefix+"-nonexistent-rotate", []byte("data"))
		require.Error(t, err, "Rotate should fail for nonexistent secret")
	})
}

func testVersions(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret and rotate it multiple times
	secretName := prefix + "-versions-test"
	storeOpts := StoreOptions{
		Name: secretName,
		Data: []byte("version-1-data"),
	}
	_, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")
	defer CleanupSecret(cmd, testCtx, secretName)

	// Rotate a few times
	for i := 2; i <= 3; i++ {
		_, err := cmd.Rotate(testCtx, secretName, []byte(fmt.Sprintf("version-%d-data", i)))
		require.NoError(t, err, "Setup: Rotate should succeed")
	}

	t.Run("ListSecretVersions", func(t *testing.T) {
		result, err := cmd.Versions(testCtx, secretName)
		require.NoError(t, err, "Versions should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Versions), 3, "Should have at least 3 versions")
	})
}

func testVersion(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret and rotate it
	secretName := prefix + "-version-test"
	storeOpts := StoreOptions{
		Name: secretName,
		Data: []byte("version-1-data"),
	}
	_, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")
	defer CleanupSecret(cmd, testCtx, secretName)

	// Rotate once
	_, err = cmd.Rotate(testCtx, secretName, []byte("version-2-data"))
	require.NoError(t, err, "Setup: Rotate should succeed")

	t.Run("GetSpecificVersion", func(t *testing.T) {
		result, err := cmd.Version(testCtx, secretName, 1)
		require.NoError(t, err, "Version should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, uint64(1), result.Version, "Version should be 1")
		assert.True(t, bytes.Equal([]byte("version-1-data"), result.Data), "Data should match version 1")
	})

	t.Run("GetLatestVersion", func(t *testing.T) {
		result, err := cmd.Version(testCtx, secretName, 2)
		require.NoError(t, err, "Version should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, uint64(2), result.Version, "Version should be 2")
		assert.True(t, bytes.Equal([]byte("version-2-data"), result.Data), "Data should match version 2")
	})
}

func testRollback(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret and rotate it
	secretName := prefix + "-rollback-test"
	originalData := []byte("original-rollback-data")
	storeOpts := StoreOptions{
		Name: secretName,
		Data: originalData,
	}
	_, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")
	defer CleanupSecret(cmd, testCtx, secretName)

	// Rotate to create version 2
	_, err = cmd.Rotate(testCtx, secretName, []byte("rotated-data"))
	require.NoError(t, err, "Setup: Rotate should succeed")

	t.Run("RollbackToVersion1", func(t *testing.T) {
		result, err := cmd.Rollback(testCtx, secretName, 1)
		require.NoError(t, err, "Rollback should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Greater(t, result.NewVersion, uint64(2), "NewVersion should be > 2 (creates new version)")
	})

	t.Run("VerifyRollbackData", func(t *testing.T) {
		result, err := cmd.Get(testCtx, secretName)
		require.NoError(t, err, "Get should succeed")
		assert.True(t, bytes.Equal(originalData, result.Data), "Data should match version 1 after rollback")
	})
}

// =============================================================================
// Status and Policy Tests
// =============================================================================

func testStatus(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret first
	secretName := prefix + "-status-test"
	storeOpts := StoreOptions{
		Name: secretName,
		Data: []byte("status-test-data"),
	}
	_, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")
	defer CleanupSecret(cmd, testCtx, secretName)

	t.Run("DisableSecret", func(t *testing.T) {
		result, err := cmd.Status(testCtx, secretName, false)
		require.NoError(t, err, "Status (disable) should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Contains(t, result.Status, "DISABLED", "Status should indicate disabled")
	})

	t.Run("EnableSecret", func(t *testing.T) {
		result, err := cmd.Status(testCtx, secretName, true)
		require.NoError(t, err, "Status (enable) should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Contains(t, result.Status, "ENABLED", "Status should indicate enabled")
	})
}

func testPolicy(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret first
	secretName := prefix + "-policy-test"
	storeOpts := StoreOptions{
		Name: secretName,
		Data: []byte("policy-test-data"),
	}
	_, err := cmd.Store(testCtx, storeOpts)
	require.NoError(t, err, "Setup: Store should succeed")
	defer CleanupSecret(cmd, testCtx, secretName)

	t.Run("SetRotationPolicy", func(t *testing.T) {
		policyOpts := PolicySetOptions{
			Enabled:         true,
			IntervalSeconds: 86400, // 24 hours
			RetainVersions:  10,
		}

		result, err := cmd.PolicySet(testCtx, secretName, policyOpts)
		require.NoError(t, err, "PolicySet should succeed")
		require.NotNil(t, result, "Result should not be nil")
	})

	t.Run("GetRotationPolicy", func(t *testing.T) {
		result, err := cmd.Policy(testCtx, secretName)
		require.NoError(t, err, "Policy should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Enabled, "Policy should be enabled")
		assert.Equal(t, int64(86400), result.IntervalSeconds, "Interval should match")
		assert.Equal(t, int32(10), result.RetainVersions, "RetainVersions should match")
	})

	t.Run("DisableRotationPolicy", func(t *testing.T) {
		policyOpts := PolicySetOptions{
			Enabled: false,
		}

		result, err := cmd.PolicySet(testCtx, secretName, policyOpts)
		require.NoError(t, err, "PolicySet should succeed")
		require.NotNil(t, result, "Result should not be nil")

		// Verify disabled
		policyResult, err := cmd.Policy(testCtx, secretName)
		require.NoError(t, err, "Policy should succeed")
		assert.False(t, policyResult.Enabled, "Policy should be disabled")
	})
}

// =============================================================================
// Advanced Operations Tests
// =============================================================================

func testPrefix(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store multiple secrets with a common prefix
	secretPrefix := prefix + "-prefix-test"
	var secretNames []string
	for i := 0; i < 3; i++ {
		secretName := fmt.Sprintf("%s/item-%d", secretPrefix, i)
		secretNames = append(secretNames, secretName)
		opts := StoreOptions{
			Name: secretName,
			Data: []byte(fmt.Sprintf("prefix-data-%d", i)),
		}
		_, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Setup: Store should succeed")
	}
	defer CleanupSecrets(cmd, testCtx, secretNames)

	t.Run("GetSecretsByPrefix", func(t *testing.T) {
		result, err := cmd.Prefix(testCtx, secretPrefix, false)
		require.NoError(t, err, "Prefix should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Secrets), 3, "Should have at least 3 secrets")
	})

	t.Run("GetSecretsByPrefixWithData", func(t *testing.T) {
		result, err := cmd.Prefix(testCtx, secretPrefix, true)
		require.NoError(t, err, "Prefix with data should succeed")
		require.NotNil(t, result, "Result should not be nil")
		// Verify data is included
		for _, secret := range result.Secrets {
			assert.NotNil(t, secret.Data, "Secret data should be included")
		}
	})
}

func testBinarySecrets(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("StoreBinarySecret", func(t *testing.T) {
		secretName := prefix + "-binary-test"
		// Generate binary data with all byte values
		binaryData := make([]byte, 256)
		for i := range binaryData {
			binaryData[i] = byte(i)
		}

		opts := StoreOptions{
			Name:        secretName,
			Data:        binaryData,
			Description: "Binary secret data",
		}

		result, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Store should succeed for binary data")
		require.NotNil(t, result, "Result should not be nil")
		defer CleanupSecret(cmd, testCtx, secretName)

		// Verify binary data is preserved
		getResult, err := cmd.Get(testCtx, secretName)
		require.NoError(t, err, "Get should succeed")
		assert.True(t, bytes.Equal(binaryData, getResult.Data), "Binary data should match")
	})
}

func testLargeSecrets(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	t.Run("StoreLargeSecret", func(t *testing.T) {
		secretName := prefix + "-large-test"
		// 64KB secret
		largeData := make([]byte, 64*1024)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}

		opts := StoreOptions{
			Name:        secretName,
			Data:        largeData,
			Description: "Large secret data",
		}

		result, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Store should succeed for large data")
		require.NotNil(t, result, "Result should not be nil")
		defer CleanupSecret(cmd, testCtx, secretName)

		// Verify large data is preserved
		getResult, err := cmd.Get(testCtx, secretName)
		require.NoError(t, err, "Get should succeed")
		assert.True(t, bytes.Equal(largeData, getResult.Data), "Large data should match")
	})
}

func testSecretMetadata(t *testing.T, ctx context.Context, cmd SecretsCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("StoreAndRetrieveWithMetadata", func(t *testing.T) {
		secretName := prefix + "-metadata-test"
		secretData := []byte("secret-with-metadata")
		metadata := map[string]string{
			"environment": "integration-test",
			"owner":       "test-user",
			"purpose":     "testing",
		}

		opts := StoreOptions{
			Name:        secretName,
			Data:        secretData,
			Description: "Secret with metadata",
			Metadata:    metadata,
		}

		result, err := cmd.Store(testCtx, opts)
		require.NoError(t, err, "Store should succeed")
		require.NotNil(t, result, "Result should not be nil")
		defer CleanupSecret(cmd, testCtx, secretName)

		// Verify metadata is preserved
		getResult, err := cmd.Get(testCtx, secretName)
		require.NoError(t, err, "Get should succeed")
		assert.True(t, bytes.Equal(secretData, getResult.Data), "Data should match")
	})
}
