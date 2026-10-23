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

// Package kms provides multi-protocol integration tests for the KMS services.
// These tests verify that KMS operations work consistently across all protocol adapters
// (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified KMSCommands interface.
//
// Run tests via:
//
//	make integration-test-kms
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package kms

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
)

// =============================================================================
// Multi-Protocol Test Entry Point
// =============================================================================

// TestKMSMultiProtocol runs the complete KMS test suite against all protocol adapters.
// Each adapter implements the KMSCommands interface, enabling unified testing across
// CLI, REST, and future protocols (gRPC, QUIC, MCP, Socket).
func TestKMSMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Get all protocol adapters that implement KMSCommands
	adapters := []KMSCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "kms", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // Capture for closure
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			}()

			testKMSProtocol(t, ctx, adapter)
		})
	}
}

// testKMSProtocol runs the complete KMS test suite against a single protocol adapter.
func testKMSProtocol(t *testing.T, ctx context.Context, cmd KMSCommands) {
	// Generate unique test prefix for this protocol run
	prefix := fmt.Sprintf("%s-%d", cmd.Name(), time.Now().Unix())

	t.Run("KeyManagement", func(t *testing.T) {
		testKeyGenerate(t, ctx, cmd, prefix)
		testKeyGet(t, ctx, cmd, prefix)
		testKeyList(t, ctx, cmd, prefix)
		testKeyRotate(t, ctx, cmd, prefix)
		testKeyDelete(t, ctx, cmd, prefix)
		testKeyStatus(t, ctx, cmd, prefix)
		testKeyAlgorithms(t, ctx, cmd, prefix)
		testKeyPolicy(t, ctx, cmd, prefix)
		testKeyMetadata(t, ctx, cmd, prefix)
		testKeyRevoke(t, ctx, cmd, prefix)
	})

	t.Run("CryptoOperations", func(t *testing.T) {
		testEncryptDecrypt(t, ctx, cmd, prefix)
		testSignVerify(t, ctx, cmd, prefix)
		testHash(t, ctx, cmd, prefix)
		testHMAC(t, ctx, cmd, prefix)
		testRandom(t, ctx, cmd, prefix)
	})

	t.Run("DEKManagement", func(t *testing.T) {
		testDEKCreate(t, ctx, cmd, prefix)
		testDEKGet(t, ctx, cmd, prefix)
		testDEKList(t, ctx, cmd, prefix)
		testDEKRotate(t, ctx, cmd, prefix)
		testDEKDelete(t, ctx, cmd, prefix)
		testDEKStatus(t, ctx, cmd, prefix)
	})

	t.Run("SecretsManagement", func(t *testing.T) {
		testSecretsStore(t, ctx, cmd, prefix)
		testSecretsGet(t, ctx, cmd, prefix)
		testSecretsList(t, ctx, cmd, prefix)
		testSecretsRotate(t, ctx, cmd, prefix)
		testSecretsVersions(t, ctx, cmd, prefix)
		testSecretsRollback(t, ctx, cmd, prefix)
		testSecretsDelete(t, ctx, cmd, prefix)
		testSecretsStatus(t, ctx, cmd, prefix)
	})
}

// =============================================================================
// Key Management Tests
// =============================================================================

func testKeyGenerate(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GenerateAES256GCMKey", func(t *testing.T) {
		keyID := prefix + "-keygen-aes256"
		opts := KeyGenerateOptions{
			KeyID:       keyID,
			Algorithm:   "AES-256-GCM",
			Purpose:     "encrypt",
			Name:        "Test AES-256-GCM Key",
			Description: "Multi-protocol test key for encryption",
		}

		result, err := cmd.KeyGenerate(testCtx, opts)
		require.NoError(t, err, "KeyGenerate should succeed for AES-256-GCM")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.KeyID, "KeyID should not be empty")
		assert.Equal(t, uint64(1), result.Version, "Initial version should be 1")
		assert.Contains(t, result.Algorithm, "AES", "Algorithm should contain AES")
	})

	t.Run("GenerateECDSAP256Key", func(t *testing.T) {
		keyID := prefix + "-keygen-ecdsa"
		opts := KeyGenerateOptions{
			KeyID:       keyID,
			Algorithm:   "ECDSA-P256",
			Purpose:     "sign",
			Name:        "Test ECDSA P-256 Key",
			Description: "Multi-protocol test key for signing",
		}

		result, err := cmd.KeyGenerate(testCtx, opts)
		require.NoError(t, err, "KeyGenerate should succeed for ECDSA-P256")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.KeyID, "KeyID should not be empty")
	})

	t.Run("GenerateRSA2048Key", func(t *testing.T) {
		keyID := prefix + "-keygen-rsa"
		opts := KeyGenerateOptions{
			KeyID:       keyID,
			Algorithm:   "RSA-2048",
			Purpose:     "sign",
			Name:        "Test RSA-2048 Key",
			Description: "Multi-protocol test key for RSA signing",
		}

		result, err := cmd.KeyGenerate(testCtx, opts)
		require.NoError(t, err, "KeyGenerate should succeed for RSA-2048")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.KeyID, "KeyID should not be empty")
	})

	t.Run("GenerateKeyWithDeletionProtection", func(t *testing.T) {
		keyID := prefix + "-keygen-protected"
		opts := KeyGenerateOptions{
			KeyID:              keyID,
			Algorithm:          "AES-256-GCM",
			Purpose:            "encrypt",
			DeletionProtection: true,
			Name:               "Protected Key",
		}

		result, err := cmd.KeyGenerate(testCtx, opts)
		require.NoError(t, err, "KeyGenerate should succeed with deletion protection")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.DeletionProtection, "DeletionProtection should be true")
	})

	t.Run("GenerateKeyWithEmptyIDFails", func(t *testing.T) {
		opts := KeyGenerateOptions{
			KeyID:     "",
			Algorithm: "AES-256-GCM",
		}

		_, err := cmd.KeyGenerate(testCtx, opts)
		require.Error(t, err, "KeyGenerate should fail with empty KeyID")
	})
}

func testKeyGet(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a key first
	keyID := prefix + "-keyget-test"
	genOpts := KeyGenerateOptions{
		KeyID:       keyID,
		Algorithm:   "AES-256-GCM",
		Purpose:     "encrypt",
		Name:        "KeyGet Test Key",
		Description: "Key for testing KeyGet operation",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("GetExistingKey", func(t *testing.T) {
		result, err := cmd.KeyGet(testCtx, keyID, 0)
		require.NoError(t, err, "KeyGet should succeed for existing key")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
		assert.Equal(t, "KeyGet Test Key", result.Name, "Name should match")
	})

	t.Run("GetKeyWithSpecificVersion", func(t *testing.T) {
		result, err := cmd.KeyGet(testCtx, keyID, 1)
		require.NoError(t, err, "KeyGet should succeed for specific version")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, uint64(1), result.Version, "Version should be 1")
	})

	t.Run("GetNonexistentKeyFails", func(t *testing.T) {
		_, err := cmd.KeyGet(testCtx, prefix+"-nonexistent-key", 0)
		require.Error(t, err, "KeyGet should fail for nonexistent key")
	})
}

func testKeyList(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple keys for listing
	for i := 0; i < 3; i++ {
		keyID := fmt.Sprintf("%s-keylist-%d", prefix, i)
		opts := KeyGenerateOptions{
			KeyID:     keyID,
			Algorithm: "AES-256-GCM",
			Purpose:   "encrypt",
		}
		_, err := cmd.KeyGenerate(testCtx, opts)
		require.NoError(t, err, "Setup: KeyGenerate should succeed")
	}

	t.Run("ListAllKeys", func(t *testing.T) {
		result, err := cmd.KeyList(testCtx, KeyListOptions{Limit: 100})
		require.NoError(t, err, "KeyList should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Keys), 3, "Should have at least 3 keys")
	})

	t.Run("ListKeysWithPagination", func(t *testing.T) {
		result, err := cmd.KeyList(testCtx, KeyListOptions{Limit: 2})
		require.NoError(t, err, "KeyList should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Keys)), int32(2), "Should respect limit")
	})
}

func testKeyRotate(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a key for rotation
	keyID := prefix + "-keyrotate-test"
	genOpts := KeyGenerateOptions{
		KeyID:     keyID,
		Algorithm: "AES-256-GCM",
		Purpose:   "encrypt",
	}
	genResult, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")
	originalVersion := genResult.Version

	t.Run("RotateExistingKey", func(t *testing.T) {
		result, err := cmd.KeyRotate(testCtx, keyID, true)
		require.NoError(t, err, "KeyRotate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
		assert.Equal(t, originalVersion, result.OldVersion, "OldVersion should match original")
		assert.Greater(t, result.NewVersion, result.OldVersion, "NewVersion should be greater")
	})

	t.Run("VerifyKeyHasNewVersion", func(t *testing.T) {
		getResult, err := cmd.KeyGet(testCtx, keyID, 0)
		require.NoError(t, err, "KeyGet should succeed")
		assert.Greater(t, getResult.Version, originalVersion, "Key version should be incremented")
	})

	t.Run("RotateNonexistentKeyFails", func(t *testing.T) {
		_, err := cmd.KeyRotate(testCtx, prefix+"-nonexistent-rotate", false)
		require.Error(t, err, "KeyRotate should fail for nonexistent key")
	})
}

func testKeyDelete(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a key for deletion
	keyID := prefix + "-keydelete-test"
	genOpts := KeyGenerateOptions{
		KeyID:              keyID,
		Algorithm:          "AES-256-GCM",
		Purpose:            "encrypt",
		DeletionProtection: false,
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("DeleteExistingKey", func(t *testing.T) {
		result, err := cmd.KeyDelete(testCtx, keyID, KeyDeleteOptions{Force: true})
		require.NoError(t, err, "KeyDelete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
	})

	t.Run("VerifyKeyIsDeleted", func(t *testing.T) {
		_, err := cmd.KeyGet(testCtx, keyID, 0)
		require.Error(t, err, "KeyGet should fail for deleted key")
	})

	t.Run("DeleteNonexistentKeyFails", func(t *testing.T) {
		_, err := cmd.KeyDelete(testCtx, prefix+"-nonexistent-delete", KeyDeleteOptions{})
		require.Error(t, err, "KeyDelete should fail for nonexistent key")
	})
}

func testKeyStatus(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a key for status testing
	keyID := prefix + "-keystatus-test"
	genOpts := KeyGenerateOptions{
		KeyID:     keyID,
		Algorithm: "AES-256-GCM",
		Purpose:   "encrypt",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("DisableKey", func(t *testing.T) {
		result, err := cmd.KeyStatus(testCtx, keyID, 0, false)
		if requireKeyStatusSDKGap(t, cmd.Name(), err) {
			return
		}
		require.NoError(t, err, "KeyStatus (disable) should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Contains(t, result.Status, "DISABLED", "Status should indicate disabled")
	})

	t.Run("EnableKey", func(t *testing.T) {
		result, err := cmd.KeyStatus(testCtx, keyID, 0, true)
		if requireKeyStatusSDKGap(t, cmd.Name(), err) {
			return
		}
		require.NoError(t, err, "KeyStatus (enable) should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Contains(t, result.Status, "ENABLED", "Status should indicate enabled")
	})
}

// keyStatusSDKGapAdapters are the adapters whose key status update reaches
// kms.Client.UpdateKeyStatus through the daemon's KMS adapter, which the
// pinned SDK's embedded transport refuses (helpers.KMSKeyStatusSDKGap).
var keyStatusSDKGapAdapters = map[string]bool{
	"gRPC": true,
	"QUIC": true,
	"Unix": true,
}

// requireKeyStatusSDKGap asserts the typed SDK-gap refusal for the adapters in
// keyStatusSDKGapAdapters and reports whether it did; other adapters return
// false and keep their own assertions.
func requireKeyStatusSDKGap(t *testing.T, adapter string, err error) bool {
	t.Helper()
	if !keyStatusSDKGapAdapters[adapter] {
		return false
	}
	require.ErrorIs(t, helpers.CLIUpstreamGap("kms key status", helpers.KMSKeyStatusSDKGap, err),
		helpers.ErrCLIUpstreamGap{}, "%s key status must answer the SDK refusal", adapter)
	return true
}

func testKeyAlgorithms(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("GetSupportedAlgorithms", func(t *testing.T) {
		result, err := cmd.KeyAlgorithms(testCtx)
		require.NoError(t, err, "KeyAlgorithms should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.Algorithms, "Algorithms list should not be empty")

		// Verify common algorithms are present
		algorithms := result.Algorithms
		hasAES := false
		hasECDSA := false
		hasRSA := false
		for _, alg := range algorithms {
			if contains(alg, "AES") {
				hasAES = true
			}
			if contains(alg, "ECDSA") {
				hasECDSA = true
			}
			if contains(alg, "RSA") {
				hasRSA = true
			}
		}
		assert.True(t, hasAES, "AES algorithm should be supported")
		assert.True(t, hasECDSA, "ECDSA algorithm should be supported")
		assert.True(t, hasRSA, "RSA algorithm should be supported")
	})
}

func testKeyPolicy(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a key for policy testing
	keyID := prefix + "-keypolicy-test"
	genOpts := KeyGenerateOptions{
		KeyID:     keyID,
		Algorithm: "AES-256-GCM",
		Purpose:   "encrypt",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("SetKeyPolicy", func(t *testing.T) {
		setOpts := KeyPolicySetOptions{
			Operations:       []string{"encrypt", "decrypt"},
			AllowPrincipals:  []string{"user:admin@example.com", "service:kms-service"},
			DenyPrincipals:   []string{"user:blocked@example.com"},
			RotationRequired: true,
			MaxUsageCount:    10000,
			RequireMFA:       false,
		}
		result, err := cmd.KeyPolicySet(testCtx, keyID, setOpts)
		require.NoError(t, err, "KeyPolicySet should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
		assert.Greater(t, result.PolicyVersion, int32(0), "PolicyVersion should be positive")
	})

	t.Run("GetKeyPolicy", func(t *testing.T) {
		result, err := cmd.KeyPolicy(testCtx, keyID)
		require.NoError(t, err, "KeyPolicy should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
		assert.True(t, containsFold(result.AllowedOperations, "encrypt"), "Policy should allow encrypt")
		assert.True(t, containsFold(result.AllowedOperations, "decrypt"), "Policy should allow decrypt")
		assert.True(t, result.RotationRequired, "RotationRequired should be true")
		assert.Equal(t, uint64(10000), result.MaxUsageCount, "MaxUsageCount should match")
	})

	t.Run("GetPolicyNonexistentKeyFails", func(t *testing.T) {
		_, err := cmd.KeyPolicy(testCtx, prefix+"-nonexistent-policy")
		require.Error(t, err, "KeyPolicy should fail for nonexistent key")
	})
}

func testKeyMetadata(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a key for metadata testing
	keyID := prefix + "-keymetadata-test"
	genOpts := KeyGenerateOptions{
		KeyID:       keyID,
		Algorithm:   "AES-256-GCM",
		Purpose:     "encrypt",
		Name:        "Original Metadata Name",
		Description: "Original metadata description",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("GetKeyMetadata", func(t *testing.T) {
		result, err := cmd.KeyMetadata(testCtx, keyID)
		require.NoError(t, err, "KeyMetadata should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
		assert.Equal(t, "Original Metadata Name", result.Name, "Name should match")
		assert.Equal(t, "Original metadata description", result.Description, "Description should match")
		assert.Contains(t, result.Algorithm, "AES", "Algorithm should contain AES")
	})

	t.Run("UpdateKeyMetadata", func(t *testing.T) {
		updateOpts := KeyMetadataUpdateOptions{
			Name:        "Updated Metadata Name",
			Description: "Updated metadata description",
			Tags: map[string]string{
				"environment": "test",
				"team":        "security",
			},
		}
		result, err := cmd.KeyMetadataUpdate(testCtx, keyID, updateOpts)
		require.NoError(t, err, "KeyMetadataUpdate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
		assert.Equal(t, "Updated Metadata Name", result.Name, "Name should be updated")
	})

	t.Run("VerifyUpdatedMetadata", func(t *testing.T) {
		result, err := cmd.KeyMetadata(testCtx, keyID)
		require.NoError(t, err, "KeyMetadata should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, "Updated Metadata Name", result.Name, "Name should be updated")
		assert.Equal(t, "Updated metadata description", result.Description, "Description should be updated")
		assert.Equal(t, "test", result.Tags["environment"], "Tag 'environment' should be set")
		assert.Equal(t, "security", result.Tags["team"], "Tag 'team' should be set")
	})

	t.Run("GetMetadataNonexistentKeyFails", func(t *testing.T) {
		_, err := cmd.KeyMetadata(testCtx, prefix+"-nonexistent-metadata")
		require.Error(t, err, "KeyMetadata should fail for nonexistent key")
	})
}

func testKeyRevoke(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create a key for revocation testing
	keyID := prefix + "-keyrevoke-test"
	genOpts := KeyGenerateOptions{
		KeyID:     keyID,
		Algorithm: "AES-256-GCM",
		Purpose:   "encrypt",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("RevokeKey", func(t *testing.T) {
		result, err := cmd.KeyRevoke(testCtx, keyID, "Key compromised in test scenario")
		require.NoError(t, err, "KeyRevoke should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, keyID, result.KeyID, "KeyID should match")
		// The platform has no REVOKED key status: the QuicBaaS service
		// reports revoked keys as COMPROMISED and persists them DISABLED,
		// so either unusable state satisfies the revocation contract.
		assert.Contains(t, []string{"COMPROMISED", "DISABLED"}, result.Status,
			"Status should be an unusable post-revocation state")
		assert.False(t, result.RevokedAt.IsZero(), "RevokedAt should be set")
	})

	t.Run("EncryptWithRevokedKeyFails", func(t *testing.T) {
		_, err := cmd.CryptoEncrypt(testCtx, CryptoEncryptOptions{
			KeyID:     keyID,
			Plaintext: []byte("test data"),
		})
		require.Error(t, err, "CryptoEncrypt should fail with revoked key")
	})

	t.Run("RevokeNonexistentKeyFails", func(t *testing.T) {
		_, err := cmd.KeyRevoke(testCtx, prefix+"-nonexistent-revoke", "test reason")
		require.Error(t, err, "KeyRevoke should fail for nonexistent key")
	})
}

// =============================================================================
// Cryptographic Operations Tests
// =============================================================================

func testEncryptDecrypt(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create encryption key
	keyID := prefix + "-crypto-encrypt"
	genOpts := KeyGenerateOptions{
		KeyID:     keyID,
		Algorithm: "AES-256-GCM",
		Purpose:   "encrypt",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("EncryptDecryptRoundTrip", func(t *testing.T) {
		plaintext := []byte("Multi-protocol test: Hello, KMS encryption!")

		// Encrypt
		encResult, err := cmd.CryptoEncrypt(testCtx, CryptoEncryptOptions{
			KeyID:     keyID,
			Plaintext: plaintext,
		})
		require.NoError(t, err, "CryptoEncrypt should succeed")
		require.NotNil(t, encResult, "Encrypt result should not be nil")
		assert.NotEmpty(t, encResult.Ciphertext, "Ciphertext should not be empty")
		assert.False(t, bytes.Equal(plaintext, encResult.Ciphertext), "Ciphertext should differ from plaintext")

		// Decrypt
		decResult, err := cmd.CryptoDecrypt(testCtx, CryptoDecryptOptions{
			KeyID:      keyID,
			Ciphertext: encResult.Ciphertext,
			Nonce:      encResult.Nonce,
			KeyVersion: encResult.KeyVersion,
		})
		require.NoError(t, err, "CryptoDecrypt should succeed")
		require.NotNil(t, decResult, "Decrypt result should not be nil")
		assert.True(t, bytes.Equal(plaintext, decResult.Plaintext), "Decrypted plaintext should match original")
	})

	t.Run("EncryptDecryptWithAAD", func(t *testing.T) {
		plaintext := []byte("Authenticated encryption test")
		aad := []byte("additional authenticated data")

		// Encrypt with AAD
		encResult, err := cmd.CryptoEncrypt(testCtx, CryptoEncryptOptions{
			KeyID:     keyID,
			Plaintext: plaintext,
			Context:   aad,
		})
		require.NoError(t, err, "CryptoEncrypt with AAD should succeed")

		// Decrypt with same AAD
		decResult, err := cmd.CryptoDecrypt(testCtx, CryptoDecryptOptions{
			KeyID:      keyID,
			Ciphertext: encResult.Ciphertext,
			Nonce:      encResult.Nonce,
			Context:    aad,
			KeyVersion: encResult.KeyVersion,
		})
		require.NoError(t, err, "CryptoDecrypt with AAD should succeed")
		assert.True(t, bytes.Equal(plaintext, decResult.Plaintext), "Decrypted plaintext should match original")
	})

	t.Run("DecryptWithModifiedCiphertextFails", func(t *testing.T) {
		plaintext := []byte("Integrity test data")

		encResult, err := cmd.CryptoEncrypt(testCtx, CryptoEncryptOptions{
			KeyID:     keyID,
			Plaintext: plaintext,
		})
		require.NoError(t, err, "CryptoEncrypt should succeed")

		// Modify ciphertext
		modifiedCiphertext := make([]byte, len(encResult.Ciphertext))
		copy(modifiedCiphertext, encResult.Ciphertext)
		if len(modifiedCiphertext) > 0 {
			modifiedCiphertext[0] ^= 0xFF
		}

		_, err = cmd.CryptoDecrypt(testCtx, CryptoDecryptOptions{
			KeyID:      keyID,
			Ciphertext: modifiedCiphertext,
			Nonce:      encResult.Nonce,
		})
		require.Error(t, err, "CryptoDecrypt with modified ciphertext should fail")
	})
}

func testSignVerify(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create signing key
	keyID := prefix + "-crypto-sign"
	genOpts := KeyGenerateOptions{
		KeyID:     keyID,
		Algorithm: "ECDSA-P256",
		Purpose:   "sign",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("SignVerifyRoundTrip", func(t *testing.T) {
		message := []byte("Multi-protocol test: Sign this message")

		// Sign
		signResult, err := cmd.CryptoSign(testCtx, CryptoSignOptions{
			KeyID:         keyID,
			Message:       message,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoSign should succeed")
		require.NotNil(t, signResult, "Sign result should not be nil")
		assert.NotEmpty(t, signResult.Signature, "Signature should not be empty")

		// Verify
		verifyResult, err := cmd.CryptoVerify(testCtx, CryptoVerifyOptions{
			KeyID:         keyID,
			Message:       message,
			Signature:     signResult.Signature,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoVerify should succeed")
		require.NotNil(t, verifyResult, "Verify result should not be nil")
		assert.True(t, verifyResult.Valid, "Signature should be valid")
	})

	t.Run("VerifyModifiedMessageFails", func(t *testing.T) {
		message := []byte("Original message")

		signResult, err := cmd.CryptoSign(testCtx, CryptoSignOptions{
			KeyID:         keyID,
			Message:       message,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoSign should succeed")

		// Verify with modified message
		verifyResult, err := cmd.CryptoVerify(testCtx, CryptoVerifyOptions{
			KeyID:         keyID,
			Message:       []byte("Modified message"),
			Signature:     signResult.Signature,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoVerify should succeed (not error, just invalid)")
		assert.False(t, verifyResult.Valid, "Signature should be invalid for modified message")
	})
}

func testHash(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	t.Run("HashSHA256", func(t *testing.T) {
		data := []byte("Multi-protocol test: Hash this data")

		result, err := cmd.CryptoHash(testCtx, data, "SHA256")
		require.NoError(t, err, "CryptoHash should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Len(t, result.Hash, 32, "SHA256 should produce 32 bytes")
		assert.Equal(t, "SHA256", result.Algorithm, "Algorithm should be SHA256")
	})

	t.Run("HashDeterministic", func(t *testing.T) {
		data := []byte("Deterministic hash test")

		result1, err := cmd.CryptoHash(testCtx, data, "SHA256")
		require.NoError(t, err, "First CryptoHash should succeed")

		result2, err := cmd.CryptoHash(testCtx, data, "SHA256")
		require.NoError(t, err, "Second CryptoHash should succeed")

		assert.True(t, bytes.Equal(result1.Hash, result2.Hash), "Same data should produce same hash")
	})

	t.Run("HashDifferentData", func(t *testing.T) {
		data1 := []byte("First data")
		data2 := []byte("Second data")

		result1, err := cmd.CryptoHash(testCtx, data1, "SHA256")
		require.NoError(t, err, "First CryptoHash should succeed")

		result2, err := cmd.CryptoHash(testCtx, data2, "SHA256")
		require.NoError(t, err, "Second CryptoHash should succeed")

		assert.False(t, bytes.Equal(result1.Hash, result2.Hash), "Different data should produce different hashes")
	})
}

func testHMAC(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create HMAC key
	keyID := prefix + "-crypto-hmac"
	genOpts := KeyGenerateOptions{
		KeyID:     keyID,
		Algorithm: "AES-256-GCM",
		Purpose:   "mac",
	}
	_, err := cmd.KeyGenerate(testCtx, genOpts)
	require.NoError(t, err, "Setup: KeyGenerate should succeed")

	t.Run("GenerateVerifyHMAC", func(t *testing.T) {
		message := []byte("Multi-protocol test: HMAC message")

		// Generate HMAC
		hmacResult, err := cmd.CryptoHMAC(testCtx, CryptoHMACOptions{
			KeyID:         keyID,
			Message:       message,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoHMAC should succeed")
		require.NotNil(t, hmacResult, "HMAC result should not be nil")
		assert.NotEmpty(t, hmacResult.HMAC, "HMAC should not be empty")

		// Verify HMAC
		verifyResult, err := cmd.CryptoVerifyHMAC(testCtx, CryptoVerifyHMACOptions{
			KeyID:         keyID,
			Message:       message,
			HMAC:          hmacResult.HMAC,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoVerifyHMAC should succeed")
		require.NotNil(t, verifyResult, "Verify result should not be nil")
		assert.True(t, verifyResult.Valid, "HMAC should be valid")
	})

	t.Run("VerifyHMACModifiedMessageFails", func(t *testing.T) {
		message := []byte("Original HMAC message")

		hmacResult, err := cmd.CryptoHMAC(testCtx, CryptoHMACOptions{
			KeyID:         keyID,
			Message:       message,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoHMAC should succeed")

		// Verify with modified message
		verifyResult, err := cmd.CryptoVerifyHMAC(testCtx, CryptoVerifyHMACOptions{
			KeyID:         keyID,
			Message:       []byte("Modified HMAC message"),
			HMAC:          hmacResult.HMAC,
			HashAlgorithm: "SHA256",
		})
		require.NoError(t, err, "CryptoVerifyHMAC should succeed (not error, just invalid)")
		assert.False(t, verifyResult.Valid, "HMAC should be invalid for modified message")
	})
}

func testRandom(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	t.Run("GenerateRandomBytes", func(t *testing.T) {
		result, err := cmd.CryptoRandom(testCtx, 32)
		require.NoError(t, err, "CryptoRandom should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Len(t, result.RandomBytes, 32, "Should return requested number of bytes")
	})

	t.Run("GenerateRandomBytesAreUnique", func(t *testing.T) {
		result1, err := cmd.CryptoRandom(testCtx, 32)
		require.NoError(t, err, "First CryptoRandom should succeed")

		result2, err := cmd.CryptoRandom(testCtx, 32)
		require.NoError(t, err, "Second CryptoRandom should succeed")

		assert.False(t, bytes.Equal(result1.RandomBytes, result2.RandomBytes),
			"Random bytes should be different each call")
	})

	t.Run("GenerateRandomDifferentSizes", func(t *testing.T) {
		sizes := []int{16, 32, 64, 128}
		for _, size := range sizes {
			result, err := cmd.CryptoRandom(testCtx, size)
			require.NoError(t, err, "CryptoRandom should succeed for size %d", size)
			assert.Len(t, result.RandomBytes, size, "Should return %d bytes", size)
		}
	})
}

// =============================================================================
// DEK Management Tests
// =============================================================================

// withoutCLIDEKDescription returns opts unchanged on every transport but the
// CLI. kms dek create has no --description flag (docs/kms/cli.md §7), so on
// the CLI it asserts the typed refusal and returns opts without the
// description, for the leaf to create the DEK with.
func withoutCLIDEKDescription(t *testing.T, ctx context.Context, cmd KMSCommands, opts DEKCreateOptions) DEKCreateOptions {
	t.Helper()
	if _, isCLI := cmd.(*CLIAdapter); !isCLI {
		return opts
	}
	_, err := cmd.DEKCreate(ctx, opts)
	require.ErrorIs(t, err, ErrCLINoFlag{Operation: "DEKCreate", Flag: "--description"})
	opts.Description = ""
	return opts
}

func testDEKCreate(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("CreateDEKWithDefaults", func(t *testing.T) {
		path := prefix + "/dek/create-test"
		opts := DEKCreateOptions{
			Path:        path,
			Algorithm:   "AES-256-GCM",
			Description: "Multi-protocol test DEK",
		}
		opts = withoutCLIDEKDescription(t, testCtx, cmd, opts)

		result, err := cmd.DEKCreate(testCtx, opts)
		require.NoError(t, err, "DEKCreate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, path, result.Path, "Path should match")
		assert.Equal(t, uint64(1), result.Version, "Initial version should be 1")
	})

	t.Run("CreateDEKWithLimits", func(t *testing.T) {
		path := prefix + "/dek/create-limits"
		opts := DEKCreateOptions{
			Path:           path,
			Algorithm:      "AES-256-GCM",
			MaxOperations:  1000,
			MaxBytes:       1000000,
			WarningPercent: 80,
		}

		result, err := cmd.DEKCreate(testCtx, opts)
		require.NoError(t, err, "DEKCreate with limits should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, path, result.Path, "Path should match")
	})

	t.Run("CreateDEKEmptyPathFails", func(t *testing.T) {
		opts := DEKCreateOptions{
			Path:      "",
			Algorithm: "AES-256-GCM",
		}

		_, err := cmd.DEKCreate(testCtx, opts)
		require.Error(t, err, "DEKCreate should fail with empty path")
	})
}

func testDEKGet(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create DEK first
	path := prefix + "/dek/get-test"
	createOpts := DEKCreateOptions{
		Path:        path,
		Algorithm:   "AES-256-GCM",
		Description: "DEK for get test",
	}
	createOpts = withoutCLIDEKDescription(t, testCtx, cmd, createOpts)
	_, err := cmd.DEKCreate(testCtx, createOpts)
	require.NoError(t, err, "Setup: DEKCreate should succeed")

	t.Run("GetExistingDEK", func(t *testing.T) {
		result, err := cmd.DEKGet(testCtx, path)
		require.NoError(t, err, "DEKGet should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, path, result.Path, "Path should match")
		assert.Equal(t, createOpts.Description, result.Description, "Description should match")
	})

	t.Run("GetNonexistentDEKFails", func(t *testing.T) {
		_, err := cmd.DEKGet(testCtx, prefix+"/dek/nonexistent")
		require.Error(t, err, "DEKGet should fail for nonexistent DEK")
	})
}

func testDEKList(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create multiple DEKs
	dekPrefix := prefix + "/dek/list"
	for i := 0; i < 3; i++ {
		path := fmt.Sprintf("%s/item-%d", dekPrefix, i)
		opts := DEKCreateOptions{
			Path:      path,
			Algorithm: "AES-256-GCM",
		}
		_, err := cmd.DEKCreate(testCtx, opts)
		require.NoError(t, err, "Setup: DEKCreate should succeed")
	}

	t.Run("ListDEKsWithPrefix", func(t *testing.T) {
		result, err := cmd.DEKList(testCtx, DEKListOptions{
			Prefix:    dekPrefix,
			Recursive: true,
			Limit:     100,
		})
		require.NoError(t, err, "DEKList should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.DEKs), 3, "Should have at least 3 DEKs")
	})

	t.Run("ListDEKsWithPagination", func(t *testing.T) {
		result, err := cmd.DEKList(testCtx, DEKListOptions{
			Prefix: dekPrefix,
			Limit:  2,
		})
		require.NoError(t, err, "DEKList should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.DEKs)), int32(2), "Should respect limit")
	})
}

func testDEKRotate(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create DEK for rotation
	path := prefix + "/dek/rotate-test"
	createOpts := DEKCreateOptions{
		Path:      path,
		Algorithm: "AES-256-GCM",
	}
	createResult, err := cmd.DEKCreate(testCtx, createOpts)
	require.NoError(t, err, "Setup: DEKCreate should succeed")
	originalVersion := createResult.Version

	t.Run("RotateDEK", func(t *testing.T) {
		result, err := cmd.DEKRotate(testCtx, path, false)
		require.NoError(t, err, "DEKRotate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, path, result.Path, "Path should match")
		assert.Equal(t, originalVersion, result.OldVersion, "OldVersion should match original")
		assert.Greater(t, result.NewVersion, result.OldVersion, "NewVersion should be greater")
	})

	t.Run("RotateNonexistentDEKFails", func(t *testing.T) {
		_, err := cmd.DEKRotate(testCtx, prefix+"/dek/nonexistent", false)
		require.Error(t, err, "DEKRotate should fail for nonexistent DEK")
	})
}

func testDEKDelete(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create DEK for deletion
	path := prefix + "/dek/delete-test"
	createOpts := DEKCreateOptions{
		Path:      path,
		Algorithm: "AES-256-GCM",
	}
	_, err := cmd.DEKCreate(testCtx, createOpts)
	require.NoError(t, err, "Setup: DEKCreate should succeed")

	t.Run("DeleteDEK", func(t *testing.T) {
		result, err := cmd.DEKDelete(testCtx, path, DEKDeleteOptions{Force: true})
		require.NoError(t, err, "DEKDelete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Deleted, "DEK should be deleted")
	})

	t.Run("VerifyDEKIsDeleted", func(t *testing.T) {
		_, err := cmd.DEKGet(testCtx, path)
		require.Error(t, err, "DEKGet should fail for deleted DEK")
	})

	t.Run("DeleteNonexistentDEKFails", func(t *testing.T) {
		_, err := cmd.DEKDelete(testCtx, prefix+"/dek/nonexistent", DEKDeleteOptions{})
		require.Error(t, err, "DEKDelete should fail for nonexistent DEK")
	})
}

func testDEKStatus(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Create DEK with limits for status testing
	path := prefix + "/dek/status-test"
	createOpts := DEKCreateOptions{
		Path:           path,
		Algorithm:      "AES-256-GCM",
		Description:    "DEK for status test",
		MaxOperations:  5000,
		MaxBytes:       500000,
		WarningPercent: 75,
	}
	createOpts = withoutCLIDEKDescription(t, testCtx, cmd, createOpts)
	_, err := cmd.DEKCreate(testCtx, createOpts)
	require.NoError(t, err, "Setup: DEKCreate should succeed")

	t.Run("GetDEKStatus", func(t *testing.T) {
		result, err := cmd.DEKStatus(testCtx, path)
		require.NoError(t, err, "DEKStatus should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, path, result.Path, "Path should match")
		assert.Equal(t, createOpts.Description, result.Description, "Description should match")
		assert.Equal(t, uint64(5000), result.MaxUsageCount, "MaxUsageCount should match")
		assert.Equal(t, uint64(500000), result.MaxBytesUsed, "MaxBytesUsed should match")
		assert.Equal(t, int32(75), result.WarningPercent, "WarningPercent should match")
		assert.Contains(t, result.Algorithm, "AES", "Algorithm should contain AES")
	})

	t.Run("GetStatusNonexistentDEKFails", func(t *testing.T) {
		_, err := cmd.DEKStatus(testCtx, prefix+"/dek/nonexistent-status")
		require.Error(t, err, "DEKStatus should fail for nonexistent DEK")
	})
}

// =============================================================================
// Secrets Management Tests
// =============================================================================

func testSecretsStore(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	t.Run("StoreSecret", func(t *testing.T) {
		secretName := prefix + "-secret-store"
		secretData := []byte("super-secret-password-123")
		opts := SecretsStoreOptions{
			Name:        secretName,
			Data:        secretData,
			Description: "Multi-protocol test secret",
		}

		result, err := cmd.SecretsStore(testCtx, opts)
		require.NoError(t, err, "SecretsStore should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.NotEmpty(t, result.SecretID, "SecretID should not be empty")
		assert.Equal(t, uint64(1), result.Version, "Initial version should be 1")
	})

	t.Run("StoreSecretEmptyNameFails", func(t *testing.T) {
		opts := SecretsStoreOptions{
			Name: "",
			Data: []byte("data"),
		}

		_, err := cmd.SecretsStore(testCtx, opts)
		require.Error(t, err, "SecretsStore should fail with empty name")
	})
}

func testSecretsGet(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret first
	secretName := prefix + "-secret-get"
	secretData := []byte("secret-data-for-get")
	storeOpts := SecretsStoreOptions{
		Name:        secretName,
		Data:        secretData,
		Description: "Secret for get test",
	}
	_, err := cmd.SecretsStore(testCtx, storeOpts)
	require.NoError(t, err, "Setup: SecretsStore should succeed")

	t.Run("GetExistingSecret", func(t *testing.T) {
		result, err := cmd.SecretsGet(testCtx, secretName)
		require.NoError(t, err, "SecretsGet should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, bytes.Equal(secretData, result.Data), "Secret data should match")
	})

	t.Run("GetNonexistentSecretFails", func(t *testing.T) {
		_, err := cmd.SecretsGet(testCtx, prefix+"-nonexistent-secret")
		require.Error(t, err, "SecretsGet should fail for nonexistent secret")
	})
}

func testSecretsList(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store multiple secrets
	for i := 0; i < 3; i++ {
		secretName := fmt.Sprintf("%s-secret-list-%d", prefix, i)
		opts := SecretsStoreOptions{
			Name: secretName,
			Data: []byte(fmt.Sprintf("secret-data-%d", i)),
		}
		_, err := cmd.SecretsStore(testCtx, opts)
		require.NoError(t, err, "Setup: SecretsStore should succeed")
	}

	t.Run("ListSecrets", func(t *testing.T) {
		result, err := cmd.SecretsList(testCtx, SecretsListOptions{Limit: 100})
		require.NoError(t, err, "SecretsList should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Secrets), 3, "Should have at least 3 secrets")
	})

	t.Run("ListSecretsWithPagination", func(t *testing.T) {
		result, err := cmd.SecretsList(testCtx, SecretsListOptions{Limit: 2})
		require.NoError(t, err, "SecretsList should succeed with limit")
		require.NotNil(t, result, "Result should not be nil")
		assert.LessOrEqual(t, int32(len(result.Secrets)), int32(2), "Should respect limit")
	})
}

func testSecretsRotate(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret first
	secretName := prefix + "-secret-rotate"
	originalData := []byte("original-secret-data")
	storeOpts := SecretsStoreOptions{
		Name: secretName,
		Data: originalData,
	}
	storeResult, err := cmd.SecretsStore(testCtx, storeOpts)
	require.NoError(t, err, "Setup: SecretsStore should succeed")
	originalVersion := storeResult.Version

	// wantData is what SecretsGet must answer after the rotate: the new data,
	// or the original data when the CLI's rotate is the declared SDK refusal.
	wantData := []byte("new-rotated-secret-data")

	t.Run("RotateSecret", func(t *testing.T) {
		newData := []byte("new-rotated-secret-data")
		rotateOpts := SecretsRotateOptions{
			Name:    secretName,
			NewData: newData,
		}

		result, err := cmd.SecretsRotate(testCtx, rotateOpts)
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			wantData = originalData
			return
		}
		require.NoError(t, err, "SecretsRotate should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, originalVersion, result.OldVersion, "OldVersion should match original")
		assert.Greater(t, result.NewVersion, result.OldVersion, "NewVersion should be greater")
	})

	t.Run("VerifyRotatedSecret", func(t *testing.T) {
		result, err := cmd.SecretsGet(testCtx, secretName)
		require.NoError(t, err, "SecretsGet should succeed")
		assert.True(t, bytes.Equal(wantData, result.Data), "Secret data should be rotated, or unchanged after a refused rotate")
	})

	t.Run("RotateNonexistentSecretFails", func(t *testing.T) {
		rotateOpts := SecretsRotateOptions{
			Name:    prefix + "-nonexistent-rotate",
			NewData: []byte("data"),
		}
		_, err := cmd.SecretsRotate(testCtx, rotateOpts)
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			return
		}
		require.Error(t, err, "SecretsRotate should fail for nonexistent secret")
	})
}

func testSecretsVersions(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret and rotate it
	secretName := prefix + "-secret-versions"
	storeOpts := SecretsStoreOptions{
		Name: secretName,
		Data: []byte("version-1-data"),
	}
	_, err := cmd.SecretsStore(testCtx, storeOpts)
	require.NoError(t, err, "Setup: SecretsStore should succeed")

	// Rotate a few times
	for i := 2; i <= 3; i++ {
		rotateOpts := SecretsRotateOptions{
			Name:    secretName,
			NewData: []byte(fmt.Sprintf("version-%d-data", i)),
		}
		_, err := cmd.SecretsRotate(testCtx, rotateOpts)
		if !helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			require.NoError(t, err, "Setup: SecretsRotate should succeed")
		}
	}

	t.Run("ListSecretVersions", func(t *testing.T) {
		result, err := cmd.SecretsVersions(testCtx, secretName, SecretsVersionsOptions{Limit: 10})
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			return
		}
		require.NoError(t, err, "SecretsVersions should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.GreaterOrEqual(t, len(result.Versions), 3, "Should have at least 3 versions")
	})

	t.Run("GetSpecificSecretVersion", func(t *testing.T) {
		result, err := cmd.SecretsVersion(testCtx, secretName, 1)
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			return
		}
		require.NoError(t, err, "SecretsVersion should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Equal(t, uint64(1), result.Version, "Version should be 1")
		assert.True(t, bytes.Equal([]byte("version-1-data"), result.Data), "Data should match version 1")
	})
}

func testSecretsRollback(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret and rotate it
	secretName := prefix + "-secret-rollback"
	originalData := []byte("original-rollback-data")
	storeOpts := SecretsStoreOptions{
		Name: secretName,
		Data: originalData,
	}
	_, err := cmd.SecretsStore(testCtx, storeOpts)
	require.NoError(t, err, "Setup: SecretsStore should succeed")

	// Rotate to create version 2
	rotateOpts := SecretsRotateOptions{
		Name:    secretName,
		NewData: []byte("rotated-data"),
	}
	_, err = cmd.SecretsRotate(testCtx, rotateOpts)
	if !helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
		require.NoError(t, err, "Setup: SecretsRotate should succeed")
	}

	t.Run("RollbackToVersion1", func(t *testing.T) {
		result, err := cmd.SecretsRollback(testCtx, secretName, 1)
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			return
		}
		require.NoError(t, err, "SecretsRollback should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Greater(t, result.NewVersion, uint64(2), "NewVersion should be > 2 (creates new version)")
	})

	t.Run("VerifyRollbackData", func(t *testing.T) {
		result, err := cmd.SecretsGet(testCtx, secretName)
		require.NoError(t, err, "SecretsGet should succeed")
		assert.True(t, bytes.Equal(originalData, result.Data), "Data should match version 1 after rollback")
	})
}

func testSecretsDelete(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret first
	secretName := prefix + "-secret-delete"
	storeOpts := SecretsStoreOptions{
		Name: secretName,
		Data: []byte("delete-me"),
	}
	_, err := cmd.SecretsStore(testCtx, storeOpts)
	require.NoError(t, err, "Setup: SecretsStore should succeed")

	t.Run("DeleteSecret", func(t *testing.T) {
		result, err := cmd.SecretsDelete(testCtx, secretName, true)
		require.NoError(t, err, "SecretsDelete should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.True(t, result.Deleted, "Secret should be deleted")
	})

	t.Run("VerifySecretIsDeleted", func(t *testing.T) {
		_, err := cmd.SecretsGet(testCtx, secretName)
		require.Error(t, err, "SecretsGet should fail for deleted secret")
	})

	t.Run("DeleteNonexistentSecretFails", func(t *testing.T) {
		_, err := cmd.SecretsDelete(testCtx, prefix+"-nonexistent-secret", false)
		require.Error(t, err, "SecretsDelete should fail for nonexistent secret")
	})
}

func testSecretsStatus(t *testing.T, ctx context.Context, cmd KMSCommands, prefix string) {
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Store a secret for status testing
	secretName := prefix + "-secret-status"
	storeOpts := SecretsStoreOptions{
		Name:        secretName,
		Data:        []byte("secret-for-status-test"),
		Description: "Secret for status testing",
	}
	_, err := cmd.SecretsStore(testCtx, storeOpts)
	require.NoError(t, err, "Setup: SecretsStore should succeed")

	t.Run("DisableSecret", func(t *testing.T) {
		result, err := cmd.SecretsStatus(testCtx, secretName, false)
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			return
		}
		require.NoError(t, err, "SecretsStatus (disable) should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Contains(t, result.Status, "DISABLED", "Status should indicate disabled")
		assert.Equal(t, secretName, result.SecretID, "SecretID should match")
	})

	t.Run("EnableSecret", func(t *testing.T) {
		result, err := cmd.SecretsStatus(testCtx, secretName, true)
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			return
		}
		require.NoError(t, err, "SecretsStatus (enable) should succeed")
		require.NotNil(t, result, "Result should not be nil")
		assert.Contains(t, result.Status, "ENABLED", "Status should indicate enabled")
	})

	t.Run("StatusNonexistentSecretFails", func(t *testing.T) {
		_, err := cmd.SecretsStatus(testCtx, prefix+"-nonexistent-status", true)
		if helpers.RequireCLIRefusal(t, cmd.Name(), err, helpers.ErrCLIUpstreamGap{}) {
			return
		}
		require.Error(t, err, "SecretsStatus should fail for nonexistent secret")
	})
}

// =============================================================================
// Helper Functions
// =============================================================================

// contains checks if a string contains a substring (case-insensitive check).
// containsFold reports whether list contains want, compared
// case-insensitively, since transports differ in usage-name casing
// (SDK canonical "ENCRYPT" vs proto helper "encrypt").
func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
