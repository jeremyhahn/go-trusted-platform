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

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newKMSToolTestRegistry builds a registry backed by the given mock provider.
func newKMSToolTestRegistry(svc *mockServiceProvider) *ToolRegistry {
	return NewToolRegistry(svc, newTestLogger())
}

// executeKMSToolViaDispatch runs a tool through ExecuteTool so the
// map-based dispatch path is exercised end to end.
func executeKMSToolViaDispatch(t *testing.T, registry *ToolRegistry, name string, args map[string]interface{}) (interface{}, error) {
	t.Helper()
	return registry.ExecuteTool(context.Background(), name, args)
}

// =============================================================================
// Dispatch coverage: every registered KMS/secrets tool must resolve
// =============================================================================

func TestDispatchKMSToolResolvesAllTools(t *testing.T) {
	registry := newKMSToolTestRegistry(newMockServiceProvider())

	for name := range kmsToolDispatch {
		t.Run(name, func(t *testing.T) {
			_, handled, _ := registry.dispatchKMSTool(context.Background(), name, map[string]interface{}{})
			assert.True(t, handled, "tool %s must be handled by the KMS dispatcher", name)
		})
	}
}

func TestDispatchKMSToolUnknownToolNotHandled(t *testing.T) {
	registry := newKMSToolTestRegistry(newMockServiceProvider())

	_, handled, err := registry.dispatchKMSTool(context.Background(), "not_a_kms_tool", nil)
	assert.False(t, handled)
	assert.NoError(t, err)
}

// =============================================================================
// kms_generate_key
// =============================================================================

func TestExecuteKMSGenerateKey(t *testing.T) {
	t.Run("SuccessWithExportableAndDeletionProtection", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *KMSCreateKeyRequest
		svc.kmsCreateKeyFunc = func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"key_id": "key-1"}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		result, err := executeKMSToolViaDispatch(t, registry, "kms_generate_key", map[string]interface{}{
			"name":                "test-key",
			"algorithm":           "AES-256-GCM",
			"usage":               []interface{}{"encrypt", "decrypt"},
			"exportable":          true,
			"deletion_protection": true,
			"owner":               "alice",
		})
		require.NoError(t, err)
		assert.NotNil(t, result)

		require.NotNil(t, captured)
		assert.Equal(t, "test-key", captured.Name)
		assert.Equal(t, "AES-256-GCM", captured.Algorithm)
		assert.True(t, captured.Exportable)
		assert.True(t, captured.DeletionProtection)
		assert.Equal(t, "alice", captured.Owner)
	})

	t.Run("MissingName", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_generate_key", map[string]interface{}{
			"algorithm": "AES-256-GCM",
		})
		assert.ErrorIs(t, err, ErrKMSKeyNameRequired)
	})

	t.Run("DisplayNameRefusedBeforeGenerate", func(t *testing.T) {
		svc := newMockServiceProvider()
		generated := false
		svc.kmsCreateKeyFunc = func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
			generated = true
			return map[string]interface{}{"key_id": "key-1"}, nil
		}
		registry := newKMSToolTestRegistry(svc)
		_, err := executeKMSToolViaDispatch(t, registry, "kms_generate_key", map[string]interface{}{
			"name":         "test-key",
			"display_name": "Test Key",
			"algorithm":    "AES-256-GCM",
			"usage":        []interface{}{"encrypt"},
		})
		assert.ErrorIs(t, err, ErrKMSDisplayNameNotSupported)
		assert.False(t, generated, "a refused display_name must leave no key behind")
	})

	t.Run("MissingAlgorithm", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_generate_key", map[string]interface{}{
			"name": "test-key",
		})
		assert.ErrorIs(t, err, ErrKMSAlgorithmRequired)
	})
}

// =============================================================================
// Key management tools
// =============================================================================

func TestExecuteKMSKeyManagementTools(t *testing.T) {
	t.Run("GetKeySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsGetKeyFunc = func(ctx context.Context, keyID string, version uint64) (interface{}, error) {
			assert.Equal(t, "key-1", keyID)
			assert.Equal(t, uint64(2), version)
			return map[string]interface{}{"key_id": keyID}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_get_key", map[string]interface{}{
			"key_id":  "key-1",
			"version": float64(2),
		})
		require.NoError(t, err)
	})

	t.Run("GetKeyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_get_key", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("ListKeysSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsListKeysFunc = func(ctx context.Context, limit, offset int) (interface{}, error) {
			assert.Equal(t, 50, limit)
			return map[string]interface{}{"keys": []interface{}{}}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_list_keys", map[string]interface{}{})
		require.NoError(t, err)
	})

	t.Run("DeleteKeySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		deleted := ""
		svc.kmsDeleteKeyFunc = func(ctx context.Context, keyID string) error {
			deleted = keyID
			return nil
		}
		registry := newKMSToolTestRegistry(svc)

		result, err := executeKMSToolViaDispatch(t, registry, "kms_delete_key", map[string]interface{}{
			"key_id": "key-1",
		})
		require.NoError(t, err)
		assert.Equal(t, "key-1", deleted)
		assert.NotNil(t, result)
	})

	t.Run("DeleteKeyError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsDeleteKeyFunc = func(ctx context.Context, keyID string) error {
			return errors.New("delete failed")
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_delete_key", map[string]interface{}{
			"key_id": "key-1",
		})
		assert.Error(t, err)
	})

	t.Run("RotateKeySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsRotateKeyFunc = func(ctx context.Context, keyID string) (interface{}, error) {
			return map[string]interface{}{"key_id": keyID, "new_version": 2}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_rotate_key", map[string]interface{}{
			"key_id": "key-1",
		})
		require.NoError(t, err)
	})

	t.Run("RotateKeyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_rotate_key", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("ExportPublicKeySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsExportPublicKeyFunc = func(ctx context.Context, req *KMSExportPublicKeyRequest) (interface{}, error) {
			assert.Equal(t, "key-1", req.KeyID)
			return map[string]interface{}{"public_key": "abc"}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_export_public_key", map[string]interface{}{
			"key_id": "key-1",
		})
		require.NoError(t, err)
	})

	t.Run("ExportPublicKeyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_export_public_key", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})
}

// =============================================================================
// Key lifecycle tools
// =============================================================================

func TestExecuteKMSLifecycleTools(t *testing.T) {
	t.Run("RevokeKeySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsRevokeKeyFunc = func(ctx context.Context, keyID, reason string) (interface{}, error) {
			assert.Equal(t, "key-1", keyID)
			assert.Equal(t, "compromised", reason)
			return map[string]interface{}{"key_id": keyID, "status": "DISABLED"}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_revoke_key", map[string]interface{}{
			"key_id": "key-1",
			"reason": "compromised",
		})
		require.NoError(t, err)
	})

	t.Run("RevokeKeyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_revoke_key", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("GetKeyMetadataSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsGetKeyMetadataFunc = func(ctx context.Context, keyID string) (interface{}, error) {
			return map[string]interface{}{"key_id": keyID, "name": "prod"}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		result, err := executeKMSToolViaDispatch(t, registry, "kms_get_key_metadata", map[string]interface{}{
			"key_id": "key-1",
		})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("GetKeyMetadataError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsGetKeyMetadataFunc = func(ctx context.Context, keyID string) (interface{}, error) {
			return nil, errors.New("not found")
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_get_key_metadata", map[string]interface{}{
			"key_id": "missing",
		})
		assert.Error(t, err)
	})

	t.Run("UpdateKeyMetadataSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *KMSUpdateKeyMetadataRequest
		svc.kmsUpdateKeyMetadataFunc = func(ctx context.Context, req *KMSUpdateKeyMetadataRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"key_id": req.KeyID}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_update_key_metadata", map[string]interface{}{
			"key_id":      "key-1",
			"name":        "renamed",
			"tags":        map[string]interface{}{"env": "prod"},
			"remove_tags": []interface{}{"old"},
		})
		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Equal(t, "renamed", captured.Name)
		assert.Equal(t, "prod", captured.Tags["env"])
		assert.Equal(t, []string{"old"}, captured.RemoveTags)
	})

	t.Run("UpdateKeyMetadataMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_update_key_metadata", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("SetKeyPolicySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *KMSSetKeyPolicyRequest
		svc.kmsSetKeyPolicyFunc = func(ctx context.Context, req *KMSSetKeyPolicyRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"key_id": req.KeyID}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_set_key_policy", map[string]interface{}{
			"key_id":             "key-1",
			"allowed_operations": []interface{}{"encrypt"},
			"allowed_principals": []interface{}{"user:alice"},
			"require_mfa":        true,
			"max_usage_count":    float64(50),
		})
		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Equal(t, []string{"encrypt"}, captured.AllowedOperations)
		assert.Equal(t, []string{"user:alice"}, captured.AllowedPrincipals)
		assert.True(t, captured.RequireMFA)
		assert.Equal(t, uint64(50), captured.MaxUsageCount)
	})

	t.Run("SetKeyPolicyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_set_key_policy", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("GetKeyPolicySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsGetKeyPolicyFunc = func(ctx context.Context, keyID string) (interface{}, error) {
			return map[string]interface{}{"key_id": keyID}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_get_key_policy", map[string]interface{}{
			"key_id": "key-1",
		})
		require.NoError(t, err)
	})

	t.Run("GetKeyPolicyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_get_key_policy", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("SupportedAlgorithmsSuccess", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		result, err := executeKMSToolViaDispatch(t, registry, "kms_supported_algorithms", map[string]interface{}{})
		require.NoError(t, err)
		out, ok := result.(map[string]interface{})
		require.True(t, ok)
		assert.Contains(t, out["algorithms"], "AES-256-GCM")
	})

	t.Run("SupportedAlgorithmsError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsGetSupportedAlgorithmsFunc = func(ctx context.Context) ([]string, error) {
			return nil, errors.New("backend down")
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_supported_algorithms", map[string]interface{}{})
		assert.Error(t, err)
	})

	t.Run("BackendStatusSuccess", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		result, err := executeKMSToolViaDispatch(t, registry, "kms_backend_status", map[string]interface{}{})
		require.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("BackendStatusError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsBackendStatusFunc = func(ctx context.Context) (interface{}, error) {
			return nil, errors.New("backend down")
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_backend_status", map[string]interface{}{})
		assert.Error(t, err)
	})
}

// =============================================================================
// Crypto tools (dispatch additions)
// =============================================================================

func TestExecuteKMSCryptoTools(t *testing.T) {
	plaintext := base64.StdEncoding.EncodeToString([]byte("secret data"))
	ciphertext := base64.StdEncoding.EncodeToString([]byte("encrypted"))
	message := base64.StdEncoding.EncodeToString([]byte("message"))
	signature := base64.StdEncoding.EncodeToString([]byte("signature"))

	t.Run("EncryptSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsEncryptFunc = func(ctx context.Context, req *KMSEncryptRequest) (interface{}, error) {
			assert.Equal(t, []byte("secret data"), req.Plaintext)
			return map[string]interface{}{"ciphertext": "abc"}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_encrypt", map[string]interface{}{
			"key_id":    "key-1",
			"plaintext": plaintext,
		})
		require.NoError(t, err)
	})

	t.Run("EncryptInvalidBase64", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_encrypt", map[string]interface{}{
			"key_id":    "key-1",
			"plaintext": "!!!not-base64!!!",
		})
		assert.Error(t, err)
	})

	t.Run("DecryptSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsDecryptFunc = func(ctx context.Context, req *KMSDecryptRequest) (interface{}, error) {
			assert.Equal(t, []byte("encrypted"), req.Ciphertext)
			return map[string]interface{}{"plaintext": "abc"}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_decrypt", map[string]interface{}{
			"key_id":     "key-1",
			"ciphertext": ciphertext,
		})
		require.NoError(t, err)
	})

	t.Run("DecryptMissingCiphertext", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_decrypt", map[string]interface{}{
			"key_id": "key-1",
		})
		assert.ErrorIs(t, err, ErrKMSCiphertextRequired)
	})

	t.Run("VerifySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsVerifyFunc = func(ctx context.Context, req *KMSVerifyRequest) (interface{}, error) {
			assert.Equal(t, []byte("message"), req.Message)
			assert.Equal(t, []byte("signature"), req.Signature)
			return map[string]interface{}{"valid": true}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "kms_verify", map[string]interface{}{
			"key_id":    "key-1",
			"message":   message,
			"signature": signature,
		})
		require.NoError(t, err)
	})

	t.Run("VerifyMissingSignature", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "kms_verify", map[string]interface{}{
			"key_id":  "key-1",
			"message": message,
		})
		assert.ErrorIs(t, err, ErrKMSSignatureRequired)
	})
}

// =============================================================================
// Secrets tools
// =============================================================================

func TestExecuteSecretTools(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte("hunter2"))

	t.Run("StoreSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *SecretStoreRequest
		svc.secretStoreFunc = func(ctx context.Context, req *SecretStoreRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"secret_id": req.SecretID, "version": 1}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_store", map[string]interface{}{
			"secret_id": "db/password",
			"data":      data,
			"metadata":  map[string]interface{}{"env": "prod"},
		})
		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Equal(t, []byte("hunter2"), captured.Data)
		assert.Equal(t, "prod", captured.Metadata["env"])
	})

	t.Run("StoreMissingData", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_store", map[string]interface{}{
			"secret_id": "db/password",
		})
		assert.ErrorIs(t, err, ErrSecretDataRequired)
	})

	t.Run("GetSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretGetFunc = func(ctx context.Context, secretID string, version uint64) (interface{}, error) {
			assert.Equal(t, "db/password", secretID)
			assert.Equal(t, uint64(3), version)
			return map[string]interface{}{"secret_id": secretID}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_get", map[string]interface{}{
			"secret_id": "db/password",
			"version":   float64(3),
		})
		require.NoError(t, err)
	})

	t.Run("GetMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_get", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrSecretIDRequired)
	})

	t.Run("ListSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretListFunc = func(ctx context.Context, limit int, cursor string) (interface{}, error) {
			assert.Equal(t, 50, limit)
			return map[string]interface{}{"secrets": []interface{}{}}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list", map[string]interface{}{})
		require.NoError(t, err)
	})

	t.Run("ListError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretListFunc = func(ctx context.Context, limit int, cursor string) (interface{}, error) {
			return nil, errors.New("backend down")
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list", map[string]interface{}{})
		assert.Error(t, err)
	})

	t.Run("ListForwardsLimitAndCursor", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretListFunc = func(ctx context.Context, limit int, cursor string) (interface{}, error) {
			assert.Equal(t, 2, limit)
			assert.Equal(t, "db/b", cursor)
			return map[string]interface{}{"secrets": []interface{}{}}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list", map[string]interface{}{"limit": 2, "cursor": "db/b"})
		require.NoError(t, err)
	})

	t.Run("ListNegativeLimitIsInvalidArgument", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretListFunc = func(ctx context.Context, limit int, cursor string) (interface{}, error) {
			t.Fatal("a negative limit must not reach the service")
			return nil, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list", map[string]interface{}{"limit": -1})
		var invalid ErrInvalidArgument
		assert.ErrorAs(t, err, &invalid)
	})

	t.Run("DeleteSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		deleted := ""
		svc.secretDeleteFunc = func(ctx context.Context, secretID string) error {
			deleted = secretID
			return nil
		}
		registry := newKMSToolTestRegistry(svc)

		result, err := executeKMSToolViaDispatch(t, registry, "secret_delete", map[string]interface{}{
			"secret_id": "db/password",
		})
		require.NoError(t, err)
		assert.Equal(t, "db/password", deleted)
		assert.NotNil(t, result)
	})

	t.Run("DeleteMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_delete", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrSecretIDRequired)
	})

	t.Run("SetRotationPolicySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *SecretSetRotationPolicyRequest
		svc.secretSetRotationPolicyFunc = func(ctx context.Context, req *SecretSetRotationPolicyRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"secret_id": req.SecretID}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_set_rotation_policy", map[string]interface{}{
			"secret_id":        "db/password",
			"enabled":          true,
			"interval_seconds": float64(3600),
			"retain_versions":  float64(5),
		})
		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.True(t, captured.Enabled)
		assert.Equal(t, int64(3600), captured.IntervalSeconds)
		assert.Equal(t, 5, captured.RetainVersions)
	})

	t.Run("SetRotationPolicyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_set_rotation_policy", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrSecretIDRequired)
	})

	t.Run("GetRotationPolicySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretGetRotationPolicyFunc = func(ctx context.Context, secretID string) (interface{}, error) {
			return map[string]interface{}{"secret_id": secretID, "retain_versions": 5}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_get_rotation_policy", map[string]interface{}{
			"secret_id": "db/password",
		})
		require.NoError(t, err)
	})

	t.Run("GetRotationPolicyMissingID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_get_rotation_policy", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrSecretIDRequired)
	})
}

// =============================================================================
// Tool registration
// =============================================================================

func TestKMSLifecycleAndSecretToolsRegistered(t *testing.T) {
	registry := newKMSToolTestRegistry(newMockServiceProvider())
	registered := make(map[string]bool)
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = true
	}

	expected := []string{
		"kms_revoke_key",
		"kms_get_key_metadata",
		"kms_update_key_metadata",
		"kms_get_key_policy",
		"kms_set_key_policy",
		"kms_supported_algorithms",
		"kms_backend_status",
		"secret_store",
		"secret_get",
		"secret_list",
		"secret_delete",
		"secret_set_rotation_policy",
		"secret_get_rotation_policy",
	}
	for _, name := range expected {
		assert.True(t, registered[name], "tool %s must be registered", name)
	}

	// Every dispatched tool must also be a registered tool.
	for name := range kmsToolDispatch {
		assert.True(t, registered[name], "dispatched tool %s must be registered", name)
	}
}
