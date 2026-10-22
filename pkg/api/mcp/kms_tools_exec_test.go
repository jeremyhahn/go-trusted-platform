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

func TestExecuteKMSDigestTools(t *testing.T) {
	message := base64.StdEncoding.EncodeToString([]byte("message"))
	mac := base64.StdEncoding.EncodeToString([]byte("mac"))
	ciphertext := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	backendErr := &KMSError{Code: "KMS_KEY_NOT_FOUND", Message: "no key"}

	t.Run("HashSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsHashFunc = func(ctx context.Context, req *KMSHashRequest) (interface{}, error) {
			assert.Equal(t, []byte("message"), req.Data)
			assert.Equal(t, int32(3), req.HashAlgorithm)
			return map[string]interface{}{"hash": "aGFzaA=="}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_hash", map[string]interface{}{
			"data":      message,
			"algorithm": float64(3),
		})
		require.NoError(t, err)
	})

	t.Run("HashMissingData", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_hash", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSDataRequired)
	})

	t.Run("HashInvalidBase64", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_hash", map[string]interface{}{
			"data": "not-base64!!!",
		})
		var kmsErr *KMSError
		require.ErrorAs(t, err, &kmsErr)
		assert.Equal(t, "KMS_INVALID_BASE64", kmsErr.Code)
	})

	t.Run("HMACSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsHMACFunc = func(ctx context.Context, req *KMSHMACRequest) (interface{}, error) {
			assert.Equal(t, "key-1", req.KeyID)
			assert.Equal(t, []byte("message"), req.Message)
			assert.Equal(t, int32(4), req.HashAlgorithm)
			return map[string]interface{}{"hmac": mac}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_hmac", map[string]interface{}{
			"key_id":         "key-1",
			"message":        message,
			"hash_algorithm": float64(4),
		})
		require.NoError(t, err)
	})

	t.Run("HMACMissingKeyID", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_hmac", map[string]interface{}{
			"message": message,
		})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("HMACMissingMessage", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_hmac", map[string]interface{}{
			"key_id": "key-1",
		})
		assert.ErrorIs(t, err, ErrKMSMessageRequired)
	})

	t.Run("HMACServiceError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsHMACFunc = func(ctx context.Context, req *KMSHMACRequest) (interface{}, error) {
			return nil, backendErr
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_hmac", map[string]interface{}{
			"key_id":  "key-1",
			"message": message,
		})
		assert.ErrorIs(t, err, backendErr)
	})

	t.Run("VerifyHMACSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsVerifyHMACFunc = func(ctx context.Context, req *KMSVerifyHMACRequest) (interface{}, error) {
			assert.Equal(t, []byte("mac"), req.HMAC)
			assert.Equal(t, uint64(2), req.KeyVersion)
			return map[string]interface{}{"valid": true}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_verify_hmac", map[string]interface{}{
			"key_id":      "key-1",
			"message":     message,
			"hmac":        mac,
			"key_version": float64(2),
		})
		require.NoError(t, err)
	})

	t.Run("VerifyHMACMissingHMAC", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_verify_hmac", map[string]interface{}{
			"key_id":  "key-1",
			"message": message,
		})
		assert.ErrorIs(t, err, ErrKMSHMACRequired)
	})

	t.Run("VerifyHMACNegativeKeyVersion", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_verify_hmac", map[string]interface{}{
			"key_id":      "key-1",
			"message":     message,
			"hmac":        mac,
			"key_version": float64(-1),
		})
		assert.ErrorIs(t, err, ErrKMSVersionNegative)
	})

	t.Run("RewrapSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsRewrapFunc = func(ctx context.Context, req *KMSRewrapRequest) (interface{}, error) {
			assert.Equal(t, "key-1", req.KeyID)
			assert.Equal(t, []byte("ciphertext"), req.Ciphertext)
			assert.Equal(t, uint64(0), req.SourceVersion)
			return map[string]interface{}{"ciphertext": ciphertext}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_rewrap", map[string]interface{}{
			"key_id":     "key-1",
			"ciphertext": ciphertext,
		})
		require.NoError(t, err)
	})

	t.Run("RewrapPassesSourceVersionToTheBackend", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsRewrapFunc = func(ctx context.Context, req *KMSRewrapRequest) (interface{}, error) {
			assert.Equal(t, uint64(5), req.SourceVersion)
			return nil, backendErr
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_rewrap", map[string]interface{}{
			"key_id":         "key-1",
			"ciphertext":     ciphertext,
			"source_version": float64(5),
		})
		assert.ErrorIs(t, err, backendErr)
	})

	t.Run("RewrapMissingCiphertext", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_rewrap", map[string]interface{}{
			"key_id": "key-1",
		})
		assert.ErrorIs(t, err, ErrKMSCiphertextRequired)
	})

	t.Run("RewrapNegativeSourceVersion", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_rewrap", map[string]interface{}{
			"key_id":         "key-1",
			"ciphertext":     ciphertext,
			"source_version": float64(-3),
		})
		assert.ErrorIs(t, err, ErrKMSVersionNegative)
	})
}

func TestExecuteKMSKeyAdminTools(t *testing.T) {
	material := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	backendErr := &KMSError{Code: "KMS_KEY_NOT_FOUND", Message: "no key"}

	t.Run("ImportKeySuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsImportKeyFunc = func(ctx context.Context, req *KMSImportKeyRequest) (interface{}, error) {
			assert.Equal(t, []byte("0123456789abcdef0123456789abcdef"), req.KeyMaterial)
			assert.Equal(t, "imported", req.Name)
			assert.Equal(t, "wrap-1", req.WrappingKeyID)
			assert.Equal(t, int32(22), req.Algorithm)
			assert.Equal(t, int32(256), req.KeySize)
			assert.Equal(t, []int32{1, 2}, req.Usage)
			assert.True(t, req.Exportable)
			assert.True(t, req.DeletionProtection)
			assert.Equal(t, map[string]string{"env": "test"}, req.Tags)
			return map[string]interface{}{"key_id": "key-1"}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_import_key", map[string]interface{}{
			"key_material":    material,
			"wrapping_key_id": "wrap-1",
			"name":            "imported",
			"tags":            map[string]interface{}{"env": "test"},
			"key_spec": map[string]interface{}{
				"algorithm":           float64(22),
				"key_size":            float64(256),
				"usage":               []interface{}{float64(1), float64(2)},
				"exportable":          true,
				"deletion_protection": true,
			},
		})
		require.NoError(t, err)
	})

	t.Run("ImportKeyMissingMaterial", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_import_key", map[string]interface{}{
			"key_spec": map[string]interface{}{"algorithm": float64(22)},
		})
		assert.ErrorIs(t, err, ErrKMSKeyMaterialRequired)
	})

	t.Run("ImportKeyMissingKeySpec", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_import_key", map[string]interface{}{
			"key_material": material,
		})
		assert.ErrorIs(t, err, ErrKMSKeySpecRequired)
	})

	t.Run("ImportKeyInvalidBase64", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_import_key", map[string]interface{}{
			"key_material": "not-base64!!!",
			"key_spec":     map[string]interface{}{},
		})
		var kmsErr *KMSError
		require.ErrorAs(t, err, &kmsErr)
		assert.Equal(t, "KMS_INVALID_BASE64", kmsErr.Code)
	})

	t.Run("UpdateKeyStatusSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsUpdateKeyStatusFunc = func(ctx context.Context, req *KMSUpdateKeyStatusRequest) (interface{}, error) {
			assert.Equal(t, "key-1", req.KeyID)
			assert.Equal(t, uint64(3), req.Version)
			assert.Equal(t, int32(2), req.Status)
			return map[string]interface{}{"status": 2}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_update_key_status", map[string]interface{}{
			"key_id":  "key-1",
			"version": float64(3),
			"status":  float64(2),
		})
		require.NoError(t, err)
	})

	t.Run("UpdateKeyStatusMissingKeyID", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_update_key_status", map[string]interface{}{
			"status": float64(2),
		})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("UpdateKeyStatusNegativeVersion", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_update_key_status", map[string]interface{}{
			"key_id":  "key-1",
			"version": float64(-1),
			"status":  float64(2),
		})
		assert.ErrorIs(t, err, ErrKMSVersionNegative)
	})

	t.Run("ListKeyVersionsSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsListKeyVersionsFunc = func(ctx context.Context, req *KMSListKeyVersionsRequest) (interface{}, error) {
			assert.Equal(t, "key-1", req.KeyID)
			assert.Equal(t, int32(5), req.Limit)
			assert.Equal(t, "2", req.Cursor)
			return map[string]interface{}{"versions": []interface{}{}}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_list_key_versions", map[string]interface{}{
			"key_id": "key-1",
			"limit":  float64(5),
			"cursor": "2",
		})
		require.NoError(t, err)
	})

	t.Run("ListKeyVersionsMissingKeyID", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_list_key_versions", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrKMSKeyIDRequired)
	})

	t.Run("ListKeyVersionsServiceError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsListKeyVersionsFunc = func(ctx context.Context, req *KMSListKeyVersionsRequest) (interface{}, error) {
			return nil, backendErr
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_list_key_versions", map[string]interface{}{
			"key_id": "key-1",
		})
		assert.ErrorIs(t, err, backendErr)
	})
}

func TestExecuteKMSBatchTools(t *testing.T) {
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	t.Run("BatchEncryptSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsBatchEncryptFunc = func(ctx context.Context, req *KMSBatchEncryptRequest) (interface{}, error) {
			assert.Equal(t, "key-1", req.KeyID)
			require.Len(t, req.Items, 2)
			assert.Equal(t, KMSBatchEncryptItem{ItemID: "a", Plaintext: []byte("one"), Context: []byte("aad")}, req.Items[0])
			assert.Equal(t, KMSBatchEncryptItem{ItemID: "b", Plaintext: []byte("two"), Nonce: []byte("nonce")}, req.Items[1])
			return map[string]interface{}{"success_count": 2}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_batch_encrypt", map[string]interface{}{
			"key_id": "key-1",
			"items": []interface{}{
				map[string]interface{}{"item_id": "a", "plaintext": encode("one"), "context": encode("aad")},
				map[string]interface{}{"item_id": "b", "plaintext": encode("two"), "nonce": encode("nonce")},
			},
		})
		require.NoError(t, err)
	})

	t.Run("BatchDecryptSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.kmsBatchDecryptFunc = func(ctx context.Context, req *KMSBatchDecryptRequest) (interface{}, error) {
			assert.Equal(t, "key-1", req.KeyID)
			require.Len(t, req.Items, 1)
			assert.Equal(t, KMSBatchDecryptItem{ItemID: "a", Ciphertext: []byte("sealed"), KeyVersion: 2}, req.Items[0])
			return map[string]interface{}{"success_count": 1}, nil
		}
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(svc), "kms_batch_decrypt", map[string]interface{}{
			"key_id": "key-1",
			"items": []interface{}{
				map[string]interface{}{"item_id": "a", "ciphertext": encode("sealed"), "key_version": float64(2)},
			},
		})
		require.NoError(t, err)
	})

	tooMany := make([]interface{}, kmsMaxBatchItems+1)
	for i := range tooMany {
		tooMany[i] = map[string]interface{}{"plaintext": encode("x")}
	}
	invalid := []struct {
		name string
		tool string
		args map[string]interface{}
		want error
	}{
		{"EncryptMissingKeyID", "kms_batch_encrypt", map[string]interface{}{"items": []interface{}{map[string]interface{}{}}}, ErrKMSKeyIDRequired},
		{"EncryptMissingItems", "kms_batch_encrypt", map[string]interface{}{"key_id": "key-1"}, ErrKMSBatchItemsRequired},
		{"EncryptTooManyItems", "kms_batch_encrypt", map[string]interface{}{"key_id": "key-1", "items": tooMany}, ErrKMSBatchTooLarge},
		{"EncryptItemNotObject", "kms_batch_encrypt", map[string]interface{}{"key_id": "key-1", "items": []interface{}{"plaintext"}}, ErrKMSBatchItemInvalid},
		{"DecryptMissingKeyID", "kms_batch_decrypt", map[string]interface{}{"items": []interface{}{map[string]interface{}{}}}, ErrKMSKeyIDRequired},
		{"DecryptEmptyItems", "kms_batch_decrypt", map[string]interface{}{"key_id": "key-1", "items": []interface{}{}}, ErrKMSBatchItemsRequired},
		{"DecryptTooManyItems", "kms_batch_decrypt", map[string]interface{}{"key_id": "key-1", "items": tooMany}, ErrKMSBatchTooLarge},
		{"DecryptNegativeKeyVersion", "kms_batch_decrypt", map[string]interface{}{"key_id": "key-1", "items": []interface{}{map[string]interface{}{"key_version": float64(-1)}}}, ErrKMSVersionNegative},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), tc.tool, tc.args)
			assert.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("BatchItemInvalidBase64", func(t *testing.T) {
		_, err := executeKMSToolViaDispatch(t, newKMSToolTestRegistry(newMockServiceProvider()), "kms_batch_decrypt", map[string]interface{}{
			"key_id": "key-1",
			"items":  []interface{}{map[string]interface{}{"ciphertext": "not-base64!!!"}},
		})
		var kmsErr *KMSError
		require.ErrorAs(t, err, &kmsErr)
		assert.Equal(t, "KMS_INVALID_BASE64", kmsErr.Code)
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
		svc.secretListFunc = func(ctx context.Context, limit int) (interface{}, error) {
			assert.Equal(t, 50, limit)
			return map[string]interface{}{"secrets": []interface{}{}}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list", map[string]interface{}{})
		require.NoError(t, err)
	})

	t.Run("ListError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretListFunc = func(ctx context.Context, limit int) (interface{}, error) {
			return nil, errors.New("backend down")
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list", map[string]interface{}{})
		assert.Error(t, err)
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

func TestExecuteSecretVersionTools(t *testing.T) {
	t.Run("GetVersionSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretGetVersionFunc = func(ctx context.Context, secretID string, version uint64) (interface{}, error) {
			assert.Equal(t, "db/password", secretID)
			assert.Equal(t, uint64(2), version)
			return map[string]interface{}{"secret_id": secretID}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_get_version", map[string]interface{}{
			"secret_id": "db/password",
			"version":   float64(2),
		})
		require.NoError(t, err)
	})

	t.Run("GetVersionMissingVersion", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_get_version", map[string]interface{}{
			"secret_id": "db/password",
		})
		assert.ErrorIs(t, err, ErrSecretVersionRequired)
	})

	t.Run("ListVersionsSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretListVersionsFunc = func(ctx context.Context, secretID string, limit int) (interface{}, error) {
			assert.Equal(t, "db/password", secretID)
			assert.Equal(t, 10, limit)
			return map[string]interface{}{"versions": []interface{}{}}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list_versions", map[string]interface{}{
			"secret_id": "db/password",
			"limit":     float64(10),
		})
		require.NoError(t, err)
	})

	t.Run("ListVersionsError", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretListVersionsFunc = func(ctx context.Context, secretID string, limit int) (interface{}, error) {
			return nil, errors.New("backend down")
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_list_versions", map[string]interface{}{
			"secret_id": "db/password",
		})
		assert.Error(t, err)
	})

	t.Run("RotateSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		var captured *SecretRotateRequest
		svc.secretRotateFunc = func(ctx context.Context, req *SecretRotateRequest) (interface{}, error) {
			captured = req
			return map[string]interface{}{"secret_id": req.SecretID, "new_version": 2}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_rotate", map[string]interface{}{
			"secret_id": "db/password",
			"new_data":  base64.StdEncoding.EncodeToString([]byte("hunter3")),
			"metadata":  map[string]interface{}{"reason": "scheduled"},
		})
		require.NoError(t, err)
		require.NotNil(t, captured)
		assert.Equal(t, []byte("hunter3"), captured.NewData)
		assert.Equal(t, "scheduled", captured.Metadata["reason"])
	})

	t.Run("RotateMissingData", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_rotate", map[string]interface{}{
			"secret_id": "db/password",
		})
		assert.ErrorIs(t, err, ErrSecretDataRequired)
	})

	t.Run("RollbackSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretRollbackFunc = func(ctx context.Context, secretID string, targetVersion uint64) (interface{}, error) {
			assert.Equal(t, uint64(1), targetVersion)
			return map[string]interface{}{"secret_id": secretID, "new_version": 3}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_rollback", map[string]interface{}{
			"secret_id":      "db/password",
			"target_version": float64(1),
		})
		require.NoError(t, err)
	})

	t.Run("RollbackMissingVersion", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_rollback", map[string]interface{}{
			"secret_id": "db/password",
		})
		assert.ErrorIs(t, err, ErrSecretVersionRequired)
	})

	t.Run("UpdateStatusSuccess", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretUpdateStatusFunc = func(ctx context.Context, secretID, status string) (interface{}, error) {
			assert.Equal(t, "disabled", status)
			return map[string]interface{}{"secret_id": secretID, "status": status}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_update_status", map[string]interface{}{
			"secret_id": "db/password",
			"status":    "disabled",
		})
		require.NoError(t, err)
	})

	t.Run("UpdateStatusMissingStatus", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		_, err := executeKMSToolViaDispatch(t, registry, "secret_update_status", map[string]interface{}{
			"secret_id": "db/password",
		})
		assert.ErrorIs(t, err, ErrSecretStatusRequired)
	})

	t.Run("MissingSecretID", func(t *testing.T) {
		registry := newKMSToolTestRegistry(newMockServiceProvider())
		for _, tool := range []string{"secret_get_version", "secret_list_versions", "secret_rotate", "secret_rollback", "secret_update_status"} {
			_, err := executeKMSToolViaDispatch(t, registry, tool, map[string]interface{}{})
			assert.ErrorIs(t, err, ErrSecretIDRequired, tool)
		}
	})
}

func TestExecuteSecretGetByPrefix(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretGetByPrefixFunc = func(ctx context.Context, prefix string, includeData bool, limit int, cursor string) (interface{}, error) {
			assert.Equal(t, "app/", prefix)
			assert.True(t, includeData)
			assert.Equal(t, 10, limit)
			assert.Equal(t, "2", cursor)
			return map[string]interface{}{
				"secrets": map[string]interface{}{"app/a": map[string]interface{}{"version": 1}},
			}, nil
		}
		registry := newKMSToolTestRegistry(svc)

		result, err := executeKMSToolViaDispatch(t, registry, "secret_get_by_prefix", map[string]interface{}{
			"prefix":       "app/",
			"include_data": true,
			"limit":        float64(10),
			"cursor":       "2",
		})
		require.NoError(t, err)
		resultMap, ok := result.(map[string]interface{})
		require.True(t, ok, "result is %T", result)
		assert.Contains(t, resultMap["secrets"], "app/a")
	})

	t.Run("MissingPrefix", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.secretGetByPrefixFunc = func(context.Context, string, bool, int, string) (interface{}, error) {
			t.Fatal("service must not be called without a prefix")
			return nil, nil
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_get_by_prefix", map[string]interface{}{})
		assert.ErrorIs(t, err, ErrSecretPrefixRequired)
	})

	t.Run("ServiceError", func(t *testing.T) {
		svc := newMockServiceProvider()
		upstream := errors.New("secrets backend down")
		svc.secretGetByPrefixFunc = func(context.Context, string, bool, int, string) (interface{}, error) {
			return nil, upstream
		}
		registry := newKMSToolTestRegistry(svc)

		_, err := executeKMSToolViaDispatch(t, registry, "secret_get_by_prefix", map[string]interface{}{"prefix": "app/"})
		assert.ErrorIs(t, err, upstream)
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
		"secret_get_version",
		"secret_list_versions",
		"secret_rotate",
		"secret_rollback",
		"secret_update_status",
		"secret_get_by_prefix",
	}
	for _, name := range expected {
		assert.True(t, registered[name], "tool %s must be registered", name)
	}

	// Every dispatched tool must also be a registered tool.
	for name := range kmsToolDispatch {
		assert.True(t, registered[name], "dispatched tool %s must be registered", name)
	}
}
