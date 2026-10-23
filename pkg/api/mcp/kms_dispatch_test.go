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
	"strings"
	"testing"
)

// =============================================================================
// KMS Tool Dispatch Parity
// =============================================================================

// TestKMSToolDispatchParity ensures every registered kms_* and secret_* tool
// is actually routed by ExecuteTool. A registered tool that falls through to
// "unknown tool" is a silent production breakage for MCP clients.
func TestKMSToolDispatchParity(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	for _, tool := range registry.ListTools() {
		if !strings.HasPrefix(tool.Name, "kms_") && !strings.HasPrefix(tool.Name, "secret_") {
			continue
		}
		_, err := registry.ExecuteTool(ctx, tool.Name, map[string]interface{}{})
		if err != nil && strings.Contains(err.Error(), "unknown tool") {
			t.Errorf("registered tool %q is not routed by ExecuteTool", tool.Name)
		}
	}
}

// TestKMSBundleToolsRemoved ensures the key bundle tools, which have no
// backend anywhere in the stack, are no longer registered.
func TestKMSBundleToolsRemoved(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	for _, tool := range registry.ListTools() {
		if tool.Name == "kms_create_key_bundle" || tool.Name == "kms_list_key_bundles" {
			t.Errorf("tool %q must not be registered: key bundles have no backend", tool.Name)
		}
	}
}

// TestKMSAdapterMappedToolsRegistered ensures every tool name the SDK MCP
// transport adapter emits for the KeyManagementService resolves to a
// registered tool.
func TestKMSAdapterMappedToolsRegistered(t *testing.T) {
	adapterTools := []string{
		"kms_generate_key",
		"kms_delete_key",
		"kms_get_key",
		"kms_list_keys",
		"kms_rotate_key",
		"kms_encrypt",
		"kms_decrypt",
		"kms_sign",
		"kms_verify",
		"kms_random",
		"kms_generate_data_key",
		"kms_generate_wrapped_data_key",
		"kms_hash",
		"kms_hmac",
		"kms_verify_hmac",
		"kms_rewrap",
		"kms_import_key",
		"kms_update_key_status",
		"kms_list_key_versions",
		"kms_batch_encrypt",
		"kms_batch_decrypt",
	}

	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())
	registered := make(map[string]struct{})
	for _, tool := range registry.ListTools() {
		registered[tool.Name] = struct{}{}
	}

	for _, name := range adapterTools {
		if _, ok := registered[name]; !ok {
			t.Errorf("SDK MCP adapter tool %q is not registered", name)
		}
	}
}

// =============================================================================
// kms_generate_key
// =============================================================================

func TestExecuteKMSGenerateKey_FlatArgs(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSCreateKeyRequest
	svc.kmsCreateKeyFunc = func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"key_id": "key-1"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":                "signing-key",
		"algorithm":           "ECDSA-P384",
		"key_size":            float64(384),
		"usage":               []interface{}{"sign", "verify"},
		"exportable":          true,
		"deletion_protection": true,
		"description":         "test signing key",
		"owner":               "platform",
		"tags":                map[string]interface{}{"env": "test"},
	}

	if _, err := registry.ExecuteTool(ctx, "kms_generate_key", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSCreateKey was not called")
	}
	if captured.Name != "signing-key" {
		t.Errorf("Name = %q, want signing-key", captured.Name)
	}
	if captured.Algorithm != "ECDSA-P384" {
		t.Errorf("Algorithm = %q, want ECDSA-P384", captured.Algorithm)
	}
	if captured.KeySize != 384 {
		t.Errorf("KeySize = %d, want 384", captured.KeySize)
	}
	if len(captured.KeyUsage) != 2 || captured.KeyUsage[0] != "sign" || captured.KeyUsage[1] != "verify" {
		t.Errorf("KeyUsage = %v, want [sign verify]", captured.KeyUsage)
	}
	if !captured.Exportable || !captured.DeletionProtection {
		t.Errorf("Exportable/DeletionProtection = %v/%v, want true/true",
			captured.Exportable, captured.DeletionProtection)
	}
	if captured.Owner != "platform" {
		t.Errorf("Owner = %q, want platform", captured.Owner)
	}
	if captured.Tags["env"] != "test" {
		t.Errorf("Tags = %v, want map[env:test]", captured.Tags)
	}
}

// TestExecuteKMSGenerateKey_ProtoKeySpec mirrors the SDK MCP transport
// adapter, which JSON-encodes the platform.v1 GenerateKeyRequest proto:
// algorithm and usage arrive as numeric enum values nested inside key_spec.
func TestExecuteKMSGenerateKey_ProtoKeySpec(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSCreateKeyRequest
	svc.kmsCreateKeyFunc = func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"key_id": "key-1"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	// KMS_KEY_ALGORITHM_ECDSA_P256 = 4, KEY_USAGE_SIGN = 3, KEY_USAGE_VERIFY = 4
	args := map[string]interface{}{
		"name": "sdk-key",
		"key_spec": map[string]interface{}{
			"algorithm":           float64(4),
			"key_size":            float64(256),
			"usage":               []interface{}{float64(3), float64(4)},
			"exportable":          true,
			"deletion_protection": true,
		},
	}

	if _, err := registry.ExecuteTool(ctx, "kms_generate_key", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSCreateKey was not called")
	}
	if captured.Algorithm != "ECDSA-P256" {
		t.Errorf("Algorithm = %q, want ECDSA-P256", captured.Algorithm)
	}
	if captured.KeySize != 256 {
		t.Errorf("KeySize = %d, want 256", captured.KeySize)
	}
	if len(captured.KeyUsage) != 2 || captured.KeyUsage[0] != "sign" || captured.KeyUsage[1] != "verify" {
		t.Errorf("KeyUsage = %v, want [sign verify]", captured.KeyUsage)
	}
	if !captured.Exportable || !captured.DeletionProtection {
		t.Errorf("Exportable/DeletionProtection = %v/%v, want true/true",
			captured.Exportable, captured.DeletionProtection)
	}
}

func TestExecuteKMSGenerateKey_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_generate_key", map[string]interface{}{
		"algorithm": "AES-256-GCM",
		"usage":     []interface{}{"encrypt"},
	}); !errors.Is(err, ErrKMSKeyNameRequired) {
		t.Errorf("missing name: err = %v, want ErrKMSKeyNameRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_generate_key", map[string]interface{}{
		"name":  "no-alg",
		"usage": []interface{}{"encrypt"},
	}); !errors.Is(err, ErrKMSAlgorithmRequired) {
		t.Errorf("missing algorithm: err = %v, want ErrKMSAlgorithmRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_generate_key", map[string]interface{}{
		"name":      "no-usage",
		"algorithm": "AES-256-GCM",
	}); !errors.Is(err, ErrKMSKeyUsageRequired) {
		t.Errorf("missing usage: err = %v, want ErrKMSKeyUsageRequired", err)
	}
}

// =============================================================================
// kms_get_key
// =============================================================================

func TestExecuteKMSGetKey_VersionCapture(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var capturedID string
	var capturedVersion uint64
	svc.kmsGetKeyFunc = func(ctx context.Context, keyID string, version uint64) (interface{}, error) {
		capturedID = keyID
		capturedVersion = version
		return map[string]interface{}{"key_id": keyID}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":  "key-42",
		"version": float64(3),
	}
	if _, err := registry.ExecuteTool(ctx, "kms_get_key", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if capturedID != "key-42" {
		t.Errorf("keyID = %q, want key-42", capturedID)
	}
	if capturedVersion != 3 {
		t.Errorf("version = %d, want 3", capturedVersion)
	}
}

func TestExecuteKMSGetKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_get_key", map[string]interface{}{}); !errors.Is(err, ErrKMSKeyIDRequired) {
		t.Errorf("err = %v, want ErrKMSKeyIDRequired", err)
	}
}

// =============================================================================
// kms_list_keys
// =============================================================================

func TestExecuteKMSListKeys_DefaultLimit(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var capturedLimit int
	svc.kmsListKeysFunc = func(ctx context.Context, limit, offset int) (interface{}, error) {
		capturedLimit = limit
		return map[string]interface{}{"keys": []interface{}{}}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_list_keys", map[string]interface{}{}); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if capturedLimit != 50 {
		t.Errorf("default limit = %d, want 50", capturedLimit)
	}

	if _, err := registry.ExecuteTool(ctx, "kms_list_keys", map[string]interface{}{
		"limit": float64(7),
	}); err != nil {
		t.Fatalf("ExecuteTool with limit: %v", err)
	}
	if capturedLimit != 7 {
		t.Errorf("explicit limit = %d, want 7", capturedLimit)
	}
}

// =============================================================================
// kms_delete_key / kms_rotate_key
// =============================================================================

func TestExecuteKMSDeleteKey_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var capturedID string
	svc.kmsDeleteKeyFunc = func(ctx context.Context, keyID string) error {
		capturedID = keyID
		return nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.ExecuteTool(ctx, "kms_delete_key", map[string]interface{}{
		"key_id": "key-del",
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if capturedID != "key-del" {
		t.Errorf("keyID = %q, want key-del", capturedID)
	}
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	if success, _ := resultMap["success"].(bool); !success {
		t.Error("success = false, want true")
	}
}

func TestExecuteKMSDeleteKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_delete_key", map[string]interface{}{}); !errors.Is(err, ErrKMSKeyIDRequired) {
		t.Errorf("err = %v, want ErrKMSKeyIDRequired", err)
	}
}

func TestExecuteKMSRotateKey_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var capturedID string
	svc.kmsRotateKeyFunc = func(ctx context.Context, keyID string) (interface{}, error) {
		capturedID = keyID
		return map[string]interface{}{"key_id": keyID, "new_version": 2}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_rotate_key", map[string]interface{}{
		"key_id": "key-rot",
	}); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if capturedID != "key-rot" {
		t.Errorf("keyID = %q, want key-rot", capturedID)
	}
}

func TestExecuteKMSRotateKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_rotate_key", map[string]interface{}{}); !errors.Is(err, ErrKMSKeyIDRequired) {
		t.Errorf("err = %v, want ErrKMSKeyIDRequired", err)
	}
}

// =============================================================================
// kms_export_public_key
// =============================================================================

func TestExecuteKMSExportPublicKey_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSExportPublicKeyRequest
	svc.kmsExportPublicKeyFunc = func(ctx context.Context, req *KMSExportPublicKeyRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{
			"key_id":     req.KeyID,
			"format":     req.Format,
			"public_key": "-----BEGIN PUBLIC KEY-----",
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":  "key-exp",
		"format":  "DER",
		"version": float64(2),
	}
	if _, err := registry.ExecuteTool(ctx, "kms_export_public_key", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSExportPublicKey was not called")
	}
	if captured.KeyID != "key-exp" {
		t.Errorf("KeyID = %q, want key-exp", captured.KeyID)
	}
	if captured.Format != "DER" {
		t.Errorf("Format = %q, want DER", captured.Format)
	}
	if captured.Version != 2 {
		t.Errorf("Version = %d, want 2", captured.Version)
	}
}

func TestExecuteKMSExportPublicKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_export_public_key", map[string]interface{}{
		"format": "PEM",
	}); !errors.Is(err, ErrKMSKeyIDRequired) {
		t.Errorf("err = %v, want ErrKMSKeyIDRequired", err)
	}
}

func TestExecuteKMSExportPublicKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsExportPublicKeyFunc = func(ctx context.Context, req *KMSExportPublicKeyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_export_public_key", map[string]interface{}{
		"key_id": "key-exp",
	}); !errors.Is(err, ErrMockServiceError) {
		t.Errorf("err = %v, want ErrMockServiceError", err)
	}
}

// =============================================================================
// kms_encrypt / kms_decrypt
// =============================================================================

func TestExecuteKMSEncrypt_DecodesFields(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSEncryptRequest
	svc.kmsEncryptFunc = func(ctx context.Context, req *KMSEncryptRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"ciphertext": "enc"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "key-enc",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("secret data")),
		"context":   base64.StdEncoding.EncodeToString([]byte("aad")),
		"nonce":     base64.StdEncoding.EncodeToString([]byte("nonce-value")),
	}
	if _, err := registry.ExecuteTool(ctx, "kms_encrypt", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSEncrypt was not called")
	}
	if string(captured.Plaintext) != "secret data" {
		t.Errorf("Plaintext = %q, want secret data", captured.Plaintext)
	}
	if string(captured.Context) != "aad" {
		t.Errorf("Context = %q, want aad", captured.Context)
	}
	if string(captured.Nonce) != "nonce-value" {
		t.Errorf("Nonce = %q, want nonce-value", captured.Nonce)
	}
}

func TestExecuteKMSEncrypt_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_encrypt", map[string]interface{}{
		"plaintext": "aGVsbG8=",
	}); !errors.Is(err, ErrKMSKeyIDRequired) {
		t.Errorf("missing key_id: err = %v, want ErrKMSKeyIDRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_encrypt", map[string]interface{}{
		"key_id": "key-enc",
	}); !errors.Is(err, ErrKMSPlaintextRequired) {
		t.Errorf("missing plaintext: err = %v, want ErrKMSPlaintextRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_encrypt", map[string]interface{}{
		"key_id":    "key-enc",
		"plaintext": "not-base64!!!",
	}); err == nil {
		t.Error("expected error for invalid base64 plaintext")
	}
	if _, err := registry.ExecuteTool(ctx, "kms_encrypt", map[string]interface{}{
		"key_id":    "key-enc",
		"plaintext": "aGVsbG8=",
		"nonce":     "not-base64!!!",
	}); err == nil {
		t.Error("expected error for invalid base64 nonce")
	}
}

func TestExecuteKMSDecrypt_DecodesFields(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSDecryptRequest
	svc.kmsDecryptFunc = func(ctx context.Context, req *KMSDecryptRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"plaintext": "dec"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":      "key-dec",
		"ciphertext":  base64.StdEncoding.EncodeToString([]byte("cipher")),
		"context":     base64.StdEncoding.EncodeToString([]byte("aad")),
		"nonce":       base64.StdEncoding.EncodeToString([]byte("nonce-value")),
		"key_version": float64(4),
	}
	if _, err := registry.ExecuteTool(ctx, "kms_decrypt", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSDecrypt was not called")
	}
	if string(captured.Ciphertext) != "cipher" {
		t.Errorf("Ciphertext = %q, want cipher", captured.Ciphertext)
	}
	if string(captured.Context) != "aad" {
		t.Errorf("Context = %q, want aad", captured.Context)
	}
	if string(captured.Nonce) != "nonce-value" {
		t.Errorf("Nonce = %q, want nonce-value", captured.Nonce)
	}
	if captured.KeyVersion != 4 {
		t.Errorf("KeyVersion = %d, want 4", captured.KeyVersion)
	}
}

func TestExecuteKMSDecrypt_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_decrypt", map[string]interface{}{
		"ciphertext": "aGVsbG8=",
	}); !errors.Is(err, ErrKMSKeyIDRequired) {
		t.Errorf("missing key_id: err = %v, want ErrKMSKeyIDRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_decrypt", map[string]interface{}{
		"key_id": "key-dec",
	}); !errors.Is(err, ErrKMSCiphertextRequired) {
		t.Errorf("missing ciphertext: err = %v, want ErrKMSCiphertextRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_decrypt", map[string]interface{}{
		"key_id":     "key-dec",
		"ciphertext": "not-base64!!!",
	}); err == nil {
		t.Error("expected error for invalid base64 ciphertext")
	}
}

// =============================================================================
// kms_verify
// =============================================================================

func TestExecuteKMSVerify_DecodesAndCoercesHash(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSVerifyRequest
	svc.kmsVerifyFunc = func(ctx context.Context, req *KMSVerifyRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"valid": true}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	// Numeric hash_algorithm mirrors the SDK MCP transport adapter
	// (platform.v1 HASH_ALGORITHM_SHA384 = 3).
	args := map[string]interface{}{
		"key_id":         "key-ver",
		"message":        base64.StdEncoding.EncodeToString([]byte("message")),
		"signature":      base64.StdEncoding.EncodeToString([]byte("signature")),
		"hash_algorithm": float64(3),
		"key_version":    float64(5),
	}
	if _, err := registry.ExecuteTool(ctx, "kms_verify", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSVerify was not called")
	}
	if string(captured.Message) != "message" {
		t.Errorf("Message = %q, want message", captured.Message)
	}
	if string(captured.Signature) != "signature" {
		t.Errorf("Signature = %q, want signature", captured.Signature)
	}
	if captured.HashAlgorithm != "SHA384" {
		t.Errorf("HashAlgorithm = %q, want SHA384", captured.HashAlgorithm)
	}
	if captured.KeyVersion != 5 {
		t.Errorf("KeyVersion = %d, want 5", captured.KeyVersion)
	}
}

func TestExecuteKMSVerify_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_verify", map[string]interface{}{
		"message":   "bWVzc2FnZQ==",
		"signature": "c2ln",
	}); !errors.Is(err, ErrKMSKeyIDRequired) {
		t.Errorf("missing key_id: err = %v, want ErrKMSKeyIDRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_verify", map[string]interface{}{
		"key_id":    "key-ver",
		"signature": "c2ln",
	}); !errors.Is(err, ErrKMSMessageRequired) {
		t.Errorf("missing message: err = %v, want ErrKMSMessageRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_verify", map[string]interface{}{
		"key_id":  "key-ver",
		"message": "bWVzc2FnZQ==",
	}); !errors.Is(err, ErrKMSSignatureRequired) {
		t.Errorf("missing signature: err = %v, want ErrKMSSignatureRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_verify", map[string]interface{}{
		"key_id":    "key-ver",
		"message":   "not-base64!!!",
		"signature": "c2ln",
	}); err == nil {
		t.Error("expected error for invalid base64 message")
	}
}

// =============================================================================
// kms_random
// =============================================================================

func TestExecuteKMSGenerateRandom_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var capturedNumBytes int
	svc.kmsGenerateRandomFunc = func(ctx context.Context, numBytes int) ([]byte, error) {
		capturedNumBytes = numBytes
		return []byte{0xde, 0xad, 0xbe, 0xef}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.ExecuteTool(ctx, "kms_random", map[string]interface{}{
		"num_bytes": float64(4),
	})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if capturedNumBytes != 4 {
		t.Errorf("numBytes = %d, want 4", capturedNumBytes)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result type = %T, want map", result)
	}
	encoded, ok := resultMap["random_bytes"].(string)
	if !ok {
		t.Fatalf("random_bytes type = %T, want string", resultMap["random_bytes"])
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("random_bytes is not base64: %v", err)
	}
	if len(decoded) != 4 || decoded[0] != 0xde || decoded[3] != 0xef {
		t.Errorf("random_bytes = %x, want deadbeef", decoded)
	}
}

func TestExecuteKMSGenerateRandom_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_random", map[string]interface{}{}); !errors.Is(err, ErrKMSNumBytesRequired) {
		t.Errorf("missing num_bytes: err = %v, want ErrKMSNumBytesRequired", err)
	}
	if _, err := registry.ExecuteTool(ctx, "kms_random", map[string]interface{}{
		"num_bytes": float64(0),
	}); !errors.Is(err, ErrKMSNumBytesRequired) {
		t.Errorf("zero num_bytes: err = %v, want ErrKMSNumBytesRequired", err)
	}
}
