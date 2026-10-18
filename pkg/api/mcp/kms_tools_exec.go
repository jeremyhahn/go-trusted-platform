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
	"fmt"
)

// KMS and secrets tool execution.
//
// dispatchKMSTool routes the kms_* and secret_* tools that are not part of
// the legacy switch in ExecuteTool. It uses map-based dispatch for O(1)
// lookup per project conventions and delegates every operation to the
// ServiceProvider, which is backed by the quicbaas service layer.

// kmsToolHandler executes a single KMS or secrets tool.
type kmsToolHandler func(r *ToolRegistry, ctx context.Context, args map[string]interface{}) (interface{}, error)

// kmsToolDispatch maps tool names to their handlers.
var kmsToolDispatch = map[string]kmsToolHandler{
	// Key management
	"kms_generate_key": (*ToolRegistry).executeKMSGenerateKey,
	"kms_get_key":      (*ToolRegistry).executeKMSGetKey,
	"kms_list_keys":    (*ToolRegistry).executeKMSListKeys,
	"kms_delete_key":   (*ToolRegistry).executeKMSDeleteKey,
	"kms_rotate_key":   (*ToolRegistry).executeKMSRotateKey,

	"kms_export_public_key": (*ToolRegistry).executeKMSExportPublicKey,

	// Random generation
	"kms_random": (*ToolRegistry).executeKMSGenerateRandom,

	// Key lifecycle
	"kms_revoke_key":           (*ToolRegistry).executeKMSRevokeKey,
	"kms_get_key_metadata":     (*ToolRegistry).executeKMSGetKeyMetadata,
	"kms_update_key_metadata":  (*ToolRegistry).executeKMSUpdateKeyMetadata,
	"kms_update_key_status":    (*ToolRegistry).executeKMSUpdateKeyStatus,
	"kms_get_key_policy":       (*ToolRegistry).executeKMSGetKeyPolicy,
	"kms_set_key_policy":       (*ToolRegistry).executeKMSSetKeyPolicy,
	"kms_supported_algorithms": (*ToolRegistry).executeKMSSupportedAlgorithms,
	"kms_backend_status":       (*ToolRegistry).executeKMSBackendStatus,

	// Crypto
	"kms_encrypt": (*ToolRegistry).executeKMSEncrypt,
	"kms_decrypt": (*ToolRegistry).executeKMSDecrypt,
	"kms_verify":  (*ToolRegistry).executeKMSVerify,

	// Secrets
	"secret_store":               (*ToolRegistry).executeSecretStore,
	"secret_get":                 (*ToolRegistry).executeSecretGet,
	"secret_list":                (*ToolRegistry).executeSecretList,
	"secret_delete":              (*ToolRegistry).executeSecretDelete,
	"secret_set_rotation_policy": (*ToolRegistry).executeSecretSetRotationPolicy,
	"secret_get_rotation_policy": (*ToolRegistry).executeSecretGetRotationPolicy,
}

// dispatchKMSTool routes a KMS or secrets tool by name. It returns
// handled=false when the tool name is not a KMS/secrets tool.
func (r *ToolRegistry) dispatchKMSTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := kmsToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Key Management Executors
// =============================================================================

func (r *ToolRegistry) executeKMSGenerateKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	name := getString(args, "name")
	if name == "" {
		return nil, ErrKMSKeyNameRequired
	}
	if getString(args, "display_name") != "" {
		return nil, ErrKMSDisplayNameNotSupported
	}

	// The SDK MCP transport adapter JSON-encodes the platform.v1 proto
	// GenerateKeyRequest, which nests algorithm, usage, key_size,
	// exportable and deletion_protection inside a key_spec object with
	// numeric enum values. Flat fields take precedence when both forms
	// are present.
	spec := getMap(args, "key_spec")

	algorithm := getString(args, "algorithm")
	if algorithm == "" && spec != nil {
		algorithm = kmsKeyAlgorithmName(spec)
	}
	if algorithm == "" {
		return nil, ErrKMSAlgorithmRequired
	}

	usage := getStringSlice(args, "usage")
	if len(usage) == 0 && spec != nil {
		usage = kmsKeyUsageNames(spec)
	}
	if len(usage) == 0 {
		return nil, ErrKMSKeyUsageRequired
	}

	keySize := getInt(args, "key_size")
	exportable := getBool(args, "exportable")
	deletionProtection := getBool(args, "deletion_protection")
	if spec != nil {
		if keySize == 0 {
			keySize = getInt(spec, "key_size")
		}
		exportable = exportable || getBool(spec, "exportable")
		deletionProtection = deletionProtection || getBool(spec, "deletion_protection")
	}

	req := &KMSCreateKeyRequest{
		Name:               name,
		Description:        getString(args, "description"),
		Algorithm:          algorithm,
		KeyUsage:           usage,
		KeySize:            keySize,
		Tags:               getStringMap(args, "tags"),
		Exportable:         exportable,
		DeletionProtection: deletionProtection,
		Owner:              getString(args, "owner"),
	}

	result, err := r.service.KMSCreateKey(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// kmsKeyAlgorithmNames maps platform.v1 KMSKeyAlgorithm enum values to the
// canonical algorithm names accepted by the KMS service layer.
var kmsKeyAlgorithmNames = map[int]string{
	1:  "RSA-2048",
	2:  "RSA-3072",
	3:  "RSA-4096",
	4:  "ECDSA-P256",
	5:  "ECDSA-P384",
	6:  "ECDSA-P521",
	7:  "ED25519",
	8:  "DILITHIUM2",
	9:  "DILITHIUM3",
	10: "DILITHIUM5",
	20: "AES-128-GCM",
	21: "AES-192-GCM",
	22: "AES-256-GCM",
	23: "CHACHA20-POLY1305",
	30: "HMAC-SHA256",
	31: "HMAC-SHA384",
	32: "HMAC-SHA512",
}

// kmsKeyUsageValueNames maps platform.v1 KeyUsage enum values to the usage
// names accepted by the KMS service layer.
var kmsKeyUsageValueNames = map[int]string{
	1: "encrypt",
	2: "decrypt",
	3: "sign",
	4: "verify",
	5: "wrap",
	6: "unwrap",
	7: "derive",
	8: "generate_mac",
}

// kmsKeyAlgorithmName resolves the algorithm from a proto key_spec object,
// accepting either a string name or a numeric platform.v1 KMSKeyAlgorithm
// enum value.
func kmsKeyAlgorithmName(spec map[string]interface{}) string {
	if name := getString(spec, "algorithm"); name != "" {
		return name
	}
	return kmsKeyAlgorithmNames[getInt(spec, "algorithm")]
}

// kmsKeyUsageNames resolves the usage list from a proto key_spec object,
// accepting string names or numeric platform.v1 KeyUsage enum values.
func kmsKeyUsageNames(spec map[string]interface{}) []string {
	raw, ok := spec["usage"].([]interface{})
	if !ok {
		return nil
	}
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		switch v := item.(type) {
		case string:
			names = append(names, v)
		case float64:
			if name, ok := kmsKeyUsageValueNames[int(v)]; ok {
				names = append(names, name)
			}
		case int:
			if name, ok := kmsKeyUsageValueNames[v]; ok {
				names = append(names, name)
			}
		}
	}
	return names
}

// executeKMSGenerateRandom handles the kms_random tool, which the SDK MCP
// transport adapter maps to /platform.v1.KeyManagementService/GenerateRandom.
func (r *ToolRegistry) executeKMSGenerateRandom(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	numBytes := getInt(args, "num_bytes")
	if numBytes <= 0 {
		return nil, ErrKMSNumBytesRequired
	}

	data, err := r.service.KMSGenerateRandom(ctx, numBytes)
	if err != nil {
		return nil, err
	}
	// random_bytes mirrors the platform.v1 GenerateRandomResponse proto
	// field so the SDK MCP transport adapter can unmarshal the reply.
	return map[string]interface{}{
		"random_bytes": base64.StdEncoding.EncodeToString(data),
		"num_bytes":    numBytes,
	}, nil
}

func (r *ToolRegistry) executeKMSGetKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	result, err := r.service.KMSGetKey(ctx, keyID, uint64(getInt64(args, "version")))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSListKeys(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := getInt(args, "limit")
	if limit <= 0 {
		limit = 50
	}

	result, err := r.service.KMSListKeys(ctx, limit, 0)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSDeleteKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	if err := r.service.KMSDeleteKey(ctx, keyID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "key_id": keyID}, nil
}

func (r *ToolRegistry) executeKMSRotateKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	result, err := r.service.KMSRotateKey(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSExportPublicKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	result, err := r.service.KMSExportPublicKey(ctx, &KMSExportPublicKeyRequest{
		KeyID:   keyID,
		Format:  getString(args, "format"),
		Version: uint64(getInt64(args, "version")),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// =============================================================================
// Key Lifecycle Executors
// =============================================================================

func (r *ToolRegistry) executeKMSRevokeKey(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	result, err := r.service.KMSRevokeKey(ctx, keyID, getString(args, "reason"))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSGetKeyMetadata(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	result, err := r.service.KMSGetKeyMetadata(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSUpdateKeyMetadata(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	req := &KMSUpdateKeyMetadataRequest{
		KeyID:       keyID,
		Name:        getString(args, "name"),
		Description: getString(args, "description"),
		Tags:        getStringMap(args, "tags"),
		RemoveTags:  getStringSlice(args, "remove_tags"),
	}

	result, err := r.service.KMSUpdateKeyMetadata(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// kmsSettableKeyStatuses are the statuses kms_update_key_status accepts.
var kmsSettableKeyStatuses = map[string]bool{
	"enabled":  true,
	"disabled": true,
}

func (r *ToolRegistry) executeKMSUpdateKeyStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	status := getString(args, "status")
	if !kmsSettableKeyStatuses[status] {
		return nil, ErrKMSKeyStatusInvalid
	}

	version := getInt64(args, "version")
	if version < 0 {
		return nil, ErrKMSKeyVersionInvalid
	}

	req := &KMSUpdateKeyStatusRequest{
		KeyID:   keyID,
		Version: uint64(version),
		Status:  status,
		Reason:  getString(args, "reason"),
	}

	result, err := r.service.KMSUpdateKeyStatus(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSGetKeyPolicy(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	result, err := r.service.KMSGetKeyPolicy(ctx, keyID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSSetKeyPolicy(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}

	req := &KMSSetKeyPolicyRequest{
		KeyID:             keyID,
		AllowedOperations: getStringSlice(args, "allowed_operations"),
		AllowedPrincipals: getStringSlice(args, "allowed_principals"),
		DeniedPrincipals:  getStringSlice(args, "denied_principals"),
		ExpiresAt:         getInt64(args, "expires_at"),
		RotationRequired:  getBool(args, "rotation_required"),
		MaxUsageCount:     uint64(getInt64(args, "max_usage_count")),
		RequireMFA:        getBool(args, "require_mfa"),
	}

	result, err := r.service.KMSSetKeyPolicy(ctx, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSSupportedAlgorithms(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	algorithms, err := r.service.KMSGetSupportedAlgorithms(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"algorithms": algorithms}, nil
}

func (r *ToolRegistry) executeKMSBackendStatus(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	result, err := r.service.KMSBackendStatus(ctx)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// =============================================================================
// Crypto Executors
// =============================================================================

func (r *ToolRegistry) executeKMSEncrypt(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}
	plaintext, err := decodeBase64Arg(args, "plaintext")
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, ErrKMSPlaintextRequired
	}
	aad, err := decodeBase64Arg(args, "context")
	if err != nil {
		return nil, err
	}
	nonce, err := decodeBase64Arg(args, "nonce")
	if err != nil {
		return nil, err
	}

	result, err := r.service.KMSEncrypt(ctx, &KMSEncryptRequest{
		KeyID:     keyID,
		Plaintext: plaintext,
		Context:   aad,
		Nonce:     nonce,
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSDecrypt(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}
	ciphertext, err := decodeBase64Arg(args, "ciphertext")
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, ErrKMSCiphertextRequired
	}
	aad, err := decodeBase64Arg(args, "context")
	if err != nil {
		return nil, err
	}
	nonce, err := decodeBase64Arg(args, "nonce")
	if err != nil {
		return nil, err
	}

	result, err := r.service.KMSDecrypt(ctx, &KMSDecryptRequest{
		KeyID:      keyID,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Context:    aad,
		KeyVersion: getInt(args, "key_version"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeKMSVerify(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	keyID := getString(args, "key_id")
	if keyID == "" {
		return nil, ErrKMSKeyIDRequired
	}
	message, err := decodeBase64Arg(args, "message")
	if err != nil {
		return nil, err
	}
	if len(message) == 0 {
		return nil, ErrKMSMessageRequired
	}
	signature, err := decodeBase64Arg(args, "signature")
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, ErrKMSSignatureRequired
	}

	result, err := r.service.KMSVerify(ctx, &KMSVerifyRequest{
		KeyID:         keyID,
		Message:       message,
		Signature:     signature,
		HashAlgorithm: signHashAlgorithmName(args),
		KeyVersion:    getInt(args, "key_version"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// =============================================================================
// Secrets Executors
// =============================================================================

func (r *ToolRegistry) executeSecretStore(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	secretID := getString(args, "secret_id")
	if secretID == "" {
		return nil, ErrSecretIDRequired
	}
	data, err := decodeBase64Arg(args, "data")
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrSecretDataRequired
	}

	result, err := r.service.SecretStore(ctx, &SecretStoreRequest{
		SecretID: secretID,
		Data:     data,
		Metadata: getStringMap(args, "metadata"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeSecretGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	secretID := getString(args, "secret_id")
	if secretID == "" {
		return nil, ErrSecretIDRequired
	}

	result, err := r.service.SecretGet(ctx, secretID, uint64(getInt64(args, "version")))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeSecretList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	limit := getInt(args, "limit")
	if limit < 0 {
		return nil, ErrInvalidArgument{Msg: "limit must not be negative"}
	}
	if limit == 0 {
		limit = 50
	}

	result, err := r.service.SecretList(ctx, limit, getString(args, "cursor"))
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeSecretDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	secretID := getString(args, "secret_id")
	if secretID == "" {
		return nil, ErrSecretIDRequired
	}

	if err := r.service.SecretDelete(ctx, secretID); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "secret_id": secretID}, nil
}

func (r *ToolRegistry) executeSecretSetRotationPolicy(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	secretID := getString(args, "secret_id")
	if secretID == "" {
		return nil, ErrSecretIDRequired
	}

	result, err := r.service.SecretSetRotationPolicy(ctx, &SecretSetRotationPolicyRequest{
		SecretID:        secretID,
		Enabled:         getBool(args, "enabled"),
		IntervalSeconds: getInt64(args, "interval_seconds"),
		RetainVersions:  getInt(args, "retain_versions"),
	})
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeSecretGetRotationPolicy(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	secretID := getString(args, "secret_id")
	if secretID == "" {
		return nil, ErrSecretIDRequired
	}

	result, err := r.service.SecretGetRotationPolicy(ctx, secretID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

// decodeBase64Arg decodes an optional base64 string argument. An absent or
// empty argument yields (nil, nil).
func decodeBase64Arg(args map[string]interface{}, key string) ([]byte, error) {
	v := getString(args, key)
	if v == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, &KMSError{
			Code:    "KMS_INVALID_BASE64",
			Message: fmt.Sprintf("%s must be base64 encoded: %v", key, err),
		}
	}
	return data, nil
}
