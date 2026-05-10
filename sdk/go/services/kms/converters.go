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

package kms

import (
	"fmt"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
)

// ErrInvalidKeyAlgorithm is returned when an invalid key algorithm string is specified.
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// ErrInvalidKeyUsage is returned when an invalid key usage string is specified.
type ErrInvalidKeyUsage struct {
	Usage string
}

func (e ErrInvalidKeyUsage) Error() string {
	return fmt.Sprintf("invalid key usage: %s", e.Usage)
}

// ErrInvalidHashAlgorithm is returned when an invalid hash algorithm string is specified.
type ErrInvalidHashAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidHashAlgorithm) Error() string {
	return fmt.Sprintf("invalid hash algorithm: %s", e.Algorithm)
}

// protoKeyAlgorithmToKeyAlgorithm maps proto key algorithm to domain key algorithm.
var protoKeyAlgorithmToKeyAlgorithm = map[platformv1.KMSKeyAlgorithm]KeyAlgorithm{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED:      KeyAlgorithmUnspecified,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128:          KeyAlgorithmAES128,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192:          KeyAlgorithmAES192,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:          KeyAlgorithmAES256,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305: KeyAlgorithmChaCha20Poly,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048:         KeyAlgorithmRSA2048,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072:         KeyAlgorithmRSA3072,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096:         KeyAlgorithmRSA4096,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256:       KeyAlgorithmECDSAP256,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384:       KeyAlgorithmECDSAP384,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521:       KeyAlgorithmECDSAP521,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:          KeyAlgorithmED25519,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM2:       KeyAlgorithmDilithium2,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM3:       KeyAlgorithmDilithium3,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM5:       KeyAlgorithmDilithium5,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256:      KeyAlgorithmHMACSHA256,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA384:      KeyAlgorithmHMACSHA384,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA512:      KeyAlgorithmHMACSHA512,
}

// stringToProtoKeyAlgorithm maps user-facing algorithm strings to proto enum values.
var stringToProtoKeyAlgorithm = map[string]platformv1.KMSKeyAlgorithm{
	"aes-128":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128,
	"aes_128":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128,
	"aes-192":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192,
	"aes_192":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192,
	"aes-256":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
	"aes_256":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
	"chacha20-poly1305": platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305,
	"chacha20_poly1305": platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305,
	"rsa-2048":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048,
	"rsa_2048":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048,
	"rsa-3072":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072,
	"rsa_3072":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072,
	"rsa-4096":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096,
	"rsa_4096":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096,
	"ec-p256":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256,
	"ecdsa-p256":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256,
	"ecdsa_p256":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256,
	"ec-p384":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384,
	"ecdsa-p384":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384,
	"ecdsa_p384":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384,
	"ec-p521":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521,
	"ecdsa-p521":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521,
	"ecdsa_p521":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521,
	"ed25519":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519,
	"dilithium2":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM2,
	"dilithium3":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM3,
	"dilithium5":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_DILITHIUM5,
	"hmac-sha256":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256,
	"hmac_sha256":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256,
	"hmac-sha384":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA384,
	"hmac_sha384":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA384,
	"hmac-sha512":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA512,
	"hmac_sha512":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA512,
}

// protoKeyStatusToKeyStatus maps proto key status to domain key status.
var protoKeyStatusToKeyStatus = map[platformv1.KeyStatus]KeyStatus{
	platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED:      KeyStatusUnspecified,
	platformv1.KeyStatus_KEY_STATUS_ENABLED:          KeyStatusEnabled,
	platformv1.KeyStatus_KEY_STATUS_DISABLED:         KeyStatusDisabled,
	platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION: KeyStatusPendingDeletion,
	platformv1.KeyStatus_KEY_STATUS_DESTROYED:        KeyStatusDestroyed,
	platformv1.KeyStatus_KEY_STATUS_PENDING_IMPORT:   KeyStatusPendingImport,
}

// protoKeyUsageToKeyUsage maps proto key usage to domain key usage.
var protoKeyUsageToKeyUsage = map[platformv1.KeyUsage]KeyUsage{
	platformv1.KeyUsage_KEY_USAGE_UNSPECIFIED: KeyUsageUnspecified,
	platformv1.KeyUsage_KEY_USAGE_ENCRYPT:     KeyUsageEncrypt,
	platformv1.KeyUsage_KEY_USAGE_DECRYPT:     KeyUsageDecrypt,
	platformv1.KeyUsage_KEY_USAGE_SIGN:        KeyUsageSign,
	platformv1.KeyUsage_KEY_USAGE_VERIFY:      KeyUsageVerify,
	platformv1.KeyUsage_KEY_USAGE_WRAP:        KeyUsageWrap,
	platformv1.KeyUsage_KEY_USAGE_UNWRAP:      KeyUsageUnwrap,
	platformv1.KeyUsage_KEY_USAGE_DERIVE:      KeyUsageDerive,
	platformv1.KeyUsage_KEY_USAGE_HMAC:        KeyUsageHMAC,
}

// stringToProtoKeyUsage maps user-facing key usage strings to proto enum values.
var stringToProtoKeyUsage = map[string]platformv1.KeyUsage{
	"encrypt":      platformv1.KeyUsage_KEY_USAGE_ENCRYPT,
	"decrypt":      platformv1.KeyUsage_KEY_USAGE_DECRYPT,
	"sign":         platformv1.KeyUsage_KEY_USAGE_SIGN,
	"verify":       platformv1.KeyUsage_KEY_USAGE_VERIFY,
	"wrap":         platformv1.KeyUsage_KEY_USAGE_WRAP,
	"wrap-key":     platformv1.KeyUsage_KEY_USAGE_WRAP,
	"unwrap":       platformv1.KeyUsage_KEY_USAGE_UNWRAP,
	"unwrap-key":   platformv1.KeyUsage_KEY_USAGE_UNWRAP,
	"derive":       platformv1.KeyUsage_KEY_USAGE_DERIVE,
	"derive-key":   platformv1.KeyUsage_KEY_USAGE_DERIVE,
	"hmac":         platformv1.KeyUsage_KEY_USAGE_HMAC,
	"generate-mac": platformv1.KeyUsage_KEY_USAGE_HMAC,
	"mac":          platformv1.KeyUsage_KEY_USAGE_HMAC,
}

// protoHashAlgToHashAlg maps proto hash algorithm to domain hash algorithm.
var protoHashAlgToHashAlg = map[platformv1.HashAlgorithm]HashAlgorithm{
	platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED: HashAlgorithmUnspecified,
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1:        HashAlgorithmSHA1,
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256:      HashAlgorithmSHA256,
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384:      HashAlgorithmSHA384,
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512:      HashAlgorithmSHA512,
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256:    HashAlgorithmSHA3256,
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_384:    HashAlgorithmSHA3384,
	platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_512:    HashAlgorithmSHA3512,
}

// stringToProtoHashAlgorithm maps user-facing hash algorithm strings to proto enum values.
var stringToProtoHashAlgorithm = map[string]platformv1.HashAlgorithm{
	"sha1":     platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1,
	"sha-1":    platformv1.HashAlgorithm_HASH_ALGORITHM_SHA1,
	"sha256":   platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	"sha-256":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	"sha384":   platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	"sha-384":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	"sha512":   platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	"sha-512":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	"sha3-256": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256,
	"sha3256":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256,
	"sha3-384": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_384,
	"sha3384":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_384,
	"sha3-512": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_512,
	"sha3512":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_512,
}

// ParseKeyAlgorithm converts a user-facing algorithm string to the domain KeyAlgorithm.
func ParseKeyAlgorithm(alg string) (KeyAlgorithm, error) {
	normalized := strings.ToLower(strings.ReplaceAll(alg, "_", "-"))
	if protoVal, ok := stringToProtoKeyAlgorithm[normalized]; ok {
		if domainVal, ok := protoKeyAlgorithmToKeyAlgorithm[protoVal]; ok {
			return domainVal, nil
		}
	}
	// Also try the original string for uppercase variants
	if protoVal, ok := stringToProtoKeyAlgorithm[strings.ToLower(alg)]; ok {
		if domainVal, ok := protoKeyAlgorithmToKeyAlgorithm[protoVal]; ok {
			return domainVal, nil
		}
	}
	return KeyAlgorithmUnspecified, ErrInvalidKeyAlgorithm{Algorithm: alg}
}

// ParseKeyUsage converts a user-facing key usage string to the domain KeyUsage.
func ParseKeyUsage(usage string) (KeyUsage, error) {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(usage), "_", "-"))
	if _, ok := stringToProtoKeyUsage[normalized]; ok {
		if domainVal, ok := protoKeyUsageToKeyUsage[stringToProtoKeyUsage[normalized]]; ok {
			return domainVal, nil
		}
	}
	return KeyUsageUnspecified, ErrInvalidKeyUsage{Usage: usage}
}

// ParseKeyUsages converts a comma-separated key usage string to a slice of domain KeyUsage values.
func ParseKeyUsages(purpose string) ([]KeyUsage, error) {
	if purpose == "" {
		return nil, nil
	}
	parts := strings.Split(purpose, ",")
	usages := make([]KeyUsage, 0, len(parts))
	for _, p := range parts {
		usage, err := ParseKeyUsage(p)
		if err != nil {
			return nil, err
		}
		usages = append(usages, usage)
	}
	return usages, nil
}

// ParseHashAlgorithm converts a user-facing hash algorithm string to the domain HashAlgorithm.
func ParseHashAlgorithm(alg string) (HashAlgorithm, error) {
	normalized := strings.ToLower(strings.ReplaceAll(alg, "_", "-"))
	if protoVal, ok := stringToProtoHashAlgorithm[normalized]; ok {
		if domainVal, ok := protoHashAlgToHashAlg[protoVal]; ok {
			return domainVal, nil
		}
	}
	return HashAlgorithmUnspecified, ErrInvalidHashAlgorithm{Algorithm: alg}
}

// keyAlgorithmToProto converts a domain KeyAlgorithm to proto KMSKeyAlgorithm.
func keyAlgorithmToProto(alg KeyAlgorithm) platformv1.KMSKeyAlgorithm {
	for protoVal, domainVal := range protoKeyAlgorithmToKeyAlgorithm {
		if domainVal == alg {
			return protoVal
		}
	}
	return platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED
}

// keyUsagesToProto converts a slice of domain KeyUsage to proto KeyUsage values.
func keyUsagesToProto(usages []KeyUsage) []platformv1.KeyUsage {
	if len(usages) == 0 {
		return nil
	}
	result := make([]platformv1.KeyUsage, 0, len(usages))
	for _, u := range usages {
		for protoVal, domainVal := range protoKeyUsageToKeyUsage {
			if domainVal == u {
				result = append(result, protoVal)
				break
			}
		}
	}
	return result
}

// hashAlgorithmToProto converts a domain HashAlgorithm to proto HashAlgorithm.
func hashAlgorithmToProto(alg HashAlgorithm) platformv1.HashAlgorithm {
	for protoVal, domainVal := range protoHashAlgToHashAlg {
		if domainVal == alg {
			return protoVal
		}
	}
	return platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED
}

// keyInfoFromProto converts a proto key to a domain KeyInfo.
func keyInfoFromProto(alg platformv1.KMSKeyAlgorithm, status platformv1.KeyStatus, keyID string, version uint64, createdAt int64) *KeyInfo {
	algDomain, ok := protoKeyAlgorithmToKeyAlgorithm[alg]
	if !ok {
		algDomain = KeyAlgorithmUnspecified
	}
	statusDomain, ok := protoKeyStatusToKeyStatus[status]
	if !ok {
		statusDomain = KeyStatusUnspecified
	}
	return &KeyInfo{
		KeyID:     keyID,
		Version:   version,
		Algorithm: algDomain,
		Status:    statusDomain,
		CreatedAt: createdAt,
	}
}

// keyUsagesFromProto converts a slice of proto KeyUsage to domain KeyUsage values.
func keyUsagesFromProto(usages []platformv1.KeyUsage) []KeyUsage {
	if len(usages) == 0 {
		return nil
	}
	result := make([]KeyUsage, 0, len(usages))
	for _, u := range usages {
		if domainVal, ok := protoKeyUsageToKeyUsage[u]; ok {
			result = append(result, domainVal)
		}
	}
	return result
}

// hashAlgorithmFromProto converts a proto HashAlgorithm to domain HashAlgorithm.
func hashAlgorithmFromProto(alg platformv1.HashAlgorithm) HashAlgorithm {
	if domainVal, ok := protoHashAlgToHashAlg[alg]; ok {
		return domainVal
	}
	return HashAlgorithmUnspecified
}

// keyStatusFromProto converts a proto KeyStatus to domain KeyStatus.
func keyStatusFromProto(status platformv1.KeyStatus) KeyStatus {
	if domainVal, ok := protoKeyStatusToKeyStatus[status]; ok {
		return domainVal
	}
	return KeyStatusUnspecified
}

// generateKeyResultFromProto converts a proto GenerateKeyResponse to domain GenerateKeyResult.
func generateKeyResultFromProto(resp *platformv1.GenerateKeyResponse) *GenerateKeyResult {
	if resp == nil {
		return nil
	}
	result := &GenerateKeyResult{}
	if resp.Key != nil {
		result.Key = keyInfoFromProto(resp.Key.Algorithm, resp.Key.Status, resp.Key.KeyId, resp.Key.Version, resp.Key.CreatedAt)
	}
	if resp.Metadata != nil {
		result.Metadata = &KeyMetadata{
			Name:               resp.Metadata.Name,
			Description:        resp.Metadata.Description,
			Exportable:         resp.Metadata.Exportable,
			DeletionProtection: resp.Metadata.DeletionProtection,
		}
	}
	return result
}

// getKeyResultFromProto converts a proto GetKeyResponse to domain GetKeyResult.
func getKeyResultFromProto(resp *platformv1.GetKeyResponse) *GetKeyResult {
	if resp == nil {
		return nil
	}
	result := &GetKeyResult{}
	if resp.Key != nil {
		result.Key = keyInfoFromProto(resp.Key.Algorithm, resp.Key.Status, resp.Key.KeyId, resp.Key.Version, resp.Key.CreatedAt)
	}
	if resp.Metadata != nil {
		result.Metadata = &KeyMetadata{
			Name:               resp.Metadata.Name,
			Description:        resp.Metadata.Description,
			Exportable:         resp.Metadata.Exportable,
			DeletionProtection: resp.Metadata.DeletionProtection,
			Owner:              resp.Metadata.Owner,
			UpdatedAt:          resp.Metadata.UpdatedAt,
			LastUsedAt:         resp.Metadata.LastUsedAt,
			Usage:              keyUsagesFromProto(resp.Metadata.Usage),
		}
	}
	return result
}

// listKeysResultFromProto converts a proto ListKeysResponse to domain ListKeysResult.
func listKeysResultFromProto(resp *platformv1.ListKeysResponse) *ListKeysResult {
	if resp == nil {
		return nil
	}
	keys := make([]*KeyInfo, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, keyInfoFromProto(k.Algorithm, k.Status, k.KeyId, k.Version, k.CreatedAt))
	}
	return &ListKeysResult{
		Keys:       keys,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}
}

// deleteKeyResultFromProto converts a proto DeleteKeyResponse to domain DeleteKeyResult.
func deleteKeyResultFromProto(resp *platformv1.DeleteKeyResponse) *DeleteKeyResult {
	if resp == nil {
		return nil
	}
	return &DeleteKeyResult{
		KeyID:        resp.KeyId,
		KeyStatus:    keyStatusFromProto(resp.KeyStatus),
		DeletionDate: resp.DeletionDate,
	}
}

// rotateKeyResultFromProto converts a proto RotateKeyResponse to domain RotateKeyResult.
func rotateKeyResultFromProto(resp *platformv1.RotateKeyResponse) *RotateKeyResult {
	if resp == nil {
		return nil
	}
	return &RotateKeyResult{
		KeyID:      resp.KeyId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	}
}

// encryptResultFromProto converts a proto EncryptResponse to domain EncryptResult.
func encryptResultFromProto(resp *platformv1.EncryptResponse) *EncryptResult {
	if resp == nil {
		return nil
	}
	return &EncryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Timestamp:  resp.Timestamp,
	}
}

// decryptResultFromProto converts a proto DecryptResponse to domain DecryptResult.
func decryptResultFromProto(resp *platformv1.DecryptResponse) *DecryptResult {
	if resp == nil {
		return nil
	}
	return &DecryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  resp.Timestamp,
	}
}

// signResultFromProto converts a proto SignResponse to domain SignResult.
func signResultFromProto(resp *platformv1.SignResponse) *SignResult {
	if resp == nil {
		return nil
	}
	return &SignResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: hashAlgorithmFromProto(resp.HashAlgorithm),
		Timestamp:     resp.Timestamp,
	}
}

// verifyResultFromProto converts a proto VerifyResponse to domain VerifyResult.
func verifyResultFromProto(resp *platformv1.VerifyResponse) *VerifyResult {
	if resp == nil {
		return nil
	}
	return &VerifyResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	}
}

// hashResultFromProto converts a proto HashResponse to domain HashResult.
func hashResultFromProto(resp *platformv1.HashResponse) *HashResult {
	if resp == nil {
		return nil
	}
	return &HashResult{
		Hash:      resp.Hash,
		Algorithm: hashAlgorithmFromProto(resp.Algorithm),
		Timestamp: resp.Timestamp,
	}
}

// hmacResultFromProto converts a proto HMACResponse to domain HMACResult.
func hmacResultFromProto(resp *platformv1.HMACResponse) *HMACResult {
	if resp == nil {
		return nil
	}
	return &HMACResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		HMAC:          resp.Hmac,
		HashAlgorithm: hashAlgorithmFromProto(resp.HashAlgorithm),
		Timestamp:     resp.Timestamp,
	}
}

// verifyHMACResultFromProto converts a proto VerifyHMACResponse to domain VerifyHMACResult.
func verifyHMACResultFromProto(resp *platformv1.VerifyHMACResponse) *VerifyHMACResult {
	if resp == nil {
		return nil
	}
	return &VerifyHMACResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	}
}

// generateRandomResultFromProto converts a proto GenerateRandomResponse to domain GenerateRandomResult.
func generateRandomResultFromProto(resp *platformv1.GenerateRandomResponse) *GenerateRandomResult {
	if resp == nil {
		return nil
	}
	return &GenerateRandomResult{
		RandomBytes: resp.RandomBytes,
		Timestamp:   resp.Timestamp,
	}
}

// generateDataKeyResultFromProto converts a proto GenerateDataKeyResponse to domain GenerateDataKeyResult.
func generateDataKeyResultFromProto(resp *platformv1.GenerateDataKeyResponse) *GenerateDataKeyResult {
	if resp == nil {
		return nil
	}
	return &GenerateDataKeyResult{
		KeyID:        resp.KeyId,
		PlaintextKey: resp.PlaintextKey,
		EncryptedKey: resp.EncryptedKey,
		Timestamp:    resp.Timestamp,
	}
}

// generateWrappedDataKeyResultFromProto converts a proto GenerateWrappedDataKeyResponse to domain.
func generateWrappedDataKeyResultFromProto(resp *platformv1.GenerateWrappedDataKeyResponse) *GenerateWrappedDataKeyResult {
	if resp == nil {
		return nil
	}
	return &GenerateWrappedDataKeyResult{
		WrappingKeyID: resp.WrappingKeyId,
		WrappedKey:    resp.WrappedKey,
		Timestamp:     resp.Timestamp,
	}
}

// rewrapResultFromProto converts a proto RewrapResponse to domain RewrapResult.
func rewrapResultFromProto(resp *platformv1.RewrapResponse) *RewrapResult {
	if resp == nil {
		return nil
	}
	return &RewrapResult{
		KeyID:         resp.KeyId,
		SourceVersion: resp.SourceVersion,
		TargetVersion: resp.TargetVersion,
		Ciphertext:    resp.Ciphertext,
		Nonce:         resp.Nonce,
		Timestamp:     resp.Timestamp,
	}
}

// backendStatusResultFromProto converts a proto BackendStatusResponse to domain BackendStatusResult.
func backendStatusResultFromProto(resp *platformv1.BackendStatusResponse) *BackendStatusResult {
	if resp == nil {
		return nil
	}
	return &BackendStatusResult{
		BackendStatus: resp.BackendStatus,
		BackendType:   resp.BackendType,
		Device:        resp.Device,
		Region:        resp.Region,
		KeyID:         resp.KeyId,
		PcrBanks:      resp.PcrBanks,
		PcrRegisters:  resp.PcrRegisters,
		Capabilities:  resp.Capabilities,
		Timestamp:     resp.Timestamp,
	}
}

// batchEncryptResultFromProto converts a proto BatchEncryptResponse to domain BatchEncryptResult.
func batchEncryptResultFromProto(resp *platformv1.BatchEncryptResponse) *BatchEncryptResult {
	if resp == nil {
		return nil
	}
	results := make([]*BatchEncryptItemResult, 0, len(resp.Results))
	for _, r := range resp.Results {
		item := &BatchEncryptItemResult{
			ItemID:     r.ItemId,
			KeyVersion: r.KeyVersion,
		}
		if r.Status != nil && r.Status.Success {
			item.Success = true
			item.Ciphertext = r.Ciphertext
			item.Nonce = r.Nonce
		} else {
			item.Success = false
			if r.Status != nil {
				item.Message = r.Status.Message
			}
		}
		results = append(results, item)
	}
	return &BatchEncryptResult{
		KeyID:        resp.KeyId,
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Results:      results,
		Timestamp:    resp.Timestamp,
	}
}

// batchDecryptResultFromProto converts a proto BatchDecryptResponse to domain BatchDecryptResult.
func batchDecryptResultFromProto(resp *platformv1.BatchDecryptResponse) *BatchDecryptResult {
	if resp == nil {
		return nil
	}
	results := make([]*BatchDecryptItemResult, 0, len(resp.Results))
	for _, r := range resp.Results {
		item := &BatchDecryptItemResult{
			ItemID:     r.ItemId,
			KeyVersion: r.KeyVersion,
		}
		if r.Status != nil && r.Status.Success {
			item.Success = true
			item.Plaintext = r.Plaintext
		} else {
			item.Success = false
			if r.Status != nil {
				item.Message = r.Status.Message
			}
		}
		results = append(results, item)
	}
	return &BatchDecryptResult{
		KeyID:        resp.KeyId,
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Results:      results,
		Timestamp:    resp.Timestamp,
	}
}
