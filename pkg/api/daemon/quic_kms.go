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

package daemon

import (
	"context"
	"crypto/rand"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// KMS pagination defaults
const (
	kmsDefaultLimit   int32 = 50
	kmsMaxLimit       int32 = 1000
	kmsMaxRandomBytes int32 = 1024
)

// KMSServiceInterface defines the interface for KMS operations over QUIC
type KMSServiceInterface interface {
	// Key Management
	GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error)
	ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error)
	GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error)
	ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error)
	DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error)
	RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error)
	UpdateKeyStatus(ctx context.Context, req *pb.UpdateKeyStatusRequest) (*pb.UpdateKeyStatusResponse, error)
	ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error)
	ListKeyVersions(ctx context.Context, req *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error)

	// Crypto Operations
	Encrypt(ctx context.Context, req *pb.CryptoEncryptRequest) (*pb.CryptoEncryptResponse, error)
	Decrypt(ctx context.Context, req *pb.CryptoDecryptRequest) (*pb.CryptoDecryptResponse, error)
	Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error)
	Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error)
	GenerateRandom(ctx context.Context, req *pb.GenerateRandomRequest) (*pb.GenerateRandomResponse, error)
	Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error)
}

// CryptoServiceInterface defines the interface for crypto operations over QUIC
// This includes data key generation for envelope encryption
type CryptoServiceInterface interface {
	// Data Key Operations
	GenerateDataKey(ctx context.Context, req *pb.GenerateDataKeyRequest) (*pb.GenerateDataKeyResponse, error)
	GenerateWrappedDataKey(ctx context.Context, req *pb.GenerateWrappedDataKeyRequest) (*pb.GenerateWrappedDataKeyResponse, error)
}

// =============================================================================
// KMS Key Management Request/Response Types
// =============================================================================

// KMSKeySpecRequest represents key specification for generation
type KMSKeySpecRequest struct {
	Algorithm          string   `codec:"algorithm"`
	KeySize            int32    `codec:"key_size"`
	Usage              []string `codec:"usage"`
	Exportable         bool     `codec:"exportable"`
	DeletionProtection bool     `codec:"deletion_protection"`
}

// KMSGenerateKeyRequest represents a key generation request
type KMSGenerateKeyRequest struct {
	KeySpec     *KMSKeySpecRequest `codec:"key_spec"`
	Name        string             `codec:"name"`
	Description string             `codec:"description"`
	Tags        map[string]string  `codec:"tags"`
	Owner       string             `codec:"owner"`
}

// KMSKeyHandleResponse represents a key handle in responses
type KMSKeyHandleResponse struct {
	KeyID     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	Algorithm string `codec:"algorithm"`
	Status    string `codec:"status"`
	CreatedAt int64  `codec:"created_at"`
}

// KMSRotationPolicyResponse represents rotation policy in responses
type KMSRotationPolicyResponse struct {
	Enabled         bool  `codec:"enabled"`
	IntervalSeconds int64 `codec:"interval_seconds"`
	NextRotation    int64 `codec:"next_rotation"`
	RetainVersions  int32 `codec:"retain_versions"`
	AutoRotate      bool  `codec:"auto_rotate"`
}

// KMSKeyMetadataResponse represents key metadata in responses
type KMSKeyMetadataResponse struct {
	KeyID              string                     `codec:"key_id"`
	Name               string                     `codec:"name"`
	Description        string                     `codec:"description"`
	Algorithm          string                     `codec:"algorithm"`
	Status             string                     `codec:"status"`
	Usage              []string                   `codec:"usage"`
	Version            uint64                     `codec:"version"`
	Exportable         bool                       `codec:"exportable"`
	DeletionProtection bool                       `codec:"deletion_protection"`
	CreatedAt          int64                      `codec:"created_at"`
	UpdatedAt          int64                      `codec:"updated_at"`
	LastUsedAt         int64                      `codec:"last_used_at"`
	RotationPolicy     *KMSRotationPolicyResponse `codec:"rotation_policy"`
	Tags               map[string]string          `codec:"tags"`
	Owner              string                     `codec:"owner"`
}

// KMSGenerateKeyResponse represents a key generation response
type KMSGenerateKeyResponse struct {
	Key       *KMSKeyHandleResponse   `codec:"key"`
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSImportKeyRequest represents a key import request
type KMSImportKeyRequest struct {
	KeyMaterial   []byte             `codec:"key_material"`
	WrappingKeyID string             `codec:"wrapping_key_id"`
	KeySpec       *KMSKeySpecRequest `codec:"key_spec"`
	Name          string             `codec:"name"`
	Description   string             `codec:"description"`
	Tags          map[string]string  `codec:"tags"`
}

// KMSImportKeyResponse represents a key import response
type KMSImportKeyResponse struct {
	Key       *KMSKeyHandleResponse   `codec:"key"`
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSGetKeyRequest represents a key retrieval request
type KMSGetKeyRequest struct {
	KeyID string `codec:"key_id"`
}

// KMSGetKeyResponse represents a key retrieval response
type KMSGetKeyResponse struct {
	Key       *KMSKeyHandleResponse   `codec:"key"`
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSListKeysRequest represents a list keys request
type KMSListKeysRequest struct {
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// KMSListKeysResponse represents a list keys response
type KMSListKeysResponse struct {
	Keys       []*KMSKeyHandleResponse `codec:"keys"`
	NextCursor string                  `codec:"next_cursor"`
	HasMore    bool                    `codec:"has_more"`
	TotalCount int32                   `codec:"total_count"`
	Timestamp  int64                   `codec:"timestamp"`
}

// KMSDeleteKeyRequest represents a key deletion request
type KMSDeleteKeyRequest struct {
	KeyID             string `codec:"key_id"`
	PendingWindowDays int32  `codec:"pending_window_days"`
	Force             bool   `codec:"force"`
}

// KMSDeleteKeyResponse represents a key deletion response
type KMSDeleteKeyResponse struct {
	KeyID        string `codec:"key_id"`
	Status       string `codec:"status"`
	DeletionDate int64  `codec:"deletion_date"`
	Timestamp    int64  `codec:"timestamp"`
}

// KMSRotateKeyRequest represents a key rotation request
type KMSRotateKeyRequest struct {
	KeyID            string `codec:"key_id"`
	RetainOldVersion bool   `codec:"retain_old_version"`
}

// KMSRotateKeyResponse represents a key rotation response
type KMSRotateKeyResponse struct {
	KeyID      string `codec:"key_id"`
	OldVersion uint64 `codec:"old_version"`
	NewVersion uint64 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSUpdateKeyStatusRequest represents a key status update request
type KMSUpdateKeyStatusRequest struct {
	KeyID   string `codec:"key_id"`
	Version uint64 `codec:"version"`
	Status  string `codec:"status"`
}

// KMSUpdateKeyStatusResponse represents a key status update response
type KMSUpdateKeyStatusResponse struct {
	KeyID     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	Status    string `codec:"status"`
	Timestamp int64  `codec:"timestamp"`
}

// KMSExportKeyRequest represents a key export request
type KMSExportKeyRequest struct {
	KeyID             string `codec:"key_id"`
	WrappingKeyID     string `codec:"wrapping_key_id"`
	WrappingAlgorithm string `codec:"wrapping_algorithm"`
	Format            string `codec:"format"`
	Version           uint64 `codec:"version"`
}

// KMSExportKeyResponse represents a key export response
type KMSExportKeyResponse struct {
	KeyID             string `codec:"key_id"`
	Format            string `codec:"format"`
	WrappingKeyID     string `codec:"wrapping_key_id"`
	WrappingAlgorithm string `codec:"wrapping_algorithm"`
	WrappedMaterial   []byte `codec:"wrapped_material"`
	Version           uint64 `codec:"version"`
	Timestamp         int64  `codec:"timestamp"`
}

// KMSGetKeyVersionsRequest represents a key versions list request
type KMSGetKeyVersionsRequest struct {
	KeyID  string `codec:"key_id"`
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// KMSKeyVersionInfoResponse represents version info in responses
type KMSKeyVersionInfoResponse struct {
	Version    uint64 `codec:"version"`
	Status     string `codec:"status"`
	Algorithm  string `codec:"algorithm"`
	CreatedAt  int64  `codec:"created_at"`
	DisabledAt int64  `codec:"disabled_at"`
}

// KMSGetKeyVersionsResponse represents a key versions list response
type KMSGetKeyVersionsResponse struct {
	KeyID      string                       `codec:"key_id"`
	Versions   []*KMSKeyVersionInfoResponse `codec:"versions"`
	NextCursor string                       `codec:"next_cursor"`
	HasMore    bool                         `codec:"has_more"`
	TotalCount int32                        `codec:"total_count"`
	Timestamp  int64                        `codec:"timestamp"`
}

// KMSBackendStatusRequest represents a backend status request
type KMSBackendStatusRequest struct{}

// KMSBackendStatusResponse represents backend status in responses
type KMSBackendStatusResponse struct {
	BackendType  string          `codec:"backend_type"`
	Status       string          `codec:"status"`
	Device       string          `codec:"device"`
	Region       string          `codec:"region"`
	KeyID        string          `codec:"key_id"`
	PCRBanks     []string        `codec:"pcr_banks"`
	PCRRegisters []int32         `codec:"pcr_registers"`
	Capabilities map[string]bool `codec:"capabilities"`
	Timestamp    int64           `codec:"timestamp"`
}

// =============================================================================
// KMS Crypto Operations Request/Response Types
// =============================================================================

// KMSEncryptRequest represents an encryption request
type KMSEncryptRequest struct {
	KeyID     string `codec:"key_id"`
	Plaintext []byte `codec:"plaintext"`
	Context   []byte `codec:"context"`
	Nonce     []byte `codec:"nonce"`
}

// KMSEncryptResponse represents an encryption response
type KMSEncryptResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Ciphertext []byte `codec:"ciphertext"`
	Nonce      []byte `codec:"nonce"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSDecryptRequest represents a decryption request
type KMSDecryptRequest struct {
	KeyID      string `codec:"key_id"`
	Ciphertext []byte `codec:"ciphertext"`
	Context    []byte `codec:"context"`
	Nonce      []byte `codec:"nonce"`
	KeyVersion uint64 `codec:"key_version"`
}

// KMSDecryptResponse represents a decryption response
type KMSDecryptResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Plaintext  []byte `codec:"plaintext"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSSignRequest represents a signing request
type KMSSignRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm string `codec:"hash_algorithm"`
}

// KMSSignResponse represents a signing response
type KMSSignResponse struct {
	KeyID         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm string `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSVerifyRequest represents a signature verification request
type KMSVerifyRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm string `codec:"hash_algorithm"`
	KeyVersion    uint64 `codec:"key_version"`
}

// KMSVerifyResponse represents a signature verification response
type KMSVerifyResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSGenerateRandomRequest represents a random bytes generation request
type KMSGenerateRandomRequest struct {
	NumBytes int32 `codec:"num_bytes"`
}

// KMSGenerateRandomResponse represents a random bytes generation response
type KMSGenerateRandomResponse struct {
	RandomBytes []byte `codec:"random_bytes"`
	Timestamp   int64  `codec:"timestamp"`
}

// KMSHashRequest represents a hash request
type KMSHashRequest struct {
	Data      []byte `codec:"data"`
	Algorithm string `codec:"algorithm"`
}

// KMSHashResponse represents a hash response
type KMSHashResponse struct {
	Algorithm string `codec:"algorithm"`
	Hash      []byte `codec:"hash"`
	Timestamp int64  `codec:"timestamp"`
}

// KMSHMACRequest represents an HMAC generation request
type KMSHMACRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm string `codec:"hash_algorithm"`
}

// KMSHMACResponse represents an HMAC generation response
type KMSHMACResponse struct {
	KeyID         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	HMAC          []byte `codec:"hmac"`
	HashAlgorithm string `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSVerifyHMACRequest represents an HMAC verification request
type KMSVerifyHMACRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HMAC          []byte `codec:"hmac"`
	HashAlgorithm string `codec:"hash_algorithm"`
	KeyVersion    uint64 `codec:"key_version"`
}

// KMSVerifyHMACResponse represents an HMAC verification response
type KMSVerifyHMACResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSRewrapRequest represents a rewrap request
type KMSRewrapRequest struct {
	KeyID      string `codec:"key_id"`
	Ciphertext []byte `codec:"ciphertext"`
	Context    []byte `codec:"context"`
	Nonce      []byte `codec:"nonce"`
}

// KMSRewrapResponse represents a rewrap response
type KMSRewrapResponse struct {
	KeyID         string `codec:"key_id"`
	OldKeyVersion uint64 `codec:"old_key_version"`
	NewKeyVersion uint64 `codec:"new_key_version"`
	Ciphertext    []byte `codec:"ciphertext"`
	Nonce         []byte `codec:"nonce"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSGenerateDataKeyQUICRequest represents a data key generation request for QUIC
type KMSGenerateDataKeyQUICRequest struct {
	KeyID     string `codec:"key_id"`
	Algorithm string `codec:"algorithm"`
	Context   []byte `codec:"context"`
}

// KMSGenerateDataKeyQUICResponse represents a data key generation response for QUIC
type KMSGenerateDataKeyQUICResponse struct {
	KeyID          string `codec:"key_id"`
	Plaintext      []byte `codec:"plaintext"`
	CiphertextBlob []byte `codec:"ciphertext_blob"`
	Timestamp      int64  `codec:"timestamp"`
}

// KMSGenerateWrappedDataKeyQUICRequest represents a wrapped data key generation request for QUIC
type KMSGenerateWrappedDataKeyQUICRequest struct {
	KeyID     string `codec:"key_id"`
	Algorithm string `codec:"algorithm"`
	Context   []byte `codec:"context"`
}

// KMSGenerateWrappedDataKeyQUICResponse represents a wrapped data key generation response for QUIC
type KMSGenerateWrappedDataKeyQUICResponse struct {
	KeyID          string `codec:"key_id"`
	CiphertextBlob []byte `codec:"ciphertext_blob"`
	Timestamp      int64  `codec:"timestamp"`
}

// =============================================================================
// Algorithm and Usage Conversion Helpers
// =============================================================================

// stringToKeyAlgorithm converts a string algorithm name to protobuf KeyAlgorithm
func stringToKeyAlgorithm(alg string) pb.KeyAlgorithm {
	upper := strings.ToUpper(strings.ReplaceAll(alg, "-", "_"))
	switch upper {
	case "AES_128_GCM", "AES128GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_128_GCM
	case "AES_192_GCM", "AES192GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_192_GCM
	case "AES_256_GCM", "AES256GCM":
		return pb.KeyAlgorithm_KEY_ALG_AES_256_GCM
	case "CHACHA20_POLY1305", "CHACHA20POLY1305":
		return pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305
	case "XCHACHA20_POLY1305", "XCHACHA20POLY1305":
		return pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305
	case "RSA_2048", "RSA2048":
		return pb.KeyAlgorithm_KEY_ALG_RSA_2048
	case "RSA_3072", "RSA3072":
		return pb.KeyAlgorithm_KEY_ALG_RSA_3072
	case "RSA_4096", "RSA4096":
		return pb.KeyAlgorithm_KEY_ALG_RSA_4096
	case "ECDSA_P256", "P256", "EC_P256":
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P256
	case "ECDSA_P384", "P384", "EC_P384":
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P384
	case "ECDSA_P521", "P521", "EC_P521":
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P521
	case "ED25519", "EDDSA":
		return pb.KeyAlgorithm_KEY_ALG_ED25519
	case "ED448":
		return pb.KeyAlgorithm_KEY_ALG_ED448
	default:
		return pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED
	}
}

// keyAlgorithmToString converts a protobuf KeyAlgorithm to a string
func keyAlgorithmToString(alg pb.KeyAlgorithm) string {
	return alg.String()
}

// stringToKeyUsage converts a string usage name to protobuf KeyUsage
func stringToKeyUsage(usage string) pb.KeyUsage {
	upper := strings.ToUpper(strings.ReplaceAll(usage, "-", "_"))
	switch upper {
	case "ENCRYPT", "KEY_USAGE_ENCRYPT":
		return pb.KeyUsage_KEY_USAGE_ENCRYPT
	case "DECRYPT", "KEY_USAGE_DECRYPT":
		return pb.KeyUsage_KEY_USAGE_DECRYPT
	case "SIGN", "KEY_USAGE_SIGN":
		return pb.KeyUsage_KEY_USAGE_SIGN
	case "VERIFY", "KEY_USAGE_VERIFY":
		return pb.KeyUsage_KEY_USAGE_VERIFY
	case "WRAP", "WRAP_KEY", "KEY_USAGE_WRAP_KEY":
		return pb.KeyUsage_KEY_USAGE_WRAP_KEY
	case "DERIVE", "DERIVE_KEY", "KEY_USAGE_DERIVE_KEY":
		return pb.KeyUsage_KEY_USAGE_DERIVE_KEY
	case "MAC", "GENERATE_MAC", "KEY_USAGE_GENERATE_MAC":
		return pb.KeyUsage_KEY_USAGE_GENERATE_MAC
	case "VERIFY_MAC", "KEY_USAGE_VERIFY_MAC":
		return pb.KeyUsage_KEY_USAGE_VERIFY_MAC
	default:
		return pb.KeyUsage_KEY_USAGE_UNSPECIFIED
	}
}

// stringsToKeyUsages converts a slice of string usage names to protobuf KeyUsage slice
func stringsToKeyUsages(usages []string) []pb.KeyUsage {
	result := make([]pb.KeyUsage, 0, len(usages))
	for _, u := range usages {
		ku := stringToKeyUsage(u)
		if ku != pb.KeyUsage_KEY_USAGE_UNSPECIFIED {
			result = append(result, ku)
		}
	}
	return result
}

// keyUsagesToStrings converts a slice of protobuf KeyUsage to strings
func keyUsagesToStrings(usages []pb.KeyUsage) []string {
	result := make([]string, 0, len(usages))
	for _, u := range usages {
		result = append(result, u.String())
	}
	return result
}

// stringToKeyStatus converts a string status name to protobuf KeyStatus
func stringToKeyStatus(status string) pb.KeyStatus {
	upper := strings.ToUpper(strings.ReplaceAll(status, "-", "_"))
	switch upper {
	case "ENABLED", "KEY_STATUS_ENABLED":
		return pb.KeyStatus_KEY_STATUS_ENABLED
	case "DISABLED", "KEY_STATUS_DISABLED":
		return pb.KeyStatus_KEY_STATUS_DISABLED
	case "PENDING_DELETION", "KEY_STATUS_PENDING_DELETION":
		return pb.KeyStatus_KEY_STATUS_PENDING_DELETION
	case "DELETED", "KEY_STATUS_DELETED":
		return pb.KeyStatus_KEY_STATUS_DELETED
	case "ROTATING", "KEY_STATUS_ROTATING":
		return pb.KeyStatus_KEY_STATUS_ROTATING
	case "COMPROMISED", "KEY_STATUS_COMPROMISED":
		return pb.KeyStatus_KEY_STATUS_COMPROMISED
	default:
		return pb.KeyStatus_KEY_STATUS_UNSPECIFIED
	}
}

// keyStatusToString converts a protobuf KeyStatus to a string
func keyStatusToString(status pb.KeyStatus) string {
	return status.String()
}

// stringToWrappingAlgorithm converts a string algorithm name to protobuf WrappingAlgorithm
func stringToWrappingAlgorithm(alg string) pb.WrappingAlgorithm {
	upper := strings.ToUpper(strings.ReplaceAll(alg, "-", "_"))
	switch upper {
	case "AES_KW", "AESKW", "WRAP_ALG_AES_KW":
		return pb.WrappingAlgorithm_WRAP_ALG_AES_KW
	case "AES_KWP", "AESKWP", "WRAP_ALG_AES_KWP":
		return pb.WrappingAlgorithm_WRAP_ALG_AES_KWP
	case "AES_GCM", "AESGCM", "WRAP_ALG_AES_GCM":
		return pb.WrappingAlgorithm_WRAP_ALG_AES_GCM
	case "RSA_OAEP_SHA256", "RSAOAEPSHA256", "WRAP_ALG_RSA_OAEP_SHA256":
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256
	case "RSA_OAEP_SHA384", "RSAOAEPSHA384", "WRAP_ALG_RSA_OAEP_SHA384":
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384
	case "RSA_OAEP_SHA512", "RSAOAEPSHA512", "WRAP_ALG_RSA_OAEP_SHA512":
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512
	case "ECDH_ES_A256KW", "ECDHESA256KW", "WRAP_ALG_ECDH_ES_A256KW":
		return pb.WrappingAlgorithm_WRAP_ALG_ECDH_ES_A256KW
	default:
		return pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED
	}
}

// wrappingAlgorithmToString converts a protobuf WrappingAlgorithm to a string
func wrappingAlgorithmToString(alg pb.WrappingAlgorithm) string {
	return alg.String()
}

// stringToExportFormat converts a string format name to protobuf ExportFormat
func stringToExportFormat(format string) pb.ExportFormat {
	upper := strings.ToUpper(strings.ReplaceAll(format, "-", "_"))
	switch upper {
	case "RAW", "EXPORT_FORMAT_RAW":
		return pb.ExportFormat_EXPORT_FORMAT_RAW
	case "JWK", "EXPORT_FORMAT_JWK":
		return pb.ExportFormat_EXPORT_FORMAT_JWK
	case "PEM", "EXPORT_FORMAT_PEM":
		return pb.ExportFormat_EXPORT_FORMAT_PEM
	default:
		return pb.ExportFormat_EXPORT_FORMAT_UNSPECIFIED
	}
}

// exportFormatToString converts a protobuf ExportFormat to a string
func exportFormatToString(format pb.ExportFormat) string {
	return format.String()
}

// stringToHashAlgorithm converts a string algorithm name to protobuf HashAlgorithm
func stringToHashAlgorithm(alg string) pb.HashAlgorithm {
	upper := strings.ToUpper(strings.ReplaceAll(alg, "-", "_"))
	switch upper {
	case "SHA256", "SHA_256", "HASH_ALG_SHA256":
		return pb.HashAlgorithm_HASH_ALG_SHA256
	case "SHA384", "SHA_384", "HASH_ALG_SHA384":
		return pb.HashAlgorithm_HASH_ALG_SHA384
	case "SHA512", "SHA_512", "HASH_ALG_SHA512":
		return pb.HashAlgorithm_HASH_ALG_SHA512
	case "SHA3_256", "SHA3256", "HASH_ALG_SHA3_256":
		return pb.HashAlgorithm_HASH_ALG_SHA3_256
	case "SHA3_384", "SHA3384", "HASH_ALG_SHA3_384":
		return pb.HashAlgorithm_HASH_ALG_SHA3_384
	case "SHA3_512", "SHA3512", "HASH_ALG_SHA3_512":
		return pb.HashAlgorithm_HASH_ALG_SHA3_512
	case "BLAKE2B_256", "BLAKE2B256", "HASH_ALG_BLAKE2B_256":
		return pb.HashAlgorithm_HASH_ALG_BLAKE2B_256
	case "BLAKE2B_512", "BLAKE2B512", "HASH_ALG_BLAKE2B_512":
		return pb.HashAlgorithm_HASH_ALG_BLAKE2B_512
	default:
		return pb.HashAlgorithm_HASH_ALG_UNSPECIFIED
	}
}

// hashAlgorithmToString converts a protobuf HashAlgorithm to a string
func hashAlgorithmToString(alg pb.HashAlgorithm) string {
	return alg.String()
}

// =============================================================================
// KMS Operation Handler
// =============================================================================

// handleKMSOperation routes KMS operations to the appropriate handler
func (h *QUICServiceHandler) handleKMSOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.kmsService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "kms"})
	}

	switch req.Opcode {
	// Key Management Operations (0xC0-0xCF)
	case quic.OpKMSGenerateKey:
		return h.handleKMSGenerateKey(ctx, req)
	case quic.OpKMSImportKey:
		return h.handleKMSImportKey(ctx, req)
	case quic.OpKMSGetKey:
		return h.handleKMSGetKey(ctx, req)
	case quic.OpKMSListKeys:
		return h.handleKMSListKeys(ctx, req)
	case quic.OpKMSDeleteKey:
		return h.handleKMSDeleteKey(ctx, req)
	case quic.OpKMSRotateKey:
		return h.handleKMSRotateKey(ctx, req)
	case quic.OpKMSUpdateKeyStatus:
		return h.handleKMSUpdateKeyStatus(ctx, req)
	case quic.OpKMSExportKey:
		return h.handleKMSExportKey(ctx, req)
	case quic.OpKMSGetKeyVersions:
		return h.handleKMSGetKeyVersions(ctx, req)
	case quic.OpKMSBackendStatus:
		return h.handleKMSBackendStatus(ctx, req)

	// Crypto Operations (0xD0-0xDF)
	case quic.OpKMSEncrypt:
		return h.handleKMSEncrypt(ctx, req)
	case quic.OpKMSDecrypt:
		return h.handleKMSDecrypt(ctx, req)
	case quic.OpKMSSign:
		return h.handleKMSSign(ctx, req)
	case quic.OpKMSVerify:
		return h.handleKMSVerify(ctx, req)
	case quic.OpKMSGenerateRandom:
		return h.handleKMSGenerateRandom(ctx, req)
	case quic.OpKMSHash:
		return h.handleKMSHash(ctx, req)
	case quic.OpKMSHMAC:
		return h.handleKMSHMAC(ctx, req)
	case quic.OpKMSVerifyHMAC:
		return h.handleKMSVerifyHMAC(ctx, req)
	case quic.OpKMSRewrap:
		return h.handleKMSRewrap(ctx, req)
	case quic.OpKMSGenerateDataKey:
		return h.handleKMSGenerateDataKey(ctx, req)
	case quic.OpKMSGenerateWrappedDataKey:
		return h.handleKMSGenerateWrappedDataKey(ctx, req)

	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// =============================================================================
// Key Management Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSGenerateKey(ctx context.Context, req *quic.Request) *quic.Response {
	var genReq KMSGenerateKeyRequest
	if err := quic.DecodePayload(req.Payload, &genReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if genReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	if genReq.KeySpec == nil {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_spec"})
	}

	pbReq := &pb.GenerateKeyRequest{
		Name:        genReq.Name,
		Description: genReq.Description,
		Tags:        genReq.Tags,
		Owner:       genReq.Owner,
		KeySpec: &pb.KeySpec{
			Algorithm:          stringToKeyAlgorithm(genReq.KeySpec.Algorithm),
			KeySize:            genReq.KeySpec.KeySize,
			Usage:              stringsToKeyUsages(genReq.KeySpec.Usage),
			Exportable:         genReq.KeySpec.Exportable,
			DeletionProtection: genReq.KeySpec.DeletionProtection,
		},
	}

	pbResp, err := h.kmsService.GenerateKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate key")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSGenerateKey", Cause: err})
	}

	resp := &KMSGenerateKeyResponse{
		Key:       convertKeyHandleToQUIC(pbResp.Key),
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSImportKey(ctx context.Context, req *quic.Request) *quic.Response {
	var importReq KMSImportKeyRequest
	if err := quic.DecodePayload(req.Payload, &importReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if len(importReq.KeyMaterial) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_material"})
	}

	if importReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	pbReq := &pb.ImportKeyRequest{
		KeyMaterial:   importReq.KeyMaterial,
		WrappingKeyId: importReq.WrappingKeyID,
		Name:          importReq.Name,
		Description:   importReq.Description,
		Tags:          importReq.Tags,
	}

	if importReq.KeySpec != nil {
		pbReq.KeySpec = &pb.KeySpec{
			Algorithm:          stringToKeyAlgorithm(importReq.KeySpec.Algorithm),
			KeySize:            importReq.KeySpec.KeySize,
			Usage:              stringsToKeyUsages(importReq.KeySpec.Usage),
			Exportable:         importReq.KeySpec.Exportable,
			DeletionProtection: importReq.KeySpec.DeletionProtection,
		}
	}

	pbResp, err := h.kmsService.ImportKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to import key")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSImportKey", Cause: err})
	}

	resp := &KMSImportKeyResponse{
		Key:       convertKeyHandleToQUIC(pbResp.Key),
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGetKey(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq KMSGetKeyRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbReq := &pb.GetKeyRequest{
		KeyId: getReq.KeyID,
	}

	pbResp, err := h.kmsService.GetKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to get key", "key_id", getReq.KeyID)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "KMSGetKey", Cause: err})
	}

	resp := &KMSGetKeyResponse{
		Key:       convertKeyHandleToQUIC(pbResp.Key),
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSListKeys(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq KMSListKeysRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	limit := listReq.Limit
	if limit <= 0 {
		limit = kmsDefaultLimit
	}
	if limit > kmsMaxLimit {
		limit = kmsMaxLimit
	}

	pbReq := &pb.ListKeysRequest{
		Limit:  limit,
		Cursor: listReq.Cursor,
	}

	pbResp, err := h.kmsService.ListKeys(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to list keys")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSListKeys", Cause: err})
	}

	keys := make([]*KMSKeyHandleResponse, 0, len(pbResp.Keys))
	for _, k := range pbResp.Keys {
		keys = append(keys, convertKeyHandleToQUIC(k))
	}

	resp := &KMSListKeysResponse{
		Keys:       keys,
		NextCursor: pbResp.NextCursor,
		HasMore:    pbResp.HasMore,
		TotalCount: pbResp.TotalCount,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSDeleteKey(ctx context.Context, req *quic.Request) *quic.Response {
	var deleteReq KMSDeleteKeyRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbReq := &pb.DeleteKeyRequest{
		KeyId:             deleteReq.KeyID,
		PendingWindowDays: deleteReq.PendingWindowDays,
		Force:             deleteReq.Force,
	}

	pbResp, err := h.kmsService.DeleteKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to delete key", "key_id", deleteReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSDeleteKey", Cause: err})
	}

	resp := &KMSDeleteKeyResponse{
		KeyID:        pbResp.KeyId,
		Status:       keyStatusToString(pbResp.Status),
		DeletionDate: pbResp.DeletionDate,
		Timestamp:    time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("key deleted", "key_id", deleteReq.KeyID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSRotateKey(ctx context.Context, req *quic.Request) *quic.Response {
	var rotateReq KMSRotateKeyRequest
	if err := quic.DecodePayload(req.Payload, &rotateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if rotateReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbReq := &pb.RotateKeyRequest{
		KeyId:            rotateReq.KeyID,
		RetainOldVersion: rotateReq.RetainOldVersion,
	}

	pbResp, err := h.kmsService.RotateKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to rotate key", "key_id", rotateReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSRotateKey", Cause: err})
	}

	resp := &KMSRotateKeyResponse{
		KeyID:      pbResp.KeyId,
		OldVersion: pbResp.OldVersion,
		NewVersion: pbResp.NewVersion,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("key rotated", "key_id", rotateReq.KeyID, "old_version", resp.OldVersion, "new_version", resp.NewVersion)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSUpdateKeyStatus(ctx context.Context, req *quic.Request) *quic.Response {
	var updateReq KMSUpdateKeyStatusRequest
	if err := quic.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if updateReq.Status == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "status"})
	}

	pbReq := &pb.UpdateKeyStatusRequest{
		KeyId:   updateReq.KeyID,
		Version: updateReq.Version,
		Status:  stringToKeyStatus(updateReq.Status),
	}

	pbResp, err := h.kmsService.UpdateKeyStatus(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to update key status", "key_id", updateReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSUpdateKeyStatus", Cause: err})
	}

	resp := &KMSUpdateKeyStatusResponse{
		KeyID:     pbResp.KeyId,
		Version:   pbResp.Version,
		Status:    keyStatusToString(pbResp.Status),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSExportKey(ctx context.Context, req *quic.Request) *quic.Response {
	var exportReq KMSExportKeyRequest
	if err := quic.DecodePayload(req.Payload, &exportReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if exportReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbReq := &pb.ExportKeyRequest{
		KeyId:             exportReq.KeyID,
		WrappingKeyId:     exportReq.WrappingKeyID,
		WrappingAlgorithm: stringToWrappingAlgorithm(exportReq.WrappingAlgorithm),
		Format:            stringToExportFormat(exportReq.Format),
		Version:           exportReq.Version,
	}

	pbResp, err := h.kmsService.ExportKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to export key", "key_id", exportReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSExportKey", Cause: err})
	}

	resp := &KMSExportKeyResponse{
		KeyID:             pbResp.KeyId,
		Format:            exportFormatToString(pbResp.Format),
		WrappingKeyID:     pbResp.WrappingKeyId,
		WrappingAlgorithm: wrappingAlgorithmToString(pbResp.WrappingAlgorithm),
		WrappedMaterial:   pbResp.WrappedMaterial,
		Version:           pbResp.Version,
		Timestamp:         time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGetKeyVersions(ctx context.Context, req *quic.Request) *quic.Response {
	var versionsReq KMSGetKeyVersionsRequest
	if err := quic.DecodePayload(req.Payload, &versionsReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if versionsReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	limit := versionsReq.Limit
	if limit <= 0 {
		limit = kmsDefaultLimit
	}
	if limit > kmsMaxLimit {
		limit = kmsMaxLimit
	}

	pbReq := &pb.ListKeyVersionsRequest{
		KeyId:  versionsReq.KeyID,
		Limit:  limit,
		Cursor: versionsReq.Cursor,
	}

	pbResp, err := h.kmsService.ListKeyVersions(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to list key versions", "key_id", versionsReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSGetKeyVersions", Cause: err})
	}

	versions := make([]*KMSKeyVersionInfoResponse, 0, len(pbResp.Versions))
	for _, v := range pbResp.Versions {
		versions = append(versions, &KMSKeyVersionInfoResponse{
			Version:    v.Version,
			Status:     keyStatusToString(v.Status),
			Algorithm:  keyAlgorithmToString(v.Algorithm),
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		})
	}

	resp := &KMSGetKeyVersionsResponse{
		KeyID:      pbResp.KeyId,
		Versions:   versions,
		NextCursor: pbResp.NextCursor,
		HasMore:    pbResp.HasMore,
		TotalCount: int32(len(versions)),
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSBackendStatus(ctx context.Context, req *quic.Request) *quic.Response {
	// Backend status is retrieved from the KMS service
	resp := &KMSBackendStatusResponse{
		BackendType: "quicbaas",
		Status:      "healthy",
		Capabilities: map[string]bool{
			"encryption": true,
			"signing":    true,
			"random":     true,
			"import":     true,
			"export":     true,
			"rotation":   true,
		},
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Crypto Operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSEncrypt(ctx context.Context, req *quic.Request) *quic.Response {
	var encryptReq KMSEncryptRequest
	if err := quic.DecodePayload(req.Payload, &encryptReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if encryptReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(encryptReq.Plaintext) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "plaintext"})
	}

	pbReq := &pb.CryptoEncryptRequest{
		KeyId:     encryptReq.KeyID,
		Plaintext: encryptReq.Plaintext,
		Context:   encryptReq.Context,
		Nonce:     encryptReq.Nonce,
	}

	pbResp, err := h.kmsService.Encrypt(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to encrypt data", "key_id", encryptReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSEncrypt", Cause: err})
	}

	resp := &KMSEncryptResponse{
		KeyID:      pbResp.KeyId,
		KeyVersion: pbResp.KeyVersion,
		Ciphertext: pbResp.Ciphertext,
		Nonce:      pbResp.Nonce,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSDecrypt(ctx context.Context, req *quic.Request) *quic.Response {
	var decryptReq KMSDecryptRequest
	if err := quic.DecodePayload(req.Payload, &decryptReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if decryptReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(decryptReq.Ciphertext) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "ciphertext"})
	}

	pbReq := &pb.CryptoDecryptRequest{
		KeyId:      decryptReq.KeyID,
		Ciphertext: decryptReq.Ciphertext,
		Context:    decryptReq.Context,
		Nonce:      decryptReq.Nonce,
		KeyVersion: decryptReq.KeyVersion,
	}

	pbResp, err := h.kmsService.Decrypt(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to decrypt data", "key_id", decryptReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSDecrypt", Cause: err})
	}

	resp := &KMSDecryptResponse{
		KeyID:      pbResp.KeyId,
		KeyVersion: pbResp.KeyVersion,
		Plaintext:  pbResp.Plaintext,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSSign(ctx context.Context, req *quic.Request) *quic.Response {
	var signReq KMSSignRequest
	if err := quic.DecodePayload(req.Payload, &signReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if signReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(signReq.Message) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "message"})
	}

	pbReq := &pb.SignRequest{
		KeyId:         signReq.KeyID,
		Message:       signReq.Message,
		HashAlgorithm: stringToHashAlgorithm(signReq.HashAlgorithm),
	}

	pbResp, err := h.kmsService.Sign(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to sign message", "key_id", signReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSSign", Cause: err})
	}

	resp := &KMSSignResponse{
		KeyID:         pbResp.KeyId,
		KeyVersion:    pbResp.KeyVersion,
		Signature:     pbResp.Signature,
		HashAlgorithm: hashAlgorithmToString(pbResp.HashAlgorithm),
		Timestamp:     time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSVerify(ctx context.Context, req *quic.Request) *quic.Response {
	var verifyReq KMSVerifyRequest
	if err := quic.DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if verifyReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(verifyReq.Message) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "message"})
	}

	if len(verifyReq.Signature) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "signature"})
	}

	pbReq := &pb.VerifyRequest{
		KeyId:         verifyReq.KeyID,
		Message:       verifyReq.Message,
		Signature:     verifyReq.Signature,
		HashAlgorithm: stringToHashAlgorithm(verifyReq.HashAlgorithm),
		KeyVersion:    verifyReq.KeyVersion,
	}

	pbResp, err := h.kmsService.Verify(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to verify signature", "key_id", verifyReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSVerify", Cause: err})
	}

	resp := &KMSVerifyResponse{
		KeyID:      pbResp.KeyId,
		KeyVersion: pbResp.KeyVersion,
		Valid:      pbResp.Valid,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGenerateRandom(ctx context.Context, req *quic.Request) *quic.Response {
	var randomReq KMSGenerateRandomRequest
	if err := quic.DecodePayload(req.Payload, &randomReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if randomReq.NumBytes <= 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "num_bytes"})
	}

	pbReq := &pb.GenerateRandomRequest{
		NumBytes: randomReq.NumBytes,
	}

	pbResp, err := h.kmsService.GenerateRandom(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate random bytes")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSGenerateRandom", Cause: err})
	}

	resp := &KMSGenerateRandomResponse{
		RandomBytes: pbResp.RandomBytes,
		Timestamp:   time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSHash(ctx context.Context, req *quic.Request) *quic.Response {
	var hashReq KMSHashRequest
	if err := quic.DecodePayload(req.Payload, &hashReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if len(hashReq.Data) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "data"})
	}

	pbReq := &pb.HashRequest{
		Data:      hashReq.Data,
		Algorithm: stringToHashAlgorithm(hashReq.Algorithm),
	}

	pbResp, err := h.kmsService.Hash(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to hash data")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSHash", Cause: err})
	}

	resp := &KMSHashResponse{
		Algorithm: hashAlgorithmToString(pbResp.Algorithm),
		Hash:      pbResp.Hash,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSHMAC(ctx context.Context, req *quic.Request) *quic.Response {
	// HMAC operations not yet implemented in protobuf interface
	return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
}

func (h *QUICServiceHandler) handleKMSVerifyHMAC(ctx context.Context, req *quic.Request) *quic.Response {
	// HMAC verification operations not yet implemented in protobuf interface
	return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
}

func (h *QUICServiceHandler) handleKMSRewrap(ctx context.Context, req *quic.Request) *quic.Response {
	// Rewrap operations not yet implemented in protobuf interface
	return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
}

// =============================================================================
// Conversion Helpers
// =============================================================================

func convertKeyHandleToQUIC(k *pb.KeyHandle) *KMSKeyHandleResponse {
	if k == nil {
		return nil
	}
	return &KMSKeyHandleResponse{
		KeyID:     k.KeyId,
		Version:   k.Version,
		Algorithm: keyAlgorithmToString(k.Algorithm),
		Status:    keyStatusToString(k.Status),
		CreatedAt: k.CreatedAt,
	}
}

func convertKeyMetadataToQUIC(m *pb.KeyMetadata) *KMSKeyMetadataResponse {
	if m == nil {
		return nil
	}
	resp := &KMSKeyMetadataResponse{
		KeyID:              m.KeyId,
		Name:               m.Name,
		Description:        m.Description,
		Algorithm:          keyAlgorithmToString(m.Algorithm),
		Status:             keyStatusToString(m.Status),
		Usage:              keyUsagesToStrings(m.Usage),
		Version:            m.Version,
		Exportable:         m.Exportable,
		DeletionProtection: m.DeletionProtection,
		CreatedAt:          m.CreatedAt,
		UpdatedAt:          m.UpdatedAt,
		LastUsedAt:         m.LastUsedAt,
		Tags:               m.Tags,
		Owner:              m.Owner,
	}

	if m.RotationPolicy != nil {
		resp.RotationPolicy = &KMSRotationPolicyResponse{
			Enabled:         m.RotationPolicy.Enabled,
			IntervalSeconds: m.RotationPolicy.IntervalSeconds,
			NextRotation:    m.RotationPolicy.NextRotation,
			RetainVersions:  m.RotationPolicy.RetainVersions,
			AutoRotate:      m.RotationPolicy.AutoRotate,
		}
	}

	return resp
}

// =============================================================================
// Data Key Operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSGenerateDataKey(ctx context.Context, req *quic.Request) *quic.Response {
	if h.cryptoService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "crypto"})
	}

	var dataKeyReq KMSGenerateDataKeyQUICRequest
	if err := quic.DecodePayload(req.Payload, &dataKeyReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if dataKeyReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	// Default to AES-256-GCM if not specified
	algorithm := dataKeyReq.Algorithm
	if algorithm == "" {
		algorithm = "aes-256-gcm"
	}

	// Build key attributes
	keySpec, err := buildDataKeySpecForQUIC(algorithm)
	if err != nil {
		return h.errorResponse(quic.StatusInvalidArgument, err)
	}

	// Build and execute the request
	pbReq := &pb.GenerateDataKeyRequest{
		KeyId:   dataKeyReq.KeyID,
		KeySpec: keySpec,
		Context: dataKeyReq.Context,
	}

	pbResp, err := h.cryptoService.GenerateDataKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate data key", "key_id", dataKeyReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSGenerateDataKey", Cause: err})
	}

	resp := &KMSGenerateDataKeyQUICResponse{
		KeyID:          pbResp.KeyId,
		Plaintext:      pbResp.Plaintext,
		CiphertextBlob: pbResp.CiphertextBlob,
		Timestamp:      time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("generated data encryption key",
		"key_id", dataKeyReq.KeyID,
		"algorithm", algorithm,
	)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGenerateWrappedDataKey(ctx context.Context, req *quic.Request) *quic.Response {
	if h.cryptoService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "crypto"})
	}

	var dataKeyReq KMSGenerateWrappedDataKeyQUICRequest
	if err := quic.DecodePayload(req.Payload, &dataKeyReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if dataKeyReq.KeyID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	// Default to AES-256-GCM if not specified
	algorithm := dataKeyReq.Algorithm
	if algorithm == "" {
		algorithm = "aes-256-gcm"
	}

	// Build key attributes
	keySpec, err := buildDataKeySpecForQUIC(algorithm)
	if err != nil {
		return h.errorResponse(quic.StatusInvalidArgument, err)
	}

	// Build and execute the request
	pbReq := &pb.GenerateWrappedDataKeyRequest{
		KeyId:   dataKeyReq.KeyID,
		KeySpec: keySpec,
		Context: dataKeyReq.Context,
	}

	pbResp, err := h.cryptoService.GenerateWrappedDataKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate wrapped data key", "key_id", dataKeyReq.KeyID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "KMSGenerateWrappedDataKey", Cause: err})
	}

	resp := &KMSGenerateWrappedDataKeyQUICResponse{
		KeyID:          pbResp.KeyId,
		CiphertextBlob: pbResp.CiphertextBlob,
		Timestamp:      time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("generated wrapped data encryption key",
		"key_id", dataKeyReq.KeyID,
		"algorithm", algorithm,
	)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// buildDataKeySpecForQUIC builds KeySpec for data key generation for QUIC handlers
func buildDataKeySpecForQUIC(algorithm string) (*pb.KeySpec, error) {
	spec := &pb.KeySpec{}

	normalizedAlg := strings.ToLower(strings.TrimSpace(algorithm))
	switch normalizedAlg {
	case "aes-128-gcm", "aes128gcm", "aes128":
		spec.Algorithm = pb.KeyAlgorithm_KEY_ALG_AES_128_GCM
	case "aes-192-gcm", "aes192gcm", "aes192":
		spec.Algorithm = pb.KeyAlgorithm_KEY_ALG_AES_192_GCM
	case "aes-256-gcm", "aes256gcm", "aes256":
		spec.Algorithm = pb.KeyAlgorithm_KEY_ALG_AES_256_GCM
	case "chacha20-poly1305", "chacha20poly1305", "chacha20":
		spec.Algorithm = pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305
	case "xchacha20-poly1305", "xchacha20poly1305", "xchacha20":
		spec.Algorithm = pb.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305
	default:
		return nil, ErrKMSInvalidAlgorithm{Algorithm: algorithm}
	}

	return spec, nil
}

// =============================================================================
// KMS QUIC Adapter
// =============================================================================

// kmsQUICAdapter implements KMSServiceInterface by composing the KMSServerAdapter
// (key management) and CryptoServerAdapter (crypto operations) from a KMSService.
// Operations not yet implemented in the underlying adapters return
// ErrKMSOperationNotImplemented, allowing partial service availability over QUIC.
type kmsQUICAdapter struct {
	kms    *KMSServerAdapter
	crypto *CryptoServerAdapter
}

// newKMSQUICAdapter creates a new adapter that bridges KMSService to KMSServiceInterface.
// Both kms and crypto adapters must be non-nil.
func newKMSQUICAdapter(kms *KMSServerAdapter, crypto *CryptoServerAdapter) *kmsQUICAdapter {
	return &kmsQUICAdapter{
		kms:    kms,
		crypto: crypto,
	}
}

// Key Management - delegated to KMSServerAdapter

func (a *kmsQUICAdapter) GenerateKey(ctx context.Context, req *pb.GenerateKeyRequest) (*pb.GenerateKeyResponse, error) {
	return a.kms.GenerateKey(ctx, req)
}

func (a *kmsQUICAdapter) GetKey(ctx context.Context, req *pb.GetKeyRequest) (*pb.GetKeyResponse, error) {
	return a.kms.GetKey(ctx, req)
}

func (a *kmsQUICAdapter) ListKeys(ctx context.Context, req *pb.ListKeysRequest) (*pb.ListKeysResponse, error) {
	return a.kms.ListKeys(ctx, req)
}

func (a *kmsQUICAdapter) DeleteKey(ctx context.Context, req *pb.DeleteKeyRequest) (*pb.DeleteKeyResponse, error) {
	return a.kms.DeleteKey(ctx, req)
}

func (a *kmsQUICAdapter) RotateKey(ctx context.Context, req *pb.RotateKeyRequest) (*pb.RotateKeyResponse, error) {
	return a.kms.RotateKey(ctx, req)
}

// Key Management - not yet available in SDK backend

func (a *kmsQUICAdapter) ImportKey(_ context.Context, _ *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return nil, ErrKMSOperationNotImplemented{Operation: "ImportKey"}
}

func (a *kmsQUICAdapter) UpdateKeyStatus(_ context.Context, _ *pb.UpdateKeyStatusRequest) (*pb.UpdateKeyStatusResponse, error) {
	return nil, ErrKMSOperationNotImplemented{Operation: "UpdateKeyStatus"}
}

func (a *kmsQUICAdapter) ExportKey(_ context.Context, _ *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	return nil, ErrKMSOperationNotImplemented{Operation: "ExportKey"}
}

func (a *kmsQUICAdapter) ListKeyVersions(_ context.Context, _ *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error) {
	return nil, ErrKMSOperationNotImplemented{Operation: "ListKeyVersions"}
}

// Crypto Operations - delegated to CryptoServerAdapter

func (a *kmsQUICAdapter) Encrypt(ctx context.Context, req *pb.CryptoEncryptRequest) (*pb.CryptoEncryptResponse, error) {
	return a.crypto.Encrypt(ctx, req)
}

func (a *kmsQUICAdapter) Decrypt(ctx context.Context, req *pb.CryptoDecryptRequest) (*pb.CryptoDecryptResponse, error) {
	return a.crypto.Decrypt(ctx, req)
}

func (a *kmsQUICAdapter) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	return a.crypto.Sign(ctx, req)
}

func (a *kmsQUICAdapter) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	return a.crypto.Verify(ctx, req)
}

// GenerateRandom generates cryptographically secure random bytes using crypto/rand.
// This operation does not require the SDK backend and is implemented directly.
func (a *kmsQUICAdapter) GenerateRandom(_ context.Context, req *pb.GenerateRandomRequest) (*pb.GenerateRandomResponse, error) {
	numBytes := req.GetNumBytes()
	if numBytes <= 0 {
		return nil, ErrKMSInvalidParameter{Parameter: "num_bytes", Reason: "number of bytes must be positive"}
	}
	if numBytes > kmsMaxRandomBytes {
		return nil, ErrKMSInvalidParameter{Parameter: "num_bytes", Reason: "maximum 1024 bytes allowed"}
	}

	randomBytes := make([]byte, numBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, ErrKMSRandomGenerationFailed{Cause: err}
	}

	return &pb.GenerateRandomResponse{
		RandomBytes: randomBytes,
		Timestamp:   time.Now().Unix(),
	}, nil
}

func (a *kmsQUICAdapter) Hash(_ context.Context, _ *pb.HashRequest) (*pb.HashResponse, error) {
	return nil, ErrKMSOperationNotImplemented{Operation: "Hash"}
}
