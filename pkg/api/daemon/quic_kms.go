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
	"errors"
	"strings"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	kmssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/kms"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

	// Key Lifecycle Operations
	RevokeKey(ctx context.Context, req *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error)
	GetKeyMetadata(ctx context.Context, req *pb.GetKeyMetadataRequest) (*pb.GetKeyMetadataResponse, error)
	UpdateKeyMetadata(ctx context.Context, req *pb.UpdateKeyMetadataRequest) (*pb.UpdateKeyMetadataResponse, error)
	SetKeyPolicy(ctx context.Context, req *pb.SetKeyPolicyRequest) (*pb.SetKeyPolicyResponse, error)
	GetKeyPolicy(ctx context.Context, req *pb.GetKeyPolicyRequest) (*pb.GetKeyPolicyResponse, error)
	GetSupportedAlgorithms(ctx context.Context, req *pb.GetSupportedAlgorithmsRequest) (*pb.GetSupportedAlgorithmsResponse, error)

	// Backend Operations
	BackendStatus(ctx context.Context, req *pb.BackendStatusRequest) (*pb.BackendStatusResponse, error)

	// Crypto Operations
	Encrypt(ctx context.Context, req *pb.CryptoEncryptRequest) (*pb.CryptoEncryptResponse, error)
	Decrypt(ctx context.Context, req *pb.CryptoDecryptRequest) (*pb.CryptoDecryptResponse, error)
	Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error)
	Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error)
	GenerateRandom(ctx context.Context, req *pb.GenerateRandomRequest) (*pb.GenerateRandomResponse, error)
	Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error)
	GenerateHMAC(ctx context.Context, req *pb.HMACRequest) (*pb.HMACResponse, error)
	VerifyHMAC(ctx context.Context, req *pb.VerifyHMACRequest) (*pb.VerifyHMACResponse, error)
	Rewrap(ctx context.Context, req *pb.RewrapRequest) (*pb.RewrapResponse, error)
	BatchEncrypt(ctx context.Context, req *pb.EncryptBatchRequest) (*pb.EncryptBatchResponse, error)
	BatchDecrypt(ctx context.Context, req *pb.DecryptBatchRequest) (*pb.DecryptBatchResponse, error)
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
//
// All KMS wire structs mirror the platform.v1 proto shape exactly
// (pkg/api/grpc/proto/kms.proto): Go field names equal the protoc-gen-go
// generated field names (the go-codec msgpack codec keys struct entries on
// the Go field name, so exact name equality is the wire contract), the codec
// tags carry the proto json names for tag-aware codecs, and enum fields are
// int32 values carrying platform.v1 enum constants. The platform SDK QUIC
// transport (sdk/go/transport/quic) encodes the platformv1 proto request
// structs directly and decodes daemon replies into the platformv1 response
// structs, so any drift here breaks every SDK KMS call over QUIC.
// =============================================================================

// KMSKeySpecRequest mirrors platform.v1 KMSKeySpec. Algorithm carries a
// platform.v1 KMSKeyAlgorithm value and Usage carries platform.v1 KeyUsage
// values.
type KMSKeySpecRequest struct {
	Algorithm          int32   `codec:"algorithm"`
	KeySize            int32   `codec:"key_size"`
	Usage              []int32 `codec:"usage"`
	Exportable         bool    `codec:"exportable"`
	DeletionProtection bool    `codec:"deletion_protection"`
}

// KMSGenerateKeyRequest mirrors platform.v1 GenerateKeyRequest.
type KMSGenerateKeyRequest struct {
	KeySpec     *KMSKeySpecRequest `codec:"key_spec"`
	Name        string             `codec:"name"`
	Description string             `codec:"description"`
	Tags        map[string]string  `codec:"tags"`
	Owner       string             `codec:"owner"`
}

// KMSKeyHandleResponse mirrors platform.v1 KMSKeyHandle. Algorithm carries a
// platform.v1 KMSKeyAlgorithm value and Status a platform.v1 KeyStatus value.
type KMSKeyHandleResponse struct {
	KeyId     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	Algorithm int32  `codec:"algorithm"`
	Status    int32  `codec:"status"`
	CreatedAt int64  `codec:"created_at"`
}

// KMSKeyMetadataResponse mirrors platform.v1 KMSKeyMetadata.
type KMSKeyMetadataResponse struct {
	KeyId              string            `codec:"key_id"`
	Name               string            `codec:"name"`
	Description        string            `codec:"description"`
	Algorithm          int32             `codec:"algorithm"`
	Status             int32             `codec:"status"`
	Usage              []int32           `codec:"usage"`
	Version            uint64            `codec:"version"`
	Exportable         bool              `codec:"exportable"`
	DeletionProtection bool              `codec:"deletion_protection"`
	CreatedAt          int64             `codec:"created_at"`
	UpdatedAt          int64             `codec:"updated_at"`
	LastUsedAt         int64             `codec:"last_used_at"`
	Tags               map[string]string `codec:"tags"`
	Owner              string            `codec:"owner"`
}

// KMSGenerateKeyResponse mirrors platform.v1 GenerateKeyResponse.
type KMSGenerateKeyResponse struct {
	Key       *KMSKeyHandleResponse   `codec:"key"`
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSImportKeyRequest mirrors platform.v1 ImportKeyRequest.
type KMSImportKeyRequest struct {
	KeyMaterial   []byte             `codec:"key_material"`
	WrappingKeyId string             `codec:"wrapping_key_id"`
	KeySpec       *KMSKeySpecRequest `codec:"key_spec"`
	Name          string             `codec:"name"`
	Description   string             `codec:"description"`
	Tags          map[string]string  `codec:"tags"`
}

// KMSImportKeyResponse mirrors platform.v1 ImportKeyResponse.
type KMSImportKeyResponse struct {
	Key       *KMSKeyHandleResponse   `codec:"key"`
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSGetKeyRequest mirrors platform.v1 GetKeyRequest.
type KMSGetKeyRequest struct {
	KeyId   string `codec:"key_id"`
	Version uint64 `codec:"version"`
}

// KMSGetKeyResponse mirrors platform.v1 GetKeyResponse.
type KMSGetKeyResponse struct {
	Key       *KMSKeyHandleResponse   `codec:"key"`
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSListKeysRequest mirrors platform.v1 ListKeysRequest.
type KMSListKeysRequest struct {
	Limit  int32             `codec:"limit"`
	Cursor string            `codec:"cursor"`
	Filter map[string]string `codec:"filter"`
}

// KMSListKeysResponse mirrors platform.v1 ListKeysResponse.
type KMSListKeysResponse struct {
	Keys       []*KMSKeyHandleResponse `codec:"keys"`
	NextCursor string                  `codec:"next_cursor"`
	HasMore    bool                    `codec:"has_more"`
	TotalCount int32                   `codec:"total_count"`
	Timestamp  int64                   `codec:"timestamp"`
}

// KMSDeleteKeyRequest mirrors platform.v1 DeleteKeyRequest.
type KMSDeleteKeyRequest struct {
	KeyId             string `codec:"key_id"`
	PendingWindowDays int32  `codec:"pending_window_days"`
	Force             bool   `codec:"force"`
}

// KMSDeleteKeyResponse mirrors platform.v1 DeleteKeyResponse. KeyStatus
// carries a platform.v1 KeyStatus value.
type KMSDeleteKeyResponse struct {
	KeyId        string `codec:"key_id"`
	KeyStatus    int32  `codec:"key_status"`
	DeletionDate int64  `codec:"deletion_date"`
	Timestamp    int64  `codec:"timestamp"`
}

// KMSRotateKeyRequest mirrors platform.v1 RotateKeyRequest.
type KMSRotateKeyRequest struct {
	KeyId            string `codec:"key_id"`
	RetainOldVersion bool   `codec:"retain_old_version"`
}

// KMSRotateKeyResponse mirrors platform.v1 RotateKeyResponse.
type KMSRotateKeyResponse struct {
	KeyId      string `codec:"key_id"`
	OldVersion uint64 `codec:"old_version"`
	NewVersion uint64 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSUpdateKeyStatusRequest mirrors platform.v1 UpdateKeyStatusRequest.
// Status carries a platform.v1 KeyStatus value.
type KMSUpdateKeyStatusRequest struct {
	KeyId   string `codec:"key_id"`
	Version uint64 `codec:"version"`
	Status  int32  `codec:"status"`
}

// KMSUpdateKeyStatusResponse mirrors platform.v1 UpdateKeyStatusResponse.
type KMSUpdateKeyStatusResponse struct {
	KeyId     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	KeyStatus int32  `codec:"key_status"`
	Timestamp int64  `codec:"timestamp"`
}

// KMSExportKeyRequest mirrors platform.v1 ExportKeyRequest. WrappingAlgorithm
// carries a platform.v1 WrappingAlgorithm value and Format a platform.v1
// KeyExportFormat value.
type KMSExportKeyRequest struct {
	KeyId             string `codec:"key_id"`
	WrappingKeyId     string `codec:"wrapping_key_id"`
	WrappingAlgorithm int32  `codec:"wrapping_algorithm"`
	Format            int32  `codec:"format"`
	Version           uint64 `codec:"version"`
}

// KMSExportKeyResponse mirrors platform.v1 ExportKeyResponse.
type KMSExportKeyResponse struct {
	KeyId             string `codec:"key_id"`
	Format            int32  `codec:"format"`
	WrappingKeyId     string `codec:"wrapping_key_id"`
	WrappingAlgorithm int32  `codec:"wrapping_algorithm"`
	WrappedMaterial   []byte `codec:"wrapped_material"`
	Version           uint64 `codec:"version"`
	Timestamp         int64  `codec:"timestamp"`
}

// KMSGetKeyVersionsRequest mirrors platform.v1 GetKeyVersionsRequest.
type KMSGetKeyVersionsRequest struct {
	KeyId  string `codec:"key_id"`
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// KMSKeyVersionInfoResponse mirrors platform.v1 KMSKeyVersionInfo.
type KMSKeyVersionInfoResponse struct {
	Version    uint64 `codec:"version"`
	Status     int32  `codec:"status"`
	Algorithm  int32  `codec:"algorithm"`
	CreatedAt  int64  `codec:"created_at"`
	DisabledAt int64  `codec:"disabled_at"`
}

// KMSGetKeyVersionsResponse mirrors platform.v1 GetKeyVersionsResponse.
type KMSGetKeyVersionsResponse struct {
	KeyId      string                       `codec:"key_id"`
	Versions   []*KMSKeyVersionInfoResponse `codec:"versions"`
	NextCursor string                       `codec:"next_cursor"`
	HasMore    bool                         `codec:"has_more"`
	Timestamp  int64                        `codec:"timestamp"`
}

// KMSBackendStatusRequest mirrors platform.v1 BackendStatusRequest.
type KMSBackendStatusRequest struct{}

// KMSBackendStatusResponse mirrors platform.v1 BackendStatusResponse.
type KMSBackendStatusResponse struct {
	BackendType   string          `codec:"backend_type"`
	BackendStatus string          `codec:"backend_status"`
	Device        string          `codec:"device"`
	Region        string          `codec:"region"`
	KeyId         string          `codec:"key_id"`
	PcrBanks      []string        `codec:"pcr_banks"`
	PcrRegisters  []int32         `codec:"pcr_registers"`
	Capabilities  map[string]bool `codec:"capabilities"`
	Timestamp     int64           `codec:"timestamp"`
}

// =============================================================================
// KMS Crypto Operations Request/Response Types
// =============================================================================

// KMSEncryptRequest mirrors platform.v1 EncryptRequest.
type KMSEncryptRequest struct {
	KeyId     string `codec:"key_id"`
	Plaintext []byte `codec:"plaintext"`
	Context   []byte `codec:"context"`
	Nonce     []byte `codec:"nonce"`
}

// KMSEncryptResponse mirrors platform.v1 EncryptResponse.
type KMSEncryptResponse struct {
	KeyId      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Ciphertext []byte `codec:"ciphertext"`
	Nonce      []byte `codec:"nonce"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSDecryptRequest mirrors platform.v1 DecryptRequest.
type KMSDecryptRequest struct {
	KeyId      string `codec:"key_id"`
	Ciphertext []byte `codec:"ciphertext"`
	Context    []byte `codec:"context"`
	Nonce      []byte `codec:"nonce"`
	KeyVersion uint64 `codec:"key_version"`
}

// KMSDecryptResponse mirrors platform.v1 DecryptResponse.
type KMSDecryptResponse struct {
	KeyId      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Plaintext  []byte `codec:"plaintext"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSSignRequest mirrors platform.v1 SignRequest. HashAlgorithm carries a
// platform.v1 HashAlgorithm value.
type KMSSignRequest struct {
	KeyId         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
	PreHashed     bool   `codec:"pre_hashed"`
}

// KMSSignResponse mirrors platform.v1 SignResponse.
type KMSSignResponse struct {
	KeyId         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSVerifyRequest mirrors platform.v1 VerifyRequest.
type KMSVerifyRequest struct {
	KeyId         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
	KeyVersion    uint64 `codec:"key_version"`
}

// KMSVerifyResponse mirrors platform.v1 VerifyResponse.
type KMSVerifyResponse struct {
	KeyId      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSGenerateRandomRequest mirrors platform.v1 GenerateRandomRequest.
type KMSGenerateRandomRequest struct {
	NumBytes int32 `codec:"num_bytes"`
}

// KMSGenerateRandomResponse mirrors platform.v1 GenerateRandomResponse.
type KMSGenerateRandomResponse struct {
	RandomBytes []byte `codec:"random_bytes"`
	Timestamp   int64  `codec:"timestamp"`
}

// KMSHashRequest mirrors platform.v1 HashRequest. Algorithm carries a
// platform.v1 HashAlgorithm value.
type KMSHashRequest struct {
	Data      []byte `codec:"data"`
	Algorithm int32  `codec:"algorithm"`
}

// KMSHashResponse mirrors platform.v1 HashResponse.
type KMSHashResponse struct {
	Algorithm int32  `codec:"algorithm"`
	Hash      []byte `codec:"hash"`
	Timestamp int64  `codec:"timestamp"`
}

// KMSHMACRequest mirrors platform.v1 HMACRequest.
type KMSHMACRequest struct {
	KeyId         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
}

// KMSHMACResponse mirrors platform.v1 HMACResponse.
type KMSHMACResponse struct {
	KeyId         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	Hmac          []byte `codec:"hmac"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSVerifyHMACRequest mirrors platform.v1 VerifyHMACRequest.
type KMSVerifyHMACRequest struct {
	KeyId         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	Hmac          []byte `codec:"hmac"`
	HashAlgorithm int32  `codec:"hash_algorithm"`
	KeyVersion    uint64 `codec:"key_version"`
}

// KMSVerifyHMACResponse mirrors platform.v1 VerifyHMACResponse.
type KMSVerifyHMACResponse struct {
	KeyId      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// KMSRewrapRequest mirrors platform.v1 RewrapRequest. SourceVersion must be
// zero (auto-detect); the QuicBaaS backend derives the source version from
// the ciphertext and cannot honor an explicit source version.
type KMSRewrapRequest struct {
	KeyId         string `codec:"key_id"`
	Ciphertext    []byte `codec:"ciphertext"`
	Context       []byte `codec:"context"`
	Nonce         []byte `codec:"nonce"`
	SourceVersion uint64 `codec:"source_version"`
}

// KMSRewrapResponse mirrors platform.v1 RewrapResponse.
type KMSRewrapResponse struct {
	KeyId         string `codec:"key_id"`
	SourceVersion uint64 `codec:"source_version"`
	TargetVersion uint64 `codec:"target_version"`
	Ciphertext    []byte `codec:"ciphertext"`
	Nonce         []byte `codec:"nonce"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSStatusResponse mirrors the platform.v1 Status message used inside batch
// result items.
type KMSStatusResponse struct {
	Success bool   `codec:"success"`
	Message string `codec:"message"`
}

// KMSBatchEncryptItem mirrors platform.v1 BatchEncryptItem. Nonce must be
// empty; the QuicBaaS backend generates nonces server-side and cannot accept
// client-supplied nonces for batch encryption.
type KMSBatchEncryptItem struct {
	ItemId    string `codec:"item_id"`
	Plaintext []byte `codec:"plaintext"`
	Context   []byte `codec:"context"`
	Nonce     []byte `codec:"nonce"`
}

// KMSBatchEncryptRequest mirrors platform.v1 BatchEncryptRequest.
type KMSBatchEncryptRequest struct {
	KeyId string                 `codec:"key_id"`
	Items []*KMSBatchEncryptItem `codec:"items"`
}

// KMSBatchEncryptResultItem mirrors platform.v1 BatchEncryptResultItem.
type KMSBatchEncryptResultItem struct {
	ItemId     string             `codec:"item_id"`
	Status     *KMSStatusResponse `codec:"status"`
	Ciphertext []byte             `codec:"ciphertext"`
	Nonce      []byte             `codec:"nonce"`
	KeyVersion uint64             `codec:"key_version"`
}

// KMSBatchEncryptResponse mirrors platform.v1 BatchEncryptResponse.
type KMSBatchEncryptResponse struct {
	KeyId        string                       `codec:"key_id"`
	Results      []*KMSBatchEncryptResultItem `codec:"results"`
	SuccessCount int32                        `codec:"success_count"`
	FailureCount int32                        `codec:"failure_count"`
	Timestamp    int64                        `codec:"timestamp"`
}

// KMSBatchDecryptItem mirrors platform.v1 BatchDecryptItem. KeyVersion must
// be zero (latest); the QuicBaaS backend derives the key version from the
// ciphertext and cannot honor a per-item key version.
type KMSBatchDecryptItem struct {
	ItemId     string `codec:"item_id"`
	Ciphertext []byte `codec:"ciphertext"`
	Context    []byte `codec:"context"`
	Nonce      []byte `codec:"nonce"`
	KeyVersion uint64 `codec:"key_version"`
}

// KMSBatchDecryptRequest mirrors platform.v1 BatchDecryptRequest.
type KMSBatchDecryptRequest struct {
	KeyId string                 `codec:"key_id"`
	Items []*KMSBatchDecryptItem `codec:"items"`
}

// KMSBatchDecryptResultItem mirrors platform.v1 BatchDecryptResultItem.
type KMSBatchDecryptResultItem struct {
	ItemId     string             `codec:"item_id"`
	Status     *KMSStatusResponse `codec:"status"`
	Plaintext  []byte             `codec:"plaintext"`
	KeyVersion uint64             `codec:"key_version"`
}

// KMSBatchDecryptResponse mirrors platform.v1 BatchDecryptResponse.
type KMSBatchDecryptResponse struct {
	KeyId        string                       `codec:"key_id"`
	Results      []*KMSBatchDecryptResultItem `codec:"results"`
	SuccessCount int32                        `codec:"success_count"`
	FailureCount int32                        `codec:"failure_count"`
	Timestamp    int64                        `codec:"timestamp"`
}

// KMSGenerateDataKeyQUICRequest mirrors platform.v1 GenerateDataKeyRequest.
// Algorithm carries a platform.v1 KMSKeyAlgorithm value.
type KMSGenerateDataKeyQUICRequest struct {
	KeyId     string `codec:"key_id"`
	Algorithm int32  `codec:"algorithm"`
	KeySize   int32  `codec:"key_size"`
	Context   []byte `codec:"context"`
}

// KMSGenerateDataKeyQUICResponse mirrors platform.v1 GenerateDataKeyResponse.
type KMSGenerateDataKeyQUICResponse struct {
	PlaintextKey []byte `codec:"plaintext_key"`
	EncryptedKey []byte `codec:"encrypted_key"`
	KeyId        string `codec:"key_id"`
	Timestamp    int64  `codec:"timestamp"`
}

// KMSGenerateWrappedDataKeyQUICRequest mirrors platform.v1
// GenerateWrappedDataKeyRequest. WrappingAlgorithm must be zero; the QuicBaaS
// backend wraps data keys with the master key's own algorithm and cannot
// honor an explicit wrapping algorithm.
type KMSGenerateWrappedDataKeyQUICRequest struct {
	WrappingKeyId     string `codec:"wrapping_key_id"`
	WrappingAlgorithm int32  `codec:"wrapping_algorithm"`
	KeyAlgorithm      int32  `codec:"key_algorithm"`
	KeySize           int32  `codec:"key_size"`
	Context           []byte `codec:"context"`
}

// KMSGenerateWrappedDataKeyQUICResponse mirrors platform.v1
// GenerateWrappedDataKeyResponse.
type KMSGenerateWrappedDataKeyQUICResponse struct {
	WrappedKey        []byte `codec:"wrapped_key"`
	WrappingKeyId     string `codec:"wrapping_key_id"`
	WrappingAlgorithm int32  `codec:"wrapping_algorithm"`
	Timestamp         int64  `codec:"timestamp"`
}

// =============================================================================
// Enum Conversions (platform.v1 wire values <-> QuicBaaS pb enums)
//
// The platform.v1 enum NUMBERS intentionally differ from the QuicBaaS pb enum
// numbers, so every conversion is an explicit typed mapping — never a numeric
// cast. Values the QuicBaaS backend cannot express are rejected with a typed
// error (surfaced as StatusInvalidArgument); the only silent defaults are the
// proto3 UNSPECIFIED values, which map to the documented defaults.
// =============================================================================

// platformKMSAlgorithmToPb converts a platform.v1 KMSKeyAlgorithm value to
// the QuicBaaS pb KeyAlgorithm. KMS_KEY_ALGORITHM_UNSPECIFIED maps to the
// documented default (AES-256-GCM); algorithms the QuicBaaS SDK cannot
// service return a typed error.
func platformKMSAlgorithmToPb(alg int32) (pb.KeyAlgorithm, error) {
	switch platformv1.KMSKeyAlgorithm(alg) {
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:
		return pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305:
		return pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048:
		return pb.KeyAlgorithm_KEY_ALG_RSA_2048, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096:
		return pb.KeyAlgorithm_KEY_ALG_RSA_4096, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256:
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P256, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384:
		return pb.KeyAlgorithm_KEY_ALG_ECDSA_P384, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:
		return pb.KeyAlgorithm_KEY_ALG_ED25519, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "key algorithm", Value: alg}
	}
}

// pbKeyAlgorithmToPlatformKMS converts a QuicBaaS pb KeyAlgorithm to the
// platform.v1 KMSKeyAlgorithm value. Algorithms the platform proto cannot
// express map to KMS_KEY_ALGORITHM_UNSPECIFIED.
func pbKeyAlgorithmToPlatformKMS(alg pb.KeyAlgorithm) int32 {
	switch alg {
	case pb.KeyAlgorithm_KEY_ALG_AES_128_GCM:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128)
	case pb.KeyAlgorithm_KEY_ALG_AES_192_GCM:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192)
	case pb.KeyAlgorithm_KEY_ALG_AES_256_GCM:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256)
	case pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305)
	case pb.KeyAlgorithm_KEY_ALG_RSA_2048:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048)
	case pb.KeyAlgorithm_KEY_ALG_RSA_3072:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_3072)
	case pb.KeyAlgorithm_KEY_ALG_RSA_4096:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096)
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P256:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256)
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P384:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384)
	case pb.KeyAlgorithm_KEY_ALG_ECDSA_P521:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P521)
	case pb.KeyAlgorithm_KEY_ALG_ED25519:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519)
	case pb.KeyAlgorithm_KEY_ALG_HMAC_SHA256:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA256)
	case pb.KeyAlgorithm_KEY_ALG_HMAC_SHA384:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA384)
	case pb.KeyAlgorithm_KEY_ALG_HMAC_SHA512:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_HMAC_SHA512)
	default:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED)
	}
}

// platformKMSUsagesToPb converts platform.v1 KeyUsage values to QuicBaaS pb
// KeyUsage values. Usages the QuicBaaS pb cannot express (UNWRAP, DERIVE,
// HMAC) return a typed error.
func platformKMSUsagesToPb(usages []int32) ([]pb.KeyUsage, error) {
	return convertKeyUsages(usages, platformKMSUsageToPb)
}

// platformKMSUsageToPb maps each platform wire usage to the go-quicbaas
// wire usages QUIC forwards to the KMS adapter. HMAC maps to the MAC
// usages, which pbKeyUsageToSDK grants as sign and verify; UNWRAP, DERIVE
// and UNSPECIFIED are absent and therefore refused.
var platformKMSUsageToPb = map[platformv1.KeyUsage][]pb.KeyUsage{
	platformv1.KeyUsage_KEY_USAGE_ENCRYPT: {pb.KeyUsage_KEY_USAGE_ENCRYPT},
	platformv1.KeyUsage_KEY_USAGE_DECRYPT: {pb.KeyUsage_KEY_USAGE_DECRYPT},
	platformv1.KeyUsage_KEY_USAGE_SIGN:    {pb.KeyUsage_KEY_USAGE_SIGN},
	platformv1.KeyUsage_KEY_USAGE_VERIFY:  {pb.KeyUsage_KEY_USAGE_VERIFY},
	platformv1.KeyUsage_KEY_USAGE_WRAP:    {pb.KeyUsage_KEY_USAGE_WRAP_KEY},
	platformv1.KeyUsage_KEY_USAGE_HMAC:    {pb.KeyUsage_KEY_USAGE_GENERATE_MAC, pb.KeyUsage_KEY_USAGE_VERIFY_MAC},
}

// pbKeyUsagesToPlatformKMS converts QuicBaaS pb KeyUsage values to platform.v1
// KeyUsage values. Usages the platform proto cannot express map to
// KEY_USAGE_UNSPECIFIED.
func pbKeyUsagesToPlatformKMS(usages []pb.KeyUsage) []int32 {
	result := make([]int32, 0, len(usages))
	for _, u := range usages {
		switch u {
		case pb.KeyUsage_KEY_USAGE_ENCRYPT:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT))
		case pb.KeyUsage_KEY_USAGE_DECRYPT:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT))
		case pb.KeyUsage_KEY_USAGE_SIGN:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_SIGN))
		case pb.KeyUsage_KEY_USAGE_VERIFY:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_VERIFY))
		case pb.KeyUsage_KEY_USAGE_WRAP_KEY:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_WRAP))
		case pb.KeyUsage_KEY_USAGE_DERIVE_KEY:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_DERIVE))
		case pb.KeyUsage_KEY_USAGE_GENERATE_MAC, pb.KeyUsage_KEY_USAGE_VERIFY_MAC:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_HMAC))
		default:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_UNSPECIFIED))
		}
	}
	return result
}

// platformKMSStatusToPb converts a platform.v1 KeyStatus value to the
// QuicBaaS pb KeyStatus. Statuses the QuicBaaS backend cannot express
// (PENDING_IMPORT) return a typed error.
func platformKMSStatusToPb(status int32) (pb.KeyStatus, error) {
	switch platformv1.KeyStatus(status) {
	case platformv1.KeyStatus_KEY_STATUS_ENABLED:
		return pb.KeyStatus_KEY_STATUS_ENABLED, nil
	case platformv1.KeyStatus_KEY_STATUS_DISABLED:
		return pb.KeyStatus_KEY_STATUS_DISABLED, nil
	case platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION:
		return pb.KeyStatus_KEY_STATUS_PENDING_DELETION, nil
	case platformv1.KeyStatus_KEY_STATUS_DESTROYED:
		return pb.KeyStatus_KEY_STATUS_DELETED, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "key status", Value: status}
	}
}

// pbKeyStatusToPlatformKMS converts a QuicBaaS pb KeyStatus to the
// platform.v1 KeyStatus value. Rotating keys remain usable so they report as
// enabled; compromised keys report as disabled since the platform proto has
// no dedicated state for either.
func pbKeyStatusToPlatformKMS(status pb.KeyStatus) int32 {
	switch status {
	case pb.KeyStatus_KEY_STATUS_ENABLED, pb.KeyStatus_KEY_STATUS_ROTATING:
		return int32(platformv1.KeyStatus_KEY_STATUS_ENABLED)
	case pb.KeyStatus_KEY_STATUS_DISABLED, pb.KeyStatus_KEY_STATUS_COMPROMISED:
		return int32(platformv1.KeyStatus_KEY_STATUS_DISABLED)
	case pb.KeyStatus_KEY_STATUS_PENDING_DELETION:
		return int32(platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION)
	case pb.KeyStatus_KEY_STATUS_DELETED:
		return int32(platformv1.KeyStatus_KEY_STATUS_DESTROYED)
	default:
		return int32(platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED)
	}
}

// platformKMSHashToPb converts a platform.v1 HashAlgorithm value to the
// QuicBaaS pb HashAlgorithm. HASH_ALGORITHM_UNSPECIFIED maps to the
// documented default (SHA-256); algorithms the QuicBaaS SDK cannot service
// (SHA-1, SHA-3) return a typed error.
func platformKMSHashToPb(alg int32) (pb.HashAlgorithm, error) {
	switch platformv1.HashAlgorithm(alg) {
	case platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256:
		return pb.HashAlgorithm_HASH_ALG_SHA256, nil
	case platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384:
		return pb.HashAlgorithm_HASH_ALG_SHA384, nil
	case platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return pb.HashAlgorithm_HASH_ALG_SHA512, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "hash algorithm", Value: alg}
	}
}

// pbHashAlgorithmToPlatformKMS converts a QuicBaaS pb HashAlgorithm to the
// platform.v1 HashAlgorithm value. Algorithms the platform proto cannot
// express (BLAKE2b) map to HASH_ALGORITHM_UNSPECIFIED.
func pbHashAlgorithmToPlatformKMS(alg pb.HashAlgorithm) int32 {
	switch alg {
	case pb.HashAlgorithm_HASH_ALG_SHA256:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256)
	case pb.HashAlgorithm_HASH_ALG_SHA384:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384)
	case pb.HashAlgorithm_HASH_ALG_SHA512:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512)
	case pb.HashAlgorithm_HASH_ALG_SHA3_256:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_256)
	case pb.HashAlgorithm_HASH_ALG_SHA3_384:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_384)
	case pb.HashAlgorithm_HASH_ALG_SHA3_512:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA3_512)
	default:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	}
}

// platformKMSExportFormatToPb converts a platform.v1 KeyExportFormat value to
// the QuicBaaS pb ExportFormat. KEY_EXPORT_FORMAT_UNSPECIFIED maps to the
// documented default (raw); formats the QuicBaaS backend cannot express
// (PKCS#8) return a typed error.
func platformKMSExportFormatToPb(format int32) (pb.ExportFormat, error) {
	switch platformv1.KeyExportFormat(format) {
	case platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_UNSPECIFIED,
		platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW:
		return pb.ExportFormat_EXPORT_FORMAT_RAW, nil
	case platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_JWK:
		return pb.ExportFormat_EXPORT_FORMAT_JWK, nil
	case platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM:
		return pb.ExportFormat_EXPORT_FORMAT_PEM, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "key export format", Value: format}
	}
}

// pbExportFormatToPlatformKMS converts a QuicBaaS pb ExportFormat to the
// platform.v1 KeyExportFormat value.
func pbExportFormatToPlatformKMS(format pb.ExportFormat) int32 {
	switch format {
	case pb.ExportFormat_EXPORT_FORMAT_RAW:
		return int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW)
	case pb.ExportFormat_EXPORT_FORMAT_JWK:
		return int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_JWK)
	case pb.ExportFormat_EXPORT_FORMAT_PEM:
		return int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM)
	default:
		return int32(platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_UNSPECIFIED)
	}
}

// platformKMSWrappingToPb converts a platform.v1 WrappingAlgorithm value to
// the QuicBaaS pb WrappingAlgorithm. WRAPPING_ALGORITHM_UNSPECIFIED maps to
// pb WRAP_ALG_UNSPECIFIED, which the server adapter resolves to the
// documented default (RFC 3394 AES-KW).
func platformKMSWrappingToPb(alg int32) (pb.WrappingAlgorithm, error) {
	switch platformv1.WrappingAlgorithm(alg) {
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED:
		return pb.WrappingAlgorithm_WRAP_ALG_UNSPECIFIED, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA256:
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA384:
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA512:
		return pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM:
		return pb.WrappingAlgorithm_WRAP_ALG_AES_GCM, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP:
		return pb.WrappingAlgorithm_WRAP_ALG_AES_KWP, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "wrapping algorithm", Value: alg}
	}
}

// pbWrappingToPlatformKMS converts a QuicBaaS pb WrappingAlgorithm to the
// platform.v1 WrappingAlgorithm value. Algorithms the platform proto cannot
// express (AES-KW, ECDH-ES) map to WRAPPING_ALGORITHM_UNSPECIFIED.
func pbWrappingToPlatformKMS(alg pb.WrappingAlgorithm) int32 {
	switch alg {
	case pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA256:
		return int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA256)
	case pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA384:
		return int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA384)
	case pb.WrappingAlgorithm_WRAP_ALG_RSA_OAEP_SHA512:
		return int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA512)
	case pb.WrappingAlgorithm_WRAP_ALG_AES_GCM:
		return int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM)
	case pb.WrappingAlgorithm_WRAP_ALG_AES_KWP:
		return int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP)
	default:
		return int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED)
	}
}

// platformKeySpecToPb converts a platform.v1-shaped key spec wire struct to
// the QuicBaaS pb KeySpec.
func platformKeySpecToPb(spec *KMSKeySpecRequest) (*pb.KeySpec, error) {
	alg, err := platformKMSAlgorithmToPb(spec.Algorithm)
	if err != nil {
		return nil, err
	}
	usages, err := platformKMSUsagesToPb(spec.Usage)
	if err != nil {
		return nil, err
	}
	return &pb.KeySpec{
		Algorithm:          alg,
		KeySize:            spec.KeySize,
		Usage:              usages,
		Exportable:         spec.Exportable,
		DeletionProtection: spec.DeletionProtection,
	}, nil
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
		// The short name (ENCRYPT, WRAP_KEY, ...) is the form REST answers
		// and stringToKeyUsage accepts, so a policy read over QUIC can be
		// written back unchanged.
		result = append(result, strings.TrimPrefix(u.String(), "KEY_USAGE_"))
	}
	return result
}

// keyStatusToString converts a protobuf KeyStatus to a string
func keyStatusToString(status pb.KeyStatus) string {
	return status.String()
}

// =============================================================================
// KMS Operation Handler
// =============================================================================

// handleKMSOperation routes KMS operations to the appropriate handler
func (h *QUICServiceHandler) handleKMSOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.kmsService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "kms"})
	}

	switch req.Opcode {
	// Key Management Operations (0xC0-0xCF)
	case quicwire.OpKMSGenerateKey:
		return h.handleKMSGenerateKey(ctx, req)
	case quicwire.OpKMSImportKey:
		return h.handleKMSImportKey(ctx, req)
	case quicwire.OpKMSGetKey:
		return h.handleKMSGetKey(ctx, req)
	case quicwire.OpKMSListKeys:
		return h.handleKMSListKeys(ctx, req)
	case quicwire.OpKMSDeleteKey:
		return h.handleKMSDeleteKey(ctx, req)
	case quicwire.OpKMSRotateKey:
		return h.handleKMSRotateKey(ctx, req)
	case quicwire.OpKMSUpdateKeyStatus:
		return h.handleKMSUpdateKeyStatus(ctx, req)
	case quicwire.OpKMSExportKey:
		return h.handleKMSExportKey(ctx, req)
	case quicwire.OpKMSGetKeyVersions:
		return h.handleKMSGetKeyVersions(ctx, req)
	case quicwire.OpKMSBackendStatus:
		return h.handleKMSBackendStatus(ctx, req)
	case quicwire.OpKMSBatchEncrypt:
		return h.handleKMSBatchEncrypt(ctx, req)
	case quicwire.OpKMSBatchDecrypt:
		return h.handleKMSBatchDecrypt(ctx, req)

	// Crypto Operations (0xD0-0xDF)
	case quicwire.OpKMSEncrypt:
		return h.handleKMSEncrypt(ctx, req)
	case quicwire.OpKMSDecrypt:
		return h.handleKMSDecrypt(ctx, req)
	case quicwire.OpKMSSign:
		return h.handleKMSSign(ctx, req)
	case quicwire.OpKMSVerify:
		return h.handleKMSVerify(ctx, req)
	case quicwire.OpKMSGenerateRandom:
		return h.handleKMSGenerateRandom(ctx, req)
	case quicwire.OpKMSHash:
		return h.handleKMSHash(ctx, req)
	case quicwire.OpKMSHMAC:
		return h.handleKMSHMAC(ctx, req)
	case quicwire.OpKMSVerifyHMAC:
		return h.handleKMSVerifyHMAC(ctx, req)
	case quicwire.OpKMSRewrap:
		return h.handleKMSRewrap(ctx, req)
	case quicwire.OpKMSGenerateDataKey:
		return h.handleKMSGenerateDataKey(ctx, req)
	case quicwire.OpKMSGenerateWrappedDataKey:
		return h.handleKMSGenerateWrappedDataKey(ctx, req)

	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// =============================================================================
// Key Management Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSGenerateKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var genReq KMSGenerateKeyRequest
	if err := quicwire.DecodePayload(req.Payload, &genReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if genReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	if genReq.KeySpec == nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_spec"})
	}

	keySpec, err := platformKeySpecToPb(genReq.KeySpec)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbReq := &pb.GenerateKeyRequest{
		Name:        genReq.Name,
		Description: genReq.Description,
		Tags:        genReq.Tags,
		Owner:       genReq.Owner,
		KeySpec:     keySpec,
	}

	pbResp, err := h.kmsService.GenerateKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate key")
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGenerateKey", Cause: err})
	}

	resp := &KMSGenerateKeyResponse{
		Key:       convertKeyHandleToQUIC(pbResp.Key),
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSImportKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var importReq KMSImportKeyRequest
	if err := quicwire.DecodePayload(req.Payload, &importReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if len(importReq.KeyMaterial) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_material"})
	}

	if importReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	pbReq := &pb.ImportKeyRequest{
		KeyMaterial:   importReq.KeyMaterial,
		WrappingKeyId: importReq.WrappingKeyId,
		Name:          importReq.Name,
		Description:   importReq.Description,
		Tags:          importReq.Tags,
	}

	if importReq.KeySpec != nil {
		keySpec, err := platformKeySpecToPb(importReq.KeySpec)
		if err != nil {
			return h.errorResponse(quicwire.StatusInvalidArgument, err)
		}
		pbReq.KeySpec = keySpec
	}

	pbResp, err := h.kmsService.ImportKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to import key")
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSImportKey", Cause: err})
	}

	resp := &KMSImportKeyResponse{
		Key:       convertKeyHandleToQUIC(pbResp.Key),
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGetKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq KMSGetKeyRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbReq := &pb.GetKeyRequest{
		KeyId:   getReq.KeyId,
		Version: getReq.Version,
	}

	pbResp, err := h.kmsService.GetKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to get key", "key_id", getReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGetKey", Cause: err})
	}

	resp := &KMSGetKeyResponse{
		Key:       convertKeyHandleToQUIC(pbResp.Key),
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSListKeys(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var listReq KMSListKeysRequest
	if len(req.Payload) > 0 {
		if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
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
		Filter: listReq.Filter,
	}

	pbResp, err := h.kmsService.ListKeys(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to list keys")
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSListKeys", Cause: err})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSDeleteKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq KMSDeleteKeyRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbReq := &pb.DeleteKeyRequest{
		KeyId:             deleteReq.KeyId,
		PendingWindowDays: deleteReq.PendingWindowDays,
		Force:             deleteReq.Force,
	}

	pbResp, err := h.kmsService.DeleteKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to delete key", "key_id", deleteReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSDeleteKey", Cause: err})
	}

	resp := &KMSDeleteKeyResponse{
		KeyId:        pbResp.KeyId,
		KeyStatus:    pbKeyStatusToPlatformKMS(pbResp.Status),
		DeletionDate: pbResp.DeletionDate,
		Timestamp:    time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("key deleted", "key_id", deleteReq.KeyId)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSRotateKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var rotateReq KMSRotateKeyRequest
	if err := quicwire.DecodePayload(req.Payload, &rotateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if rotateReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbReq := &pb.RotateKeyRequest{
		KeyId:            rotateReq.KeyId,
		RetainOldVersion: rotateReq.RetainOldVersion,
	}

	pbResp, err := h.kmsService.RotateKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to rotate key", "key_id", rotateReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSRotateKey", Cause: err})
	}

	resp := &KMSRotateKeyResponse{
		KeyId:      pbResp.KeyId,
		OldVersion: pbResp.OldVersion,
		NewVersion: pbResp.NewVersion,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("key rotated", "key_id", rotateReq.KeyId, "old_version", resp.OldVersion, "new_version", resp.NewVersion)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSUpdateKeyStatus(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var updateReq KMSUpdateKeyStatusRequest
	if err := quicwire.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if platformv1.KeyStatus(updateReq.Status) == platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "status"})
	}

	pbStatus, err := platformKMSStatusToPb(updateReq.Status)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbReq := &pb.UpdateKeyStatusRequest{
		KeyId:   updateReq.KeyId,
		Version: updateReq.Version,
		Status:  pbStatus,
	}

	pbResp, err := h.kmsService.UpdateKeyStatus(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to update key status", "key_id", updateReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSUpdateKeyStatus", Cause: err})
	}

	resp := &KMSUpdateKeyStatusResponse{
		KeyId:     pbResp.KeyId,
		Version:   pbResp.Version,
		KeyStatus: pbKeyStatusToPlatformKMS(pbResp.Status),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSExportKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var exportReq KMSExportKeyRequest
	if err := quicwire.DecodePayload(req.Payload, &exportReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if exportReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	wrappingAlg, err := platformKMSWrappingToPb(exportReq.WrappingAlgorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	format, err := platformKMSExportFormatToPb(exportReq.Format)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbReq := &pb.ExportKeyRequest{
		KeyId:             exportReq.KeyId,
		WrappingKeyId:     exportReq.WrappingKeyId,
		WrappingAlgorithm: wrappingAlg,
		Format:            format,
		Version:           exportReq.Version,
	}

	pbResp, err := h.kmsService.ExportKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to export key", "key_id", exportReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSExportKey", Cause: err})
	}

	resp := &KMSExportKeyResponse{
		KeyId:             pbResp.KeyId,
		Format:            pbExportFormatToPlatformKMS(pbResp.Format),
		WrappingKeyId:     pbResp.WrappingKeyId,
		WrappingAlgorithm: pbWrappingToPlatformKMS(pbResp.WrappingAlgorithm),
		WrappedMaterial:   pbResp.WrappedMaterial,
		Version:           pbResp.Version,
		Timestamp:         time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGetKeyVersions(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var versionsReq KMSGetKeyVersionsRequest
	if err := quicwire.DecodePayload(req.Payload, &versionsReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if versionsReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	limit := versionsReq.Limit
	if limit <= 0 {
		limit = kmsDefaultLimit
	}
	if limit > kmsMaxLimit {
		limit = kmsMaxLimit
	}

	pbReq := &pb.ListKeyVersionsRequest{
		KeyId:  versionsReq.KeyId,
		Limit:  limit,
		Cursor: versionsReq.Cursor,
	}

	pbResp, err := h.kmsService.ListKeyVersions(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to list key versions", "key_id", versionsReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGetKeyVersions", Cause: err})
	}

	versions := make([]*KMSKeyVersionInfoResponse, 0, len(pbResp.Versions))
	for _, v := range pbResp.Versions {
		versions = append(versions, &KMSKeyVersionInfoResponse{
			Version:    v.Version,
			Status:     pbKeyStatusToPlatformKMS(v.Status),
			Algorithm:  pbKeyAlgorithmToPlatformKMS(v.Algorithm),
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		})
	}

	resp := &KMSGetKeyVersionsResponse{
		KeyId:      pbResp.KeyId,
		Versions:   versions,
		NextCursor: pbResp.NextCursor,
		HasMore:    pbResp.HasMore,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSBackendStatus(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	pbResp, err := h.kmsService.BackendStatus(ctx, &pb.BackendStatusRequest{})
	if err != nil {
		h.logger.Error(err, "failed to get KMS backend status")
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSBackendStatus", Cause: err})
	}

	resp := &KMSBackendStatusResponse{
		BackendType:   pbResp.BackendType,
		BackendStatus: pbResp.Status,
		Device:        pbResp.Device,
		Region:        pbResp.Region,
		KeyId:         pbResp.KeyId,
		PcrBanks:      pbResp.PcrBanks,
		PcrRegisters:  pbResp.PcrRegisters,
		Capabilities:  pbResp.Capabilities,
		Timestamp:     time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Batch Operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSBatchEncrypt(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var batchReq KMSBatchEncryptRequest
	if err := quicwire.DecodePayload(req.Payload, &batchReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if batchReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(batchReq.Items) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "items"})
	}

	items := make([]*pb.BatchEncryptItem, 0, len(batchReq.Items))
	for _, item := range batchReq.Items {
		if item == nil {
			return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "items"})
		}
		if len(item.Nonce) > 0 {
			// The QuicBaaS backend generates nonces server-side; a
			// client-supplied nonce cannot be honored and silently
			// dropping it would change the produced ciphertext.
			return h.errorResponse(quicwire.StatusInvalidArgument, ErrKMSInvalidParameter{
				Parameter: "items.nonce",
				Reason:    "client-supplied nonces are not supported for batch encryption",
			})
		}
		items = append(items, &pb.BatchEncryptItem{
			Plaintext: item.Plaintext,
			Context:   item.Context,
		})
	}

	pbResp, err := h.kmsService.BatchEncrypt(ctx, &pb.EncryptBatchRequest{
		KeyId: batchReq.KeyId,
		Items: items,
	})
	if err != nil {
		h.logger.Error(err, "failed to batch encrypt", "key_id", batchReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSBatchEncrypt", Cause: err})
	}

	// The QuicBaaS pb batch messages are positional without item IDs;
	// correlate results back to the request item IDs by position.
	results := make([]*KMSBatchEncryptResultItem, 0, len(pbResp.Results))
	var successCount, failureCount int32
	for i, r := range pbResp.Results {
		result := &KMSBatchEncryptResultItem{
			Status: &KMSStatusResponse{
				Success: r.GetError() == "",
				Message: r.GetError(),
			},
			Ciphertext: r.GetCiphertext(),
			Nonce:      r.GetNonce(),
		}
		if i < len(batchReq.Items) {
			result.ItemId = batchReq.Items[i].ItemId
		}
		if result.Status.Success {
			result.KeyVersion = pbResp.KeyVersion
			successCount++
		} else {
			failureCount++
		}
		results = append(results, result)
	}

	resp := &KMSBatchEncryptResponse{
		KeyId:        pbResp.KeyId,
		Results:      results,
		SuccessCount: successCount,
		FailureCount: failureCount,
		Timestamp:    time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSBatchDecrypt(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var batchReq KMSBatchDecryptRequest
	if err := quicwire.DecodePayload(req.Payload, &batchReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if batchReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(batchReq.Items) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "items"})
	}

	items := make([]*pb.BatchDecryptItem, 0, len(batchReq.Items))
	for _, item := range batchReq.Items {
		if item == nil {
			return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "items"})
		}
		if item.KeyVersion != 0 {
			// The QuicBaaS backend derives the key version from the
			// ciphertext; an explicit per-item key version cannot be
			// honored and silently ignoring it could decrypt with the
			// wrong key material.
			return h.errorResponse(quicwire.StatusInvalidArgument, ErrKMSInvalidParameter{
				Parameter: "items.key_version",
				Reason:    "per-item key versions are not supported for batch decryption",
			})
		}
		items = append(items, &pb.BatchDecryptItem{
			Ciphertext: item.Ciphertext,
			Context:    item.Context,
			Nonce:      item.Nonce,
		})
	}

	pbResp, err := h.kmsService.BatchDecrypt(ctx, &pb.DecryptBatchRequest{
		KeyId: batchReq.KeyId,
		Items: items,
	})
	if err != nil {
		h.logger.Error(err, "failed to batch decrypt", "key_id", batchReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSBatchDecrypt", Cause: err})
	}

	// Correlate positional pb results back to the request item IDs.
	results := make([]*KMSBatchDecryptResultItem, 0, len(pbResp.Results))
	var successCount, failureCount int32
	for i, r := range pbResp.Results {
		result := &KMSBatchDecryptResultItem{
			Status: &KMSStatusResponse{
				Success: r.GetError() == "",
				Message: r.GetError(),
			},
			Plaintext: r.GetPlaintext(),
		}
		if i < len(batchReq.Items) {
			result.ItemId = batchReq.Items[i].ItemId
		}
		if result.Status.Success {
			successCount++
		} else {
			failureCount++
		}
		results = append(results, result)
	}

	resp := &KMSBatchDecryptResponse{
		KeyId:        pbResp.KeyId,
		Results:      results,
		SuccessCount: successCount,
		FailureCount: failureCount,
		Timestamp:    time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Crypto Operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSEncrypt(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var encryptReq KMSEncryptRequest
	if err := quicwire.DecodePayload(req.Payload, &encryptReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if encryptReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(encryptReq.Plaintext) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "plaintext"})
	}

	pbReq := &pb.CryptoEncryptRequest{
		KeyId:     encryptReq.KeyId,
		Plaintext: encryptReq.Plaintext,
		Context:   encryptReq.Context,
		Nonce:     encryptReq.Nonce,
	}

	pbResp, err := h.kmsService.Encrypt(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to encrypt data", "key_id", encryptReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSEncrypt", Cause: err})
	}

	resp := &KMSEncryptResponse{
		KeyId:      pbResp.KeyId,
		KeyVersion: pbResp.KeyVersion,
		Ciphertext: pbResp.Ciphertext,
		Nonce:      pbResp.Nonce,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSDecrypt(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var decryptReq KMSDecryptRequest
	if err := quicwire.DecodePayload(req.Payload, &decryptReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if decryptReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(decryptReq.Ciphertext) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "ciphertext"})
	}

	pbReq := &pb.CryptoDecryptRequest{
		KeyId:      decryptReq.KeyId,
		Ciphertext: decryptReq.Ciphertext,
		Context:    decryptReq.Context,
		Nonce:      decryptReq.Nonce,
		KeyVersion: decryptReq.KeyVersion,
	}

	pbResp, err := h.kmsService.Decrypt(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to decrypt data", "key_id", decryptReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSDecrypt", Cause: err})
	}

	resp := &KMSDecryptResponse{
		KeyId:      pbResp.KeyId,
		KeyVersion: pbResp.KeyVersion,
		Plaintext:  pbResp.Plaintext,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSSign(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var signReq KMSSignRequest
	if err := quicwire.DecodePayload(req.Payload, &signReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if signReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(signReq.Message) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "message"})
	}

	hashAlg, err := platformKMSHashToPb(signReq.HashAlgorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbReq := &pb.SignRequest{
		KeyId:         signReq.KeyId,
		Message:       signReq.Message,
		HashAlgorithm: hashAlg,
		PreHashed:     signReq.PreHashed,
	}

	pbResp, err := h.kmsService.Sign(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to sign message", "key_id", signReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSSign", Cause: err})
	}

	resp := &KMSSignResponse{
		KeyId:         pbResp.KeyId,
		KeyVersion:    pbResp.KeyVersion,
		Signature:     pbResp.Signature,
		HashAlgorithm: pbHashAlgorithmToPlatformKMS(pbResp.HashAlgorithm),
		Timestamp:     time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSVerify(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var verifyReq KMSVerifyRequest
	if err := quicwire.DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if verifyReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(verifyReq.Message) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "message"})
	}

	if len(verifyReq.Signature) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "signature"})
	}

	hashAlg, err := platformKMSHashToPb(verifyReq.HashAlgorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbReq := &pb.VerifyRequest{
		KeyId:         verifyReq.KeyId,
		Message:       verifyReq.Message,
		Signature:     verifyReq.Signature,
		HashAlgorithm: hashAlg,
		KeyVersion:    verifyReq.KeyVersion,
	}

	pbResp, err := h.kmsService.Verify(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to verify signature", "key_id", verifyReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSVerify", Cause: err})
	}

	resp := &KMSVerifyResponse{
		KeyId:      pbResp.KeyId,
		KeyVersion: pbResp.KeyVersion,
		Valid:      pbResp.Valid,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGenerateRandom(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var randomReq KMSGenerateRandomRequest
	if err := quicwire.DecodePayload(req.Payload, &randomReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if randomReq.NumBytes <= 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "num_bytes"})
	}

	pbReq := &pb.GenerateRandomRequest{
		NumBytes: randomReq.NumBytes,
	}

	pbResp, err := h.kmsService.GenerateRandom(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate random bytes")
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGenerateRandom", Cause: err})
	}

	resp := &KMSGenerateRandomResponse{
		RandomBytes: pbResp.RandomBytes,
		Timestamp:   time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSHash(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var hashReq KMSHashRequest
	if err := quicwire.DecodePayload(req.Payload, &hashReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if len(hashReq.Data) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "data"})
	}

	hashAlg, err := platformKMSHashToPb(hashReq.Algorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbReq := &pb.HashRequest{
		Data:      hashReq.Data,
		Algorithm: hashAlg,
	}

	pbResp, err := h.kmsService.Hash(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to hash data")
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSHash", Cause: err})
	}

	resp := &KMSHashResponse{
		Algorithm: pbHashAlgorithmToPlatformKMS(pbResp.Algorithm),
		Hash:      pbResp.Hash,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSHMAC(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var hmacReq KMSHMACRequest
	if err := quicwire.DecodePayload(req.Payload, &hmacReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if hmacReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(hmacReq.Message) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "message"})
	}

	hashAlg, err := platformKMSHashToPb(hmacReq.HashAlgorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbResp, err := h.kmsService.GenerateHMAC(ctx, &pb.HMACRequest{
		KeyId:         hmacReq.KeyId,
		Message:       hmacReq.Message,
		HashAlgorithm: hashAlg,
	})
	if err != nil {
		h.logger.Error(err, "failed to generate HMAC", "key_id", hmacReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSHMAC", Cause: err})
	}

	resp := &KMSHMACResponse{
		KeyId:         pbResp.KeyId,
		KeyVersion:    pbResp.KeyVersion,
		Hmac:          pbResp.Hmac,
		HashAlgorithm: pbHashAlgorithmToPlatformKMS(pbResp.HashAlgorithm),
		Timestamp:     time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSVerifyHMAC(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var verifyReq KMSVerifyHMACRequest
	if err := quicwire.DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if verifyReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(verifyReq.Message) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "message"})
	}

	if len(verifyReq.Hmac) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "hmac"})
	}

	hashAlg, err := platformKMSHashToPb(verifyReq.HashAlgorithm)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	pbResp, err := h.kmsService.VerifyHMAC(ctx, &pb.VerifyHMACRequest{
		KeyId:         verifyReq.KeyId,
		Message:       verifyReq.Message,
		Hmac:          verifyReq.Hmac,
		HashAlgorithm: hashAlg,
		KeyVersion:    verifyReq.KeyVersion,
	})
	if err != nil {
		h.logger.Error(err, "failed to verify HMAC", "key_id", verifyReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSVerifyHMAC", Cause: err})
	}

	resp := &KMSVerifyHMACResponse{
		KeyId:      pbResp.KeyId,
		KeyVersion: pbResp.KeyVersion,
		Valid:      pbResp.Valid,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSRewrap(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var rewrapReq KMSRewrapRequest
	if err := quicwire.DecodePayload(req.Payload, &rewrapReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if rewrapReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	if len(rewrapReq.Ciphertext) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "ciphertext"})
	}

	if rewrapReq.SourceVersion != 0 {
		// The QuicBaaS backend derives the source version from the
		// ciphertext; an explicit source version cannot be honored.
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrKMSInvalidParameter{
			Parameter: "source_version",
			Reason:    "explicit source versions are not supported; use 0 to auto-detect",
		})
	}

	pbResp, err := h.kmsService.Rewrap(ctx, &pb.RewrapRequest{
		KeyId:      rewrapReq.KeyId,
		Ciphertext: rewrapReq.Ciphertext,
		Context:    rewrapReq.Context,
		Nonce:      rewrapReq.Nonce,
	})
	if err != nil {
		h.logger.Error(err, "failed to rewrap ciphertext", "key_id", rewrapReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSRewrap", Cause: err})
	}

	resp := &KMSRewrapResponse{
		KeyId:         pbResp.KeyId,
		SourceVersion: pbResp.OldKeyVersion,
		TargetVersion: pbResp.NewKeyVersion,
		Ciphertext:    pbResp.Ciphertext,
		Nonce:         pbResp.Nonce,
		Timestamp:     time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Conversion Helpers
// =============================================================================

func convertKeyHandleToQUIC(k *pb.KeyHandle) *KMSKeyHandleResponse {
	if k == nil {
		return nil
	}
	return &KMSKeyHandleResponse{
		KeyId:     k.KeyId,
		Version:   k.Version,
		Algorithm: pbKeyAlgorithmToPlatformKMS(k.Algorithm),
		Status:    pbKeyStatusToPlatformKMS(k.Status),
		CreatedAt: k.CreatedAt,
	}
}

func convertKeyMetadataToQUIC(m *pb.KeyMetadata) *KMSKeyMetadataResponse {
	if m == nil {
		return nil
	}
	return &KMSKeyMetadataResponse{
		KeyId:              m.KeyId,
		Name:               m.Name,
		Description:        m.Description,
		Algorithm:          pbKeyAlgorithmToPlatformKMS(m.Algorithm),
		Status:             pbKeyStatusToPlatformKMS(m.Status),
		Usage:              pbKeyUsagesToPlatformKMS(m.Usage),
		Version:            m.Version,
		Exportable:         m.Exportable,
		DeletionProtection: m.DeletionProtection,
		CreatedAt:          m.CreatedAt,
		UpdatedAt:          m.UpdatedAt,
		LastUsedAt:         m.LastUsedAt,
		Tags:               m.Tags,
		Owner:              m.Owner,
	}
}

// =============================================================================
// Data Key Operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSGenerateDataKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.cryptoService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "crypto"})
	}

	var dataKeyReq KMSGenerateDataKeyQUICRequest
	if err := quicwire.DecodePayload(req.Payload, &dataKeyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if dataKeyReq.KeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	// Build key attributes; an unspecified algorithm defaults to AES-256-GCM.
	keySpec, err := buildDataKeySpecForQUIC(dataKeyReq.Algorithm, dataKeyReq.KeySize)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	// Build and execute the request
	pbReq := &pb.GenerateDataKeyRequest{
		KeyId:   dataKeyReq.KeyId,
		KeySpec: keySpec,
		Context: dataKeyReq.Context,
	}

	pbResp, err := h.cryptoService.GenerateDataKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate data key", "key_id", dataKeyReq.KeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGenerateDataKey", Cause: err})
	}

	resp := &KMSGenerateDataKeyQUICResponse{
		PlaintextKey: pbResp.Plaintext,
		EncryptedKey: pbResp.CiphertextBlob,
		KeyId:        pbResp.KeyId,
		Timestamp:    time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("generated data encryption key",
		"key_id", dataKeyReq.KeyId,
		"algorithm", keySpec.Algorithm.String(),
	)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

func (h *QUICServiceHandler) handleKMSGenerateWrappedDataKey(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.cryptoService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "crypto"})
	}

	var dataKeyReq KMSGenerateWrappedDataKeyQUICRequest
	if err := quicwire.DecodePayload(req.Payload, &dataKeyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if dataKeyReq.WrappingKeyId == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "wrapping_key_id"})
	}

	if platformv1.WrappingAlgorithm(dataKeyReq.WrappingAlgorithm) != platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED {
		// The QuicBaaS backend wraps data keys with the master key's own
		// algorithm; an explicit wrapping algorithm cannot be honored.
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrKMSInvalidParameter{
			Parameter: "wrapping_algorithm",
			Reason:    "explicit wrapping algorithms are not supported for wrapped data keys",
		})
	}

	// Build key attributes; an unspecified algorithm defaults to AES-256-GCM.
	keySpec, err := buildDataKeySpecForQUIC(dataKeyReq.KeyAlgorithm, dataKeyReq.KeySize)
	if err != nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, err)
	}

	// Build and execute the request
	pbReq := &pb.GenerateWrappedDataKeyRequest{
		KeyId:   dataKeyReq.WrappingKeyId,
		KeySpec: keySpec,
		Context: dataKeyReq.Context,
	}

	pbResp, err := h.cryptoService.GenerateWrappedDataKey(ctx, pbReq)
	if err != nil {
		h.logger.Error(err, "failed to generate wrapped data key", "wrapping_key_id", dataKeyReq.WrappingKeyId)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGenerateWrappedDataKey", Cause: err})
	}

	resp := &KMSGenerateWrappedDataKeyQUICResponse{
		WrappedKey:        pbResp.CiphertextBlob,
		WrappingKeyId:     pbResp.KeyId,
		WrappingAlgorithm: int32(platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED),
		Timestamp:         time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("generated wrapped data encryption key",
		"wrapping_key_id", dataKeyReq.WrappingKeyId,
		"algorithm", keySpec.Algorithm.String(),
	)

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// buildDataKeySpecForQUIC builds a pb KeySpec for data key generation from a
// platform.v1 KMSKeyAlgorithm value and a key_size in bits, resolved by
// kmssdk.ResolveDataKey: an unspecified algorithm is the AES-GCM variant of
// key_size, AES-256-GCM when key_size is 0.
func buildDataKeySpecForQUIC(algorithm, keySize int32) (*pb.KeySpec, error) {
	resolved, bits, err := kmssdk.ResolveDataKey(platformv1.KMSKeyAlgorithm(algorithm), keySize)
	var algErr *kmssdk.ErrUnsupportedDataKeyAlgorithm
	if errors.As(err, &algErr) {
		return nil, ErrKMSInvalidAlgorithm{Algorithm: algErr.Algorithm.String()}
	}
	if err != nil {
		return nil, err
	}
	return &pb.KeySpec{Algorithm: quicDataKeyAlgorithms[resolved], KeySize: bits}, nil
}

// quicDataKeyAlgorithms maps each data-key algorithm ResolveDataKey returns
// to its quicbaas AEAD.
var quicDataKeyAlgorithms = map[platformv1.KMSKeyAlgorithm]pb.KeyAlgorithm{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128:           pb.KeyAlgorithm_KEY_ALG_AES_128_GCM,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192:           pb.KeyAlgorithm_KEY_ALG_AES_192_GCM,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:           pb.KeyAlgorithm_KEY_ALG_AES_256_GCM,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305: pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305,
}

// =============================================================================
// KMS QUIC Adapter
// =============================================================================

// kmsQUICAdapter implements KMSServiceInterface by composing the KMSServerAdapter
// (key management) and CryptoServerAdapter (crypto operations) from a KMSService.
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

func (a *kmsQUICAdapter) RevokeKey(ctx context.Context, req *pb.RevokeKeyRequest) (*pb.RevokeKeyResponse, error) {
	return a.kms.RevokeKey(ctx, req)
}

func (a *kmsQUICAdapter) GetKeyMetadata(ctx context.Context, req *pb.GetKeyMetadataRequest) (*pb.GetKeyMetadataResponse, error) {
	return a.kms.GetKeyMetadata(ctx, req)
}

func (a *kmsQUICAdapter) UpdateKeyMetadata(ctx context.Context, req *pb.UpdateKeyMetadataRequest) (*pb.UpdateKeyMetadataResponse, error) {
	return a.kms.UpdateKeyMetadata(ctx, req)
}

func (a *kmsQUICAdapter) SetKeyPolicy(ctx context.Context, req *pb.SetKeyPolicyRequest) (*pb.SetKeyPolicyResponse, error) {
	return a.kms.SetKeyPolicy(ctx, req)
}

func (a *kmsQUICAdapter) GetKeyPolicy(ctx context.Context, req *pb.GetKeyPolicyRequest) (*pb.GetKeyPolicyResponse, error) {
	return a.kms.GetKeyPolicy(ctx, req)
}

func (a *kmsQUICAdapter) GetSupportedAlgorithms(ctx context.Context, req *pb.GetSupportedAlgorithmsRequest) (*pb.GetSupportedAlgorithmsResponse, error) {
	return a.kms.GetSupportedAlgorithms(ctx, req)
}

func (a *kmsQUICAdapter) BackendStatus(ctx context.Context, req *pb.BackendStatusRequest) (*pb.BackendStatusResponse, error) {
	return a.kms.BackendStatus(ctx, req)
}

func (a *kmsQUICAdapter) ImportKey(ctx context.Context, req *pb.ImportKeyRequest) (*pb.ImportKeyResponse, error) {
	return a.kms.ImportKey(ctx, req)
}

func (a *kmsQUICAdapter) UpdateKeyStatus(ctx context.Context, req *pb.UpdateKeyStatusRequest) (*pb.UpdateKeyStatusResponse, error) {
	return a.kms.UpdateKeyStatus(ctx, req)
}

func (a *kmsQUICAdapter) ExportKey(ctx context.Context, req *pb.ExportKeyRequest) (*pb.ExportKeyResponse, error) {
	return a.kms.ExportKey(ctx, req)
}

func (a *kmsQUICAdapter) ListKeyVersions(ctx context.Context, req *pb.ListKeyVersionsRequest) (*pb.ListKeyVersionsResponse, error) {
	return a.kms.ListKeyVersions(ctx, req)
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

func (a *kmsQUICAdapter) GenerateHMAC(ctx context.Context, req *pb.HMACRequest) (*pb.HMACResponse, error) {
	return a.crypto.GenerateHMAC(ctx, req)
}

func (a *kmsQUICAdapter) VerifyHMAC(ctx context.Context, req *pb.VerifyHMACRequest) (*pb.VerifyHMACResponse, error) {
	return a.crypto.VerifyHMAC(ctx, req)
}

func (a *kmsQUICAdapter) Rewrap(ctx context.Context, req *pb.RewrapRequest) (*pb.RewrapResponse, error) {
	return a.crypto.Rewrap(ctx, req)
}

func (a *kmsQUICAdapter) BatchEncrypt(ctx context.Context, req *pb.EncryptBatchRequest) (*pb.EncryptBatchResponse, error) {
	return a.crypto.EncryptBatch(ctx, req)
}

func (a *kmsQUICAdapter) BatchDecrypt(ctx context.Context, req *pb.DecryptBatchRequest) (*pb.DecryptBatchResponse, error) {
	return a.crypto.DecryptBatch(ctx, req)
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

func (a *kmsQUICAdapter) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	return a.crypto.Hash(ctx, req)
}
