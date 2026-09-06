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

// Package kms provides integration test adapters for KMS services.
// This file implements the KMSCommands interface using the QUIC protocol.

//go:build integration

package kms

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// Environment Variables and Constants
// =============================================================================

const (
	// EnvPlatformQUICEndpoint is the environment variable for the QUIC endpoint.
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// DefaultQUICEndpoint is the default QUIC endpoint address.
	DefaultQUICEndpoint = "localhost:9444"

	// DefaultQUICTimeout is the default timeout for QUIC operations.
	DefaultQUICTimeout = 30 * time.Second

	// DefaultQUICMaxIdleTimeout is the default max idle timeout for connections.
	DefaultQUICMaxIdleTimeout = 60 * time.Second

	// QUICProtocolVersion is the QUIC wire protocol version.
	QUICProtocolVersion byte = 0x01

	// MaxQUICPayloadSize is the maximum payload size (16MB).
	MaxQUICPayloadSize uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSize is the maximum token size (8KB).
	MaxQUICTokenSize uint16 = 8 * 1024
)

// QUIC Status codes.
const (
	QUICStatusOK                byte = 0x00
	QUICStatusInvalidRequest    byte = 0x01
	QUICStatusNotFound          byte = 0x02
	QUICStatusUnauthorized      byte = 0x03
	QUICStatusInternalError     byte = 0x04
	QUICStatusTimeout           byte = 0x05
	QUICStatusAlreadyExists     byte = 0x06
	QUICStatusPermissionDenied  byte = 0x07
	QUICStatusResourceExhausted byte = 0x08
	QUICStatusInvalidArgument   byte = 0x09
	QUICStatusUnavailable       byte = 0x0A
)

// QUIC Operation codes for KMS operations.
const (
	// KMS Key Operations (0xD0-0xD7).
	OpQUICKMSGenerateKey byte = 0xD0
	OpQUICKMSImportKey   byte = 0xD1
	OpQUICKMSGetKey      byte = 0xD2
	OpQUICKMSListKeys    byte = 0xD3
	OpQUICKMSRotateKey   byte = 0xD4
	OpQUICKMSDeleteKey   byte = 0xD5
	OpQUICKMSEncrypt     byte = 0xD6
	OpQUICKMSDecrypt     byte = 0xD7

	// KMS DEK Operations (0xD8-0xDF).
	OpQUICKMSDEKCreate     byte = 0xD8
	OpQUICKMSDEKGet        byte = 0xD9
	OpQUICKMSDEKList       byte = 0xDA
	OpQUICKMSDEKRotate     byte = 0xDB
	OpQUICKMSDEKDelete     byte = 0xDC
	OpQUICKMSDEKStatus     byte = 0xDD
	OpQUICKMSDEKSetDefault byte = 0xDE
	OpQUICKMSDEKSetSafety  byte = 0xDF

	// Secrets Operations (0xE0-0xE6).
	OpQUICSecretsStore        byte = 0xE0
	OpQUICSecretsGet          byte = 0xE1
	OpQUICSecretsList         byte = 0xE2
	OpQUICSecretsDelete       byte = 0xE3
	OpQUICSecretsListVersions byte = 0xE4
	OpQUICSecretsRollback     byte = 0xE5
	OpQUICSecretsRotate       byte = 0xE6

	// Extended KMS Operations (0xE7-0xEC).
	OpQUICKMSDEKClearSafety byte = 0xE7
	OpQUICKMSBackendStatus  byte = 0xE8
	OpQUICKMSBackendTest    byte = 0xE9
	OpQUICKMSKeyVersions    byte = 0xEA
	OpQUICKMSKeyStatus      byte = 0xEB
	OpQUICKMSKeyRevoke      byte = 0xEC

	// KMS Metadata Operations (0xED-0xEF).
	OpQUICKMSKeyMetadata       byte = 0xED
	OpQUICKMSKeyMetadataUpdate byte = 0xEE
	OpQUICKMSKeyAlgorithms     byte = 0xEF

	// KMS Policy Operations (0x70-0x71 - reusing available range).
	OpQUICKMSKeyPolicy    byte = 0x70
	OpQUICKMSKeyPolicySet byte = 0x71

	// Crypto Operations (0xF0-0xF7).
	OpQUICCryptoEncrypt byte = 0xF0
	OpQUICCryptoDecrypt byte = 0xF1
	OpQUICCryptoRewrap  byte = 0xF2
	OpQUICCryptoSign    byte = 0xF3
	OpQUICCryptoVerify  byte = 0xF4
	OpQUICCryptoHash    byte = 0xF5
	OpQUICCryptoRandom  byte = 0xF6
	OpQUICCryptoDataKey byte = 0xF7

	// HMAC Operations (0xF8-0xF9).
	OpQUICCryptoHMAC       byte = 0xF8
	OpQUICCryptoVerifyHMAC byte = 0xF9

	// Secrets Status Operations (0xFA).
	OpQUICSecretsStatus byte = 0xFA
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICConnectionFailed indicates a QUIC connection failure.
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICRequestFailed indicates a QUIC request failure.
type ErrQUICRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICEncodeFailed indicates payload encoding failure.
type ErrQUICEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICDecodeFailed indicates payload decoding failure.
type ErrQUICDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICStreamFailed indicates a stream operation failure.
type ErrQUICStreamFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICStreamFailed) Error() string {
	return fmt.Sprintf("QUIC stream operation %s failed: %v", e.Operation, e.Err)
}

func (e ErrQUICStreamFailed) Unwrap() error {
	return e.Err
}

// ErrQUICClientClosed indicates the client is closed.
type ErrQUICClientClosed struct{}

func (e ErrQUICClientClosed) Error() string {
	return "QUIC client is closed"
}

// =============================================================================
// Wire Protocol Types
// =============================================================================

// quicRequest represents a QUIC protocol request.
// Wire format: [opcode:1][tokenLen:2][token:N][payloadLen:4][payload:M].
type quicRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

// quicResponse represents a QUIC protocol response.
// Wire format: [status:1][payloadLen:4][payload:N].
type quicResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// Request/Response Payload Types (MessagePack encoded)
// =============================================================================

// keyGenerateRequest is the wire format for key generation.
type keyGenerateRequest struct {
	KeyID              string `codec:"key_id"`
	Algorithm          string `codec:"algorithm"`
	Purpose            string `codec:"purpose"`
	Exportable         bool   `codec:"exportable"`
	DeletionProtection bool   `codec:"deletion_protection"`
	Name               string `codec:"name"`
	Description        string `codec:"description"`
	Owner              string `codec:"owner"`
}

// keyGenerateResponse is the wire format for key generation response.
type keyGenerateResponse struct {
	KeyID              string `codec:"key_id"`
	Version            uint64 `codec:"version"`
	Algorithm          string `codec:"algorithm"`
	Status             string `codec:"status"`
	CreatedAt          int64  `codec:"created_at"`
	Name               string `codec:"name"`
	Description        string `codec:"description"`
	Exportable         bool   `codec:"exportable"`
	DeletionProtection bool   `codec:"deletion_protection"`
}

// keyGetRequest is the wire format for key retrieval.
type keyGetRequest struct {
	KeyID   string `codec:"key_id"`
	Version uint64 `codec:"version"`
}

// keyGetResponse is the wire format for key retrieval response.
type keyGetResponse struct {
	KeyID              string   `codec:"key_id"`
	Version            uint64   `codec:"version"`
	Algorithm          string   `codec:"algorithm"`
	Status             string   `codec:"status"`
	CreatedAt          int64    `codec:"created_at"`
	UpdatedAt          int64    `codec:"updated_at"`
	LastUsedAt         int64    `codec:"last_used_at"`
	Name               string   `codec:"name"`
	Description        string   `codec:"description"`
	Owner              string   `codec:"owner"`
	Exportable         bool     `codec:"exportable"`
	DeletionProtection bool     `codec:"deletion_protection"`
	Usage              []string `codec:"usage"`
}

// keyListRequest is the wire format for key listing.
type keyListRequest struct {
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// keyListResponse is the wire format for key listing response.
type keyListResponse struct {
	Keys       []keySummary `codec:"keys"`
	TotalCount int32        `codec:"total_count"`
	HasMore    bool         `codec:"has_more"`
	NextCursor string       `codec:"next_cursor"`
}

// keySummary is the wire format for key summary.
type keySummary struct {
	KeyID     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	Algorithm string `codec:"algorithm"`
	Status    string `codec:"status"`
	CreatedAt int64  `codec:"created_at"`
}

// keyDeleteRequest is the wire format for key deletion.
type keyDeleteRequest struct {
	KeyID             string `codec:"key_id"`
	PendingWindowDays int32  `codec:"pending_window_days"`
	Force             bool   `codec:"force"`
}

// keyDeleteResponse is the wire format for key deletion response.
type keyDeleteResponse struct {
	KeyID        string `codec:"key_id"`
	Status       string `codec:"status"`
	DeletionDate int64  `codec:"deletion_date"`
}

// keyRotateRequest is the wire format for key rotation.
type keyRotateRequest struct {
	KeyID            string `codec:"key_id"`
	RetainOldVersion bool   `codec:"retain_old_version"`
}

// keyRotateResponse is the wire format for key rotation response.
type keyRotateResponse struct {
	KeyID      string `codec:"key_id"`
	OldVersion uint64 `codec:"old_version"`
	NewVersion uint64 `codec:"new_version"`
	RotatedAt  int64  `codec:"rotated_at"`
}

// keyVersionsRequest is the wire format for key versions listing.
type keyVersionsRequest struct {
	KeyID  string `codec:"key_id"`
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// keyVersionsResponse is the wire format for key versions response.
type keyVersionsResponse struct {
	KeyID      string           `codec:"key_id"`
	Versions   []keyVersionInfo `codec:"versions"`
	HasMore    bool             `codec:"has_more"`
	NextCursor string           `codec:"next_cursor"`
}

// keyVersionInfo is the wire format for key version info.
type keyVersionInfo struct {
	Version    uint64 `codec:"version"`
	Algorithm  string `codec:"algorithm"`
	Status     string `codec:"status"`
	CreatedAt  int64  `codec:"created_at"`
	DisabledAt int64  `codec:"disabled_at"`
}

// keyStatusRequest is the wire format for key status update.
type keyStatusRequest struct {
	KeyID   string `codec:"key_id"`
	Version uint64 `codec:"version"`
	Enabled bool   `codec:"enabled"`
}

// keyStatusResponse is the wire format for key status response.
type keyStatusResponse struct {
	KeyID     string `codec:"key_id"`
	Version   uint64 `codec:"version"`
	Status    string `codec:"status"`
	UpdatedAt int64  `codec:"updated_at"`
}

// keyRevokeRequest is the wire format for key revocation.
type keyRevokeRequest struct {
	KeyID  string `codec:"key_id"`
	Reason string `codec:"reason"`
}

// keyRevokeResponse is the wire format for key revocation response.
type keyRevokeResponse struct {
	KeyID     string `codec:"key_id"`
	Status    string `codec:"status"`
	RevokedAt int64  `codec:"revoked_at"`
}

// keyMetadataRequest is the wire format for key metadata retrieval.
type keyMetadataRequest struct {
	KeyID string `codec:"key_id"`
}

// keyMetadataResponse is the wire format for key metadata response.
type keyMetadataResponse struct {
	KeyID              string            `codec:"key_id"`
	Name               string            `codec:"name"`
	Description        string            `codec:"description"`
	Algorithm          string            `codec:"algorithm"`
	Status             string            `codec:"status"`
	Version            uint64            `codec:"version"`
	Exportable         bool              `codec:"exportable"`
	DeletionProtection bool              `codec:"deletion_protection"`
	Usage              []string          `codec:"usage"`
	Owner              string            `codec:"owner"`
	CreatedAt          int64             `codec:"created_at"`
	UpdatedAt          int64             `codec:"updated_at"`
	LastUsedAt         int64             `codec:"last_used_at"`
	Tags               map[string]string `codec:"tags"`
	RotationPolicy     *rotationPolicy   `codec:"rotation_policy"`
}

// rotationPolicy is the wire format for rotation policy.
type rotationPolicy struct {
	Enabled         bool  `codec:"enabled"`
	IntervalSeconds int64 `codec:"interval_seconds"`
	NextRotation    int64 `codec:"next_rotation"`
	RetainVersions  int32 `codec:"retain_versions"`
}

// keyMetadataUpdateRequest is the wire format for key metadata update.
type keyMetadataUpdateRequest struct {
	KeyID       string            `codec:"key_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Tags        map[string]string `codec:"tags"`
	RemoveTags  []string          `codec:"remove_tags"`
}

// keyMetadataUpdateResponse is the wire format for key metadata update response.
type keyMetadataUpdateResponse struct {
	KeyID     string            `codec:"key_id"`
	Name      string            `codec:"name"`
	UpdatedAt int64             `codec:"updated_at"`
	Tags      map[string]string `codec:"tags"`
}

// keyPolicyRequest is the wire format for key policy retrieval.
type keyPolicyRequest struct {
	KeyID string `codec:"key_id"`
}

// keyPolicyResponse is the wire format for key policy response.
type keyPolicyResponse struct {
	KeyID             string   `codec:"key_id"`
	Version           int32    `codec:"version"`
	AllowedOperations []string `codec:"allowed_operations"`
	AllowedPrincipals []string `codec:"allowed_principals"`
	DeniedPrincipals  []string `codec:"denied_principals"`
	ExpiresAt         int64    `codec:"expires_at"`
	RotationRequired  bool     `codec:"rotation_required"`
	MaxUsageCount     uint64   `codec:"max_usage_count"`
	RequireMFA        bool     `codec:"require_mfa"`
	UpdatedAt         int64    `codec:"updated_at"`
}

// keyPolicySetRequest is the wire format for key policy set.
type keyPolicySetRequest struct {
	KeyID            string   `codec:"key_id"`
	Operations       []string `codec:"operations"`
	AllowPrincipals  []string `codec:"allow_principals"`
	DenyPrincipals   []string `codec:"deny_principals"`
	ExpiresIn        string   `codec:"expires_in"`
	RotationRequired bool     `codec:"rotation_required"`
	MaxUsageCount    uint64   `codec:"max_usage_count"`
	RequireMFA       bool     `codec:"require_mfa"`
}

// keyPolicySetResponse is the wire format for key policy set response.
type keyPolicySetResponse struct {
	KeyID         string `codec:"key_id"`
	PolicyVersion int32  `codec:"policy_version"`
	UpdatedAt     int64  `codec:"updated_at"`
}

// keyAlgorithmsResponse is the wire format for key algorithms response.
type keyAlgorithmsResponse struct {
	Algorithms []string `codec:"algorithms"`
}

// cryptoEncryptRequest is the wire format for encryption.
type cryptoEncryptRequest struct {
	KeyID     string `codec:"key_id"`
	Plaintext []byte `codec:"plaintext"`
	Context   []byte `codec:"context"`
	Nonce     []byte `codec:"nonce"`
}

// cryptoEncryptResponse is the wire format for encryption response.
type cryptoEncryptResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Ciphertext []byte `codec:"ciphertext"`
	Nonce      []byte `codec:"nonce"`
	Timestamp  int64  `codec:"timestamp"`
}

// cryptoDecryptRequest is the wire format for decryption.
type cryptoDecryptRequest struct {
	KeyID      string `codec:"key_id"`
	Ciphertext []byte `codec:"ciphertext"`
	Context    []byte `codec:"context"`
	Nonce      []byte `codec:"nonce"`
	KeyVersion uint64 `codec:"key_version"`
}

// cryptoDecryptResponse is the wire format for decryption response.
type cryptoDecryptResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Plaintext  []byte `codec:"plaintext"`
	Timestamp  int64  `codec:"timestamp"`
}

// cryptoSignRequest is the wire format for signing.
type cryptoSignRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm string `codec:"hash_algorithm"`
}

// cryptoSignResponse is the wire format for signing response.
type cryptoSignResponse struct {
	KeyID         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm string `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// cryptoVerifyRequest is the wire format for verification.
type cryptoVerifyRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	Signature     []byte `codec:"signature"`
	HashAlgorithm string `codec:"hash_algorithm"`
	KeyVersion    uint64 `codec:"key_version"`
}

// cryptoVerifyResponse is the wire format for verification response.
type cryptoVerifyResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// cryptoHashRequest is the wire format for hashing.
type cryptoHashRequest struct {
	Data      []byte `codec:"data"`
	Algorithm string `codec:"algorithm"`
}

// cryptoHashResponse is the wire format for hash response.
type cryptoHashResponse struct {
	Algorithm string `codec:"algorithm"`
	Hash      []byte `codec:"hash"`
	Timestamp int64  `codec:"timestamp"`
}

// cryptoHMACRequest is the wire format for HMAC generation.
type cryptoHMACRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HashAlgorithm string `codec:"hash_algorithm"`
}

// cryptoHMACResponse is the wire format for HMAC response.
type cryptoHMACResponse struct {
	KeyID         string `codec:"key_id"`
	KeyVersion    uint64 `codec:"key_version"`
	HMAC          []byte `codec:"hmac"`
	HashAlgorithm string `codec:"hash_algorithm"`
	Timestamp     int64  `codec:"timestamp"`
}

// cryptoVerifyHMACRequest is the wire format for HMAC verification.
type cryptoVerifyHMACRequest struct {
	KeyID         string `codec:"key_id"`
	Message       []byte `codec:"message"`
	HMAC          []byte `codec:"hmac"`
	HashAlgorithm string `codec:"hash_algorithm"`
	KeyVersion    uint64 `codec:"key_version"`
}

// cryptoVerifyHMACResponse is the wire format for HMAC verification response.
type cryptoVerifyHMACResponse struct {
	KeyID      string `codec:"key_id"`
	KeyVersion uint64 `codec:"key_version"`
	Valid      bool   `codec:"valid"`
	Timestamp  int64  `codec:"timestamp"`
}

// cryptoRandomRequest is the wire format for random bytes.
type cryptoRandomRequest struct {
	NumBytes int32 `codec:"num_bytes"`
}

// cryptoRandomResponse is the wire format for random bytes response.
type cryptoRandomResponse struct {
	RandomBytes []byte `codec:"random_bytes"`
	Timestamp   int64  `codec:"timestamp"`
}

// dekCreateRequest is the wire format for DEK creation.
type dekCreateRequest struct {
	Path           string `codec:"path"`
	Algorithm      string `codec:"algorithm"`
	Description    string `codec:"description"`
	MaxOperations  uint64 `codec:"max_operations"`
	MaxBytes       uint64 `codec:"max_bytes"`
	WarningPercent int32  `codec:"warning_percent"`
}

// dekCreateResponse is the wire format for DEK creation response.
type dekCreateResponse struct {
	Path        string `codec:"path"`
	Algorithm   string `codec:"algorithm"`
	Version     uint64 `codec:"version"`
	CreatedAt   int64  `codec:"created_at"`
	Description string `codec:"description"`
}

// dekGetRequest is the wire format for DEK retrieval.
type dekGetRequest struct {
	Path string `codec:"path"`
}

// dekGetResponse is the wire format for DEK retrieval response.
type dekGetResponse struct {
	Path           string `codec:"path"`
	Algorithm      string `codec:"algorithm"`
	Version        uint64 `codec:"version"`
	Status         string `codec:"status"`
	IsDefault      bool   `codec:"is_default"`
	CreatedAt      int64  `codec:"created_at"`
	RotatedAt      int64  `codec:"rotated_at"`
	Description    string `codec:"description"`
	BackendType    string `codec:"backend_type"`
	UsageCount     uint64 `codec:"usage_count"`
	BytesUsed      uint64 `codec:"bytes_used"`
	MaxUsageCount  uint64 `codec:"max_usage_count"`
	MaxBytesUsed   uint64 `codec:"max_bytes_used"`
	WarningPercent int32  `codec:"warning_percent"`
}

// dekListRequest is the wire format for DEK listing.
type dekListRequest struct {
	Prefix    string `codec:"prefix"`
	Recursive bool   `codec:"recursive"`
	Limit     int32  `codec:"limit"`
	Cursor    string `codec:"cursor"`
}

// dekListResponse is the wire format for DEK listing response.
type dekListResponse struct {
	DEKs       []dekSummary `codec:"deks"`
	HasMore    bool         `codec:"has_more"`
	NextCursor string       `codec:"next_cursor"`
}

// dekSummary is the wire format for DEK summary.
type dekSummary struct {
	Path      string `codec:"path"`
	Algorithm string `codec:"algorithm"`
	Version   uint64 `codec:"version"`
	Status    string `codec:"status"`
	IsDefault bool   `codec:"is_default"`
	CreatedAt int64  `codec:"created_at"`
}

// dekDeleteRequest is the wire format for DEK deletion.
type dekDeleteRequest struct {
	Path      string `codec:"path"`
	Force     bool   `codec:"force"`
	MigrateTo string `codec:"migrate_to"`
}

// dekDeleteResponse is the wire format for DEK deletion response.
type dekDeleteResponse struct {
	Path    string `codec:"path"`
	Deleted bool   `codec:"deleted"`
}

// dekRotateRequest is the wire format for DEK rotation.
type dekRotateRequest struct {
	Path       string `codec:"path"`
	Background bool   `codec:"background"`
}

// dekRotateResponse is the wire format for DEK rotation response.
type dekRotateResponse struct {
	Path       string `codec:"path"`
	OldVersion uint64 `codec:"old_version"`
	NewVersion uint64 `codec:"new_version"`
}

// dekStatusRequest is the wire format for DEK status.
type dekStatusRequest struct {
	Path string `codec:"path"`
}

// dekStatusResponse is the wire format for DEK status response.
type dekStatusResponse struct {
	Path                   string `codec:"path"`
	Algorithm              string `codec:"algorithm"`
	Version                uint64 `codec:"version"`
	Status                 string `codec:"status"`
	IsDefault              bool   `codec:"is_default"`
	CreatedAt              int64  `codec:"created_at"`
	RotatedAt              int64  `codec:"rotated_at"`
	Description            string `codec:"description"`
	BackendType            string `codec:"backend_type"`
	UsageCount             uint64 `codec:"usage_count"`
	BytesUsed              uint64 `codec:"bytes_used"`
	MaxUsageCount          uint64 `codec:"max_usage_count"`
	MaxBytesUsed           uint64 `codec:"max_bytes_used"`
	WarningPercent         int32  `codec:"warning_percent"`
	ReencryptionInProgress bool   `codec:"reencryption_in_progress"`
	ProcessedKeys          int64  `codec:"processed_keys"`
	TotalKeys              int64  `codec:"total_keys"`
	FailedKeys             int64  `codec:"failed_keys"`
	ReencryptionStartedAt  int64  `codec:"reencryption_started_at"`
	EstimatedCompletion    int64  `codec:"estimated_completion"`
}

// secretsStoreRequest is the wire format for secret storage.
type secretsStoreRequest struct {
	Name        string `codec:"name"`
	Data        []byte `codec:"data"`
	Description string `codec:"description"`
	TenantID    string `codec:"tenant_id"`
	KeyID       string `codec:"key_id"`
	Algorithm   string `codec:"algorithm"`
}

// secretsStoreResponse is the wire format for secret storage response.
type secretsStoreResponse struct {
	SecretID  string `codec:"secret_id"`
	Version   uint64 `codec:"version"`
	Timestamp int64  `codec:"timestamp"`
}

// secretsGetRequest is the wire format for secret retrieval.
type secretsGetRequest struct {
	Name string `codec:"name"`
}

// secretsGetResponse is the wire format for secret retrieval response.
type secretsGetResponse struct {
	SecretID      string            `codec:"secret_id"`
	Version       uint64            `codec:"version"`
	Data          []byte            `codec:"data"`
	Metadata      map[string]string `codec:"metadata"`
	Algorithm     string            `codec:"algorithm"`
	KeyIdentifier string            `codec:"key_identifier"`
	CreatedAt     int64             `codec:"created_at"`
	Timestamp     int64             `codec:"timestamp"`
}

// secretsListRequest is the wire format for secrets listing.
type secretsListRequest struct {
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// secretsListResponse is the wire format for secrets listing response.
type secretsListResponse struct {
	Secrets    []secretSummary `codec:"secrets"`
	TotalCount int32           `codec:"total_count"`
	HasMore    bool            `codec:"has_more"`
	NextCursor string          `codec:"next_cursor"`
}

// secretSummary is the wire format for secret summary.
type secretSummary struct {
	Name           string `codec:"name"`
	CurrentVersion uint64 `codec:"current_version"`
	Description    string `codec:"description"`
	Owner          string `codec:"owner"`
	CreatedAt      int64  `codec:"created_at"`
	UpdatedAt      int64  `codec:"updated_at"`
}

// secretsDeleteRequest is the wire format for secret deletion.
type secretsDeleteRequest struct {
	Name      string `codec:"name"`
	Permanent bool   `codec:"permanent"`
}

// secretsDeleteResponse is the wire format for secret deletion response.
type secretsDeleteResponse struct {
	SecretID  string `codec:"secret_id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

// secretsRotateRequest is the wire format for secret rotation.
type secretsRotateRequest struct {
	Name      string `codec:"name"`
	NewData   []byte `codec:"new_data"`
	TenantID  string `codec:"tenant_id"`
	KeyID     string `codec:"key_id"`
	Algorithm string `codec:"algorithm"`
}

// secretsRotateResponse is the wire format for secret rotation response.
type secretsRotateResponse struct {
	SecretID   string `codec:"secret_id"`
	OldVersion uint64 `codec:"old_version"`
	NewVersion uint64 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

// secretsVersionsRequest is the wire format for secrets versions listing.
type secretsVersionsRequest struct {
	Name   string `codec:"name"`
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// secretsVersionsResponse is the wire format for secrets versions response.
type secretsVersionsResponse struct {
	SecretID   string              `codec:"secret_id"`
	Versions   []secretVersionInfo `codec:"versions"`
	HasMore    bool                `codec:"has_more"`
	NextCursor string              `codec:"next_cursor"`
}

// secretVersionInfo is the wire format for secret version info.
type secretVersionInfo struct {
	Version   uint64 `codec:"version"`
	CreatedAt int64  `codec:"created_at"`
	CreatedBy string `codec:"created_by"`
	ExpiresAt int64  `codec:"expires_at"`
}

// secretsVersionRequest is the wire format for specific secret version.
type secretsVersionRequest struct {
	Name    string `codec:"name"`
	Version uint64 `codec:"version"`
}

// secretsVersionResponse is the wire format for specific secret version response.
type secretsVersionResponse struct {
	SecretID  string            `codec:"secret_id"`
	Version   uint64            `codec:"version"`
	Data      []byte            `codec:"data"`
	Metadata  map[string]string `codec:"metadata"`
	CreatedAt int64             `codec:"created_at"`
	CreatedBy string            `codec:"created_by"`
	ExpiresAt int64             `codec:"expires_at"`
	Timestamp int64             `codec:"timestamp"`
}

// secretsRollbackRequest is the wire format for secret rollback.
type secretsRollbackRequest struct {
	Name          string `codec:"name"`
	TargetVersion uint64 `codec:"target_version"`
}

// secretsRollbackResponse is the wire format for secret rollback response.
type secretsRollbackResponse struct {
	SecretID   string `codec:"secret_id"`
	NewVersion uint64 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

// secretsStatusRequest is the wire format for secret status update.
type secretsStatusRequest struct {
	Name    string `codec:"name"`
	Enabled bool   `codec:"enabled"`
}

// secretsStatusResponse is the wire format for secret status response.
type secretsStatusResponse struct {
	SecretID  string `codec:"secret_id"`
	Status    string `codec:"status"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements KMSCommands using the QUIC protocol.
// It provides high-performance, low-latency communication with the platform
// using a binary protocol over QUIC streams with MessagePack encoding.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewQUICAdapter creates a new QUIC adapter for integration testing.
// It reads the endpoint from the PLATFORM_QUIC_ENDPOINT environment variable,
// defaulting to localhost:9444.
func NewQUICAdapter() *QUICAdapter {
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = DefaultQUICEndpoint
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		timeout:        DefaultQUICTimeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
		tlsConfig:      helpers.QUICTLSConfig(),
	}
}

// NewQUICAdapterWithConfig creates a QUIC adapter with explicit configuration.
func NewQUICAdapterWithConfig(endpoint string, tlsConfig *tls.Config, timeout time.Duration) *QUICAdapter {
	if tlsConfig == nil {
		tlsConfig = helpers.QUICTLSConfig()
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		tlsConfig:      tlsConfig,
		timeout:        timeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
	}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection to the platform endpoint.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICClientClosed{}
	}

	// Create connection context with timeout
	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICConnectionFailed{Endpoint: q.endpoint, Err: err}
	}

	q.conn = conn
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return nil
	}

	q.closed = true

	if q.conn != nil {
		return q.conn.CloseWithError(0, "adapter teardown")
	}

	return nil
}

// =============================================================================
// Wire Protocol Methods
// =============================================================================

// sendRequest sends a QUIC request and returns the response.
func (q *QUICAdapter) sendRequest(ctx context.Context, opcode byte, payload interface{}) (*quicResponse, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	// Encode payload
	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = encodePayload(payload)
		if err != nil {
			return nil, ErrQUICEncodeFailed{Operation: opcodeToString(opcode), Err: err}
		}
	}

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "OpenStream", Err: err}
	}
	defer stream.Close()

	// Write request
	req := &quicRequest{
		Opcode:  opcode,
		Payload: payloadBytes,
	}

	if err := writeRequest(stream, req); err != nil {
		return nil, ErrQUICStreamFailed{Operation: "WriteRequest", Err: err}
	}

	// Read response
	resp, err := readResponse(stream)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "ReadResponse", Err: err}
	}

	// Check status
	if resp.Status != QUICStatusOK {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICRequestFailed{
			Operation: opcodeToString(opcode),
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

// writeRequest writes a request to the stream.
func writeRequest(w io.Writer, req *quicRequest) error {
	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxQUICPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSize)
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > MaxQUICTokenSize {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxQUICTokenSize)
	}

	// Write opcode
	if _, err := w.Write([]byte{req.Opcode}); err != nil {
		return fmt.Errorf("failed to write opcode: %w", err)
	}

	// Write token length
	tokenLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLenBuf, tokenLen)
	if _, err := w.Write(tokenLenBuf); err != nil {
		return fmt.Errorf("failed to write token length: %w", err)
	}

	// Write token
	if tokenLen > 0 {
		if _, err := w.Write([]byte(req.Token)); err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
	}

	// Write payload length
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(req.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

// readResponse reads a response from the stream.
func readResponse(r io.Reader) (*quicResponse, error) {
	// Read status
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, fmt.Errorf("failed to read status: %w", err)
	}

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxQUICPayloadSize {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSize)
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	return &quicResponse{
		Status:  statusBuf[0],
		Payload: payload,
	}, nil
}

// defaultCodecType is the codec type used for payload encoding/decoding
var defaultCodecType = codec.MsgPack

// getCodec creates a codec of the default type using the factory
func getCodec() (codec.Codec[any], error) {
	return factory.New[any](defaultCodecType)
}

// encodePayload encodes an entity using the configured codec.
func encodePayload(entity interface{}) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}

	c, err := getCodec()
	if err != nil {
		return nil, fmt.Errorf("failed to create codec: %w", err)
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return data, nil
}

// decodePayload decodes bytes into an entity using the configured codec.
func decodePayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	c, err := getCodec()
	if err != nil {
		return fmt.Errorf("failed to create codec: %w", err)
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	return nil
}

// opcodeToString returns a human-readable name for an opcode.
func opcodeToString(opcode byte) string {
	switch opcode {
	case OpQUICKMSGenerateKey:
		return "KMSGenerateKey"
	case OpQUICKMSGetKey:
		return "KMSGetKey"
	case OpQUICKMSListKeys:
		return "KMSListKeys"
	case OpQUICKMSDeleteKey:
		return "KMSDeleteKey"
	case OpQUICKMSRotateKey:
		return "KMSRotateKey"
	case OpQUICKMSKeyVersions:
		return "KMSKeyVersions"
	case OpQUICKMSKeyStatus:
		return "KMSKeyStatus"
	case OpQUICKMSKeyRevoke:
		return "KMSKeyRevoke"
	case OpQUICKMSKeyMetadata:
		return "KMSKeyMetadata"
	case OpQUICKMSKeyMetadataUpdate:
		return "KMSKeyMetadataUpdate"
	case OpQUICKMSKeyPolicy:
		return "KMSKeyPolicy"
	case OpQUICKMSKeyPolicySet:
		return "KMSKeyPolicySet"
	case OpQUICKMSKeyAlgorithms:
		return "KMSKeyAlgorithms"
	case OpQUICCryptoEncrypt:
		return "CryptoEncrypt"
	case OpQUICCryptoDecrypt:
		return "CryptoDecrypt"
	case OpQUICCryptoSign:
		return "CryptoSign"
	case OpQUICCryptoVerify:
		return "CryptoVerify"
	case OpQUICCryptoHash:
		return "CryptoHash"
	case OpQUICCryptoHMAC:
		return "CryptoHMAC"
	case OpQUICCryptoVerifyHMAC:
		return "CryptoVerifyHMAC"
	case OpQUICCryptoRandom:
		return "CryptoRandom"
	case OpQUICKMSDEKCreate:
		return "DEKCreate"
	case OpQUICKMSDEKGet:
		return "DEKGet"
	case OpQUICKMSDEKList:
		return "DEKList"
	case OpQUICKMSDEKDelete:
		return "DEKDelete"
	case OpQUICKMSDEKRotate:
		return "DEKRotate"
	case OpQUICKMSDEKStatus:
		return "DEKStatus"
	case OpQUICSecretsStore:
		return "SecretsStore"
	case OpQUICSecretsGet:
		return "SecretsGet"
	case OpQUICSecretsList:
		return "SecretsList"
	case OpQUICSecretsDelete:
		return "SecretsDelete"
	case OpQUICSecretsRotate:
		return "SecretsRotate"
	case OpQUICSecretsListVersions:
		return "SecretsVersions"
	case OpQUICSecretsRollback:
		return "SecretsRollback"
	case OpQUICSecretsStatus:
		return "SecretsStatus"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", opcode)
	}
}

// =============================================================================
// KMSCommands Interface Implementation - Key Management
// =============================================================================

// KeyGenerate creates a new key via QUIC protocol.
func (q *QUICAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	req := &keyGenerateRequest{
		KeyID:              opts.KeyID,
		Algorithm:          opts.Algorithm,
		Purpose:            opts.Purpose,
		Exportable:         opts.Exportable,
		DeletionProtection: opts.DeletionProtection,
		Name:               opts.Name,
		Description:        opts.Description,
		Owner:              opts.Owner,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSGenerateKey, req)
	if err != nil {
		return nil, err
	}

	var result keyGenerateResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyGenerate", Err: err}
	}

	return &KeyGenerateResult{
		KeyID:              result.KeyID,
		Version:            result.Version,
		Algorithm:          result.Algorithm,
		Status:             result.Status,
		CreatedAt:          time.Unix(result.CreatedAt, 0),
		Name:               result.Name,
		Description:        result.Description,
		Exportable:         result.Exportable,
		DeletionProtection: result.DeletionProtection,
	}, nil
}

// KeyGet retrieves a key via QUIC protocol.
func (q *QUICAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	req := &keyGetRequest{
		KeyID:   keyID,
		Version: version,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSGetKey, req)
	if err != nil {
		return nil, err
	}

	var result keyGetResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyGet", Err: err}
	}

	return &KeyGetResult{
		KeyID:              result.KeyID,
		Version:            result.Version,
		Algorithm:          result.Algorithm,
		Status:             result.Status,
		CreatedAt:          time.Unix(result.CreatedAt, 0),
		UpdatedAt:          time.Unix(result.UpdatedAt, 0),
		LastUsedAt:         time.Unix(result.LastUsedAt, 0),
		Name:               result.Name,
		Description:        result.Description,
		Owner:              result.Owner,
		Exportable:         result.Exportable,
		DeletionProtection: result.DeletionProtection,
		Usage:              result.Usage,
	}, nil
}

// KeyList lists keys via QUIC protocol.
func (q *QUICAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	req := &keyListRequest{
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSListKeys, req)
	if err != nil {
		return nil, err
	}

	var result keyListResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyList", Err: err}
	}

	keys := make([]KeySummary, len(result.Keys))
	for i, k := range result.Keys {
		keys[i] = KeySummary{
			KeyID:     k.KeyID,
			Version:   k.Version,
			Algorithm: k.Algorithm,
			Status:    k.Status,
			CreatedAt: time.Unix(k.CreatedAt, 0),
		}
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: result.TotalCount,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// KeyDelete deletes a key via QUIC protocol.
func (q *QUICAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	req := &keyDeleteRequest{
		KeyID:             keyID,
		PendingWindowDays: opts.PendingWindowDays,
		Force:             opts.Force,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSDeleteKey, req)
	if err != nil {
		return nil, err
	}

	var result keyDeleteResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyDelete", Err: err}
	}

	return &KeyDeleteResult{
		KeyID:        result.KeyID,
		Status:       result.Status,
		DeletionDate: time.Unix(result.DeletionDate, 0),
	}, nil
}

// KeyRotate rotates a key via QUIC protocol.
func (q *QUICAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	req := &keyRotateRequest{
		KeyID:            keyID,
		RetainOldVersion: retainOldVersion,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSRotateKey, req)
	if err != nil {
		return nil, err
	}

	var result keyRotateResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyRotate", Err: err}
	}

	return &KeyRotateResult{
		KeyID:      result.KeyID,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		RotatedAt:  time.Unix(result.RotatedAt, 0),
	}, nil
}

// KeyVersions lists key versions via QUIC protocol.
func (q *QUICAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	req := &keyVersionsRequest{
		KeyID:  keyID,
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSKeyVersions, req)
	if err != nil {
		return nil, err
	}

	var result keyVersionsResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyVersions", Err: err}
	}

	versions := make([]KeyVersionInfo, len(result.Versions))
	for i, v := range result.Versions {
		versions[i] = KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  v.Algorithm,
			Status:     v.Status,
			CreatedAt:  time.Unix(v.CreatedAt, 0),
			DisabledAt: time.Unix(v.DisabledAt, 0),
		}
	}

	return &KeyVersionsResult{
		KeyID:      result.KeyID,
		Versions:   versions,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// KeyStatus updates key status via QUIC protocol.
func (q *QUICAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	req := &keyStatusRequest{
		KeyID:   keyID,
		Version: version,
		Enabled: enabled,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSKeyStatus, req)
	if err != nil {
		return nil, err
	}

	var result keyStatusResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyStatus", Err: err}
	}

	return &KeyStatusResult{
		KeyID:     result.KeyID,
		Version:   result.Version,
		Status:    result.Status,
		UpdatedAt: time.Unix(result.UpdatedAt, 0),
	}, nil
}

// KeyRevoke revokes a key via QUIC protocol.
func (q *QUICAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	req := &keyRevokeRequest{
		KeyID:  keyID,
		Reason: reason,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSKeyRevoke, req)
	if err != nil {
		return nil, err
	}

	var result keyRevokeResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyRevoke", Err: err}
	}

	return &KeyRevokeResult{
		KeyID:     result.KeyID,
		Status:    result.Status,
		RevokedAt: time.Unix(result.RevokedAt, 0),
	}, nil
}

// KeyMetadata retrieves key metadata via QUIC protocol.
func (q *QUICAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	req := &keyMetadataRequest{
		KeyID: keyID,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSKeyMetadata, req)
	if err != nil {
		return nil, err
	}

	var result keyMetadataResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyMetadata", Err: err}
	}

	var rotPolicy *RotationPolicy
	if result.RotationPolicy != nil {
		rotPolicy = &RotationPolicy{
			Enabled:         result.RotationPolicy.Enabled,
			IntervalSeconds: result.RotationPolicy.IntervalSeconds,
			NextRotation:    time.Unix(result.RotationPolicy.NextRotation, 0),
			RetainVersions:  result.RotationPolicy.RetainVersions,
		}
	}

	return &KeyMetadataResult{
		KeyID:              result.KeyID,
		Name:               result.Name,
		Description:        result.Description,
		Algorithm:          result.Algorithm,
		Status:             result.Status,
		Version:            result.Version,
		Exportable:         result.Exportable,
		DeletionProtection: result.DeletionProtection,
		Usage:              result.Usage,
		Owner:              result.Owner,
		CreatedAt:          time.Unix(result.CreatedAt, 0),
		UpdatedAt:          time.Unix(result.UpdatedAt, 0),
		LastUsedAt:         time.Unix(result.LastUsedAt, 0),
		Tags:               result.Tags,
		RotationPolicy:     rotPolicy,
	}, nil
}

// KeyMetadataUpdate updates key metadata via QUIC protocol.
func (q *QUICAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	req := &keyMetadataUpdateRequest{
		KeyID:       keyID,
		Name:        opts.Name,
		Description: opts.Description,
		Tags:        opts.Tags,
		RemoveTags:  opts.RemoveTags,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSKeyMetadataUpdate, req)
	if err != nil {
		return nil, err
	}

	var result keyMetadataUpdateResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyMetadataUpdate", Err: err}
	}

	return &KeyMetadataUpdateResult{
		KeyID:     result.KeyID,
		Name:      result.Name,
		UpdatedAt: time.Unix(result.UpdatedAt, 0),
		Tags:      result.Tags,
	}, nil
}

// KeyPolicy retrieves key policy via QUIC protocol.
func (q *QUICAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	req := &keyPolicyRequest{
		KeyID: keyID,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSKeyPolicy, req)
	if err != nil {
		return nil, err
	}

	var result keyPolicyResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyPolicy", Err: err}
	}

	return &KeyPolicyResult{
		KeyID:             result.KeyID,
		Version:           result.Version,
		AllowedOperations: result.AllowedOperations,
		AllowedPrincipals: result.AllowedPrincipals,
		DeniedPrincipals:  result.DeniedPrincipals,
		ExpiresAt:         time.Unix(result.ExpiresAt, 0),
		RotationRequired:  result.RotationRequired,
		MaxUsageCount:     result.MaxUsageCount,
		RequireMFA:        result.RequireMFA,
		UpdatedAt:         time.Unix(result.UpdatedAt, 0),
	}, nil
}

// KeyPolicySet sets key policy via QUIC protocol.
func (q *QUICAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	req := &keyPolicySetRequest{
		KeyID:            keyID,
		Operations:       opts.Operations,
		AllowPrincipals:  opts.AllowPrincipals,
		DenyPrincipals:   opts.DenyPrincipals,
		ExpiresIn:        opts.ExpiresIn,
		RotationRequired: opts.RotationRequired,
		MaxUsageCount:    opts.MaxUsageCount,
		RequireMFA:       opts.RequireMFA,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSKeyPolicySet, req)
	if err != nil {
		return nil, err
	}

	var result keyPolicySetResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyPolicySet", Err: err}
	}

	return &KeyPolicySetResult{
		KeyID:         result.KeyID,
		PolicyVersion: result.PolicyVersion,
		UpdatedAt:     time.Unix(result.UpdatedAt, 0),
	}, nil
}

// KeyAlgorithms returns supported key algorithms via QUIC protocol.
func (q *QUICAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICKMSKeyAlgorithms, nil)
	if err != nil {
		return nil, err
	}

	var result keyAlgorithmsResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "KeyAlgorithms", Err: err}
	}

	return &KeyAlgorithmsResult{
		Algorithms: result.Algorithms,
	}, nil
}

// =============================================================================
// KMSCommands Interface Implementation - Crypto Operations
// =============================================================================

// CryptoEncrypt encrypts data via QUIC protocol.
func (q *QUICAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	req := &cryptoEncryptRequest{
		KeyID:     opts.KeyID,
		Plaintext: opts.Plaintext,
		Context:   opts.Context,
		Nonce:     opts.Nonce,
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoEncrypt, req)
	if err != nil {
		return nil, err
	}

	var result cryptoEncryptResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoEncrypt", Err: err}
	}

	return &CryptoEncryptResult{
		KeyID:      result.KeyID,
		KeyVersion: result.KeyVersion,
		Ciphertext: result.Ciphertext,
		Nonce:      result.Nonce,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// CryptoDecrypt decrypts data via QUIC protocol.
func (q *QUICAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	req := &cryptoDecryptRequest{
		KeyID:      opts.KeyID,
		Ciphertext: opts.Ciphertext,
		Context:    opts.Context,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoDecrypt, req)
	if err != nil {
		return nil, err
	}

	var result cryptoDecryptResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoDecrypt", Err: err}
	}

	return &CryptoDecryptResult{
		KeyID:      result.KeyID,
		KeyVersion: result.KeyVersion,
		Plaintext:  result.Plaintext,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// CryptoSign signs data via QUIC protocol.
func (q *QUICAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	req := &cryptoSignRequest{
		KeyID:         opts.KeyID,
		Message:       opts.Message,
		HashAlgorithm: opts.HashAlgorithm,
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoSign, req)
	if err != nil {
		return nil, err
	}

	var result cryptoSignResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoSign", Err: err}
	}

	return &CryptoSignResult{
		KeyID:         result.KeyID,
		KeyVersion:    result.KeyVersion,
		Signature:     result.Signature,
		HashAlgorithm: result.HashAlgorithm,
		Timestamp:     time.Unix(result.Timestamp, 0),
	}, nil
}

// CryptoVerify verifies a signature via QUIC protocol.
func (q *QUICAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	req := &cryptoVerifyRequest{
		KeyID:         opts.KeyID,
		Message:       opts.Message,
		Signature:     opts.Signature,
		HashAlgorithm: opts.HashAlgorithm,
		KeyVersion:    opts.KeyVersion,
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoVerify, req)
	if err != nil {
		return nil, err
	}

	var result cryptoVerifyResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoVerify", Err: err}
	}

	return &CryptoVerifyResult{
		KeyID:      result.KeyID,
		KeyVersion: result.KeyVersion,
		Valid:      result.Valid,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// CryptoHash computes a hash via QUIC protocol.
func (q *QUICAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	req := &cryptoHashRequest{
		Data:      data,
		Algorithm: algorithm,
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoHash, req)
	if err != nil {
		return nil, err
	}

	var result cryptoHashResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoHash", Err: err}
	}

	return &CryptoHashResult{
		Algorithm: result.Algorithm,
		Hash:      result.Hash,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// CryptoHMAC generates an HMAC via QUIC protocol.
func (q *QUICAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	req := &cryptoHMACRequest{
		KeyID:         opts.KeyID,
		Message:       opts.Message,
		HashAlgorithm: opts.HashAlgorithm,
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoHMAC, req)
	if err != nil {
		return nil, err
	}

	var result cryptoHMACResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoHMAC", Err: err}
	}

	return &CryptoHMACResult{
		KeyID:         result.KeyID,
		KeyVersion:    result.KeyVersion,
		HMAC:          result.HMAC,
		HashAlgorithm: result.HashAlgorithm,
		Timestamp:     time.Unix(result.Timestamp, 0),
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC via QUIC protocol.
func (q *QUICAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	req := &cryptoVerifyHMACRequest{
		KeyID:         opts.KeyID,
		Message:       opts.Message,
		HMAC:          opts.HMAC,
		HashAlgorithm: opts.HashAlgorithm,
		KeyVersion:    opts.KeyVersion,
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoVerifyHMAC, req)
	if err != nil {
		return nil, err
	}

	var result cryptoVerifyHMACResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoVerifyHMAC", Err: err}
	}

	return &CryptoVerifyHMACResult{
		KeyID:      result.KeyID,
		KeyVersion: result.KeyVersion,
		Valid:      result.Valid,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// CryptoRandom generates random bytes via QUIC protocol.
func (q *QUICAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	req := &cryptoRandomRequest{
		NumBytes: int32(numBytes),
	}

	resp, err := q.sendRequest(ctx, OpQUICCryptoRandom, req)
	if err != nil {
		return nil, err
	}

	var result cryptoRandomResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CryptoRandom", Err: err}
	}

	return &CryptoRandomResult{
		RandomBytes: result.RandomBytes,
		Timestamp:   time.Unix(result.Timestamp, 0),
	}, nil
}

// =============================================================================
// KMSCommands Interface Implementation - DEK Operations
// =============================================================================

// DEKCreate creates a DEK via QUIC protocol.
func (q *QUICAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	req := &dekCreateRequest{
		Path:           opts.Path,
		Algorithm:      opts.Algorithm,
		Description:    opts.Description,
		MaxOperations:  opts.MaxOperations,
		MaxBytes:       opts.MaxBytes,
		WarningPercent: opts.WarningPercent,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSDEKCreate, req)
	if err != nil {
		return nil, err
	}

	var result dekCreateResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DEKCreate", Err: err}
	}

	return &DEKCreateResult{
		Path:        result.Path,
		Algorithm:   result.Algorithm,
		Version:     result.Version,
		CreatedAt:   time.Unix(result.CreatedAt, 0),
		Description: result.Description,
	}, nil
}

// DEKGet retrieves a DEK via QUIC protocol.
func (q *QUICAdapter) DEKGet(ctx context.Context, path string) (*DEKGetResult, error) {
	req := &dekGetRequest{
		Path: path,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSDEKGet, req)
	if err != nil {
		return nil, err
	}

	var result dekGetResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DEKGet", Err: err}
	}

	return &DEKGetResult{
		Path:           result.Path,
		Algorithm:      result.Algorithm,
		Version:        result.Version,
		Status:         result.Status,
		IsDefault:      result.IsDefault,
		CreatedAt:      time.Unix(result.CreatedAt, 0),
		RotatedAt:      time.Unix(result.RotatedAt, 0),
		Description:    result.Description,
		BackendType:    result.BackendType,
		UsageCount:     result.UsageCount,
		BytesUsed:      result.BytesUsed,
		MaxUsageCount:  result.MaxUsageCount,
		MaxBytesUsed:   result.MaxBytesUsed,
		WarningPercent: result.WarningPercent,
	}, nil
}

// DEKList lists DEKs via QUIC protocol.
func (q *QUICAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	req := &dekListRequest{
		Prefix:    opts.Prefix,
		Recursive: opts.Recursive,
		Limit:     opts.Limit,
		Cursor:    opts.Cursor,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSDEKList, req)
	if err != nil {
		return nil, err
	}

	var result dekListResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DEKList", Err: err}
	}

	deks := make([]DEKSummary, len(result.DEKs))
	for i, d := range result.DEKs {
		deks[i] = DEKSummary{
			Path:      d.Path,
			Algorithm: d.Algorithm,
			Version:   d.Version,
			Status:    d.Status,
			IsDefault: d.IsDefault,
			CreatedAt: time.Unix(d.CreatedAt, 0),
		}
	}

	return &DEKListResult{
		DEKs:       deks,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// DEKDelete deletes a DEK via QUIC protocol.
func (q *QUICAdapter) DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	req := &dekDeleteRequest{
		Path:      path,
		Force:     opts.Force,
		MigrateTo: opts.MigrateTo,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSDEKDelete, req)
	if err != nil {
		return nil, err
	}

	var result dekDeleteResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DEKDelete", Err: err}
	}

	return &DEKDeleteResult{
		Path:    result.Path,
		Deleted: result.Deleted,
	}, nil
}

// DEKRotate rotates a DEK via QUIC protocol.
func (q *QUICAdapter) DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error) {
	req := &dekRotateRequest{
		Path:       path,
		Background: background,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSDEKRotate, req)
	if err != nil {
		return nil, err
	}

	var result dekRotateResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DEKRotate", Err: err}
	}

	return &DEKRotateResult{
		Path:       result.Path,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
	}, nil
}

// DEKStatus retrieves DEK status via QUIC protocol.
func (q *QUICAdapter) DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error) {
	req := &dekStatusRequest{
		Path: path,
	}

	resp, err := q.sendRequest(ctx, OpQUICKMSDEKStatus, req)
	if err != nil {
		return nil, err
	}

	var result dekStatusResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DEKStatus", Err: err}
	}

	return &DEKStatusResult{
		Path:                   result.Path,
		Algorithm:              result.Algorithm,
		Version:                result.Version,
		Status:                 result.Status,
		IsDefault:              result.IsDefault,
		CreatedAt:              time.Unix(result.CreatedAt, 0),
		RotatedAt:              time.Unix(result.RotatedAt, 0),
		Description:            result.Description,
		BackendType:            result.BackendType,
		UsageCount:             result.UsageCount,
		BytesUsed:              result.BytesUsed,
		MaxUsageCount:          result.MaxUsageCount,
		MaxBytesUsed:           result.MaxBytesUsed,
		WarningPercent:         result.WarningPercent,
		ReencryptionInProgress: result.ReencryptionInProgress,
		ProcessedKeys:          result.ProcessedKeys,
		TotalKeys:              result.TotalKeys,
		FailedKeys:             result.FailedKeys,
		ReencryptionStartedAt:  time.Unix(result.ReencryptionStartedAt, 0),
		EstimatedCompletion:    time.Unix(result.EstimatedCompletion, 0),
	}, nil
}

// =============================================================================
// KMSCommands Interface Implementation - Secrets Operations
// =============================================================================

// SecretsStore stores a secret via QUIC protocol.
func (q *QUICAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
	req := &secretsStoreRequest{
		Name:        opts.Name,
		Data:        opts.Data,
		Description: opts.Description,
		TenantID:    opts.TenantID,
		KeyID:       opts.KeyID,
		Algorithm:   opts.Algorithm,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsStore, req)
	if err != nil {
		return nil, err
	}

	var result secretsStoreResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsStore", Err: err}
	}

	return &SecretsStoreResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsGet retrieves a secret via QUIC protocol.
func (q *QUICAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	req := &secretsGetRequest{
		Name: name,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsGet, req)
	if err != nil {
		return nil, err
	}

	var result secretsGetResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsGet", Err: err}
	}

	return &SecretsGetResult{
		SecretID:      result.SecretID,
		Version:       result.Version,
		Data:          result.Data,
		Metadata:      result.Metadata,
		Algorithm:     result.Algorithm,
		KeyIdentifier: result.KeyIdentifier,
		CreatedAt:     time.Unix(result.CreatedAt, 0),
		Timestamp:     time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsList lists secrets via QUIC protocol.
func (q *QUICAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
	req := &secretsListRequest{
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsList, req)
	if err != nil {
		return nil, err
	}

	var result secretsListResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsList", Err: err}
	}

	secrets := make([]SecretSummary, len(result.Secrets))
	for i, s := range result.Secrets {
		secrets[i] = SecretSummary{
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      time.Unix(s.CreatedAt, 0),
			UpdatedAt:      time.Unix(s.UpdatedAt, 0),
		}
	}

	return &SecretsListResult{
		Secrets:    secrets,
		TotalCount: result.TotalCount,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// SecretsDelete deletes a secret via QUIC protocol.
func (q *QUICAdapter) SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error) {
	req := &secretsDeleteRequest{
		Name:      name,
		Permanent: permanent,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsDelete, req)
	if err != nil {
		return nil, err
	}

	var result secretsDeleteResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsDelete", Err: err}
	}

	return &SecretsDeleteResult{
		SecretID:  result.SecretID,
		Deleted:   result.Deleted,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsRotate rotates a secret via QUIC protocol.
func (q *QUICAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	req := &secretsRotateRequest{
		Name:      opts.Name,
		NewData:   opts.NewData,
		TenantID:  opts.TenantID,
		KeyID:     opts.KeyID,
		Algorithm: opts.Algorithm,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsRotate, req)
	if err != nil {
		return nil, err
	}

	var result secretsRotateResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsRotate", Err: err}
	}

	return &SecretsRotateResult{
		SecretID:   result.SecretID,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsVersions lists secret versions via QUIC protocol.
func (q *QUICAdapter) SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	req := &secretsVersionsRequest{
		Name:   name,
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsListVersions, req)
	if err != nil {
		return nil, err
	}

	var result secretsVersionsResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsVersions", Err: err}
	}

	versions := make([]SecretVersionInfo, len(result.Versions))
	for i, v := range result.Versions {
		versions[i] = SecretVersionInfo{
			Version:   v.Version,
			CreatedAt: time.Unix(v.CreatedAt, 0),
			CreatedBy: v.CreatedBy,
			ExpiresAt: time.Unix(v.ExpiresAt, 0),
		}
	}

	return &SecretsVersionsResult{
		SecretID:   result.SecretID,
		Versions:   versions,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// SecretsVersion retrieves a specific secret version via QUIC protocol.
func (q *QUICAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	req := &secretsVersionRequest{
		Name:    name,
		Version: version,
	}

	// Use SecretsGet with version parameter - in practice this might need a separate opcode
	// For now we use the same get endpoint and rely on the request containing version
	resp, err := q.sendRequest(ctx, OpQUICSecretsGet, req)
	if err != nil {
		return nil, err
	}

	var result secretsVersionResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsVersion", Err: err}
	}

	return &SecretsVersionResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Data:      result.Data,
		Metadata:  result.Metadata,
		CreatedAt: time.Unix(result.CreatedAt, 0),
		CreatedBy: result.CreatedBy,
		ExpiresAt: time.Unix(result.ExpiresAt, 0),
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsRollback rolls back a secret to a previous version via QUIC protocol.
func (q *QUICAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	req := &secretsRollbackRequest{
		Name:          name,
		TargetVersion: targetVersion,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsRollback, req)
	if err != nil {
		return nil, err
	}

	var result secretsRollbackResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsRollback", Err: err}
	}

	return &SecretsRollbackResult{
		SecretID:   result.SecretID,
		NewVersion: result.NewVersion,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsStatus updates secret status via QUIC protocol.
func (q *QUICAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
	req := &secretsStatusRequest{
		Name:    name,
		Enabled: enabled,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsStatus, req)
	if err != nil {
		return nil, err
	}

	var result secretsStatusResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SecretsStatus", Err: err}
	}

	return &SecretsStatusResult{
		SecretID:  result.SecretID,
		Status:    result.Status,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure QUICAdapter implements KMSCommands interface.
var _ KMSCommands = (*QUICAdapter)(nil)
