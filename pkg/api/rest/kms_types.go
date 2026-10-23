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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// KMS Service Interface
// =============================================================================

// KMSService defines the interface for KMS operations used by REST handlers.
type KMSService interface {
	GenerateKey(ctx context.Context, req *KMSGenerateKeyServiceRequest) (*KMSGenerateKeyServiceResponse, error)
	ImportKey(ctx context.Context, req *KMSImportKeyServiceRequest) (*KMSImportKeyServiceResponse, error)
	GetKey(ctx context.Context, req *KMSGetKeyServiceRequest) (*KMSGetKeyServiceResponse, error)
	ListKeys(ctx context.Context, req *KMSListKeysServiceRequest) (*KMSListKeysServiceResponse, error)
	DeleteKey(ctx context.Context, req *KMSDeleteKeyServiceRequest) (*KMSDeleteKeyServiceResponse, error)
	RotateKey(ctx context.Context, req *KMSRotateKeyServiceRequest) (*KMSRotateKeyServiceResponse, error)
	UpdateKeyStatus(ctx context.Context, req *KMSUpdateKeyStatusServiceRequest) (*KMSUpdateKeyStatusServiceResponse, error)
	ExportKey(ctx context.Context, req *KMSExportKeyServiceRequest) (*KMSExportKeyServiceResponse, error)
	GetKeyVersions(ctx context.Context, req *KMSGetKeyVersionsServiceRequest) (*KMSGetKeyVersionsServiceResponse, error)
	BackendStatus(ctx context.Context) (*KMSBackendStatusServiceResponse, error)
	Encrypt(ctx context.Context, req *KMSEncryptServiceRequest) (*KMSEncryptServiceResponse, error)
	Decrypt(ctx context.Context, req *KMSDecryptServiceRequest) (*KMSDecryptServiceResponse, error)
	BatchEncrypt(ctx context.Context, req *KMSBatchEncryptServiceRequest) (*KMSBatchEncryptServiceResponse, error)
	BatchDecrypt(ctx context.Context, req *KMSBatchDecryptServiceRequest) (*KMSBatchDecryptServiceResponse, error)
	Rewrap(ctx context.Context, req *KMSRewrapServiceRequest) (*KMSRewrapServiceResponse, error)
	Sign(ctx context.Context, req *KMSSignServiceRequest) (*KMSSignServiceResponse, error)
	Verify(ctx context.Context, req *KMSVerifyServiceRequest) (*KMSVerifyServiceResponse, error)
	GenerateRandom(ctx context.Context, req *KMSGenerateRandomServiceRequest) (*KMSGenerateRandomServiceResponse, error)
	Hash(ctx context.Context, req *KMSHashServiceRequest) (*KMSHashServiceResponse, error)
	HMAC(ctx context.Context, req *KMSHMACServiceRequest) (*KMSHMACServiceResponse, error)
	VerifyHMAC(ctx context.Context, req *KMSVerifyHMACServiceRequest) (*KMSVerifyHMACServiceResponse, error)
}

// =============================================================================
// KMS Service Types
// =============================================================================

// KMSKeySpec defines key specification for key generation.
type KMSKeySpec struct {
	Algorithm          int32
	KeySize            int32
	Usage              []int32
	Exportable         bool
	DeletionProtection bool
}

// KMSKeyHandle represents a key handle returned by the service.
type KMSKeyHandle struct {
	KeyID     string
	Version   uint64
	Algorithm int32
	Status    int32
	CreatedAt int64
}

// KMSKeyMetadata represents key metadata returned by the service.
type KMSKeyMetadata struct {
	KeyID              string
	Name               string
	Description        string
	Algorithm          int32
	Status             int32
	Usage              []int32
	Version            uint64
	Exportable         bool
	DeletionProtection bool
	CreatedAt          int64
	UpdatedAt          int64
	LastUsedAt         int64
	Tags               map[string]string
	Owner              string
}

// KMSKeyVersionInfo represents version information for a key.
type KMSKeyVersionInfo struct {
	Version    uint64
	Status     int32
	Algorithm  int32
	CreatedAt  int64
	DisabledAt int64
}

// =============================================================================
// Generate Key
// =============================================================================

// KMSGenerateKeyServiceRequest is the service request for generating a key.
type KMSGenerateKeyServiceRequest struct {
	KeySpec     *KMSKeySpec
	Name        string
	Description string
	Tags        map[string]string
	Owner       string
}

// KMSGenerateKeyServiceResponse is the service response for generating a key.
type KMSGenerateKeyServiceResponse struct {
	Key       *KMSKeyHandle
	Metadata  *KMSKeyMetadata
	Timestamp int64
}

// =============================================================================
// Import Key
// =============================================================================

// KMSImportKeyServiceRequest is the service request for importing a key.
type KMSImportKeyServiceRequest struct {
	KeyMaterial   []byte
	WrappingKeyID string
	KeySpec       *KMSKeySpec
	Name          string
	Description   string
	Tags          map[string]string
}

// KMSImportKeyServiceResponse is the service response for importing a key.
type KMSImportKeyServiceResponse struct {
	Key       *KMSKeyHandle
	Metadata  *KMSKeyMetadata
	Timestamp int64
}

// =============================================================================
// Get Key
// =============================================================================

// KMSGetKeyServiceRequest is the service request for getting a key.
type KMSGetKeyServiceRequest struct {
	KeyID   string
	Version uint64
}

// KMSGetKeyServiceResponse is the service response for getting a key.
type KMSGetKeyServiceResponse struct {
	Key       *KMSKeyHandle
	Metadata  *KMSKeyMetadata
	Timestamp int64
}

// =============================================================================
// List Keys
// =============================================================================

// KMSListKeysServiceRequest is the service request for listing keys.
type KMSListKeysServiceRequest struct {
	Limit  int32
	Cursor string
	Filter map[string]string
}

// KMSListKeysServiceResponse is the service response for listing keys.
type KMSListKeysServiceResponse struct {
	Keys       []*KMSKeyHandle
	NextCursor string
	HasMore    bool
	TotalCount int32
	Timestamp  int64
}

// =============================================================================
// Delete Key
// =============================================================================

// KMSDeleteKeyServiceRequest is the service request for deleting a key.
type KMSDeleteKeyServiceRequest struct {
	KeyID             string
	PendingWindowDays int32
	Force             bool
}

// KMSDeleteKeyServiceResponse is the service response for deleting a key.
type KMSDeleteKeyServiceResponse struct {
	KeyID        string
	Status       int32
	DeletionDate int64
	Timestamp    int64
}

// =============================================================================
// Rotate Key
// =============================================================================

// KMSRotateKeyServiceRequest is the service request for rotating a key.
type KMSRotateKeyServiceRequest struct {
	KeyID            string
	RetainOldVersion bool
}

// KMSRotateKeyServiceResponse is the service response for rotating a key.
type KMSRotateKeyServiceResponse struct {
	KeyID      string
	OldVersion uint64
	NewVersion uint64
	Timestamp  int64
}

// =============================================================================
// Update Key Status
// =============================================================================

// KMSUpdateKeyStatusServiceRequest is the service request for updating key status.
type KMSUpdateKeyStatusServiceRequest struct {
	KeyID   string
	Version uint64
	Status  int32
}

// KMSUpdateKeyStatusServiceResponse is the service response for updating key status.
type KMSUpdateKeyStatusServiceResponse struct {
	KeyID     string
	Version   uint64
	Status    int32
	Timestamp int64
}

// =============================================================================
// Export Key
// =============================================================================

// KMSExportKeyServiceRequest is the service request for exporting a key.
type KMSExportKeyServiceRequest struct {
	KeyID             string
	WrappingKeyID     string
	WrappingAlgorithm int32
	Format            int32
	Version           uint64
}

// KMSExportKeyServiceResponse is the service response for exporting a key.
type KMSExportKeyServiceResponse struct {
	KeyID             string
	Format            int32
	WrappingKeyID     string
	WrappingAlgorithm int32
	WrappedMaterial   []byte
	Version           uint64
	Timestamp         int64
}

// =============================================================================
// Get Key Versions
// =============================================================================

// KMSGetKeyVersionsServiceRequest is the service request for getting key versions.
type KMSGetKeyVersionsServiceRequest struct {
	KeyID  string
	Limit  int32
	Cursor string
}

// KMSGetKeyVersionsServiceResponse is the service response for getting key versions.
type KMSGetKeyVersionsServiceResponse struct {
	KeyID      string
	Versions   []*KMSKeyVersionInfo
	NextCursor string
	HasMore    bool
	Timestamp  int64
}

// =============================================================================
// Backend Status
// =============================================================================

// KMSBackendStatusServiceResponse is the service response for backend status.
type KMSBackendStatusServiceResponse struct {
	BackendType  string
	Status       string
	Device       string
	Region       string
	KeyID        string
	PcrBanks     []string
	PcrRegisters []int32
	Capabilities map[string]bool
	Timestamp    int64
}

// =============================================================================
// Encrypt
// =============================================================================

// KMSEncryptServiceRequest is the service request for encryption.
type KMSEncryptServiceRequest struct {
	KeyID     string
	Plaintext []byte
	Context   []byte
	Nonce     []byte
}

// KMSEncryptServiceResponse is the service response for encryption.
type KMSEncryptServiceResponse struct {
	KeyID      string
	KeyVersion uint64
	Ciphertext []byte
	Nonce      []byte
	Timestamp  int64
}

// =============================================================================
// Decrypt
// =============================================================================

// KMSDecryptServiceRequest is the service request for decryption.
type KMSDecryptServiceRequest struct {
	KeyID      string
	Ciphertext []byte
	Context    []byte
	Nonce      []byte
	KeyVersion uint64
}

// KMSDecryptServiceResponse is the service response for decryption.
type KMSDecryptServiceResponse struct {
	KeyID      string
	KeyVersion uint64
	Plaintext  []byte
	Timestamp  int64
}

// =============================================================================
// Batch Encrypt
// =============================================================================

// KMSBatchEncryptItem represents a single item in a batch encryption request.
type KMSBatchEncryptItem struct {
	ItemID    string
	Plaintext []byte
	Context   []byte
	Nonce     []byte
}

// KMSBatchEncryptServiceRequest is the service request for batch encryption.
type KMSBatchEncryptServiceRequest struct {
	KeyID string
	Items []*KMSBatchEncryptItem
}

// KMSBatchEncryptResultItem represents a single result in a batch encryption response.
type KMSBatchEncryptResultItem struct {
	ItemID     string
	Ciphertext []byte
	Nonce      []byte
	Error      string
}

// KMSBatchEncryptServiceResponse is the service response for batch encryption.
type KMSBatchEncryptServiceResponse struct {
	KeyID        string
	KeyVersion   uint64
	Results      []*KMSBatchEncryptResultItem
	SuccessCount int32
	FailureCount int32
	Timestamp    int64
}

// =============================================================================
// Batch Decrypt
// =============================================================================

// KMSBatchDecryptItem represents a single item in a batch decryption request.
type KMSBatchDecryptItem struct {
	ItemID     string
	Ciphertext []byte
	Context    []byte
	Nonce      []byte
	KeyVersion uint64
}

// KMSBatchDecryptServiceRequest is the service request for batch decryption.
type KMSBatchDecryptServiceRequest struct {
	KeyID string
	Items []*KMSBatchDecryptItem
}

// KMSBatchDecryptResultItem represents a single result in a batch decryption response.
type KMSBatchDecryptResultItem struct {
	ItemID     string
	Plaintext  []byte
	KeyVersion uint64
	Error      string
}

// KMSBatchDecryptServiceResponse is the service response for batch decryption.
type KMSBatchDecryptServiceResponse struct {
	KeyID        string
	Results      []*KMSBatchDecryptResultItem
	SuccessCount int32
	FailureCount int32
	Timestamp    int64
}

// =============================================================================
// Rewrap
// =============================================================================

// KMSRewrapServiceRequest is the service request for rewrapping ciphertext.
type KMSRewrapServiceRequest struct {
	SourceKeyID      string
	DestinationKeyID string
	Ciphertext       []byte
	SourceContext    []byte
	DestContext      []byte
	SourceNonce      []byte
	SourceKeyVersion uint64
}

// KMSRewrapServiceResponse is the service response for rewrapping ciphertext.
type KMSRewrapServiceResponse struct {
	SourceKeyID      string
	DestinationKeyID string
	SourceKeyVersion uint64
	DestKeyVersion   uint64
	Ciphertext       []byte
	Nonce            []byte
	Timestamp        int64
}

// =============================================================================
// Sign
// =============================================================================

// KMSSignServiceRequest is the service request for signing.
type KMSSignServiceRequest struct {
	KeyID         string
	Message       []byte
	HashAlgorithm int32
	PreHashed     bool
}

// KMSSignServiceResponse is the service response for signing.
type KMSSignServiceResponse struct {
	KeyID         string
	KeyVersion    uint64
	Signature     []byte
	HashAlgorithm int32
	Timestamp     int64
}

// =============================================================================
// Verify
// =============================================================================

// KMSVerifyServiceRequest is the service request for signature verification.
type KMSVerifyServiceRequest struct {
	KeyID         string
	Message       []byte
	Signature     []byte
	HashAlgorithm int32
	KeyVersion    uint64
}

// KMSVerifyServiceResponse is the service response for signature verification.
type KMSVerifyServiceResponse struct {
	KeyID      string
	KeyVersion uint64
	Valid      bool
	Timestamp  int64
}

// =============================================================================
// Generate Random
// =============================================================================

// KMSGenerateRandomServiceRequest is the service request for generating random bytes.
type KMSGenerateRandomServiceRequest struct {
	NumBytes int32
}

// KMSGenerateRandomServiceResponse is the service response for generating random bytes.
type KMSGenerateRandomServiceResponse struct {
	RandomBytes []byte
	Timestamp   int64
}

// =============================================================================
// Hash
// =============================================================================

// KMSHashServiceRequest is the service request for hashing.
type KMSHashServiceRequest struct {
	Data      []byte
	Algorithm int32
}

// KMSHashServiceResponse is the service response for hashing.
type KMSHashServiceResponse struct {
	Algorithm int32
	Hash      []byte
	Timestamp int64
}

// =============================================================================
// HMAC
// =============================================================================

// KMSHMACServiceRequest is the service request for HMAC generation.
type KMSHMACServiceRequest struct {
	KeyID         string
	Message       []byte
	HashAlgorithm int32
}

// KMSHMACServiceResponse is the service response for HMAC generation.
type KMSHMACServiceResponse struct {
	KeyID         string
	KeyVersion    uint64
	HMAC          []byte
	HashAlgorithm int32
	Timestamp     int64
}

// =============================================================================
// Verify HMAC
// =============================================================================

// KMSVerifyHMACServiceRequest is the service request for HMAC verification.
type KMSVerifyHMACServiceRequest struct {
	KeyID         string
	Message       []byte
	HMAC          []byte
	HashAlgorithm int32
	KeyVersion    uint64
}

// KMSVerifyHMACServiceResponse is the service response for HMAC verification.
type KMSVerifyHMACServiceResponse struct {
	KeyID      string
	KeyVersion uint64
	Valid      bool
	Timestamp  int64
}

// =============================================================================
// KMS Service Errors
// =============================================================================

// ErrKMSOperationFailed is returned when a KMS operation fails.
type ErrKMSOperationFailed struct {
	Reason string
}

func (e ErrKMSOperationFailed) Error() string {
	return "KMS operation failed: " + e.Reason
}

// ErrKMSKeyNotFound is returned when a key is not found.
type ErrKMSKeyNotFound struct {
	KeyID string
}

func (e ErrKMSKeyNotFound) Error() string {
	return "key not found: " + e.KeyID
}

// GRPCStatus classifies the error as NotFound.
func (e ErrKMSKeyNotFound) GRPCStatus() *status.Status {
	return status.New(codes.NotFound, e.Error())
}

// ErrKMSKeyAlreadyExists is returned when a key already exists.
type ErrKMSKeyAlreadyExists struct {
	KeyID string
}

func (e ErrKMSKeyAlreadyExists) Error() string {
	return "key already exists: " + e.KeyID
}

// GRPCStatus classifies the error as AlreadyExists.
func (e ErrKMSKeyAlreadyExists) GRPCStatus() *status.Status {
	return status.New(codes.AlreadyExists, e.Error())
}

// ErrKMSInvalidKeySpec is returned when a key spec is invalid.
type ErrKMSInvalidKeySpec struct {
	Reason string
}

func (e ErrKMSInvalidKeySpec) Error() string {
	return "invalid key spec: " + e.Reason
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSInvalidKeySpec) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSKeyNotExportable is returned when a key is not exportable.
type ErrKMSKeyNotExportable struct {
	KeyID string
}

func (e ErrKMSKeyNotExportable) Error() string {
	return "key not exportable: " + e.KeyID
}

// GRPCStatus classifies the error as PermissionDenied.
func (e ErrKMSKeyNotExportable) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// ErrKMSKeyDisabled is returned when a key is disabled.
type ErrKMSKeyDisabled struct {
	KeyID string
}

func (e ErrKMSKeyDisabled) Error() string {
	return "key disabled: " + e.KeyID
}

// GRPCStatus classifies the error as PermissionDenied.
func (e ErrKMSKeyDisabled) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// ErrKMSKeyPendingDeletion is returned when a key is pending deletion.
type ErrKMSKeyPendingDeletion struct {
	KeyID string
}

func (e ErrKMSKeyPendingDeletion) Error() string {
	return "key pending deletion: " + e.KeyID
}

// GRPCStatus classifies the error as PermissionDenied.
func (e ErrKMSKeyPendingDeletion) GRPCStatus() *status.Status {
	return status.New(codes.PermissionDenied, e.Error())
}

// ErrKMSEncryptionFailed is returned when encryption fails.
type ErrKMSEncryptionFailed struct {
	Reason string
}

func (e ErrKMSEncryptionFailed) Error() string {
	return "encryption failed: " + e.Reason
}

// ErrKMSDecryptionFailed is returned when decryption fails.
type ErrKMSDecryptionFailed struct {
	Reason string
}

func (e ErrKMSDecryptionFailed) Error() string {
	return "decryption failed: " + e.Reason
}

// ErrKMSSigningFailed is returned when signing fails.
type ErrKMSSigningFailed struct {
	Reason string
}

func (e ErrKMSSigningFailed) Error() string {
	return "signing failed: " + e.Reason
}

// ErrKMSVerificationFailed is returned when verification fails.
type ErrKMSVerificationFailed struct {
	Reason string
}

func (e ErrKMSVerificationFailed) Error() string {
	return "verification failed: " + e.Reason
}

// ErrKMSInvalidAlgorithm is returned when an algorithm is invalid.
type ErrKMSInvalidAlgorithm struct {
	Algorithm string
}

func (e ErrKMSInvalidAlgorithm) Error() string {
	return "invalid algorithm: " + e.Algorithm
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSInvalidAlgorithm) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSServiceUnavailable is returned when the KMS service is unavailable.
type ErrKMSServiceUnavailable struct {
	Reason string
}

func (e ErrKMSServiceUnavailable) Error() string {
	if e.Reason == "" {
		return "KMS service unavailable"
	}
	return "KMS service unavailable: " + e.Reason
}

// GRPCStatus classifies the error as Unavailable.
func (e ErrKMSServiceUnavailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrKMSBatchOperationFailed is returned when a batch operation fails.
type ErrKMSBatchOperationFailed struct {
	Operation    string
	SuccessCount int32
	FailureCount int32
}

func (e ErrKMSBatchOperationFailed) Error() string {
	return "batch " + e.Operation + " operation had failures"
}

// ErrKMSRewrapFailed is returned when a rewrap operation fails.
type ErrKMSRewrapFailed struct {
	Reason string
}

func (e ErrKMSRewrapFailed) Error() string {
	return "rewrap failed: " + e.Reason
}

// ErrKMSBatchItemsEmpty is returned when batch items are empty.
type ErrKMSBatchItemsEmpty struct{}

func (e ErrKMSBatchItemsEmpty) Error() string {
	return "batch items cannot be empty"
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSBatchItemsEmpty) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSBatchItemsTooMany is returned when there are too many batch items.
type ErrKMSBatchItemsTooMany struct {
	Count int
	Max   int
}

func (e ErrKMSBatchItemsTooMany) Error() string {
	return "batch items exceed maximum allowed"
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSBatchItemsTooMany) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}
