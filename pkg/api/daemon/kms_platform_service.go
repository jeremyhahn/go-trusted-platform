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
	"log/slog"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkcrypto "github.com/jeremyhahn/go-quicbaas/sdk/go/client/crypto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Platform KMS Backend Errors
// =============================================================================

// ErrKMSClientUnavailable is returned when a required QuicBaaS SDK client is
// not available on the platform KMS backend.
type ErrKMSClientUnavailable struct {
	Client string
}

func (e ErrKMSClientUnavailable) Error() string {
	return "KMS " + e.Client + " client unavailable"
}

// GRPCStatus classifies the error as Unavailable.
func (e ErrKMSClientUnavailable) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrKMSUnsupportedValue is returned when a platform.v1 enum value has no
// QuicBaaS SDK equivalent.
type ErrKMSUnsupportedValue struct {
	Kind  string
	Value int32
}

func (e ErrKMSUnsupportedValue) Error() string {
	return "unsupported " + e.Kind + ": " + strconv.Itoa(int(e.Value))
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSUnsupportedValue) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSInvalidCursor is returned when a pagination cursor cannot be parsed.
type ErrKMSInvalidCursor struct {
	Cursor string
}

func (e ErrKMSInvalidCursor) Error() string {
	return "invalid pagination cursor: " + e.Cursor
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSInvalidCursor) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSUnsupportedFilter is returned when a list filter key is not supported.
type ErrKMSUnsupportedFilter struct {
	Key string
}

func (e ErrKMSUnsupportedFilter) Error() string {
	return "unsupported list filter: " + e.Key
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSUnsupportedFilter) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSMissingRequest is returned when a required request is nil.
type ErrKMSMissingRequest struct {
	Operation string
}

func (e ErrKMSMissingRequest) Error() string {
	return "KMS " + e.Operation + " request is required"
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSMissingRequest) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSMissingKeySpec is returned when a required key specification is nil.
type ErrKMSMissingKeySpec struct {
	Operation string
}

func (e ErrKMSMissingKeySpec) Error() string {
	return "KMS " + e.Operation + " key specification is required"
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrKMSMissingKeySpec) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// ErrKMSNilMetadata is returned when the KMS answers a metadata call with
// no metadata.
type ErrKMSNilMetadata struct{}

func (e ErrKMSNilMetadata) Error() string {
	return "KMS returned no key metadata"
}

// GRPCStatus classifies the error as Internal.
func (e ErrKMSNilMetadata) GRPCStatus() *status.Status {
	return status.New(codes.Internal, e.Error())
}

// ErrKMSGeneratedKeyMetadata is returned when a key was generated but the
// description and tags of the request could not be recorded on it, or its
// metadata could not be read back.
type ErrKMSGeneratedKeyMetadata struct {
	KeyID string
	Err   error
}

func (e ErrKMSGeneratedKeyMetadata) Error() string {
	return "KMS key " + e.KeyID + " was generated but its metadata could not be recorded: " + e.Err.Error()
}

func (e ErrKMSGeneratedKeyMetadata) Unwrap() error {
	return e.Err
}

// GRPCStatus classifies the error by its cause.
func (e ErrKMSGeneratedKeyMetadata) GRPCStatus() *status.Status {
	return status.New(errclass.Code(e.Err), e.Error())
}

// =============================================================================
// Platform KMS Backend
// =============================================================================

// PlatformKMSBackend implements the platform.v1 KeyManagementService backend
// interface (grpcapi.KMSService) by delegating to the same QuicBaaS SDK KMS
// and Crypto clients used by the quicbaas.kms.v1 pb adapters. It is the
// single backing implementation for the platform.v1 KMS surface across the
// gRPC-TCP, gRPC-UDS, REST, and embedded transports.
type PlatformKMSBackend struct {
	kmsClient    quicbaas.KMSClient
	cryptoClient quicbaas.CryptoClient
	logger       *slog.Logger
}

// NewPlatformKMSBackend creates a platform KMS backend wrapping the SDK
// KMS and Crypto clients.
func NewPlatformKMSBackend(
	kmsClient quicbaas.KMSClient,
	cryptoClient quicbaas.CryptoClient,
	logger *slog.Logger,
) *PlatformKMSBackend {
	return &PlatformKMSBackend{
		kmsClient:    kmsClient,
		cryptoClient: cryptoClient,
		logger:       logger,
	}
}

// PlatformKMSBackend returns a backend implementing the platform.v1 KMS
// service interfaces, sharing the same SDK clients as the pb adapters.
// The server adapters are initialized lazily if needed.
func (s *KMSService) PlatformKMSBackend() (*PlatformKMSBackend, error) {
	if err := s.initializeServers(); err != nil {
		return nil, err
	}
	return NewPlatformKMSBackend(s.kmsAdapter.client, s.cryptoServer.client, s.logger), nil
}

// kmsOrErr returns the SDK KMS client or a typed unavailable error.
func (b *PlatformKMSBackend) kmsOrErr() (quicbaas.KMSClient, error) {
	if b == nil || b.kmsClient == nil {
		return nil, ErrKMSClientUnavailable{Client: "kms"}
	}
	return b.kmsClient, nil
}

// cryptoOrErr returns the SDK Crypto client or a typed unavailable error.
func (b *PlatformKMSBackend) cryptoOrErr() (quicbaas.CryptoClient, error) {
	if b == nil || b.cryptoClient == nil {
		return nil, ErrKMSClientUnavailable{Client: "crypto"}
	}
	return b.cryptoClient, nil
}

// =============================================================================
// Key Management
// =============================================================================

// GenerateKey creates a new cryptographic key via the SDK KMS client.
func (b *PlatformKMSBackend) GenerateKey(
	ctx context.Context,
	req *grpcapi.KMSGenerateKeyRequest,
) (*grpcapi.KMSGenerateKeyResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GenerateKey"}
	}
	if req.KeySpec == nil {
		return nil, ErrKMSMissingKeySpec{Operation: "GenerateKey"}
	}

	algorithm, err := platformKMSAlgorithmToSDK(req.KeySpec.Algorithm)
	if err != nil {
		return nil, err
	}
	usage, err := platformKMSUsagesToSDK(req.KeySpec.Usage)
	if err != nil {
		return nil, err
	}

	resp, err := client.GenerateKey(ctx, &kms.GenerateKeyRequest{
		Name:               req.Name,
		Algorithm:          algorithm,
		Usage:              usage,
		Exportable:         req.KeySpec.Exportable,
		DeletionProtection: req.KeySpec.DeletionProtection,
	})
	if err != nil {
		return nil, err
	}

	meta, err := recordGeneratedKeyMetadata(ctx, client, resp.KeyID, req.Description, req.Tags)
	if err != nil {
		return nil, err
	}

	handle, metadata := sdkKeyMetadataToPlatformKMS(meta)
	return &grpcapi.KMSGenerateKeyResponse{
		Key:       handle,
		Metadata:  metadata,
		Timestamp: unixNow(),
	}, nil
}

// ImportKey imports externally generated key material via the SDK KMS client.
func (b *PlatformKMSBackend) ImportKey(
	ctx context.Context,
	req *grpcapi.KMSImportKeyRequest,
) (*grpcapi.KMSImportKeyResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "ImportKey"}
	}
	if req.KeySpec == nil {
		return nil, ErrKMSMissingKeySpec{Operation: "ImportKey"}
	}

	algorithm, err := platformKMSAlgorithmToSDK(req.KeySpec.Algorithm)
	if err != nil {
		return nil, err
	}
	usage, err := platformKMSUsagesToSDK(req.KeySpec.Usage)
	if err != nil {
		return nil, err
	}

	resp, err := client.ImportKey(ctx, &kms.ImportKeyRequest{
		KeyMaterial:   req.KeyMaterial,
		WrappingKeyID: req.WrappingKeyID,
		Name:          req.Name,
		Description:   req.Description,
		Algorithm:     algorithm,
		Usage:         usage,
		Tags:          req.Tags,
	})
	if err != nil {
		return nil, err
	}

	now := unixNow()
	algorithmPb := sdkAlgorithmToPlatformKMS(resp.Algorithm)
	return &grpcapi.KMSImportKeyResponse{
		Key: &grpcapi.KMSKeyHandle{
			KeyID:     resp.KeyID,
			Version:   uint64(resp.Version),
			Algorithm: algorithmPb,
			Status:    int32(platformv1.KeyStatus_KEY_STATUS_ENABLED),
			CreatedAt: now,
		},
		Metadata: &grpcapi.KMSKeyMetadata{
			KeyID:       resp.KeyID,
			Name:        req.Name,
			Description: req.Description,
			Algorithm:   algorithmPb,
			Status:      int32(platformv1.KeyStatus_KEY_STATUS_ENABLED),
			Usage:       req.KeySpec.Usage,
			Version:     uint64(resp.Version),
			CreatedAt:   now,
			UpdatedAt:   now,
			Tags:        req.Tags,
		},
		Timestamp: now,
	}, nil
}

// GetKey retrieves key information and metadata via the SDK KMS client.
func (b *PlatformKMSBackend) GetKey(
	ctx context.Context,
	req *grpcapi.KMSGetKeyRequest,
) (*grpcapi.KMSGetKeyResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GetKey"}
	}

	meta, err := client.GetKeyMetadata(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}

	handle, metadata := sdkKeyMetadataToPlatformKMS(meta)
	return &grpcapi.KMSGetKeyResponse{
		Key:       handle,
		Metadata:  metadata,
		Timestamp: unixNow(),
	}, nil
}

// sdkKeyMetadataToPlatformKMS converts the metadata the KMS recorded for a key
// into the platform key handle and key metadata.
func sdkKeyMetadataToPlatformKMS(meta *kms.KeyMetadataResponse) (*grpcapi.KMSKeyHandle, *grpcapi.KMSKeyMetadata) {
	algorithmPb := sdkAlgorithmToPlatformKMS(meta.Algorithm)
	statusPb := sdkStatusToPlatformKMS(meta.Status)
	handle := &grpcapi.KMSKeyHandle{
		KeyID:     meta.KeyID,
		Version:   uint64(meta.Version),
		Algorithm: algorithmPb,
		Status:    statusPb,
		CreatedAt: unixOrZero(meta.CreatedAt),
	}
	metadata := &grpcapi.KMSKeyMetadata{
		KeyID:              meta.KeyID,
		Name:               meta.Name,
		Description:        meta.Description,
		Algorithm:          algorithmPb,
		Status:             statusPb,
		Usage:              sdkUsagesToPlatformKMS(meta.Usage),
		Version:            uint64(meta.Version),
		Exportable:         meta.Exportable,
		DeletionProtection: meta.DeletionProtection,
		CreatedAt:          unixOrZero(meta.CreatedAt),
		UpdatedAt:          unixOrZero(meta.UpdatedAt),
		LastUsedAt:         unixOrZero(meta.LastUsedAt),
		Tags:               meta.Tags,
		Owner:              meta.Owner,
	}
	return handle, metadata
}

// ListKeys lists keys via the SDK KMS client with offset-cursor pagination
// and optional name / algorithm filtering.
func (b *PlatformKMSBackend) ListKeys(
	ctx context.Context,
	req *grpcapi.KMSListKeysRequest,
) (*grpcapi.KMSListKeysResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "ListKeys"}
	}

	resp, err := client.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	keys := resp.Keys
	if len(req.Filter) > 0 {
		keys, err = filterKeyInfos(keys, req.Filter)
		if err != nil {
			return nil, err
		}
	}

	start, end, nextCursor, hasMore, err := paginateKMSOffset(len(keys), req.Limit, req.Cursor)
	if err != nil {
		return nil, err
	}

	handles := make([]*grpcapi.KMSKeyHandle, 0, end-start)
	for _, k := range keys[start:end] {
		handles = append(handles, &grpcapi.KMSKeyHandle{
			KeyID:     k.KeyID,
			Version:   uint64(k.Version),
			Algorithm: sdkAlgorithmToPlatformKMS(k.Algorithm),
			Status:    int32(platformv1.KeyStatus_KEY_STATUS_ENABLED),
			CreatedAt: unixOrZero(k.CreatedAt),
		})
	}

	return &grpcapi.KMSListKeysResponse{
		Keys:       handles,
		NextCursor: nextCursor,
		HasMore:    hasMore,
		TotalCount: int32(len(keys)),
		Timestamp:  unixNow(),
	}, nil
}

// DeleteKey deletes a key via the SDK KMS client. The SDK performs immediate
// deletion; scheduled pending-deletion windows are not supported by the
// backend, so the response reports the key as destroyed at deletion time.
func (b *PlatformKMSBackend) DeleteKey(
	ctx context.Context,
	req *grpcapi.KMSDeleteKeyRequest,
) (*grpcapi.KMSDeleteKeyResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "DeleteKey"}
	}

	if err := client.DeleteKey(ctx, req.KeyID); err != nil {
		return nil, err
	}

	now := unixNow()
	return &grpcapi.KMSDeleteKeyResponse{
		KeyID:        req.KeyID,
		Status:       int32(platformv1.KeyStatus_KEY_STATUS_DESTROYED),
		DeletionDate: now,
		Timestamp:    now,
	}, nil
}

// RotateKey rotates a key to a new version via the SDK KMS client.
func (b *PlatformKMSBackend) RotateKey(
	ctx context.Context,
	req *grpcapi.KMSRotateKeyRequest,
) (*grpcapi.KMSRotateKeyResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "RotateKey"}
	}

	resp, err := client.RotateKey(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}

	var oldVersion uint64
	if resp.NewVersion > 0 {
		oldVersion = uint64(resp.NewVersion) - 1
	}
	return &grpcapi.KMSRotateKeyResponse{
		KeyID:      resp.KeyID,
		OldVersion: oldVersion,
		NewVersion: uint64(resp.NewVersion),
		Timestamp:  unixNow(),
	}, nil
}

// UpdateKeyStatus enables or disables a key or key version via the SDK KMS
// client.
func (b *PlatformKMSBackend) UpdateKeyStatus(
	ctx context.Context,
	req *grpcapi.KMSUpdateKeyStatusRequest,
) (*grpcapi.KMSUpdateKeyStatusResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "UpdateKeyStatus"}
	}

	sdkStatus, err := platformKMSStatusToSDK(req.Status)
	if err != nil {
		return nil, err
	}

	resp, err := client.UpdateKeyStatus(ctx, &kms.UpdateKeyStatusRequest{
		KeyID:   req.KeyID,
		Version: int(req.Version),
		Status:  sdkStatus,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSUpdateKeyStatusResponse{
		KeyID:     resp.KeyID,
		Version:   uint64(resp.Version),
		Status:    sdkStatusToPlatformKMS(resp.Status),
		Timestamp: unixNow(),
	}, nil
}

// ExportKey exports wrapped key material via the SDK KMS client.
func (b *PlatformKMSBackend) ExportKey(
	ctx context.Context,
	req *grpcapi.KMSExportKeyRequest,
) (*grpcapi.KMSExportKeyResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "ExportKey"}
	}

	format, err := platformKMSExportFormatToSDK(req.Format)
	if err != nil {
		return nil, err
	}
	wrappingAlgorithm, err := platformKMSWrappingToSDK(req.WrappingAlgorithm)
	if err != nil {
		return nil, err
	}

	resp, err := client.ExportKey(ctx, &kms.ExportKeyRequest{
		KeyID:             req.KeyID,
		WrappingKeyID:     req.WrappingKeyID,
		WrappingAlgorithm: wrappingAlgorithm,
		Format:            format,
		Version:           int(req.Version),
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSExportKeyResponse{
		KeyID:             resp.KeyID,
		Format:            req.Format,
		WrappingKeyID:     resp.WrappingKeyID,
		WrappingAlgorithm: req.WrappingAlgorithm,
		WrappedMaterial:   resp.WrappedMaterial,
		Version:           uint64(resp.Version),
		Timestamp:         unixNow(),
	}, nil
}

// GetKeyVersions lists key versions via the SDK KMS client with offset-cursor
// pagination.
func (b *PlatformKMSBackend) GetKeyVersions(
	ctx context.Context,
	req *grpcapi.KMSGetKeyVersionsRequest,
) (*grpcapi.KMSGetKeyVersionsResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GetKeyVersions"}
	}

	resp, err := client.ListKeyVersions(ctx, req.KeyID)
	if err != nil {
		return nil, err
	}

	start, end, nextCursor, hasMore, err := paginateKMSOffset(len(resp.Versions), req.Limit, req.Cursor)
	if err != nil {
		return nil, err
	}

	versions := make([]*grpcapi.KMSKeyVersionInfo, 0, end-start)
	for _, v := range resp.Versions[start:end] {
		versions = append(versions, &grpcapi.KMSKeyVersionInfo{
			Version:    uint64(v.Version),
			Status:     sdkStatusToPlatformKMS(v.Status),
			Algorithm:  sdkAlgorithmToPlatformKMS(v.Algorithm),
			CreatedAt:  unixOrZero(v.CreatedAt),
			DisabledAt: unixOrZero(v.DisabledAt),
		})
	}

	return &grpcapi.KMSGetKeyVersionsResponse{
		KeyID:      resp.KeyID,
		Versions:   versions,
		NextCursor: nextCursor,
		HasMore:    hasMore,
		Timestamp:  unixNow(),
	}, nil
}

// =============================================================================
// Cryptographic Operations
// =============================================================================

// Encrypt encrypts plaintext via the SDK Crypto client.
func (b *PlatformKMSBackend) Encrypt(
	ctx context.Context,
	req *grpcapi.KMSEncryptRequest,
) (*grpcapi.KMSEncryptResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Encrypt"}
	}

	resp, err := client.Encrypt(ctx, &quicbaas.EncryptRequest{
		KeyID:     req.KeyID,
		Plaintext: req.Plaintext,
		Context:   req.Context,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSEncryptResponse{
		KeyID:      req.KeyID,
		KeyVersion: uint64(resp.KeyVersion),
		Ciphertext: resp.Ciphertext,
		Timestamp:  unixNow(),
	}, nil
}

// Decrypt decrypts ciphertext via the SDK Crypto client.
func (b *PlatformKMSBackend) Decrypt(
	ctx context.Context,
	req *grpcapi.KMSDecryptRequest,
) (*grpcapi.KMSDecryptResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Decrypt"}
	}

	resp, err := client.Decrypt(ctx, &quicbaas.DecryptRequest{
		KeyID:      req.KeyID,
		Ciphertext: req.Ciphertext,
		Context:    req.Context,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSDecryptResponse{
		KeyID:      req.KeyID,
		KeyVersion: req.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  unixNow(),
	}, nil
}

// BatchEncrypt encrypts multiple items in a single SDK Crypto client request.
func (b *PlatformKMSBackend) BatchEncrypt(
	ctx context.Context,
	req *grpcapi.KMSBatchEncryptRequest,
) (*grpcapi.KMSBatchEncryptResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "BatchEncrypt"}
	}

	items := make([]sdkcrypto.BatchEncryptItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = sdkcrypto.BatchEncryptItem{
			Plaintext: item.Plaintext,
			Context:   item.Context,
		}
	}

	resp, err := client.EncryptBatch(ctx, &quicbaas.EncryptBatchRequest{
		KeyID: req.KeyID,
		Items: items,
	})
	if err != nil {
		return nil, err
	}

	results := make([]*grpcapi.KMSBatchEncryptResultItem, len(resp.Results))
	var successCount, failureCount int32
	for i, r := range resp.Results {
		result := &grpcapi.KMSBatchEncryptResultItem{
			Success:    r.Error == "",
			Message:    r.Error,
			Ciphertext: r.Ciphertext,
			Nonce:      r.Nonce,
		}
		if i < len(req.Items) {
			result.ItemID = req.Items[i].ItemID
		}
		if result.Success {
			result.KeyVersion = uint64(resp.KeyVersion)
			successCount++
		} else {
			failureCount++
		}
		results[i] = result
	}

	return &grpcapi.KMSBatchEncryptResponse{
		KeyID:        resp.KeyID,
		Results:      results,
		SuccessCount: successCount,
		FailureCount: failureCount,
		Timestamp:    unixNow(),
	}, nil
}

// BatchDecrypt decrypts multiple items in a single SDK Crypto client request.
func (b *PlatformKMSBackend) BatchDecrypt(
	ctx context.Context,
	req *grpcapi.KMSBatchDecryptRequest,
) (*grpcapi.KMSBatchDecryptResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "BatchDecrypt"}
	}

	items := make([]sdkcrypto.BatchDecryptItem, len(req.Items))
	for i, item := range req.Items {
		items[i] = sdkcrypto.BatchDecryptItem{
			Ciphertext: item.Ciphertext,
			Context:    item.Context,
			Nonce:      item.Nonce,
		}
	}

	resp, err := client.DecryptBatch(ctx, &quicbaas.DecryptBatchRequest{
		KeyID: req.KeyID,
		Items: items,
	})
	if err != nil {
		return nil, err
	}

	results := make([]*grpcapi.KMSBatchDecryptResultItem, len(resp.Results))
	var successCount, failureCount int32
	for i, r := range resp.Results {
		result := &grpcapi.KMSBatchDecryptResultItem{
			Success:   r.Error == "",
			Message:   r.Error,
			Plaintext: r.Plaintext,
		}
		if i < len(req.Items) {
			result.ItemID = req.Items[i].ItemID
			result.KeyVersion = req.Items[i].KeyVersion
		}
		if result.Success {
			successCount++
		} else {
			failureCount++
		}
		results[i] = result
	}

	return &grpcapi.KMSBatchDecryptResponse{
		KeyID:        resp.KeyID,
		Results:      results,
		SuccessCount: successCount,
		FailureCount: failureCount,
		Timestamp:    unixNow(),
	}, nil
}

// Rewrap re-encrypts ciphertext with the latest key version via the SDK
// Crypto client.
func (b *PlatformKMSBackend) Rewrap(
	ctx context.Context,
	req *grpcapi.KMSRewrapRequest,
) (*grpcapi.KMSRewrapResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Rewrap"}
	}

	resp, err := client.Rewrap(ctx, &quicbaas.RewrapRequest{
		KeyID:      req.KeyID,
		Ciphertext: req.Ciphertext,
		Context:    req.Context,
		Nonce:      req.Nonce,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSRewrapResponse{
		KeyID:         resp.KeyID,
		SourceVersion: uint64(resp.OldKeyVersion),
		TargetVersion: uint64(resp.NewKeyVersion),
		Ciphertext:    resp.Ciphertext,
		Nonce:         resp.Nonce,
		Timestamp:     unixNow(),
	}, nil
}

// Sign creates a digital signature via the SDK Crypto client. The PreHashed
// flag is threaded through to the SDK so pre-computed digests (e.g. from
// crypto.Signer callers) are signed without being re-hashed.
func (b *PlatformKMSBackend) Sign(
	ctx context.Context,
	req *grpcapi.KMSSignRequest,
) (*grpcapi.KMSSignResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Sign"}
	}

	hashAlg, err := platformKMSHashToSDK(req.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	resp, err := client.Sign(ctx, &quicbaas.SignRequest{
		KeyID:     req.KeyID,
		Data:      req.Message,
		HashAlg:   hashAlg,
		PreHashed: req.PreHashed,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSSignResponse{
		KeyID:         req.KeyID,
		KeyVersion:    uint64(resp.KeyVersion),
		Signature:     resp.Signature,
		HashAlgorithm: sdkHashToPlatformKMS(hashAlg),
		Timestamp:     unixNow(),
	}, nil
}

// Verify verifies a digital signature via the SDK Crypto client.
func (b *PlatformKMSBackend) Verify(
	ctx context.Context,
	req *grpcapi.KMSVerifyRequest,
) (*grpcapi.KMSVerifyResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Verify"}
	}

	hashAlg, err := platformKMSHashToSDK(req.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	resp, err := client.Verify(ctx, &quicbaas.VerifyRequest{
		KeyID:     req.KeyID,
		Data:      req.Message,
		Signature: req.Signature,
		HashAlg:   hashAlg,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSVerifyResponse{
		KeyID:      req.KeyID,
		KeyVersion: req.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  unixNow(),
	}, nil
}

// Hash computes a cryptographic hash via the SDK Crypto client.
func (b *PlatformKMSBackend) Hash(
	ctx context.Context,
	req *grpcapi.KMSHashRequest,
) (*grpcapi.KMSHashResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "Hash"}
	}

	hashAlg, err := platformKMSHashToSDK(req.Algorithm)
	if err != nil {
		return nil, err
	}

	resp, err := client.Hash(ctx, &quicbaas.HashRequest{
		Data:    req.Data,
		HashAlg: hashAlg,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSHashResponse{
		Algorithm: sdkHashToPlatformKMS(resp.HashAlg),
		Hash:      resp.Hash,
		Timestamp: unixNow(),
	}, nil
}

// HMAC computes an HMAC via the SDK Crypto client.
func (b *PlatformKMSBackend) HMAC(
	ctx context.Context,
	req *grpcapi.KMSHMACRequest,
) (*grpcapi.KMSHMACResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "HMAC"}
	}

	hashAlg, err := platformKMSHashToSDK(req.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	resp, err := client.GenerateHMAC(ctx, &quicbaas.GenerateHMACRequest{
		KeyID:   req.KeyID,
		Message: req.Message,
		HashAlg: hashAlg,
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSHMACResponse{
		KeyID:         resp.KeyID,
		KeyVersion:    uint64(resp.KeyVersion),
		HMAC:          resp.HMAC,
		HashAlgorithm: sdkHashToPlatformKMS(resp.HashAlg),
		Timestamp:     unixNow(),
	}, nil
}

// VerifyHMAC verifies an HMAC via the SDK Crypto client.
func (b *PlatformKMSBackend) VerifyHMAC(
	ctx context.Context,
	req *grpcapi.KMSVerifyHMACRequest,
) (*grpcapi.KMSVerifyHMACResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "VerifyHMAC"}
	}

	hashAlg, err := platformKMSHashToSDK(req.HashAlgorithm)
	if err != nil {
		return nil, err
	}

	resp, err := client.VerifyHMAC(ctx, &quicbaas.VerifyHMACRequest{
		KeyID:      req.KeyID,
		Message:    req.Message,
		HMAC:       req.HMAC,
		HashAlg:    hashAlg,
		KeyVersion: int(req.KeyVersion),
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSVerifyHMACResponse{
		KeyID:      req.KeyID,
		KeyVersion: req.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  unixNow(),
	}, nil
}

// GenerateRandom generates cryptographically secure random bytes via the SDK
// Crypto client.
func (b *PlatformKMSBackend) GenerateRandom(
	ctx context.Context,
	req *grpcapi.KMSGenerateRandomRequest,
) (*grpcapi.KMSGenerateRandomResponse, error) {
	client, err := b.cryptoOrErr()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrKMSMissingRequest{Operation: "GenerateRandom"}
	}

	resp, err := client.GenerateRandom(ctx, &quicbaas.GenerateRandomRequest{
		NumBytes: int(req.NumBytes),
	})
	if err != nil {
		return nil, err
	}

	return &grpcapi.KMSGenerateRandomResponse{
		RandomBytes: resp.RandomBytes,
		Timestamp:   unixNow(),
	}, nil
}

// BackendStatus reports KMS backend health and capabilities via the SDK KMS
// client.
func (b *PlatformKMSBackend) BackendStatus(
	ctx context.Context,
) (*grpcapi.KMSBackendStatusResponse, error) {
	client, err := b.kmsOrErr()
	if err != nil {
		return nil, err
	}

	resp, err := client.BackendStatus(ctx)
	if err != nil {
		return nil, err
	}

	pcrRegisters := make([]int32, len(resp.PCRRegisters))
	for i, v := range resp.PCRRegisters {
		pcrRegisters[i] = int32(v)
	}

	return &grpcapi.KMSBackendStatusResponse{
		BackendType:  resp.BackendType,
		Status:       resp.Status,
		Device:       resp.Device,
		Region:       resp.Region,
		KeyID:        resp.KeyID,
		PcrBanks:     resp.PCRBanks,
		PcrRegisters: pcrRegisters,
		Capabilities: resp.Capabilities,
		Timestamp:    unixNow(),
	}, nil
}

// Ensure PlatformKMSBackend implements the platform gRPC KMS interface.
var _ grpcapi.KMSService = (*PlatformKMSBackend)(nil)

// =============================================================================
// Enum Conversions (platform.v1 <-> QuicBaaS SDK)
// =============================================================================

// platformKMSAlgorithmToSDK converts a platform.v1 KMSKeyAlgorithm value to
// the SDK KeyAlgorithm. KMS_KEY_ALGORITHM_UNSPECIFIED maps to the SDK zero
// value (AES-256-GCM); algorithms with no SDK equivalent return a typed error.
func platformKMSAlgorithmToSDK(alg int32) (kms.KeyAlgorithm, error) {
	switch platformv1.KMSKeyAlgorithm(alg) {
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED,
		platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256:
		return kms.AlgorithmAES256GCM, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305:
		return kms.AlgorithmChaCha20Poly1305, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048:
		return kms.AlgorithmRSA2048, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096:
		return kms.AlgorithmRSA4096, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256:
		return kms.AlgorithmECDSAP256, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384:
		return kms.AlgorithmECDSAP384, nil
	case platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:
		return kms.AlgorithmED25519, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "key algorithm", Value: alg}
	}
}

// sdkAlgorithmToPlatformKMS converts an SDK KeyAlgorithm to the platform.v1
// KMSKeyAlgorithm value.
func sdkAlgorithmToPlatformKMS(alg kms.KeyAlgorithm) int32 {
	switch alg {
	case kms.AlgorithmAES256GCM:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256)
	case kms.AlgorithmChaCha20Poly1305:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305)
	case kms.AlgorithmRSA2048:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048)
	case kms.AlgorithmRSA4096:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096)
	case kms.AlgorithmECDSAP256:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256)
	case kms.AlgorithmECDSAP384:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384)
	case kms.AlgorithmED25519:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519)
	default:
		return int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED)
	}
}

// platformKMSUsagesToSDK converts platform.v1 KeyUsage values to SDK KeyUsage
// values. Usages with no SDK equivalent return a typed error.
func platformKMSUsagesToSDK(usages []int32) ([]kms.KeyUsage, error) {
	result := make([]kms.KeyUsage, 0, len(usages))
	for _, u := range usages {
		switch platformv1.KeyUsage(u) {
		case platformv1.KeyUsage_KEY_USAGE_ENCRYPT:
			result = append(result, kms.KeyUsageEncrypt)
		case platformv1.KeyUsage_KEY_USAGE_DECRYPT:
			result = append(result, kms.KeyUsageDecrypt)
		case platformv1.KeyUsage_KEY_USAGE_SIGN:
			result = append(result, kms.KeyUsageSign)
		case platformv1.KeyUsage_KEY_USAGE_VERIFY:
			result = append(result, kms.KeyUsageVerify)
		case platformv1.KeyUsage_KEY_USAGE_WRAP:
			result = append(result, kms.KeyUsageWrap)
		case platformv1.KeyUsage_KEY_USAGE_UNWRAP:
			result = append(result, kms.KeyUsageUnwrap)
		default:
			return nil, ErrKMSUnsupportedValue{Kind: "key usage", Value: u}
		}
	}
	return result, nil
}

// sdkUsagesToPlatformKMS converts SDK KeyUsage values to platform.v1 KeyUsage
// values.
func sdkUsagesToPlatformKMS(usages []kms.KeyUsage) []int32 {
	result := make([]int32, 0, len(usages))
	for _, u := range usages {
		switch u {
		case kms.KeyUsageEncrypt:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT))
		case kms.KeyUsageDecrypt:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT))
		case kms.KeyUsageSign:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_SIGN))
		case kms.KeyUsageVerify:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_VERIFY))
		case kms.KeyUsageWrap:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_WRAP))
		case kms.KeyUsageUnwrap:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_UNWRAP))
		default:
			result = append(result, int32(platformv1.KeyUsage_KEY_USAGE_UNSPECIFIED))
		}
	}
	return result
}

// platformKMSStatusToSDK converts a platform.v1 KeyStatus value to the SDK
// KeyStatus. Statuses with no SDK equivalent return a typed error.
func platformKMSStatusToSDK(status int32) (kms.KeyStatus, error) {
	switch platformv1.KeyStatus(status) {
	case platformv1.KeyStatus_KEY_STATUS_ENABLED:
		return kms.KeyStatusEnabled, nil
	case platformv1.KeyStatus_KEY_STATUS_DISABLED:
		return kms.KeyStatusDisabled, nil
	case platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION:
		return kms.KeyStatusPendingDeletion, nil
	case platformv1.KeyStatus_KEY_STATUS_DESTROYED:
		return kms.KeyStatusDeleted, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "key status", Value: status}
	}
}

// sdkStatusToPlatformKMS converts an SDK KeyStatus to the platform.v1
// KeyStatus value. Rotating keys remain usable so they report as enabled;
// compromised keys report as disabled since the platform proto has no
// dedicated state for either.
func sdkStatusToPlatformKMS(status kms.KeyStatus) int32 {
	switch status {
	case kms.KeyStatusEnabled, kms.KeyStatusRotating:
		return int32(platformv1.KeyStatus_KEY_STATUS_ENABLED)
	case kms.KeyStatusDisabled, kms.KeyStatusCompromised:
		return int32(platformv1.KeyStatus_KEY_STATUS_DISABLED)
	case kms.KeyStatusPendingDeletion:
		return int32(platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION)
	case kms.KeyStatusDeleted:
		return int32(platformv1.KeyStatus_KEY_STATUS_DESTROYED)
	default:
		return int32(platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED)
	}
}

// platformKMSHashToSDK converts a platform.v1 HashAlgorithm value to the SDK
// HashAlgorithm. HASH_ALGORITHM_UNSPECIFIED maps to SHA-256 (the SDK zero
// value); algorithms with no SDK equivalent return a typed error.
func platformKMSHashToSDK(alg int32) (quicbaas.HashAlgorithm, error) {
	switch platformv1.HashAlgorithm(alg) {
	case platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256:
		return quicbaas.HashSHA256, nil
	case platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384:
		return quicbaas.HashSHA384, nil
	case platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512:
		return quicbaas.HashSHA512, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "hash algorithm", Value: alg}
	}
}

// sdkHashToPlatformKMS converts an SDK HashAlgorithm to the platform.v1
// HashAlgorithm value.
func sdkHashToPlatformKMS(alg quicbaas.HashAlgorithm) int32 {
	switch alg {
	case quicbaas.HashSHA256:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256)
	case quicbaas.HashSHA384:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384)
	case quicbaas.HashSHA512:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512)
	default:
		return int32(platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED)
	}
}

// platformKMSExportFormatToSDK converts a platform.v1 KeyExportFormat value to
// the SDK ExportFormat. KEY_EXPORT_FORMAT_UNSPECIFIED maps to the SDK zero
// value (raw); formats with no SDK equivalent return a typed error.
func platformKMSExportFormatToSDK(format int32) (kms.ExportFormat, error) {
	switch platformv1.KeyExportFormat(format) {
	case platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_UNSPECIFIED,
		platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_RAW:
		return kms.ExportFormatRaw, nil
	case platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_JWK:
		return kms.ExportFormatJWK, nil
	case platformv1.KeyExportFormat_KEY_EXPORT_FORMAT_PEM:
		return kms.ExportFormatPEM, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "key export format", Value: format}
	}
}

// platformKMSWrappingToSDK converts a platform.v1 WrappingAlgorithm value to
// the SDK WrappingAlgorithm. WRAPPING_ALGORITHM_UNSPECIFIED maps to the SDK
// zero value (RFC 3394 AES-KW).
func platformKMSWrappingToSDK(alg int32) (kms.WrappingAlgorithm, error) {
	switch platformv1.WrappingAlgorithm(alg) {
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_UNSPECIFIED:
		return kms.WrapAlgAESKW, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA256:
		return kms.WrapAlgRSAOAEPSHA256, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA384:
		return kms.WrapAlgRSAOAEPSHA384, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_RSA_OAEP_SHA512:
		return kms.WrapAlgRSAOAEPSHA512, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_GCM:
		return kms.WrapAlgAESGCM, nil
	case platformv1.WrappingAlgorithm_WRAPPING_ALGORITHM_AES_KWP:
		return kms.WrapAlgAESKWP, nil
	default:
		return 0, ErrKMSUnsupportedValue{Kind: "wrapping algorithm", Value: alg}
	}
}

// =============================================================================
// Helpers
// =============================================================================

// unixNow returns the current UTC time as a Unix timestamp.
func unixNow() int64 {
	return time.Now().UTC().Unix()
}

// unixOrZero returns the Unix timestamp for t, or 0 when t is the zero time.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// paginateKMSOffset applies offset-cursor pagination over total items. The
// cursor is a decimal offset produced by a previous call; an empty cursor
// starts at offset 0. A limit <= 0 returns all remaining items.
func paginateKMSOffset(total int, limit int32, cursor string) (start, end int, nextCursor string, hasMore bool, err error) {
	if cursor != "" {
		offset, parseErr := strconv.Atoi(cursor)
		if parseErr != nil || offset < 0 {
			return 0, 0, "", false, ErrKMSInvalidCursor{Cursor: cursor}
		}
		start = offset
	}
	if start > total {
		start = total
	}
	end = total
	if limit > 0 && start+int(limit) < total {
		end = start + int(limit)
		hasMore = true
		nextCursor = strconv.Itoa(end)
	}
	return start, end, nextCursor, hasMore, nil
}

// filterKeyInfos filters key listings by the supported filter keys "name"
// (exact match) and "algorithm" (case-insensitive match against the SDK
// algorithm name). Unsupported filter keys return a typed error rather than
// being silently ignored.
func filterKeyInfos(keys []kms.KeyInfo, filter map[string]string) ([]kms.KeyInfo, error) {
	for key := range filter {
		switch key {
		case "name", "algorithm":
		default:
			return nil, ErrKMSUnsupportedFilter{Key: key}
		}
	}
	result := make([]kms.KeyInfo, 0, len(keys))
	for _, k := range keys {
		if name, ok := filter["name"]; ok && k.Name != name {
			continue
		}
		if alg, ok := filter["algorithm"]; ok && !strings.EqualFold(k.Algorithm.String(), alg) {
			continue
		}
		result = append(result, k)
	}
	return result, nil
}
