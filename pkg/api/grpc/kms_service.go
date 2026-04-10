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

package grpc

import (
	"context"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// KMS gRPC service error types.

// ErrNilKMSService is returned when the KMS service is nil.
type ErrNilKMSService struct{}

func (e ErrNilKMSService) Error() string {
	return "kms service is nil"
}

// ErrMissingKeyID is returned when a key ID is required but not provided.
type ErrMissingKeyID struct{}

func (e ErrMissingKeyID) Error() string {
	return "key ID is required"
}

// ErrMissingKeySpec is returned when key specification is required but not provided.
type ErrMissingKeySpec struct{}

func (e ErrMissingKeySpec) Error() string {
	return "key specification is required"
}

// ErrMissingKeyMaterial is returned when key material is required but not provided.
type ErrMissingKeyMaterial struct{}

func (e ErrMissingKeyMaterial) Error() string {
	return "key material is required"
}

// ErrMissingPlaintext is returned when plaintext is required but not provided.
type ErrMissingPlaintext struct{}

func (e ErrMissingPlaintext) Error() string {
	return "plaintext is required"
}

// ErrMissingCiphertext is returned when ciphertext is required but not provided.
type ErrMissingCiphertext struct{}

func (e ErrMissingCiphertext) Error() string {
	return "ciphertext is required"
}

// ErrMissingMessage is returned when a message is required but not provided.
type ErrMissingMessage struct{}

func (e ErrMissingMessage) Error() string {
	return "message is required"
}

// ErrMissingSignature is returned when a signature is required but not provided.
type ErrMissingSignature struct{}

func (e ErrMissingSignature) Error() string {
	return "signature is required"
}

// ErrMissingData is returned when data is required but not provided.
type ErrMissingData struct{}

func (e ErrMissingData) Error() string {
	return "data is required"
}

// ErrMissingHMAC is returned when HMAC is required but not provided.
type ErrMissingHMAC struct{}

func (e ErrMissingHMAC) Error() string {
	return "hmac is required"
}

// ErrInvalidNumBytes is returned when the number of bytes requested is invalid.
type ErrInvalidNumBytes struct{}

func (e ErrInvalidNumBytes) Error() string {
	return "num_bytes must be greater than 0"
}

// ErrMissingWrappingKeyID is returned when a wrapping key ID is required but not provided.
type ErrMissingWrappingKeyID struct{}

func (e ErrMissingWrappingKeyID) Error() string {
	return "wrapping key ID is required"
}

// ErrMissingItems is returned when batch items are required but not provided.
type ErrMissingItems struct{}

func (e ErrMissingItems) Error() string {
	return "items are required"
}

// ErrTooManyItems is returned when batch items exceed the maximum allowed.
type ErrTooManyItems struct {
	Max int
}

func (e ErrTooManyItems) Error() string {
	return "too many items in batch request"
}

// KMSGRPCService implements the gRPC KeyManagementService server interface.
// It wraps the KMSService interface to provide gRPC access to KMS operations.
type KMSGRPCService struct {
	platformv1.UnimplementedKeyManagementServiceServer
	logger  *logging.Logger
	service KMSService
}

// NewKMSGRPCService creates a new KMSGRPCService instance.
func NewKMSGRPCService(
	logger *logging.Logger,
	service KMSService,
) *KMSGRPCService {
	return &KMSGRPCService{
		logger:  logger,
		service: service,
	}
}

// GenerateKey creates a new cryptographic key.
func (s *KMSGRPCService) GenerateKey(
	ctx context.Context,
	req *platformv1.GenerateKeyRequest,
) (*platformv1.GenerateKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeySpec() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeySpec{}.Error())
	}

	kmsReq := &KMSGenerateKeyRequest{
		KeySpec:     protoKeySpecToKMS(req.GetKeySpec()),
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Tags:        req.GetTags(),
		Owner:       req.GetOwner(),
	}

	resp, err := s.service.GenerateKey(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("GenerateKey", err)
	}

	return &platformv1.GenerateKeyResponse{
		Status:    successStatus("key generated successfully"),
		Key:       kmsKeyHandleToProto(resp.Key),
		Metadata:  kmsKeyMetadataToProto(resp.Metadata),
		Timestamp: resp.Timestamp,
	}, nil
}

// ImportKey imports an existing key into the KMS.
func (s *KMSGRPCService) ImportKey(
	ctx context.Context,
	req *platformv1.ImportKeyRequest,
) (*platformv1.ImportKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if len(req.GetKeyMaterial()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyMaterial{}.Error())
	}

	if req.GetKeySpec() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeySpec{}.Error())
	}

	kmsReq := &KMSImportKeyRequest{
		KeyMaterial:   req.GetKeyMaterial(),
		WrappingKeyID: req.GetWrappingKeyId(),
		KeySpec:       protoKeySpecToKMS(req.GetKeySpec()),
		Name:          req.GetName(),
		Description:   req.GetDescription(),
		Tags:          req.GetTags(),
	}

	resp, err := s.service.ImportKey(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("ImportKey", err)
	}

	return &platformv1.ImportKeyResponse{
		Status:    successStatus("key imported successfully"),
		Key:       kmsKeyHandleToProto(resp.Key),
		Metadata:  kmsKeyMetadataToProto(resp.Metadata),
		Timestamp: resp.Timestamp,
	}, nil
}

// GetKey retrieves key information by ID.
func (s *KMSGRPCService) GetKey(
	ctx context.Context,
	req *platformv1.GetKeyRequest,
) (*platformv1.GetKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	kmsReq := &KMSGetKeyRequest{
		KeyID:   req.GetKeyId(),
		Version: req.GetVersion(),
	}

	resp, err := s.service.GetKey(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("GetKey", err)
	}

	return &platformv1.GetKeyResponse{
		Key:       kmsKeyHandleToProto(resp.Key),
		Metadata:  kmsKeyMetadataToProto(resp.Metadata),
		Timestamp: resp.Timestamp,
	}, nil
}

// ListKeys returns a paginated list of keys.
func (s *KMSGRPCService) ListKeys(
	ctx context.Context,
	req *platformv1.ListKeysRequest,
) (*platformv1.ListKeysResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	kmsReq := &KMSListKeysRequest{
		Limit:  req.GetLimit(),
		Cursor: req.GetCursor(),
		Filter: req.GetFilter(),
	}

	resp, err := s.service.ListKeys(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("ListKeys", err)
	}

	keys := make([]*platformv1.KMSKeyHandle, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, kmsKeyHandleToProto(k))
	}

	return &platformv1.ListKeysResponse{
		Keys:       keys,
		NextCursor: resp.NextCursor,
		HasMore:    resp.HasMore,
		TotalCount: resp.TotalCount,
		Timestamp:  resp.Timestamp,
	}, nil
}

// DeleteKey schedules a key for deletion.
func (s *KMSGRPCService) DeleteKey(
	ctx context.Context,
	req *platformv1.DeleteKeyRequest,
) (*platformv1.DeleteKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	kmsReq := &KMSDeleteKeyRequest{
		KeyID:             req.GetKeyId(),
		PendingWindowDays: req.GetPendingWindowDays(),
		Force:             req.GetForce(),
	}

	resp, err := s.service.DeleteKey(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("DeleteKey", err)
	}

	return &platformv1.DeleteKeyResponse{
		Status:       successStatus("key scheduled for deletion"),
		KeyId:        resp.KeyID,
		KeyStatus:    platformv1.KeyStatus(resp.Status),
		DeletionDate: resp.DeletionDate,
		Timestamp:    resp.Timestamp,
	}, nil
}

// RotateKey creates a new version of an existing key.
func (s *KMSGRPCService) RotateKey(
	ctx context.Context,
	req *platformv1.RotateKeyRequest,
) (*platformv1.RotateKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	kmsReq := &KMSRotateKeyRequest{
		KeyID:            req.GetKeyId(),
		RetainOldVersion: req.GetRetainOldVersion(),
	}

	resp, err := s.service.RotateKey(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("RotateKey", err)
	}

	return &platformv1.RotateKeyResponse{
		Status:     successStatus("key rotated successfully"),
		KeyId:      resp.KeyID,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	}, nil
}

// UpdateKeyStatus changes the status of a key.
func (s *KMSGRPCService) UpdateKeyStatus(
	ctx context.Context,
	req *platformv1.UpdateKeyStatusRequest,
) (*platformv1.UpdateKeyStatusResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	kmsReq := &KMSUpdateKeyStatusRequest{
		KeyID:   req.GetKeyId(),
		Version: req.GetVersion(),
		Status:  int32(req.GetStatus()),
	}

	resp, err := s.service.UpdateKeyStatus(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("UpdateKeyStatus", err)
	}

	return &platformv1.UpdateKeyStatusResponse{
		Status:    successStatus("key status updated"),
		KeyId:     resp.KeyID,
		Version:   resp.Version,
		KeyStatus: platformv1.KeyStatus(resp.Status),
		Timestamp: resp.Timestamp,
	}, nil
}

// ExportKey exports a key if allowed by key policy.
func (s *KMSGRPCService) ExportKey(
	ctx context.Context,
	req *platformv1.ExportKeyRequest,
) (*platformv1.ExportKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	kmsReq := &KMSExportKeyRequest{
		KeyID:             req.GetKeyId(),
		WrappingKeyID:     req.GetWrappingKeyId(),
		WrappingAlgorithm: int32(req.GetWrappingAlgorithm()),
		Format:            int32(req.GetFormat()),
		Version:           req.GetVersion(),
	}

	resp, err := s.service.ExportKey(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("ExportKey", err)
	}

	return &platformv1.ExportKeyResponse{
		Status:            successStatus("key exported successfully"),
		KeyId:             resp.KeyID,
		Format:            platformv1.KeyExportFormat(resp.Format),
		WrappingKeyId:     resp.WrappingKeyID,
		WrappingAlgorithm: platformv1.WrappingAlgorithm(resp.WrappingAlgorithm),
		WrappedMaterial:   resp.WrappedMaterial,
		Version:           resp.Version,
		Timestamp:         resp.Timestamp,
	}, nil
}

// GetKeyVersions lists all versions of a key.
func (s *KMSGRPCService) GetKeyVersions(
	ctx context.Context,
	req *platformv1.GetKeyVersionsRequest,
) (*platformv1.GetKeyVersionsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	kmsReq := &KMSGetKeyVersionsRequest{
		KeyID:  req.GetKeyId(),
		Limit:  req.GetLimit(),
		Cursor: req.GetCursor(),
	}

	resp, err := s.service.GetKeyVersions(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("GetKeyVersions", err)
	}

	versions := make([]*platformv1.KMSKeyVersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, &platformv1.KMSKeyVersionInfo{
			Version:    v.Version,
			Status:     platformv1.KeyStatus(v.Status),
			Algorithm:  platformv1.KMSKeyAlgorithm(v.Algorithm),
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		})
	}

	return &platformv1.GetKeyVersionsResponse{
		KeyId:      resp.KeyID,
		Versions:   versions,
		NextCursor: resp.NextCursor,
		HasMore:    resp.HasMore,
		Timestamp:  resp.Timestamp,
	}, nil
}

// Encrypt encrypts data using a specified key.
func (s *KMSGRPCService) Encrypt(
	ctx context.Context,
	req *platformv1.EncryptRequest,
) (*platformv1.EncryptResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetPlaintext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPlaintext{}.Error())
	}

	kmsReq := &KMSEncryptRequest{
		KeyID:     req.GetKeyId(),
		Plaintext: req.GetPlaintext(),
		Context:   req.GetContext(),
		Nonce:     req.GetNonce(),
	}

	resp, err := s.service.Encrypt(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("Encrypt", err)
	}

	return &platformv1.EncryptResponse{
		Status:     successStatus("encryption successful"),
		KeyId:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Timestamp:  resp.Timestamp,
	}, nil
}

// Decrypt decrypts data using a specified key.
func (s *KMSGRPCService) Decrypt(
	ctx context.Context,
	req *platformv1.DecryptRequest,
) (*platformv1.DecryptResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetCiphertext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingCiphertext{}.Error())
	}

	kmsReq := &KMSDecryptRequest{
		KeyID:      req.GetKeyId(),
		Ciphertext: req.GetCiphertext(),
		Context:    req.GetContext(),
		Nonce:      req.GetNonce(),
		KeyVersion: req.GetKeyVersion(),
	}

	resp, err := s.service.Decrypt(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("Decrypt", err)
	}

	return &platformv1.DecryptResponse{
		Status:     successStatus("decryption successful"),
		KeyId:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  resp.Timestamp,
	}, nil
}

// BatchEncrypt encrypts multiple items in a single request for improved throughput.
func (s *KMSGRPCService) BatchEncrypt(
	ctx context.Context,
	req *platformv1.BatchEncryptRequest,
) (*platformv1.BatchEncryptResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetItems()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingItems{}.Error())
	}

	const maxBatchItems = 100
	if len(req.GetItems()) > maxBatchItems {
		return nil, status.Error(codes.InvalidArgument, ErrTooManyItems{Max: maxBatchItems}.Error())
	}

	kmsReq := &KMSBatchEncryptRequest{
		KeyID: req.GetKeyId(),
		Items: protoBatchEncryptItemsToKMS(req.GetItems()),
	}

	resp, err := s.service.BatchEncrypt(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("BatchEncrypt", err)
	}

	return &platformv1.BatchEncryptResponse{
		Status:       successStatus("batch encryption completed"),
		KeyId:        resp.KeyID,
		Results:      kmsBatchEncryptResultsToProto(resp.Results),
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Timestamp:    resp.Timestamp,
	}, nil
}

// BatchDecrypt decrypts multiple items in a single request for improved throughput.
func (s *KMSGRPCService) BatchDecrypt(
	ctx context.Context,
	req *platformv1.BatchDecryptRequest,
) (*platformv1.BatchDecryptResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetItems()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingItems{}.Error())
	}

	const maxBatchItems = 100
	if len(req.GetItems()) > maxBatchItems {
		return nil, status.Error(codes.InvalidArgument, ErrTooManyItems{Max: maxBatchItems}.Error())
	}

	kmsReq := &KMSBatchDecryptRequest{
		KeyID: req.GetKeyId(),
		Items: protoBatchDecryptItemsToKMS(req.GetItems()),
	}

	resp, err := s.service.BatchDecrypt(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("BatchDecrypt", err)
	}

	return &platformv1.BatchDecryptResponse{
		Status:       successStatus("batch decryption completed"),
		KeyId:        resp.KeyID,
		Results:      kmsBatchDecryptResultsToProto(resp.Results),
		SuccessCount: resp.SuccessCount,
		FailureCount: resp.FailureCount,
		Timestamp:    resp.Timestamp,
	}, nil
}

// Rewrap re-encrypts ciphertext with the latest key version without exposing plaintext.
func (s *KMSGRPCService) Rewrap(
	ctx context.Context,
	req *platformv1.RewrapRequest,
) (*platformv1.RewrapResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetCiphertext()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingCiphertext{}.Error())
	}

	kmsReq := &KMSRewrapRequest{
		KeyID:         req.GetKeyId(),
		Ciphertext:    req.GetCiphertext(),
		Context:       req.GetContext(),
		Nonce:         req.GetNonce(),
		SourceVersion: req.GetSourceVersion(),
	}

	resp, err := s.service.Rewrap(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("Rewrap", err)
	}

	return &platformv1.RewrapResponse{
		Status:        successStatus("rewrap successful"),
		KeyId:         resp.KeyID,
		SourceVersion: resp.SourceVersion,
		TargetVersion: resp.TargetVersion,
		Ciphertext:    resp.Ciphertext,
		Nonce:         resp.Nonce,
		Timestamp:     resp.Timestamp,
	}, nil
}

// Sign creates a digital signature.
func (s *KMSGRPCService) Sign(
	ctx context.Context,
	req *platformv1.SignRequest,
) (*platformv1.SignResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingMessage{}.Error())
	}

	kmsReq := &KMSSignRequest{
		KeyID:         req.GetKeyId(),
		Message:       req.GetMessage(),
		HashAlgorithm: int32(req.GetHashAlgorithm()),
	}

	resp, err := s.service.Sign(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("Sign", err)
	}

	return &platformv1.SignResponse{
		Status:        successStatus("signing successful"),
		KeyId:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: platformv1.HashAlgorithm(resp.HashAlgorithm),
		Timestamp:     resp.Timestamp,
	}, nil
}

// Verify verifies a digital signature.
func (s *KMSGRPCService) Verify(
	ctx context.Context,
	req *platformv1.VerifyRequest,
) (*platformv1.VerifyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingMessage{}.Error())
	}

	if len(req.GetSignature()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingSignature{}.Error())
	}

	kmsReq := &KMSVerifyRequest{
		KeyID:         req.GetKeyId(),
		Message:       req.GetMessage(),
		Signature:     req.GetSignature(),
		HashAlgorithm: int32(req.GetHashAlgorithm()),
		KeyVersion:    req.GetKeyVersion(),
	}

	resp, err := s.service.Verify(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("Verify", err)
	}

	return &platformv1.VerifyResponse{
		Status:     successStatus("verification complete"),
		KeyId:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	}, nil
}

// Hash computes a cryptographic hash.
func (s *KMSGRPCService) Hash(
	ctx context.Context,
	req *platformv1.HashRequest,
) (*platformv1.HashResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if len(req.GetData()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingData{}.Error())
	}

	kmsReq := &KMSHashRequest{
		Data:      req.GetData(),
		Algorithm: int32(req.GetAlgorithm()),
	}

	resp, err := s.service.Hash(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("Hash", err)
	}

	return &platformv1.HashResponse{
		Status:    successStatus("hash computed successfully"),
		Algorithm: platformv1.HashAlgorithm(resp.Algorithm),
		Hash:      resp.Hash,
		Timestamp: resp.Timestamp,
	}, nil
}

// HMAC computes an HMAC.
func (s *KMSGRPCService) HMAC(
	ctx context.Context,
	req *platformv1.HMACRequest,
) (*platformv1.HMACResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingMessage{}.Error())
	}

	kmsReq := &KMSHMACRequest{
		KeyID:         req.GetKeyId(),
		Message:       req.GetMessage(),
		HashAlgorithm: int32(req.GetHashAlgorithm()),
	}

	resp, err := s.service.HMAC(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("HMAC", err)
	}

	return &platformv1.HMACResponse{
		Status:        successStatus("hmac computed successfully"),
		KeyId:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		Hmac:          resp.HMAC,
		HashAlgorithm: platformv1.HashAlgorithm(resp.HashAlgorithm),
		Timestamp:     resp.Timestamp,
	}, nil
}

// VerifyHMAC verifies an HMAC.
func (s *KMSGRPCService) VerifyHMAC(
	ctx context.Context,
	req *platformv1.VerifyHMACRequest,
) (*platformv1.VerifyHMACResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	if len(req.GetMessage()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingMessage{}.Error())
	}

	if len(req.GetHmac()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingHMAC{}.Error())
	}

	kmsReq := &KMSVerifyHMACRequest{
		KeyID:         req.GetKeyId(),
		Message:       req.GetMessage(),
		HMAC:          req.GetHmac(),
		HashAlgorithm: int32(req.GetHashAlgorithm()),
		KeyVersion:    req.GetKeyVersion(),
	}

	resp, err := s.service.VerifyHMAC(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("VerifyHMAC", err)
	}

	return &platformv1.VerifyHMACResponse{
		Status:     successStatus("hmac verification complete"),
		KeyId:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	}, nil
}

// GenerateRandom generates cryptographically secure random bytes.
func (s *KMSGRPCService) GenerateRandom(
	ctx context.Context,
	req *platformv1.GenerateRandomRequest,
) (*platformv1.GenerateRandomResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetNumBytes() <= 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidNumBytes{}.Error())
	}

	kmsReq := &KMSGenerateRandomRequest{
		NumBytes: req.GetNumBytes(),
	}

	resp, err := s.service.GenerateRandom(ctx, kmsReq)
	if err != nil {
		return nil, s.mapError("GenerateRandom", err)
	}

	return &platformv1.GenerateRandomResponse{
		Status:      successStatus("random bytes generated"),
		RandomBytes: resp.RandomBytes,
		Timestamp:   resp.Timestamp,
	}, nil
}

// GenerateDataKey generates a data encryption key and returns it encrypted.
func (s *KMSGRPCService) GenerateDataKey(
	ctx context.Context,
	req *platformv1.GenerateDataKeyRequest,
) (*platformv1.GenerateDataKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyID{}.Error())
	}

	// For GenerateDataKey, we use Encrypt to wrap a generated key
	// First generate random bytes for the data key
	keySize := req.GetKeySize()
	if keySize <= 0 {
		keySize = 32 // Default to 256-bit key
	}

	randomReq := &KMSGenerateRandomRequest{
		NumBytes: keySize,
	}

	randomResp, err := s.service.GenerateRandom(ctx, randomReq)
	if err != nil {
		return nil, s.mapError("GenerateDataKey", err)
	}

	// Encrypt the data key with the master key
	encryptReq := &KMSEncryptRequest{
		KeyID:     req.GetKeyId(),
		Plaintext: randomResp.RandomBytes,
		Context:   req.GetContext(),
	}

	encryptResp, err := s.service.Encrypt(ctx, encryptReq)
	if err != nil {
		return nil, s.mapError("GenerateDataKey", err)
	}

	return &platformv1.GenerateDataKeyResponse{
		Status:       successStatus("data key generated"),
		PlaintextKey: randomResp.RandomBytes,
		EncryptedKey: encryptResp.Ciphertext,
		KeyId:        req.GetKeyId(),
		Timestamp:    time.Now().UTC().Unix(),
	}, nil
}

// GenerateWrappedDataKey generates a data encryption key wrapped by another key.
func (s *KMSGRPCService) GenerateWrappedDataKey(
	ctx context.Context,
	req *platformv1.GenerateWrappedDataKeyRequest,
) (*platformv1.GenerateWrappedDataKeyResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	if req.GetWrappingKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingWrappingKeyID{}.Error())
	}

	// Generate random bytes for the data key
	keySize := req.GetKeySize()
	if keySize <= 0 {
		keySize = 32 // Default to 256-bit key
	}

	randomReq := &KMSGenerateRandomRequest{
		NumBytes: keySize,
	}

	randomResp, err := s.service.GenerateRandom(ctx, randomReq)
	if err != nil {
		return nil, s.mapError("GenerateWrappedDataKey", err)
	}

	// Encrypt the data key with the wrapping key
	encryptReq := &KMSEncryptRequest{
		KeyID:     req.GetWrappingKeyId(),
		Plaintext: randomResp.RandomBytes,
		Context:   req.GetContext(),
	}

	encryptResp, err := s.service.Encrypt(ctx, encryptReq)
	if err != nil {
		return nil, s.mapError("GenerateWrappedDataKey", err)
	}

	return &platformv1.GenerateWrappedDataKeyResponse{
		Status:            successStatus("wrapped data key generated"),
		WrappedKey:        encryptResp.Ciphertext,
		WrappingKeyId:     req.GetWrappingKeyId(),
		WrappingAlgorithm: req.GetWrappingAlgorithm(),
		Timestamp:         time.Now().UTC().Unix(),
	}, nil
}

// BackendStatus returns the status of the KMS backend.
func (s *KMSGRPCService) BackendStatus(
	ctx context.Context,
	req *platformv1.BackendStatusRequest,
) (*platformv1.BackendStatusResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilKMSService{}.Error())
	}

	resp, err := s.service.BackendStatus(ctx)
	if err != nil {
		return nil, s.mapError("BackendStatus", err)
	}

	return &platformv1.BackendStatusResponse{
		Status:        successStatus("backend status retrieved"),
		BackendType:   resp.BackendType,
		BackendStatus: resp.Status,
		Device:        resp.Device,
		Region:        resp.Region,
		KeyId:         resp.KeyID,
		PcrBanks:      resp.PcrBanks,
		PcrRegisters:  resp.PcrRegisters,
		Capabilities:  resp.Capabilities,
		Timestamp:     resp.Timestamp,
	}, nil
}

// Helper functions

func successStatus(message string) *platformv1.Status {
	return &platformv1.Status{
		Success: true,
		Message: message,
	}
}

func protoKeySpecToKMS(spec *platformv1.KMSKeySpec) *KMSKeySpec {
	if spec == nil {
		return nil
	}
	usage := make([]int32, len(spec.GetUsage()))
	for i, u := range spec.GetUsage() {
		usage[i] = int32(u)
	}
	return &KMSKeySpec{
		Algorithm:          int32(spec.GetAlgorithm()),
		KeySize:            spec.GetKeySize(),
		Usage:              usage,
		Exportable:         spec.GetExportable(),
		DeletionProtection: spec.GetDeletionProtection(),
	}
}

func kmsKeyHandleToProto(handle *KMSKeyHandle) *platformv1.KMSKeyHandle {
	if handle == nil {
		return nil
	}
	return &platformv1.KMSKeyHandle{
		KeyId:     handle.KeyID,
		Version:   handle.Version,
		Algorithm: platformv1.KMSKeyAlgorithm(handle.Algorithm),
		Status:    platformv1.KeyStatus(handle.Status),
		CreatedAt: handle.CreatedAt,
	}
}

func kmsKeyMetadataToProto(meta *KMSKeyMetadata) *platformv1.KMSKeyMetadata {
	if meta == nil {
		return nil
	}
	usage := make([]platformv1.KeyUsage, len(meta.Usage))
	for i, u := range meta.Usage {
		usage[i] = platformv1.KeyUsage(u)
	}
	return &platformv1.KMSKeyMetadata{
		KeyId:              meta.KeyID,
		Name:               meta.Name,
		Description:        meta.Description,
		Algorithm:          platformv1.KMSKeyAlgorithm(meta.Algorithm),
		Status:             platformv1.KeyStatus(meta.Status),
		Usage:              usage,
		Version:            meta.Version,
		Exportable:         meta.Exportable,
		DeletionProtection: meta.DeletionProtection,
		CreatedAt:          meta.CreatedAt,
		UpdatedAt:          meta.UpdatedAt,
		LastUsedAt:         meta.LastUsedAt,
		Tags:               meta.Tags,
		Owner:              meta.Owner,
	}
}

// protoBatchEncryptItemsToKMS converts proto batch encrypt items to KMS types.
func protoBatchEncryptItemsToKMS(items []*platformv1.BatchEncryptItem) []*KMSBatchEncryptItem {
	if items == nil {
		return nil
	}
	result := make([]*KMSBatchEncryptItem, len(items))
	for i, item := range items {
		result[i] = &KMSBatchEncryptItem{
			ItemID:    item.GetItemId(),
			Plaintext: item.GetPlaintext(),
			Context:   item.GetContext(),
			Nonce:     item.GetNonce(),
		}
	}
	return result
}

// kmsBatchEncryptResultsToProto converts KMS batch encrypt results to proto types.
func kmsBatchEncryptResultsToProto(results []*KMSBatchEncryptResultItem) []*platformv1.BatchEncryptResultItem {
	if results == nil {
		return nil
	}
	protoResults := make([]*platformv1.BatchEncryptResultItem, len(results))
	for i, r := range results {
		protoResults[i] = &platformv1.BatchEncryptResultItem{
			ItemId: r.ItemID,
			Status: &platformv1.Status{
				Success: r.Success,
				Message: r.Message,
			},
			Ciphertext: r.Ciphertext,
			Nonce:      r.Nonce,
			KeyVersion: r.KeyVersion,
		}
	}
	return protoResults
}

// protoBatchDecryptItemsToKMS converts proto batch decrypt items to KMS types.
func protoBatchDecryptItemsToKMS(items []*platformv1.BatchDecryptItem) []*KMSBatchDecryptItem {
	if items == nil {
		return nil
	}
	result := make([]*KMSBatchDecryptItem, len(items))
	for i, item := range items {
		result[i] = &KMSBatchDecryptItem{
			ItemID:     item.GetItemId(),
			Ciphertext: item.GetCiphertext(),
			Context:    item.GetContext(),
			Nonce:      item.GetNonce(),
			KeyVersion: item.GetKeyVersion(),
		}
	}
	return result
}

// kmsBatchDecryptResultsToProto converts KMS batch decrypt results to proto types.
func kmsBatchDecryptResultsToProto(results []*KMSBatchDecryptResultItem) []*platformv1.BatchDecryptResultItem {
	if results == nil {
		return nil
	}
	protoResults := make([]*platformv1.BatchDecryptResultItem, len(results))
	for i, r := range results {
		protoResults[i] = &platformv1.BatchDecryptResultItem{
			ItemId: r.ItemID,
			Status: &platformv1.Status{
				Success: r.Success,
				Message: r.Message,
			},
			Plaintext:  r.Plaintext,
			KeyVersion: r.KeyVersion,
		}
	}
	return protoResults
}

// mapError maps KMS errors to appropriate gRPC status codes.
func (s *KMSGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "kms operation failed", "operation", operation)

	// Check for specific KMS error types
	switch e := err.(type) {
	case ErrKMSOperationFailed:
		return status.Errorf(codes.Internal, "kms operation %s failed: %s", e.Operation, e.Reason)
	}

	// Default to internal error
	return status.Error(codes.Internal, err.Error())
}

// Ensure KMSGRPCService implements the KeyManagementServiceServer interface.
var _ platformv1.KeyManagementServiceServer = (*KMSGRPCService)(nil)
