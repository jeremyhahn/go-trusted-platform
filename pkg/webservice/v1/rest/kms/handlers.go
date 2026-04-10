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
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	defaultLimit  int32 = 50
	maxLimit      int32 = 1000
	defaultCursor       = ""

	requestTimeout = 30 * time.Second

	// Maximum number of bytes for random generation
	maxRandomBytes int32 = 1048576 // 1MB
)

// KMSHandlers provides REST handlers for KMS operations
type KMSHandlers struct {
	logger        *logging.Logger
	keyMgmtClient proto.KeyManagementClient
	cryptoClient  proto.CryptoClient
	dekMgmtClient proto.DEKManagementClient
	secretsClient proto.SecretsManagementClient
	respWriter    response.HttpWriter
}

// NewKMSHandlers creates a new KMSHandlers instance
func NewKMSHandlers(
	logger *logging.Logger,
	keyMgmtClient proto.KeyManagementClient,
	cryptoClient proto.CryptoClient,
	dekMgmtClient proto.DEKManagementClient,
	secretsClient proto.SecretsManagementClient,
	respWriter response.HttpWriter,
) *KMSHandlers {
	return &KMSHandlers{
		logger:        logger,
		keyMgmtClient: keyMgmtClient,
		cryptoClient:  cryptoClient,
		dekMgmtClient: dekMgmtClient,
		secretsClient: secretsClient,
		respWriter:    respWriter,
	}
}

// Helper methods

func (h *KMSHandlers) getKeyName(r *http.Request) string {
	return mux.Vars(r)["name"]
}

func (h *KMSHandlers) getDEKPath(r *http.Request) string {
	return mux.Vars(r)["path"]
}

func (h *KMSHandlers) getSecretName(r *http.Request) string {
	return mux.Vars(r)["name"]
}

func (h *KMSHandlers) getVersion(r *http.Request) string {
	return mux.Vars(r)["version"]
}

func (h *KMSHandlers) getPaginationParams(r *http.Request) (int32, string) {
	limit := defaultLimit
	cursor := defaultCursor

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.ParseInt(l, 10, 32); err == nil {
			limit = int32(parsed)
			if limit > maxLimit {
				limit = maxLimit
			}
			if limit < 1 {
				limit = defaultLimit
			}
		}
	}

	if c := r.URL.Query().Get("cursor"); c != "" {
		cursor = c
	}

	return limit, cursor
}

func (h *KMSHandlers) createContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

func (h *KMSHandlers) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (h *KMSHandlers) handleGRPCError(w http.ResponseWriter, r *http.Request, err error) {
	st, ok := status.FromError(err)
	if !ok {
		h.respWriter.Error500(w, r, err)
		return
	}

	switch st.Code() {
	case codes.NotFound:
		h.respWriter.Error404(w, r, err)
	case codes.InvalidArgument:
		h.respWriter.Error400(w, r, err)
	case codes.PermissionDenied, codes.Unauthenticated:
		h.respWriter.Error401(w, r, err)
	case codes.AlreadyExists:
		h.respWriter.Error400(w, r, err)
	default:
		h.respWriter.Error500(w, r, err)
	}
}

// Algorithm conversion helpers

func (h *KMSHandlers) stringToKeyAlgorithm(s string) proto.KeyAlgorithm {
	switch s {
	case "AES-128-GCM":
		return proto.KeyAlgorithm_KEY_ALG_AES_128_GCM
	case "AES-192-GCM":
		return proto.KeyAlgorithm_KEY_ALG_AES_192_GCM
	case "AES-256-GCM":
		return proto.KeyAlgorithm_KEY_ALG_AES_256_GCM
	case "CHACHA20-POLY1305":
		return proto.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305
	case "XCHACHA20-POLY1305":
		return proto.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305
	case "RSA-2048":
		return proto.KeyAlgorithm_KEY_ALG_RSA_2048
	case "RSA-3072":
		return proto.KeyAlgorithm_KEY_ALG_RSA_3072
	case "RSA-4096":
		return proto.KeyAlgorithm_KEY_ALG_RSA_4096
	case "ECDSA-P256":
		return proto.KeyAlgorithm_KEY_ALG_ECDSA_P256
	case "ECDSA-P384":
		return proto.KeyAlgorithm_KEY_ALG_ECDSA_P384
	case "ECDSA-P521":
		return proto.KeyAlgorithm_KEY_ALG_ECDSA_P521
	case "ED25519":
		return proto.KeyAlgorithm_KEY_ALG_ED25519
	case "ED448":
		return proto.KeyAlgorithm_KEY_ALG_ED448
	case "X25519":
		return proto.KeyAlgorithm_KEY_ALG_X25519
	case "X448":
		return proto.KeyAlgorithm_KEY_ALG_X448
	case "HMAC-SHA256":
		return proto.KeyAlgorithm_KEY_ALG_HMAC_SHA256
	case "HMAC-SHA384":
		return proto.KeyAlgorithm_KEY_ALG_HMAC_SHA384
	case "HMAC-SHA512":
		return proto.KeyAlgorithm_KEY_ALG_HMAC_SHA512
	default:
		return proto.KeyAlgorithm_KEY_ALG_UNSPECIFIED
	}
}

func (h *KMSHandlers) keyAlgorithmToString(alg proto.KeyAlgorithm) string {
	switch alg {
	case proto.KeyAlgorithm_KEY_ALG_AES_128_GCM:
		return "AES-128-GCM"
	case proto.KeyAlgorithm_KEY_ALG_AES_192_GCM:
		return "AES-192-GCM"
	case proto.KeyAlgorithm_KEY_ALG_AES_256_GCM:
		return "AES-256-GCM"
	case proto.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305:
		return "CHACHA20-POLY1305"
	case proto.KeyAlgorithm_KEY_ALG_XCHACHA20_POLY1305:
		return "XCHACHA20-POLY1305"
	case proto.KeyAlgorithm_KEY_ALG_RSA_2048:
		return "RSA-2048"
	case proto.KeyAlgorithm_KEY_ALG_RSA_3072:
		return "RSA-3072"
	case proto.KeyAlgorithm_KEY_ALG_RSA_4096:
		return "RSA-4096"
	case proto.KeyAlgorithm_KEY_ALG_ECDSA_P256:
		return "ECDSA-P256"
	case proto.KeyAlgorithm_KEY_ALG_ECDSA_P384:
		return "ECDSA-P384"
	case proto.KeyAlgorithm_KEY_ALG_ECDSA_P521:
		return "ECDSA-P521"
	case proto.KeyAlgorithm_KEY_ALG_ED25519:
		return "ED25519"
	case proto.KeyAlgorithm_KEY_ALG_ED448:
		return "ED448"
	case proto.KeyAlgorithm_KEY_ALG_X25519:
		return "X25519"
	case proto.KeyAlgorithm_KEY_ALG_X448:
		return "X448"
	case proto.KeyAlgorithm_KEY_ALG_HMAC_SHA256:
		return "HMAC-SHA256"
	case proto.KeyAlgorithm_KEY_ALG_HMAC_SHA384:
		return "HMAC-SHA384"
	case proto.KeyAlgorithm_KEY_ALG_HMAC_SHA512:
		return "HMAC-SHA512"
	default:
		return "UNSPECIFIED"
	}
}

func (h *KMSHandlers) stringToKeyStatus(s string) proto.KeyStatus {
	switch s {
	case "ENABLED":
		return proto.KeyStatus_KEY_STATUS_ENABLED
	case "DISABLED":
		return proto.KeyStatus_KEY_STATUS_DISABLED
	case "PENDING_DELETION":
		return proto.KeyStatus_KEY_STATUS_PENDING_DELETION
	case "DELETED":
		return proto.KeyStatus_KEY_STATUS_DELETED
	case "ROTATING":
		return proto.KeyStatus_KEY_STATUS_ROTATING
	case "COMPROMISED":
		return proto.KeyStatus_KEY_STATUS_COMPROMISED
	default:
		return proto.KeyStatus_KEY_STATUS_UNSPECIFIED
	}
}

func (h *KMSHandlers) keyStatusToString(status proto.KeyStatus) string {
	switch status {
	case proto.KeyStatus_KEY_STATUS_ENABLED:
		return "ENABLED"
	case proto.KeyStatus_KEY_STATUS_DISABLED:
		return "DISABLED"
	case proto.KeyStatus_KEY_STATUS_PENDING_DELETION:
		return "PENDING_DELETION"
	case proto.KeyStatus_KEY_STATUS_DELETED:
		return "DELETED"
	case proto.KeyStatus_KEY_STATUS_ROTATING:
		return "ROTATING"
	case proto.KeyStatus_KEY_STATUS_COMPROMISED:
		return "COMPROMISED"
	default:
		return "UNSPECIFIED"
	}
}

func (h *KMSHandlers) stringToKeyUsage(s string) proto.KeyUsage {
	switch s {
	case "ENCRYPT":
		return proto.KeyUsage_KEY_USAGE_ENCRYPT
	case "DECRYPT":
		return proto.KeyUsage_KEY_USAGE_DECRYPT
	case "SIGN":
		return proto.KeyUsage_KEY_USAGE_SIGN
	case "VERIFY":
		return proto.KeyUsage_KEY_USAGE_VERIFY
	case "WRAP_KEY":
		return proto.KeyUsage_KEY_USAGE_WRAP_KEY
	case "DERIVE_KEY":
		return proto.KeyUsage_KEY_USAGE_DERIVE_KEY
	case "GENERATE_MAC":
		return proto.KeyUsage_KEY_USAGE_GENERATE_MAC
	case "VERIFY_MAC":
		return proto.KeyUsage_KEY_USAGE_VERIFY_MAC
	default:
		return proto.KeyUsage_KEY_USAGE_UNSPECIFIED
	}
}

func (h *KMSHandlers) keyUsageToString(usage proto.KeyUsage) string {
	switch usage {
	case proto.KeyUsage_KEY_USAGE_ENCRYPT:
		return "ENCRYPT"
	case proto.KeyUsage_KEY_USAGE_DECRYPT:
		return "DECRYPT"
	case proto.KeyUsage_KEY_USAGE_SIGN:
		return "SIGN"
	case proto.KeyUsage_KEY_USAGE_VERIFY:
		return "VERIFY"
	case proto.KeyUsage_KEY_USAGE_WRAP_KEY:
		return "WRAP_KEY"
	case proto.KeyUsage_KEY_USAGE_DERIVE_KEY:
		return "DERIVE_KEY"
	case proto.KeyUsage_KEY_USAGE_GENERATE_MAC:
		return "GENERATE_MAC"
	case proto.KeyUsage_KEY_USAGE_VERIFY_MAC:
		return "VERIFY_MAC"
	default:
		return "UNSPECIFIED"
	}
}

func (h *KMSHandlers) stringsToKeyUsage(ss []string) []proto.KeyUsage {
	result := make([]proto.KeyUsage, 0, len(ss))
	for _, s := range ss {
		result = append(result, h.stringToKeyUsage(s))
	}
	return result
}

func (h *KMSHandlers) keyUsageToStrings(usages []proto.KeyUsage) []string {
	result := make([]string, 0, len(usages))
	for _, u := range usages {
		result = append(result, h.keyUsageToString(u))
	}
	return result
}

// Hash algorithm conversion helpers

func (h *KMSHandlers) stringToHashAlgorithm(s string) proto.HashAlgorithm {
	switch s {
	case "SHA256", "SHA-256":
		return proto.HashAlgorithm_HASH_ALG_SHA256
	case "SHA384", "SHA-384":
		return proto.HashAlgorithm_HASH_ALG_SHA384
	case "SHA512", "SHA-512":
		return proto.HashAlgorithm_HASH_ALG_SHA512
	case "SHA3-256":
		return proto.HashAlgorithm_HASH_ALG_SHA3_256
	case "SHA3-384":
		return proto.HashAlgorithm_HASH_ALG_SHA3_384
	case "SHA3-512":
		return proto.HashAlgorithm_HASH_ALG_SHA3_512
	case "BLAKE2B-256":
		return proto.HashAlgorithm_HASH_ALG_BLAKE2B_256
	case "BLAKE2B-512":
		return proto.HashAlgorithm_HASH_ALG_BLAKE2B_512
	default:
		return proto.HashAlgorithm_HASH_ALG_UNSPECIFIED
	}
}

func (h *KMSHandlers) hashAlgorithmToString(alg proto.HashAlgorithm) string {
	switch alg {
	case proto.HashAlgorithm_HASH_ALG_SHA256:
		return "SHA256"
	case proto.HashAlgorithm_HASH_ALG_SHA384:
		return "SHA384"
	case proto.HashAlgorithm_HASH_ALG_SHA512:
		return "SHA512"
	case proto.HashAlgorithm_HASH_ALG_SHA3_256:
		return "SHA3-256"
	case proto.HashAlgorithm_HASH_ALG_SHA3_384:
		return "SHA3-384"
	case proto.HashAlgorithm_HASH_ALG_SHA3_512:
		return "SHA3-512"
	case proto.HashAlgorithm_HASH_ALG_BLAKE2B_256:
		return "BLAKE2B-256"
	case proto.HashAlgorithm_HASH_ALG_BLAKE2B_512:
		return "BLAKE2B-512"
	default:
		return "UNSPECIFIED"
	}
}

// Secret status conversion helpers

func (h *KMSHandlers) stringToSecretStatus(s string) proto.SecretStatus {
	switch s {
	case "ENABLED":
		return proto.SecretStatus_SECRET_STATUS_ENABLED
	case "DISABLED":
		return proto.SecretStatus_SECRET_STATUS_DISABLED
	case "DELETED":
		return proto.SecretStatus_SECRET_STATUS_DELETED
	default:
		return proto.SecretStatus_SECRET_STATUS_UNSPECIFIED
	}
}

func (h *KMSHandlers) secretStatusToString(status proto.SecretStatus) string {
	switch status {
	case proto.SecretStatus_SECRET_STATUS_ENABLED:
		return "ENABLED"
	case proto.SecretStatus_SECRET_STATUS_DISABLED:
		return "DISABLED"
	case proto.SecretStatus_SECRET_STATUS_DELETED:
		return "DELETED"
	default:
		return "UNSPECIFIED"
	}
}

// Response conversion helpers

func (h *KMSHandlers) keyHandleToResponse(key *proto.KeyHandle) *KeyHandleResponse {
	if key == nil {
		return nil
	}
	return &KeyHandleResponse{
		KeyID:     key.KeyId,
		Version:   key.Version,
		Algorithm: h.keyAlgorithmToString(key.Algorithm),
		Status:    h.keyStatusToString(key.Status),
		CreatedAt: key.CreatedAt,
	}
}

func (h *KMSHandlers) rotationPolicyToResponse(policy *proto.RotationPolicy) *RotationPolicyResponse {
	if policy == nil {
		return nil
	}
	return &RotationPolicyResponse{
		Enabled:         policy.Enabled,
		IntervalSeconds: policy.IntervalSeconds,
		NextRotation:    policy.NextRotation,
		RetainVersions:  policy.RetainVersions,
		AutoRotate:      policy.AutoRotate,
	}
}

func (h *KMSHandlers) keyMetadataToResponse(metadata *proto.KeyMetadata) *KeyMetadataResponse {
	if metadata == nil {
		return nil
	}
	return &KeyMetadataResponse{
		KeyID:              metadata.KeyId,
		Name:               metadata.Name,
		Description:        metadata.Description,
		Algorithm:          h.keyAlgorithmToString(metadata.Algorithm),
		Status:             h.keyStatusToString(metadata.Status),
		Usage:              h.keyUsageToStrings(metadata.Usage),
		Version:            metadata.Version,
		Exportable:         metadata.Exportable,
		DeletionProtection: metadata.DeletionProtection,
		CreatedAt:          metadata.CreatedAt,
		UpdatedAt:          metadata.UpdatedAt,
		LastUsedAt:         metadata.LastUsedAt,
		RotationPolicy:     h.rotationPolicyToResponse(metadata.RotationPolicy),
		Tags:               metadata.Tags,
		Owner:              metadata.Owner,
	}
}

func (h *KMSHandlers) dekMetadataToResponse(dek *proto.DEKMetadata) *DEKMetadataResponse {
	if dek == nil {
		return nil
	}
	return &DEKMetadataResponse{
		Path:           dek.Path,
		Algorithm:      h.keyAlgorithmToString(dek.Algorithm),
		Version:        dek.Version,
		Status:         dek.Status,
		IsDefault:      dek.IsDefault,
		CreatedAt:      dek.CreatedAt,
		RotatedAt:      dek.RotatedAt,
		UsageCount:     dek.UsageCount,
		BytesUsed:      dek.BytesUsed,
		MaxUsageCount:  dek.MaxUsageCount,
		MaxBytesUsed:   dek.MaxBytesUsed,
		WarningPercent: dek.WarningPercent,
		Description:    dek.Description,
		BackendType:    dek.BackendType,
	}
}

func (h *KMSHandlers) reencryptionProgressToResponse(progress *proto.ReencryptionProgress) *ReencryptionProgressResponse {
	if progress == nil {
		return nil
	}
	return &ReencryptionProgressResponse{
		InProgress:          progress.InProgress,
		TotalKeys:           progress.TotalKeys,
		ProcessedKeys:       progress.ProcessedKeys,
		FailedKeys:          progress.FailedKeys,
		StartedAt:           progress.StartedAt,
		EstimatedCompletion: progress.EstimatedCompletion,
	}
}

// Secret conversion helpers

func (h *KMSHandlers) secretRotationPolicyToResponse(policy *proto.SecretRotationPolicy) *SecretRotationPolicyResponse {
	if policy == nil {
		return nil
	}
	return &SecretRotationPolicyResponse{
		Enabled:         policy.Enabled,
		IntervalSeconds: policy.IntervalSeconds,
		NextRotation:    policy.NextRotation,
		RetainVersions:  policy.RetainVersions,
		RotationLambda:  policy.RotationLambda,
	}
}

func (h *KMSHandlers) secretToResponse(secret *proto.Secret) *SecretResponse {
	if secret == nil {
		return nil
	}
	return &SecretResponse{
		SecretID:       secret.SecretId,
		Name:           secret.Name,
		Description:    secret.Description,
		CurrentVersion: secret.CurrentVersion,
		CreatedAt:      secret.CreatedAt,
		UpdatedAt:      secret.UpdatedAt,
		RotationPolicy: h.secretRotationPolicyToResponse(secret.RotationPolicy),
		Tags:           secret.Tags,
		Owner:          secret.Owner,
	}
}

func (h *KMSHandlers) secretVersionToResponse(version *proto.SecretVersion) *SecretVersionResponse {
	if version == nil {
		return nil
	}
	return &SecretVersionResponse{
		SecretID:  version.SecretId,
		Version:   version.Version,
		Metadata:  version.Metadata,
		CreatedAt: version.CreatedAt,
		CreatedBy: version.CreatedBy,
		DeletedAt: version.DeletedAt,
		ExpiresAt: version.ExpiresAt,
	}
}

func (h *KMSHandlers) secretDataToResponse(data *proto.SecretData) *SecretDataResponse {
	if data == nil {
		return nil
	}
	return &SecretDataResponse{
		Data:     data.Data,
		Metadata: data.Metadata,
		Version:  data.Version,
	}
}

// Key Management Handlers

// GenerateKey handles POST /api/v1/kms/keys
func (h *KMSHandlers) GenerateKey(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	var req GenerateKeyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	keySpec := &proto.KeySpec{
		Algorithm:          h.stringToKeyAlgorithm(req.KeySpec.Algorithm),
		KeySize:            req.KeySpec.KeySize,
		Usage:              h.stringsToKeyUsage(req.KeySpec.Usage),
		Exportable:         req.KeySpec.Exportable,
		DeletionProtection: req.KeySpec.DeletionProtection,
	}

	grpcReq := &proto.GenerateKeyRequest{
		KeySpec:     keySpec,
		Name:        req.Name,
		Description: req.Description,
		Tags:        req.Tags,
		Owner:       req.Owner,
	}

	resp, err := h.keyMgmtClient.GenerateKey(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GenerateKeyResponse{
		Key:       h.keyHandleToResponse(resp.Key),
		Metadata:  h.keyMetadataToResponse(resp.Metadata),
		Timestamp: resp.Timestamp,
	})
}

// ImportKey handles POST /api/v1/kms/keys/import
func (h *KMSHandlers) ImportKey(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	var req ImportKeyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.KeyMaterial) == 0 {
		h.respWriter.Error400(w, r, ErrKeyMaterialRequired{})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	keySpec := &proto.KeySpec{
		Algorithm:          h.stringToKeyAlgorithm(req.KeySpec.Algorithm),
		KeySize:            req.KeySpec.KeySize,
		Usage:              h.stringsToKeyUsage(req.KeySpec.Usage),
		Exportable:         req.KeySpec.Exportable,
		DeletionProtection: req.KeySpec.DeletionProtection,
	}

	grpcReq := &proto.ImportKeyRequest{
		KeyMaterial:   req.KeyMaterial,
		WrappingKeyId: req.WrappingKeyID,
		KeySpec:       keySpec,
		Name:          req.Name,
		Description:   req.Description,
		Tags:          req.Tags,
	}

	resp, err := h.keyMgmtClient.ImportKey(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, ImportKeyResponse{
		Key:       h.keyHandleToResponse(resp.Key),
		Metadata:  h.keyMetadataToResponse(resp.Metadata),
		Timestamp: resp.Timestamp,
	})
}

// ListKeys handles GET /api/v1/kms/keys
func (h *KMSHandlers) ListKeys(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	limit, cursor := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	// Parse filter parameters from query string
	filter := make(map[string]string)
	for key, values := range r.URL.Query() {
		if key != "limit" && key != "cursor" && len(values) > 0 {
			filter[key] = values[0]
		}
	}

	grpcReq := &proto.ListKeysRequest{
		Limit:  limit,
		Cursor: cursor,
		Filter: filter,
	}

	resp, err := h.keyMgmtClient.ListKeys(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	keys := make([]KeyHandleResponse, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, *h.keyHandleToResponse(k))
	}

	h.respWriter.Success200(w, r, ListKeysResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: resp.NextCursor,
			HasMore:    resp.HasMore,
			TotalCount: resp.TotalCount,
		},
		Keys:      keys,
		Timestamp: resp.Timestamp,
	})
}

// GetKey handles GET /api/v1/kms/keys/{name}
func (h *KMSHandlers) GetKey(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Parse optional version from query string
	var version uint64
	if v := r.URL.Query().Get("version"); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 64); err == nil {
			version = parsed
		}
	}

	grpcReq := &proto.GetKeyRequest{
		KeyId:   keyName,
		Version: version,
	}

	resp, err := h.keyMgmtClient.GetKey(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GetKeyResponse{
		Key:       h.keyHandleToResponse(resp.Key),
		Metadata:  h.keyMetadataToResponse(resp.Metadata),
		Timestamp: resp.Timestamp,
	})
}

// RotateKey handles POST /api/v1/kms/keys/{name}/rotate
func (h *KMSHandlers) RotateKey(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req RotateKeyRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := h.decodeJSON(r, &req); err != nil {
			h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.RotateKeyRequest{
		KeyId:            keyName,
		RetainOldVersion: req.RetainOldVersion,
	}

	resp, err := h.keyMgmtClient.RotateKey(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, RotateKeyResponse{
		KeyID:      resp.KeyId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	})
}

// DeleteKey handles DELETE /api/v1/kms/keys/{name}
func (h *KMSHandlers) DeleteKey(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Parse optional parameters from query string
	var pendingWindowDays int32
	var force bool

	if pwd := r.URL.Query().Get("pending_window_days"); pwd != "" {
		if parsed, err := strconv.ParseInt(pwd, 10, 32); err == nil {
			pendingWindowDays = int32(parsed)
		}
	}

	if f := r.URL.Query().Get("force"); f == "true" {
		force = true
	}

	grpcReq := &proto.DeleteKeyRequest{
		KeyId:             keyName,
		PendingWindowDays: pendingWindowDays,
		Force:             force,
	}

	resp, err := h.keyMgmtClient.DeleteKey(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, DeleteKeyResponse{
		KeyID:        resp.KeyId,
		Status:       h.keyStatusToString(resp.Status),
		DeletionDate: resp.DeletionDate,
		Timestamp:    resp.Timestamp,
	})
}

// UpdateKeyStatus handles PUT /api/v1/kms/keys/{name}/status
func (h *KMSHandlers) UpdateKeyStatus(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req UpdateKeyStatusRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Status == "" {
		h.respWriter.Error400(w, r, ErrInvalidKeyStatus{Status: "", Reason: "status is required"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.UpdateKeyStatusRequest{
		KeyId:   keyName,
		Version: req.Version,
		Status:  h.stringToKeyStatus(req.Status),
	}

	resp, err := h.keyMgmtClient.UpdateKeyStatus(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, UpdateKeyStatusResponse{
		KeyID:     resp.KeyId,
		Version:   resp.Version,
		Status:    h.keyStatusToString(resp.Status),
		Timestamp: resp.Timestamp,
	})
}

// ListKeyVersions handles GET /api/v1/kms/keys/{name}/versions
func (h *KMSHandlers) ListKeyVersions(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	limit, cursor := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.ListKeyVersionsRequest{
		KeyId:  keyName,
		Limit:  limit,
		Cursor: cursor,
	}

	resp, err := h.keyMgmtClient.ListKeyVersions(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	versions := make([]KeyVersionInfoResponse, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, KeyVersionInfoResponse{
			Version:    v.Version,
			Status:     h.keyStatusToString(v.Status),
			Algorithm:  h.keyAlgorithmToString(v.Algorithm),
			CreatedAt:  v.CreatedAt,
			DisabledAt: v.DisabledAt,
		})
	}

	h.respWriter.Success200(w, r, ListKeyVersionsResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: resp.NextCursor,
			HasMore:    resp.HasMore,
		},
		KeyID:     resp.KeyId,
		Versions:  versions,
		Timestamp: resp.Timestamp,
	})
}

// Backend Handlers

// BackendStatus handles GET /api/v1/kms/backend/status
func (h *KMSHandlers) BackendStatus(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.BackendStatusRequest{}

	resp, err := h.keyMgmtClient.BackendStatus(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, BackendStatusResponse{
		BackendType:  resp.BackendType,
		Status:       resp.Status,
		Device:       resp.Device,
		Region:       resp.Region,
		KeyID:        resp.KeyId,
		PCRBanks:     resp.PcrBanks,
		PCRRegisters: resp.PcrRegisters,
		Capabilities: resp.Capabilities,
		Timestamp:    resp.Timestamp,
	})
}

// BackendTest handles POST /api/v1/kms/backend/test
func (h *KMSHandlers) BackendTest(w http.ResponseWriter, r *http.Request) {
	if h.keyMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrKeyManagementClientNotInitialized{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.BackendTestRequest{}

	resp, err := h.keyMgmtClient.BackendTest(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, BackendTestResponse{
		Success:    resp.Success,
		DurationMs: resp.DurationMs,
		Message:    resp.Message,
		Timestamp:  resp.Timestamp,
	})
}

// =============================================================================
// Crypto Handlers
// =============================================================================

// Encrypt handles POST /api/v1/kms/encrypt/{name}
func (h *KMSHandlers) Encrypt(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req EncryptRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Plaintext) == 0 {
		h.respWriter.Error400(w, r, ErrMissingPlaintext{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.CryptoEncryptRequest{
		KeyId:     keyName,
		Plaintext: req.Plaintext,
		Context:   req.Context,
		Nonce:     req.Nonce,
	}

	resp, err := h.cryptoClient.Encrypt(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, EncryptResponse{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Timestamp:  resp.Timestamp,
	})
}

// Decrypt handles POST /api/v1/kms/decrypt/{name}
func (h *KMSHandlers) Decrypt(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req DecryptRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Ciphertext) == 0 {
		h.respWriter.Error400(w, r, ErrMissingCiphertext{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.CryptoDecryptRequest{
		KeyId:      keyName,
		Ciphertext: req.Ciphertext,
		Context:    req.Context,
		Nonce:      req.Nonce,
		KeyVersion: req.KeyVersion,
	}

	resp, err := h.cryptoClient.Decrypt(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, DecryptResponse{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  resp.Timestamp,
	})
}

// Sign handles POST /api/v1/kms/sign/{name}
func (h *KMSHandlers) Sign(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req SignRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Message) == 0 {
		h.respWriter.Error400(w, r, ErrMissingMessage{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.SignRequest{
		KeyId:         keyName,
		Message:       req.Message,
		HashAlgorithm: h.stringToHashAlgorithm(req.HashAlgorithm),
	}

	resp, err := h.cryptoClient.Sign(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SignResponse{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: h.hashAlgorithmToString(resp.HashAlgorithm),
		Timestamp:     resp.Timestamp,
	})
}

// Verify handles POST /api/v1/kms/verify/{name}
func (h *KMSHandlers) Verify(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req VerifyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Message) == 0 {
		h.respWriter.Error400(w, r, ErrMissingMessage{})
		return
	}

	if len(req.Signature) == 0 {
		h.respWriter.Error400(w, r, ErrMissingSignature{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.VerifyRequest{
		KeyId:         keyName,
		Message:       req.Message,
		Signature:     req.Signature,
		HashAlgorithm: h.stringToHashAlgorithm(req.HashAlgorithm),
		KeyVersion:    req.KeyVersion,
	}

	resp, err := h.cryptoClient.Verify(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, VerifyResponse{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	})
}

// Hash handles POST /api/v1/kms/hash
func (h *KMSHandlers) Hash(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	var req HashRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Data) == 0 {
		h.respWriter.Error400(w, r, ErrMissingData{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.HashRequest{
		Data:      req.Data,
		Algorithm: h.stringToHashAlgorithm(req.Algorithm),
	}

	resp, err := h.cryptoClient.Hash(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, HashResponse{
		Algorithm: h.hashAlgorithmToString(resp.Algorithm),
		Hash:      resp.Hash,
		Timestamp: resp.Timestamp,
	})
}

// HMAC handles POST /api/v1/kms/hmac/{name}
func (h *KMSHandlers) HMAC(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req HMACRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Message) == 0 {
		h.respWriter.Error400(w, r, ErrMissingMessage{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.HMACRequest{
		KeyId:         keyName,
		Message:       req.Message,
		HashAlgorithm: h.stringToHashAlgorithm(req.HashAlgorithm),
	}

	resp, err := h.cryptoClient.GenerateHMAC(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, HMACResponse{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		HMAC:          resp.Hmac,
		HashAlgorithm: h.hashAlgorithmToString(resp.HashAlgorithm),
		Timestamp:     resp.Timestamp,
	})
}

// VerifyHMAC handles POST /api/v1/kms/hmac/{name}/verify
func (h *KMSHandlers) VerifyHMAC(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req VerifyHMACRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Message) == 0 {
		h.respWriter.Error400(w, r, ErrMissingMessage{})
		return
	}

	if len(req.HMAC) == 0 {
		h.respWriter.Error400(w, r, ErrMissingHMAC{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.VerifyHMACRequest{
		KeyId:         keyName,
		Message:       req.Message,
		Hmac:          req.HMAC,
		HashAlgorithm: h.stringToHashAlgorithm(req.HashAlgorithm),
		KeyVersion:    req.KeyVersion,
	}

	resp, err := h.cryptoClient.VerifyHMAC(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, VerifyHMACResponse{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  resp.Timestamp,
	})
}

// GenerateRandom handles POST /api/v1/kms/random
func (h *KMSHandlers) GenerateRandom(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	var req GenerateRandomRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.NumBytes <= 0 {
		h.respWriter.Error400(w, r, ErrInvalidNumBytes{NumBytes: req.NumBytes, Reason: "must be greater than 0"})
		return
	}

	if req.NumBytes > maxRandomBytes {
		h.respWriter.Error400(w, r, ErrInvalidNumBytes{NumBytes: req.NumBytes, Reason: "exceeds maximum allowed (1MB)"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.GenerateRandomRequest{
		NumBytes: req.NumBytes,
	}

	resp, err := h.cryptoClient.GenerateRandom(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GenerateRandomResponse{
		RandomBytes: resp.RandomBytes,
		Timestamp:   resp.Timestamp,
	})
}

// Rewrap handles POST /api/v1/kms/rewrap/{name}
func (h *KMSHandlers) Rewrap(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req RewrapRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Ciphertext) == 0 {
		h.respWriter.Error400(w, r, ErrMissingCiphertext{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.RewrapRequest{
		KeyId:      keyName,
		Ciphertext: req.Ciphertext,
		Context:    req.Context,
		Nonce:      req.Nonce,
	}

	resp, err := h.cryptoClient.Rewrap(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, RewrapResponse{
		KeyID:         resp.KeyId,
		OldKeyVersion: resp.OldKeyVersion,
		NewKeyVersion: resp.NewKeyVersion,
		Ciphertext:    resp.Ciphertext,
		Nonce:         resp.Nonce,
		Timestamp:     resp.Timestamp,
	})
}

// Batch handles POST /api/v1/kms/batch/{name}
func (h *KMSHandlers) Batch(w http.ResponseWriter, r *http.Request) {
	if h.cryptoClient == nil {
		h.respWriter.Error500(w, r, ErrCryptoClientNotInitialized{})
		return
	}

	keyName := h.getKeyName(r)
	if keyName == "" {
		h.respWriter.Error400(w, r, ErrMissingKeyName{})
		return
	}

	var req BatchRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	switch req.Operation {
	case "encrypt":
		if len(req.EncryptItems) == 0 {
			h.respWriter.Error400(w, r, ErrMissingBatchItems{})
			return
		}
		h.handleBatchEncrypt(ctx, w, r, keyName, req.EncryptItems)
	case "decrypt":
		if len(req.DecryptItems) == 0 {
			h.respWriter.Error400(w, r, ErrMissingBatchItems{})
			return
		}
		h.handleBatchDecrypt(ctx, w, r, keyName, req.DecryptItems)
	default:
		h.respWriter.Error400(w, r, ErrInvalidBatchOperation{Operation: req.Operation})
	}
}

func (h *KMSHandlers) handleBatchEncrypt(ctx context.Context, w http.ResponseWriter, r *http.Request, keyName string, items []BatchEncryptItem) {
	protoItems := make([]*proto.BatchEncryptItem, 0, len(items))
	for _, item := range items {
		protoItems = append(protoItems, &proto.BatchEncryptItem{
			Plaintext: item.Plaintext,
			Context:   item.Context,
		})
	}

	grpcReq := &proto.EncryptBatchRequest{
		KeyId: keyName,
		Items: protoItems,
	}

	resp, err := h.cryptoClient.EncryptBatch(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	results := make([]BatchEncryptResult, 0, len(resp.Results))
	for _, result := range resp.Results {
		results = append(results, BatchEncryptResult{
			Ciphertext: result.Ciphertext,
			Nonce:      result.Nonce,
			Error:      result.Error,
		})
	}

	h.respWriter.Success200(w, r, BatchResponse{
		KeyID:          resp.KeyId,
		KeyVersion:     resp.KeyVersion,
		EncryptResults: results,
		Timestamp:      resp.Timestamp,
	})
}

func (h *KMSHandlers) handleBatchDecrypt(ctx context.Context, w http.ResponseWriter, r *http.Request, keyName string, items []BatchDecryptItem) {
	protoItems := make([]*proto.BatchDecryptItem, 0, len(items))
	for _, item := range items {
		protoItems = append(protoItems, &proto.BatchDecryptItem{
			Ciphertext: item.Ciphertext,
			Context:    item.Context,
			Nonce:      item.Nonce,
		})
	}

	grpcReq := &proto.DecryptBatchRequest{
		KeyId: keyName,
		Items: protoItems,
	}

	resp, err := h.cryptoClient.DecryptBatch(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	results := make([]BatchDecryptResult, 0, len(resp.Results))
	for _, result := range resp.Results {
		results = append(results, BatchDecryptResult{
			Plaintext: result.Plaintext,
			Error:     result.Error,
		})
	}

	h.respWriter.Success200(w, r, BatchResponse{
		KeyID:          resp.KeyId,
		DecryptResults: results,
		Timestamp:      resp.Timestamp,
	})
}

// =============================================================================
// DEK Management Handlers
// =============================================================================

// CreateDEK handles POST /api/v1/kms/deks
func (h *KMSHandlers) CreateDEK(w http.ResponseWriter, r *http.Request) {
	if h.dekMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrDEKManagementClientNotInitialized{})
		return
	}

	var req CreateDEKRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Path == "" {
		h.respWriter.Error400(w, r, ErrMissingDEKPath{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.CreateDEKRequest{
		Path:           req.Path,
		Algorithm:      h.stringToKeyAlgorithm(req.Algorithm),
		Description:    req.Description,
		MaxOperations:  req.MaxOperations,
		MaxBytes:       req.MaxBytes,
		WarningPercent: req.WarningPercent,
	}

	resp, err := h.dekMgmtClient.CreateDEK(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, CreateDEKResponse{
		DEK:       h.dekMetadataToResponse(resp.Dek),
		Timestamp: resp.Timestamp,
	})
}

// ListDEKs handles GET /api/v1/kms/deks
func (h *KMSHandlers) ListDEKs(w http.ResponseWriter, r *http.Request) {
	if h.dekMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrDEKManagementClientNotInitialized{})
		return
	}

	limit, cursor := h.getPaginationParams(r)
	prefix := r.URL.Query().Get("prefix")
	recursive := r.URL.Query().Get("recursive") == "true"

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.ListDEKsRequest{
		Prefix:    prefix,
		Recursive: recursive,
		Limit:     limit,
		Cursor:    cursor,
	}

	resp, err := h.dekMgmtClient.ListDEKs(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	deks := make([]DEKMetadataResponse, 0, len(resp.Deks))
	for _, d := range resp.Deks {
		deks = append(deks, *h.dekMetadataToResponse(d))
	}

	h.respWriter.Success200(w, r, ListDEKsResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: resp.NextCursor,
			HasMore:    resp.HasMore,
		},
		DEKs:      deks,
		Timestamp: resp.Timestamp,
	})
}

// GetDEK handles GET /api/v1/kms/deks/{path}
func (h *KMSHandlers) GetDEK(w http.ResponseWriter, r *http.Request) {
	if h.dekMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrDEKManagementClientNotInitialized{})
		return
	}

	dekPath := h.getDEKPath(r)
	if dekPath == "" {
		h.respWriter.Error400(w, r, ErrMissingDEKPath{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.GetDEKRequest{
		Path: dekPath,
	}

	resp, err := h.dekMgmtClient.GetDEK(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GetDEKResponse{
		DEK:       h.dekMetadataToResponse(resp.Dek),
		Timestamp: resp.Timestamp,
	})
}

// RotateDEK handles POST /api/v1/kms/deks/{path}/rotate
func (h *KMSHandlers) RotateDEK(w http.ResponseWriter, r *http.Request) {
	if h.dekMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrDEKManagementClientNotInitialized{})
		return
	}

	dekPath := h.getDEKPath(r)
	if dekPath == "" {
		h.respWriter.Error400(w, r, ErrMissingDEKPath{})
		return
	}

	var req RotateDEKRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := h.decodeJSON(r, &req); err != nil {
			h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.RotateDEKRequest{
		Path:       dekPath,
		Background: req.Background,
	}

	resp, err := h.dekMgmtClient.RotateDEK(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, RotateDEKResponse{
		Path:       resp.Path,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	})
}

// DeleteDEK handles DELETE /api/v1/kms/deks/{path}
func (h *KMSHandlers) DeleteDEK(w http.ResponseWriter, r *http.Request) {
	if h.dekMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrDEKManagementClientNotInitialized{})
		return
	}

	dekPath := h.getDEKPath(r)
	if dekPath == "" {
		h.respWriter.Error400(w, r, ErrMissingDEKPath{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Parse optional parameters from query string
	force := r.URL.Query().Get("force") == "true"
	migrateTo := r.URL.Query().Get("migrate_to")

	grpcReq := &proto.DeleteDEKRequest{
		Path:      dekPath,
		Force:     force,
		MigrateTo: migrateTo,
	}

	resp, err := h.dekMgmtClient.DeleteDEK(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, DeleteDEKResponse{
		Path:      resp.Path,
		Deleted:   resp.Deleted,
		Timestamp: resp.Timestamp,
	})
}

// GetDEKStatus handles GET /api/v1/kms/deks/{path}/status
func (h *KMSHandlers) GetDEKStatus(w http.ResponseWriter, r *http.Request) {
	if h.dekMgmtClient == nil {
		h.respWriter.Error500(w, r, ErrDEKManagementClientNotInitialized{})
		return
	}

	dekPath := h.getDEKPath(r)
	if dekPath == "" {
		h.respWriter.Error400(w, r, ErrMissingDEKPath{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.GetDEKStatusRequest{
		Path: dekPath,
	}

	resp, err := h.dekMgmtClient.GetDEKStatus(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GetDEKStatusResponse{
		DEK:                  h.dekMetadataToResponse(resp.Dek),
		ReencryptionProgress: h.reencryptionProgressToResponse(resp.ReencryptionProgress),
		Timestamp:            resp.Timestamp,
	})
}

// =============================================================================
// Secrets Management Handlers
// =============================================================================

// StoreSecret handles POST /api/v1/kms/secrets
func (h *KMSHandlers) StoreSecret(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	var req StoreSecretRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	if len(req.Data) == 0 {
		h.respWriter.Error400(w, r, ErrMissingSecretData{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.StoreSecretRequest{
		SecretId:    req.SecretID,
		Name:        req.Name,
		Description: req.Description,
		Data:        req.Data,
		Metadata:    req.Metadata,
		Tags:        req.Tags,
		ExpiresAt:   req.ExpiresAt,
		TenantId:    req.TenantID,
		KeyId:       req.KeyID,
		Algorithm:   req.Algorithm,
	}

	resp, err := h.secretsClient.StoreSecret(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, StoreSecretResponse{
		SecretID:  resp.SecretId,
		Version:   resp.Version,
		Timestamp: resp.Timestamp,
	})
}

// GetSecret handles GET /api/v1/kms/secrets/{name}
func (h *KMSHandlers) GetSecret(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Parse optional version from query string
	var version uint64
	if v := r.URL.Query().Get("version"); v != "" {
		if parsed, err := strconv.ParseUint(v, 10, 64); err == nil {
			version = parsed
		}
	}

	grpcReq := &proto.GetSecretRequest{
		SecretId: secretName,
		Version:  version,
	}

	resp, err := h.secretsClient.GetSecret(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GetSecretResponse{
		SecretID:      resp.SecretId,
		Version:       resp.Version,
		Data:          resp.Data,
		Metadata:      resp.Metadata,
		CreatedAt:     resp.CreatedAt,
		Timestamp:     resp.Timestamp,
		Algorithm:     resp.Algorithm,
		KeyIdentifier: resp.KeyIdentifier,
	})
}

// ListSecrets handles GET /api/v1/kms/secrets
func (h *KMSHandlers) ListSecrets(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	// Check if prefix is specified - if so, use GetSecretsByPrefix
	prefix := r.URL.Query().Get("prefix")
	if prefix != "" {
		h.GetSecretsByPrefix(w, r)
		return
	}

	limit, cursor := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	// Parse filter parameters from query string
	filter := make(map[string]string)
	for key, values := range r.URL.Query() {
		if key != "limit" && key != "cursor" && key != "prefix" && len(values) > 0 {
			filter[key] = values[0]
		}
	}

	grpcReq := &proto.ListSecretsRequest{
		Limit:  limit,
		Cursor: cursor,
		Filter: filter,
	}

	resp, err := h.secretsClient.ListSecrets(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	secrets := make([]SecretResponse, 0, len(resp.Secrets))
	for _, s := range resp.Secrets {
		secrets = append(secrets, *h.secretToResponse(s))
	}

	h.respWriter.Success200(w, r, ListSecretsResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: resp.NextCursor,
			HasMore:    resp.HasMore,
			TotalCount: resp.TotalCount,
		},
		Secrets:   secrets,
		Timestamp: resp.Timestamp,
	})
}

// DeleteSecret handles DELETE /api/v1/kms/secrets/{name}
func (h *KMSHandlers) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Parse optional permanently_delete from query string
	permanentlyDelete := r.URL.Query().Get("permanently_delete") == "true"

	grpcReq := &proto.DeleteSecretRequest{
		SecretId:          secretName,
		PermanentlyDelete: permanentlyDelete,
	}

	resp, err := h.secretsClient.DeleteSecret(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, DeleteSecretResponse{
		SecretID:  resp.SecretId,
		Deleted:   resp.Deleted,
		Timestamp: resp.Timestamp,
	})
}

// RotateSecret handles POST /api/v1/kms/secrets/{name}/rotate
func (h *KMSHandlers) RotateSecret(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	var req RotateSecretRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.NewData) == 0 {
		h.respWriter.Error400(w, r, ErrMissingSecretData{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.RotateSecretRequest{
		SecretId:  secretName,
		NewData:   req.NewData,
		Metadata:  req.Metadata,
		TenantId:  req.TenantID,
		KeyId:     req.KeyID,
		Algorithm: req.Algorithm,
	}

	resp, err := h.secretsClient.RotateSecret(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, RotateSecretResponse{
		SecretID:   resp.SecretId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	})
}

// GetSecretVersion handles GET /api/v1/kms/secrets/{name}/versions/{version}
func (h *KMSHandlers) GetSecretVersion(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	versionStr := h.getVersion(r)
	if versionStr == "" {
		h.respWriter.Error400(w, r, ErrInvalidSecretVersion{Reason: "version is required"})
		return
	}

	version, err := strconv.ParseUint(versionStr, 10, 64)
	if err != nil {
		h.respWriter.Error400(w, r, ErrInvalidSecretVersion{Reason: "invalid version format"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.GetSecretVersionRequest{
		SecretId: secretName,
		Version:  version,
	}

	resp, err := h.secretsClient.GetSecretVersion(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GetSecretVersionResponse{
		Version:   h.secretVersionToResponse(resp.Version),
		Data:      resp.Data,
		Timestamp: resp.Timestamp,
	})
}

// ListSecretVersions handles GET /api/v1/kms/secrets/{name}/versions
func (h *KMSHandlers) ListSecretVersions(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	limit, cursor := h.getPaginationParams(r)

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.ListSecretVersionsRequest{
		SecretId: secretName,
		Limit:    limit,
		Cursor:   cursor,
	}

	resp, err := h.secretsClient.ListSecretVersions(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	versions := make([]SecretVersionResponse, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, *h.secretVersionToResponse(v))
	}

	h.respWriter.Success200(w, r, ListSecretVersionsResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: resp.NextCursor,
			HasMore:    resp.HasMore,
		},
		Versions:  versions,
		Timestamp: resp.Timestamp,
	})
}

// RollbackSecret handles POST /api/v1/kms/secrets/{name}/rollback
func (h *KMSHandlers) RollbackSecret(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	var req RollbackSecretRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.TargetVersion == 0 {
		h.respWriter.Error400(w, r, ErrMissingTargetVersion{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.RollbackSecretRequest{
		SecretId:      secretName,
		TargetVersion: req.TargetVersion,
	}

	resp, err := h.secretsClient.RollbackSecret(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, RollbackSecretResponse{
		SecretID:   resp.SecretId,
		NewVersion: resp.NewVersion,
		Timestamp:  resp.Timestamp,
	})
}

// UpdateSecretStatus handles PUT /api/v1/kms/secrets/{name}/status
func (h *KMSHandlers) UpdateSecretStatus(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	var req UpdateSecretStatusRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Status == "" {
		h.respWriter.Error400(w, r, ErrInvalidSecretStatus{Status: "", Reason: "status is required"})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.UpdateSecretStatusRequest{
		SecretId: secretName,
		Status:   h.stringToSecretStatus(req.Status),
	}

	resp, err := h.secretsClient.UpdateSecretStatus(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, UpdateSecretStatusResponse{
		SecretID:  resp.SecretId,
		Status:    h.secretStatusToString(resp.Status),
		Timestamp: resp.Timestamp,
	})
}

// SetRotationPolicy handles PUT /api/v1/kms/secrets/{name}/policy
func (h *KMSHandlers) SetRotationPolicy(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	var req SetSecretRotationPolicyRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.SetRotationPolicyRequest{
		SecretId: secretName,
		Policy: &proto.SecretRotationPolicy{
			Enabled:         req.Policy.Enabled,
			IntervalSeconds: req.Policy.IntervalSeconds,
			RetainVersions:  req.Policy.RetainVersions,
			RotationLambda:  req.Policy.RotationLambda,
		},
	}

	resp, err := h.secretsClient.SetRotationPolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SetSecretRotationPolicyResponse{
		SecretID:  resp.SecretId,
		Policy:    h.secretRotationPolicyToResponse(resp.Policy),
		Timestamp: resp.Timestamp,
	})
}

// GetRotationPolicy handles GET /api/v1/kms/secrets/{name}/policy
func (h *KMSHandlers) GetRotationPolicy(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	secretName := h.getSecretName(r)
	if secretName == "" {
		h.respWriter.Error400(w, r, ErrMissingSecretName{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.GetRotationPolicyRequest{
		SecretId: secretName,
	}

	resp, err := h.secretsClient.GetRotationPolicy(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, GetSecretRotationPolicyResponse{
		SecretID:  resp.SecretId,
		Policy:    h.secretRotationPolicyToResponse(resp.Policy),
		Timestamp: resp.Timestamp,
	})
}

// GetSecretsByPrefix handles GET /api/v1/kms/secrets?prefix=...
func (h *KMSHandlers) GetSecretsByPrefix(w http.ResponseWriter, r *http.Request) {
	if h.secretsClient == nil {
		h.respWriter.Error500(w, r, ErrSecretsManagementClientNotInitialized{})
		return
	}

	prefix := r.URL.Query().Get("prefix")
	if prefix == "" {
		h.respWriter.Error400(w, r, ErrInvalidRequest{Reason: "prefix is required"})
		return
	}

	limit, cursor := h.getPaginationParams(r)
	includeData := r.URL.Query().Get("include_data") == "true"

	ctx, cancel := h.createContext()
	defer cancel()

	grpcReq := &proto.GetSecretsByPrefixRequest{
		Prefix:      prefix,
		IncludeData: includeData,
		Limit:       limit,
		Cursor:      cursor,
	}

	resp, err := h.secretsClient.GetSecretsByPrefix(ctx, grpcReq)
	if err != nil {
		h.handleGRPCError(w, r, err)
		return
	}

	secrets := make(map[string]SecretDataResponse)
	for key, data := range resp.Secrets {
		secrets[key] = *h.secretDataToResponse(data)
	}

	h.respWriter.Success200(w, r, GetSecretsByPrefixResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: resp.NextCursor,
			HasMore:    resp.HasMore,
			TotalCount: resp.TotalCount,
		},
		Secrets:   secrets,
		Timestamp: resp.Timestamp,
	})
}
