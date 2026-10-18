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
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// KMS extended category (opcode 0xCD) handlers.
//
// The single-byte KMS opcode range is exhausted, so the key-lifecycle
// verbs (revoke, metadata get/update, policy get/set, supported
// algorithms) multiplex under quicwire.OpKMSExtendedCategory with the first
// payload byte selecting the sub-operation. Dispatch is map-based per
// project conventions. All handlers delegate to the KMSServiceInterface,
// which is backed by the same SDK adapters as the gRPC transport.

// =============================================================================
// Wire Types
// =============================================================================

// KMSRevokeKeyRequest represents a key revocation request.
type KMSRevokeKeyRequest struct {
	KeyID  string `codec:"key_id"`
	Reason string `codec:"reason"`
}

// KMSRevokeKeyResponse represents a key revocation response.
type KMSRevokeKeyResponse struct {
	KeyID     string `codec:"key_id"`
	Status    string `codec:"status"`
	Timestamp int64  `codec:"timestamp"`
}

// KMSGetKeyMetadataRequest represents a key metadata retrieval request.
type KMSGetKeyMetadataRequest struct {
	KeyID string `codec:"key_id"`
}

// KMSGetKeyMetadataResponse represents a key metadata retrieval response.
type KMSGetKeyMetadataResponse struct {
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSUpdateKeyMetadataRequest represents a key metadata update request.
type KMSUpdateKeyMetadataRequest struct {
	KeyID       string            `codec:"key_id"`
	Name        string            `codec:"name"`
	Description string            `codec:"description"`
	Tags        map[string]string `codec:"tags"`
	RemoveTags  []string          `codec:"remove_tags"`
}

// KMSUpdateKeyMetadataResponse represents a key metadata update response.
type KMSUpdateKeyMetadataResponse struct {
	Metadata  *KMSKeyMetadataResponse `codec:"metadata"`
	Timestamp int64                   `codec:"timestamp"`
}

// KMSKeyPolicyPayload represents a key access policy on the QUIC wire.
type KMSKeyPolicyPayload struct {
	KeyID             string   `codec:"key_id"`
	Version           uint64   `codec:"version"`
	AllowedOperations []string `codec:"allowed_operations"`
	AllowedPrincipals []string `codec:"allowed_principals"`
	DeniedPrincipals  []string `codec:"denied_principals"`
	ExpiresAt         int64    `codec:"expires_at"`
	RotationRequired  bool     `codec:"rotation_required"`
	MaxUsageCount     uint64   `codec:"max_usage_count"`
	RequireMFA        bool     `codec:"require_mfa"`
	UpdatedAt         int64    `codec:"updated_at"`
}

// KMSSetKeyPolicyRequest represents a key policy update request.
type KMSSetKeyPolicyRequest struct {
	KeyID  string               `codec:"key_id"`
	Policy *KMSKeyPolicyPayload `codec:"policy"`
}

// KMSSetKeyPolicyResponse represents a key policy update response.
type KMSSetKeyPolicyResponse struct {
	KeyID         string `codec:"key_id"`
	PolicyVersion uint64 `codec:"policy_version"`
	Timestamp     int64  `codec:"timestamp"`
}

// KMSGetKeyPolicyRequest represents a key policy retrieval request.
type KMSGetKeyPolicyRequest struct {
	KeyID string `codec:"key_id"`
}

// KMSGetKeyPolicyResponse represents a key policy retrieval response.
type KMSGetKeyPolicyResponse struct {
	Policy    *KMSKeyPolicyPayload `codec:"policy"`
	Timestamp int64                `codec:"timestamp"`
}

// KMSGetSupportedAlgorithmsResponse represents a supported algorithms response.
type KMSGetSupportedAlgorithmsResponse struct {
	Algorithms []string `codec:"algorithms"`
	Timestamp  int64    `codec:"timestamp"`
}

// =============================================================================
// Dispatch
// =============================================================================

// kmsExtendedQUICHandler handles a KMS extended sub-operation.
type kmsExtendedQUICHandler func(h *QUICServiceHandler, ctx context.Context, payload []byte) *quicwire.Response

// kmsExtendedQUICDispatch routes KMS extended sub-opcodes with O(1) lookup.
var kmsExtendedQUICDispatch = map[byte]kmsExtendedQUICHandler{
	quicwire.KMSSubRevokeKey:              (*QUICServiceHandler).handleKMSRevokeKey,
	quicwire.KMSSubGetKeyMetadata:         (*QUICServiceHandler).handleKMSGetKeyMetadata,
	quicwire.KMSSubUpdateKeyMetadata:      (*QUICServiceHandler).handleKMSUpdateKeyMetadata,
	quicwire.KMSSubSetKeyPolicy:           (*QUICServiceHandler).handleKMSSetKeyPolicy,
	quicwire.KMSSubGetKeyPolicy:           (*QUICServiceHandler).handleKMSGetKeyPolicy,
	quicwire.KMSSubGetSupportedAlgorithms: (*QUICServiceHandler).handleKMSGetSupportedAlgorithms,
	quicwire.KMSSubSignCSR:                (*QUICServiceHandler).handleCASignCSR,
}

// handleKMSExtendedCategory routes a KMS extended request to the correct
// sub-handler based on the first payload byte.
func (h *QUICServiceHandler) handleKMSExtendedCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.kmsService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "kms"})
	}
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := kmsExtendedQUICDispatch[sub]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: sub})
	}
	return fn(h, ctx, payload)
}

// =============================================================================
// Sub-operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleKMSRevokeKey(ctx context.Context, payload []byte) *quicwire.Response {
	var revokeReq KMSRevokeKeyRequest
	if err := quicwire.DecodePayload(payload, &revokeReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if revokeReq.KeyID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbResp, err := h.kmsService.RevokeKey(ctx, &pb.RevokeKeyRequest{
		KeyId:  revokeReq.KeyID,
		Reason: revokeReq.Reason,
	})
	if err != nil {
		h.logger.Error(err, "failed to revoke key", "key_id", revokeReq.KeyID)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSRevokeKey", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&KMSRevokeKeyResponse{
		KeyID:     pbResp.KeyId,
		Status:    keyStatusToString(pbResp.Status),
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleKMSGetKeyMetadata(ctx context.Context, payload []byte) *quicwire.Response {
	var metaReq KMSGetKeyMetadataRequest
	if err := quicwire.DecodePayload(payload, &metaReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if metaReq.KeyID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbResp, err := h.kmsService.GetKeyMetadata(ctx, &pb.GetKeyMetadataRequest{KeyId: metaReq.KeyID})
	if err != nil {
		h.logger.Error(err, "failed to get key metadata", "key_id", metaReq.KeyID)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGetKeyMetadata", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&KMSGetKeyMetadataResponse{
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleKMSUpdateKeyMetadata(ctx context.Context, payload []byte) *quicwire.Response {
	var updateReq KMSUpdateKeyMetadataRequest
	if err := quicwire.DecodePayload(payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if updateReq.KeyID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbResp, err := h.kmsService.UpdateKeyMetadata(ctx, &pb.UpdateKeyMetadataRequest{
		KeyId:       updateReq.KeyID,
		Name:        updateReq.Name,
		Description: updateReq.Description,
		Tags:        updateReq.Tags,
		RemoveTags:  updateReq.RemoveTags,
	})
	if err != nil {
		h.logger.Error(err, "failed to update key metadata", "key_id", updateReq.KeyID)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSUpdateKeyMetadata", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&KMSUpdateKeyMetadataResponse{
		Metadata:  convertKeyMetadataToQUIC(pbResp.Metadata),
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleKMSSetKeyPolicy(ctx context.Context, payload []byte) *quicwire.Response {
	var setReq KMSSetKeyPolicyRequest
	if err := quicwire.DecodePayload(payload, &setReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if setReq.KeyID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}
	if setReq.Policy == nil {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "policy"})
	}

	pbResp, err := h.kmsService.SetKeyPolicy(ctx, &pb.SetKeyPolicyRequest{
		KeyId:  setReq.KeyID,
		Policy: quicKeyPolicyToPb(setReq.Policy),
	})
	if err != nil {
		h.logger.Error(err, "failed to set key policy", "key_id", setReq.KeyID)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSSetKeyPolicy", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&KMSSetKeyPolicyResponse{
		KeyID:         pbResp.KeyId,
		PolicyVersion: pbResp.PolicyVersion,
		Timestamp:     time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleKMSGetKeyPolicy(ctx context.Context, payload []byte) *quicwire.Response {
	var getReq KMSGetKeyPolicyRequest
	if err := quicwire.DecodePayload(payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if getReq.KeyID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "key_id"})
	}

	pbResp, err := h.kmsService.GetKeyPolicy(ctx, &pb.GetKeyPolicyRequest{KeyId: getReq.KeyID})
	if err != nil {
		h.logger.Error(err, "failed to get key policy", "key_id", getReq.KeyID)
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGetKeyPolicy", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&KMSGetKeyPolicyResponse{
		Policy:    pbKeyPolicyToQUIC(pbResp.Policy),
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleKMSGetSupportedAlgorithms(ctx context.Context, payload []byte) *quicwire.Response {
	pbResp, err := h.kmsService.GetSupportedAlgorithms(ctx, &pb.GetSupportedAlgorithmsRequest{})
	if err != nil {
		h.logger.Error(err, "failed to get supported algorithms")
		return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: "KMSGetSupportedAlgorithms", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&KMSGetSupportedAlgorithmsResponse{
		Algorithms: pbResp.Algorithms,
		Timestamp:  time.Now().Unix(),
	})
}

// encodeKMSExtendedResponse encodes v as a StatusOK QUIC response.
func (h *QUICServiceHandler) encodeKMSExtendedResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
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

// quicKeyPolicyToPb converts a QUIC wire key policy to protobuf.
func quicKeyPolicyToPb(p *KMSKeyPolicyPayload) *pb.KeyPolicy {
	if p == nil {
		return nil
	}
	return &pb.KeyPolicy{
		KeyId:             p.KeyID,
		Version:           p.Version,
		AllowedOperations: stringsToKeyUsages(p.AllowedOperations),
		AllowedPrincipals: p.AllowedPrincipals,
		DeniedPrincipals:  p.DeniedPrincipals,
		ExpiresAt:         p.ExpiresAt,
		RotationRequired:  p.RotationRequired,
		MaxUsageCount:     p.MaxUsageCount,
		RequireMfa:        p.RequireMFA,
		UpdatedAt:         p.UpdatedAt,
	}
}

// pbKeyPolicyToQUIC converts a protobuf key policy to the QUIC wire form.
func pbKeyPolicyToQUIC(p *pb.KeyPolicy) *KMSKeyPolicyPayload {
	if p == nil {
		return nil
	}
	return &KMSKeyPolicyPayload{
		KeyID:             p.KeyId,
		Version:           p.Version,
		AllowedOperations: keyUsagesToStrings(p.AllowedOperations),
		AllowedPrincipals: p.AllowedPrincipals,
		DeniedPrincipals:  p.DeniedPrincipals,
		ExpiresAt:         p.ExpiresAt,
		RotationRequired:  p.RotationRequired,
		MaxUsageCount:     p.MaxUsageCount,
		RequireMFA:        p.RequireMfa,
		UpdatedAt:         p.UpdatedAt,
	}
}
