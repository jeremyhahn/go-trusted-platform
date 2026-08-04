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
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// Secrets category (opcode 0xCE) handlers.
//
// The secrets surface multiplexes store/get/list/delete and the
// rotation-policy pair under quic.OpSecretsCategory with the first
// payload byte selecting the sub-operation, mirroring the secrets
// subset exposed by the gRPC and Unix transports. Dispatch is map-based
// per project conventions. All handlers delegate to the
// SecretsServiceInterface, which is backed by the same SDK secrets
// adapter as the gRPC transport.

// SecretsServiceInterface defines the interface for secrets operations
// over QUIC. It mirrors the pb.SecretsManagementServer subset served on
// the gRPC and Unix transports and is satisfied by *SecretsServerAdapter.
type SecretsServiceInterface interface {
	StoreSecret(ctx context.Context, req *pb.StoreSecretRequest) (*pb.StoreSecretResponse, error)
	GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error)
	ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error)
	DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error)
	SetRotationPolicy(ctx context.Context, req *pb.SetRotationPolicyRequest) (*pb.SetRotationPolicyResponse, error)
	GetRotationPolicy(ctx context.Context, req *pb.GetRotationPolicyRequest) (*pb.GetRotationPolicyResponse, error)
}

// Compile-time check: the gRPC secrets adapter satisfies the QUIC interface.
var _ SecretsServiceInterface = (*SecretsServerAdapter)(nil)

// =============================================================================
// Wire Types
// =============================================================================

// SecretsStoreRequest represents a secret storage request.
type SecretsStoreRequest struct {
	SecretID string            `codec:"secret_id"`
	Data     []byte            `codec:"data"`
	Metadata map[string]string `codec:"metadata"`
}

// SecretsStoreResponse represents a secret storage response.
type SecretsStoreResponse struct {
	SecretID  string `codec:"secret_id"`
	Version   uint64 `codec:"version"`
	Timestamp int64  `codec:"timestamp"`
}

// SecretsGetRequest represents a secret retrieval request.
type SecretsGetRequest struct {
	SecretID string `codec:"secret_id"`
	Version  uint64 `codec:"version"`
}

// SecretsGetResponse represents a secret retrieval response.
type SecretsGetResponse struct {
	SecretID  string            `codec:"secret_id"`
	Version   uint64            `codec:"version"`
	Data      []byte            `codec:"data"`
	Metadata  map[string]string `codec:"metadata"`
	Timestamp int64             `codec:"timestamp"`
}

// SecretsListRequest represents a secrets listing request.
type SecretsListRequest struct {
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

// SecretsListResponse represents a secrets listing response.
type SecretsListResponse struct {
	SecretIDs []string `codec:"secret_ids"`
	Timestamp int64    `codec:"timestamp"`
}

// SecretsDeleteRequest represents a secret deletion request.
type SecretsDeleteRequest struct {
	SecretID string `codec:"secret_id"`
}

// SecretsDeleteResponse represents a secret deletion response.
type SecretsDeleteResponse struct {
	SecretID  string `codec:"secret_id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

// SecretsRotationPolicyPayload represents a rotation policy on the QUIC wire.
type SecretsRotationPolicyPayload struct {
	Enabled         bool   `codec:"enabled"`
	IntervalSeconds int64  `codec:"interval_seconds"`
	NextRotation    int64  `codec:"next_rotation"`
	RetainVersions  int32  `codec:"retain_versions"`
	RotationLambda  string `codec:"rotation_lambda"`
}

// SecretsSetRotationPolicyRequest represents a rotation policy update request.
type SecretsSetRotationPolicyRequest struct {
	SecretID string                        `codec:"secret_id"`
	Policy   *SecretsRotationPolicyPayload `codec:"policy"`
}

// SecretsSetRotationPolicyResponse represents a rotation policy update response.
type SecretsSetRotationPolicyResponse struct {
	SecretID  string                        `codec:"secret_id"`
	Policy    *SecretsRotationPolicyPayload `codec:"policy"`
	Timestamp int64                         `codec:"timestamp"`
}

// SecretsGetRotationPolicyRequest represents a rotation policy retrieval request.
type SecretsGetRotationPolicyRequest struct {
	SecretID string `codec:"secret_id"`
}

// SecretsGetRotationPolicyResponse represents a rotation policy retrieval response.
type SecretsGetRotationPolicyResponse struct {
	SecretID  string                        `codec:"secret_id"`
	Policy    *SecretsRotationPolicyPayload `codec:"policy"`
	Timestamp int64                         `codec:"timestamp"`
}

// =============================================================================
// Dispatch
// =============================================================================

// secretsQUICHandler handles a secrets sub-operation.
type secretsQUICHandler func(h *QUICServiceHandler, ctx context.Context, payload []byte) *quic.Response

// secretsQUICDispatch routes secrets sub-opcodes with O(1) lookup.
var secretsQUICDispatch = map[byte]secretsQUICHandler{
	quic.SecretsSubStore:             (*QUICServiceHandler).handleSecretsStore,
	quic.SecretsSubGet:               (*QUICServiceHandler).handleSecretsGet,
	quic.SecretsSubList:              (*QUICServiceHandler).handleSecretsList,
	quic.SecretsSubDelete:            (*QUICServiceHandler).handleSecretsDelete,
	quic.SecretsSubSetRotationPolicy: (*QUICServiceHandler).handleSecretsSetRotationPolicy,
	quic.SecretsSubGetRotationPolicy: (*QUICServiceHandler).handleSecretsGetRotationPolicy,
}

// handleSecretsCategory routes a secrets request to the correct
// sub-handler based on the first payload byte.
func (h *QUICServiceHandler) handleSecretsCategory(ctx context.Context, req *quic.Request) *quic.Response {
	if h.secretsService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "secrets"})
	}
	sub, payload, errResp := subPayload(req)
	if errResp != nil {
		return errResp
	}
	fn, ok := secretsQUICDispatch[sub]
	if !ok {
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: sub})
	}
	return fn(h, ctx, payload)
}

// SetSecretsService sets the secrets service after construction.
func (h *QUICServiceHandler) SetSecretsService(svc SecretsServiceInterface) {
	h.secretsService = svc
}

// =============================================================================
// Sub-operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleSecretsStore(ctx context.Context, payload []byte) *quic.Response {
	var storeReq SecretsStoreRequest
	if err := quic.DecodePayload(payload, &storeReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if storeReq.SecretID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "secret_id"})
	}
	if len(storeReq.Data) == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "data"})
	}

	pbResp, err := h.secretsService.StoreSecret(ctx, &pb.StoreSecretRequest{
		SecretId: storeReq.SecretID,
		Data:     storeReq.Data,
		Metadata: storeReq.Metadata,
	})
	if err != nil {
		h.logger.Error(err, "failed to store secret", "secret_id", storeReq.SecretID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SecretsStore", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&SecretsStoreResponse{
		SecretID:  pbResp.SecretId,
		Version:   pbResp.Version,
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleSecretsGet(ctx context.Context, payload []byte) *quic.Response {
	var getReq SecretsGetRequest
	if err := quic.DecodePayload(payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if getReq.SecretID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "secret_id"})
	}

	pbResp, err := h.secretsService.GetSecret(ctx, &pb.GetSecretRequest{
		SecretId: getReq.SecretID,
		Version:  getReq.Version,
	})
	if err != nil {
		h.logger.Error(err, "failed to get secret", "secret_id", getReq.SecretID)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "SecretsGet", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&SecretsGetResponse{
		SecretID:  pbResp.SecretId,
		Version:   pbResp.Version,
		Data:      pbResp.Data,
		Metadata:  pbResp.Metadata,
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleSecretsList(ctx context.Context, payload []byte) *quic.Response {
	var listReq SecretsListRequest
	if len(payload) > 0 {
		if err := quic.DecodePayload(payload, &listReq); err != nil {
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

	pbResp, err := h.secretsService.ListSecrets(ctx, &pb.ListSecretsRequest{
		Limit:  limit,
		Cursor: listReq.Cursor,
	})
	if err != nil {
		h.logger.Error(err, "failed to list secrets")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SecretsList", Cause: err})
	}

	secretIDs := make([]string, 0, len(pbResp.Secrets))
	for _, s := range pbResp.Secrets {
		secretIDs = append(secretIDs, s.SecretId)
	}

	return h.encodeKMSExtendedResponse(&SecretsListResponse{
		SecretIDs: secretIDs,
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleSecretsDelete(ctx context.Context, payload []byte) *quic.Response {
	var deleteReq SecretsDeleteRequest
	if err := quic.DecodePayload(payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if deleteReq.SecretID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "secret_id"})
	}

	pbResp, err := h.secretsService.DeleteSecret(ctx, &pb.DeleteSecretRequest{SecretId: deleteReq.SecretID})
	if err != nil {
		h.logger.Error(err, "failed to delete secret", "secret_id", deleteReq.SecretID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SecretsDelete", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&SecretsDeleteResponse{
		SecretID:  pbResp.SecretId,
		Deleted:   true,
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleSecretsSetRotationPolicy(ctx context.Context, payload []byte) *quic.Response {
	var setReq SecretsSetRotationPolicyRequest
	if err := quic.DecodePayload(payload, &setReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if setReq.SecretID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "secret_id"})
	}
	if setReq.Policy == nil {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "policy"})
	}

	pbResp, err := h.secretsService.SetRotationPolicy(ctx, &pb.SetRotationPolicyRequest{
		SecretId: setReq.SecretID,
		Policy:   quicSecretRotationPolicyToPb(setReq.Policy),
	})
	if err != nil {
		h.logger.Error(err, "failed to set rotation policy", "secret_id", setReq.SecretID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "SecretsSetRotationPolicy", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&SecretsSetRotationPolicyResponse{
		SecretID:  pbResp.SecretId,
		Policy:    pbSecretRotationPolicyToQUIC(pbResp.Policy),
		Timestamp: time.Now().Unix(),
	})
}

func (h *QUICServiceHandler) handleSecretsGetRotationPolicy(ctx context.Context, payload []byte) *quic.Response {
	var getReq SecretsGetRotationPolicyRequest
	if err := quic.DecodePayload(payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	if getReq.SecretID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "secret_id"})
	}

	pbResp, err := h.secretsService.GetRotationPolicy(ctx, &pb.GetRotationPolicyRequest{SecretId: getReq.SecretID})
	if err != nil {
		h.logger.Error(err, "failed to get rotation policy", "secret_id", getReq.SecretID)
		return h.errorResponse(quic.StatusNotFound, ErrQUICOperationFailed{Op: "SecretsGetRotationPolicy", Cause: err})
	}

	return h.encodeKMSExtendedResponse(&SecretsGetRotationPolicyResponse{
		SecretID:  pbResp.SecretId,
		Policy:    pbSecretRotationPolicyToQUIC(pbResp.Policy),
		Timestamp: time.Now().Unix(),
	})
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// quicSecretRotationPolicyToPb converts a QUIC wire rotation policy to protobuf.
func quicSecretRotationPolicyToPb(p *SecretsRotationPolicyPayload) *pb.SecretRotationPolicy {
	if p == nil {
		return nil
	}
	return &pb.SecretRotationPolicy{
		Enabled:         p.Enabled,
		IntervalSeconds: p.IntervalSeconds,
		NextRotation:    p.NextRotation,
		RetainVersions:  p.RetainVersions,
		RotationLambda:  p.RotationLambda,
	}
}

// pbSecretRotationPolicyToQUIC converts a protobuf rotation policy to the QUIC wire form.
func pbSecretRotationPolicyToQUIC(p *pb.SecretRotationPolicy) *SecretsRotationPolicyPayload {
	if p == nil {
		return nil
	}
	return &SecretsRotationPolicyPayload{
		Enabled:         p.Enabled,
		IntervalSeconds: p.IntervalSeconds,
		NextRotation:    p.NextRotation,
		RetainVersions:  p.RetainVersions,
		RotationLambda:  p.RotationLambda,
	}
}
