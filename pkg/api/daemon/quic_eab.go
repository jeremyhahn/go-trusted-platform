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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// EAB sub-opcode handlers, multiplexed under quicwire.OpProvisioningCategory
// (0xCF).
//
// The single-byte QUIC opcode space is fully allocated, so EAB shares
// the provisioning category with config delivery: payload[0] selects the
// sub-operation, with 0x10-0x1A reserved for EAB (see
// sdk/go/wire/quicwire/eab_opcodes.go). The dispatch in quic_service.go routes
// EAB sub-opcodes here first and falls through to the config delivery
// dispatcher for everything else, so quic_configdelivery.go stays
// untouched.
//
// All handlers delegate to the EABQUICService, which is backed by the
// same EABGRPCService as the gRPC transport, so the typed eab error ->
// status-code mapping (eabErrorMatchers) is reused by construction; this
// file only translates the resulting gRPC codes to QUIC status bytes.
//
// Wire format: the QUIC payload codec keys on exact Go field names, and
// every platform.v1 EAB message is oneof-free, so requests decode into
// (and responses encode from) the generated pb structs directly — the
// same approach ConfigDeliveryListSessionsResponse uses for
// ProvisioningSession. The SDK QUIC adapter encodes the pb request
// structs on its side, guaranteeing field-name equality end to end.

// EABQUICService is the EAB surface the QUIC transport delegates to. It
// is satisfied by *EABGRPCService, guaranteeing identical semantics and
// error mapping across transports.
type EABQUICService interface {
	CreateCredential(ctx context.Context, req *platformv1.CreateEABCredentialRequest) (*platformv1.CreateEABCredentialResponse, error)
	GetCredential(ctx context.Context, req *platformv1.GetEABCredentialRequest) (*platformv1.GetEABCredentialResponse, error)
	GetCredentialByKeyID(ctx context.Context, req *platformv1.GetEABCredentialByKeyIDRequest) (*platformv1.GetEABCredentialResponse, error)
	ListCredentials(ctx context.Context, req *platformv1.ListEABCredentialsRequest) (*platformv1.ListEABCredentialsResponse, error)
	RevokeCredential(ctx context.Context, req *platformv1.RevokeEABCredentialRequest) (*platformv1.RevokeEABCredentialResponse, error)
	ValidateCredential(ctx context.Context, req *platformv1.ValidateEABCredentialRequest) (*platformv1.ValidateEABCredentialResponse, error)
	DeleteCredential(ctx context.Context, req *platformv1.DeleteEABCredentialRequest) (*platformv1.DeleteEABCredentialResponse, error)
	GetCredentialQRCode(ctx context.Context, req *platformv1.GetEABCredentialQRCodeRequest) (*platformv1.GetEABCredentialQRCodeResponse, error)
	GetEnrollmentURL(ctx context.Context, req *platformv1.GetEABEnrollmentURLRequest) (*platformv1.GetEABEnrollmentURLResponse, error)
	MarkCredentialUsed(ctx context.Context, req *platformv1.MarkEABCredentialUsedRequest) (*platformv1.MarkEABCredentialUsedResponse, error)
	CleanupExpiredCredentials(ctx context.Context, req *platformv1.CleanupExpiredEABCredentialsRequest) (*platformv1.CleanupExpiredEABCredentialsResponse, error)
}

// Compile-time check: the gRPC service implements the QUIC surface.
var _ EABQUICService = (*EABGRPCService)(nil)

// SetEABService sets the EAB service after construction. The daemon
// wires the same EABGRPCService that serves the gRPC TCP/UDS transports
// so the QUIC surface stays in lockstep.
func (h *QUICServiceHandler) SetEABService(svc EABQUICService) {
	h.eabService = svc
}

// =============================================================================
// Dispatch
// =============================================================================

// eabQUICHandler handles an EAB sub-operation.
type eabQUICHandler func(h *QUICServiceHandler, ctx context.Context, payload []byte) *quicwire.Response

// eabQUICDispatch routes EAB sub-opcodes with O(1) lookup.
var eabQUICDispatch = map[byte]eabQUICHandler{
	quicwire.EABSubCreateCredential:          (*QUICServiceHandler).handleEABCreateCredential,
	quicwire.EABSubGetCredential:             (*QUICServiceHandler).handleEABGetCredential,
	quicwire.EABSubGetCredentialByKeyID:      (*QUICServiceHandler).handleEABGetCredentialByKeyID,
	quicwire.EABSubListCredentials:           (*QUICServiceHandler).handleEABListCredentials,
	quicwire.EABSubRevokeCredential:          (*QUICServiceHandler).handleEABRevokeCredential,
	quicwire.EABSubValidateCredential:        (*QUICServiceHandler).handleEABValidateCredential,
	quicwire.EABSubDeleteCredential:          (*QUICServiceHandler).handleEABDeleteCredential,
	quicwire.EABSubGetCredentialQRCode:       (*QUICServiceHandler).handleEABGetCredentialQRCode,
	quicwire.EABSubGetEnrollmentURL:          (*QUICServiceHandler).handleEABGetEnrollmentURL,
	quicwire.EABSubMarkCredentialUsed:        (*QUICServiceHandler).handleEABMarkCredentialUsed,
	quicwire.EABSubCleanupExpiredCredentials: (*QUICServiceHandler).handleEABCleanupExpiredCredentials,
}

// handleEABCategorySub routes an EAB sub-opcode when payload[0] belongs
// to the EAB sub-range. It reports handled=false for anything else so
// the caller can fall through to the config delivery dispatcher. A nil
// backing service yields the same typed unavailable error the gRPC
// requireService guard produces.
func (h *QUICServiceHandler) handleEABCategorySub(ctx context.Context, req *quicwire.Request) (*quicwire.Response, bool) {
	if len(req.Payload) == 0 {
		// Empty payload is handled (and rejected) by the config delivery
		// dispatcher's subPayload guard.
		return nil, false
	}
	fn, ok := eabQUICDispatch[req.Payload[0]]
	if !ok {
		return nil, false
	}
	if h.eabService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrEABNotConfigured{}), true
	}
	return fn(h, ctx, req.Payload[1:]), true
}

// encodeEABQUICResponse encodes v as a StatusOK QUIC response.
func (h *QUICServiceHandler) encodeEABQUICResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// eabErrorToQUICResponse converts a gRPC status error from the shared
// EABGRPCService into a QUIC error response, preserving the status-code
// semantics established by the eabErrorMatchers table. It reuses the
// shared gRPC-code -> QUIC-status map owned by the config delivery
// handler (both surfaces multiplex under the same category opcode).
func (h *QUICServiceHandler) eabErrorToQUICResponse(op string, err error) *quicwire.Response {
	return h.configDeliveryErrorToQUICResponse(op, err)
}

// =============================================================================
// Sub-operation Handlers
// =============================================================================

func (h *QUICServiceHandler) handleEABCreateCredential(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.CreateEABCredentialRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.CreateCredential(ctx, &req)
	if err != nil {
		h.logger.Error(err, "failed to create EAB credential", "profile_id", req.GetProfileId())
		return h.eabErrorToQUICResponse("EABCreateCredential", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABGetCredential(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetEABCredentialRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.GetCredential(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABGetCredential", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABGetCredentialByKeyID(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetEABCredentialByKeyIDRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.GetCredentialByKeyID(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABGetCredentialByKeyID", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABListCredentials(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.ListEABCredentialsRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.ListCredentials(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABListCredentials", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABRevokeCredential(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.RevokeEABCredentialRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.RevokeCredential(ctx, &req)
	if err != nil {
		h.logger.Error(err, "failed to revoke EAB credential", "credential_id", req.GetCredentialId())
		return h.eabErrorToQUICResponse("EABRevokeCredential", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABValidateCredential(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.ValidateEABCredentialRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.ValidateCredential(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABValidateCredential", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABDeleteCredential(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.DeleteEABCredentialRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.DeleteCredential(ctx, &req)
	if err != nil {
		h.logger.Error(err, "failed to delete EAB credential", "credential_id", req.GetCredentialId())
		return h.eabErrorToQUICResponse("EABDeleteCredential", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABGetCredentialQRCode(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetEABCredentialQRCodeRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.GetCredentialQRCode(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABGetCredentialQRCode", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABGetEnrollmentURL(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.GetEABEnrollmentURLRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.GetEnrollmentURL(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABGetEnrollmentURL", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABMarkCredentialUsed(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.MarkEABCredentialUsedRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.MarkCredentialUsed(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABMarkCredentialUsed", err)
	}
	return h.encodeEABQUICResponse(resp)
}

func (h *QUICServiceHandler) handleEABCleanupExpiredCredentials(ctx context.Context, payload []byte) *quicwire.Response {
	var req platformv1.CleanupExpiredEABCredentialsRequest
	if err := quicwire.DecodePayload(payload, &req); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}
	resp, err := h.eabService.CleanupExpiredCredentials(ctx, &req)
	if err != nil {
		return h.eabErrorToQUICResponse("EABCleanupExpiredCredentials", err)
	}
	return h.encodeEABQUICResponse(resp)
}
