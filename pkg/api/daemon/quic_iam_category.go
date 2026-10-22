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

// The SDK QUIC transport routes PlatformIAMService's tenant methods to
// OpIAMCategory (0x51) with the sub-opcode in payload[0] and the generated
// platform.v1 request in payload[1:]. They manage IAM tenant records and
// delegate to the shared *IAMGRPCService, never to the platform
// TenantService behind the OpTenant* opcodes (#767). UpdateGroup and
// UpdateRole ride the same category: the group bytes 0xBB-0xBF and the role
// bytes 0xB5-0xBA had no room for them.

// iamCategoryQUICHandler is one IAM category sub-operation handler. body is
// the request with the sub-opcode stripped.
type iamCategoryQUICHandler func(h *QUICServiceHandler, ctx context.Context, body []byte) *quicwire.Response

// iamCategoryQUICHandlers routes IAM category sub-opcodes to their handlers.
var iamCategoryQUICHandlers = map[byte]iamCategoryQUICHandler{
	quicwire.IAMSubTenantCreate: (*QUICServiceHandler).handleIAMTenantCreate,
	quicwire.IAMSubTenantGet:    (*QUICServiceHandler).handleIAMTenantGet,
	quicwire.IAMSubTenantList:   (*QUICServiceHandler).handleIAMTenantList,
	quicwire.IAMSubTenantUpdate: (*QUICServiceHandler).handleIAMTenantUpdate,
	quicwire.IAMSubTenantDelete: (*QUICServiceHandler).handleIAMTenantDelete,
	quicwire.IAMSubGroupUpdate:  (*QUICServiceHandler).handleIAMGroupUpdate,
	quicwire.IAMSubRoleUpdate:   (*QUICServiceHandler).handleIAMRoleUpdate,
}

// handleIAMCategory dispatches the IAM category opcode. payload[0] selects
// the sub-operation.
func (h *QUICServiceHandler) handleIAMCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.iamGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "iam"})
	}
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	handler, ok := iamCategoryQUICHandlers[req.Payload[0]]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
	}
	return handler(h, ctx, req.Payload[1:])
}

// handleIAMTenantCreate creates an IAM tenant record.
func (h *QUICServiceHandler) handleIAMTenantCreate(ctx context.Context, body []byte) *quicwire.Response {
	var pbReq platformv1.CreateIAMTenantRequest
	if err := quicwire.DecodePayload(body, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.CreateTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMTenantCreate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMTenantGet returns one IAM tenant record.
func (h *QUICServiceHandler) handleIAMTenantGet(ctx context.Context, body []byte) *quicwire.Response {
	var pbReq platformv1.GetIAMTenantRequest
	if err := quicwire.DecodePayload(body, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.GetTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMTenantGet", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMTenantList lists IAM tenant records.
func (h *QUICServiceHandler) handleIAMTenantList(ctx context.Context, body []byte) *quicwire.Response {
	var pbReq platformv1.ListIAMTenantsRequest
	if err := quicwire.DecodePayload(body, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.ListTenants(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMTenantList", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMTenantUpdate updates an IAM tenant record.
func (h *QUICServiceHandler) handleIAMTenantUpdate(ctx context.Context, body []byte) *quicwire.Response {
	var pbReq platformv1.UpdateIAMTenantRequest
	if err := quicwire.DecodePayload(body, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.UpdateTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMTenantUpdate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMTenantDelete deletes an IAM tenant record.
func (h *QUICServiceHandler) handleIAMTenantDelete(ctx context.Context, body []byte) *quicwire.Response {
	var pbReq platformv1.DeleteIAMTenantRequest
	if err := quicwire.DecodePayload(body, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.DeleteTenant(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMTenantDelete", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMGroupUpdate updates an IAM group, as gRPC UpdateGroup.
func (h *QUICServiceHandler) handleIAMGroupUpdate(ctx context.Context, body []byte) *quicwire.Response {
	var pbReq platformv1.UpdateIAMGroupRequest
	if err := quicwire.DecodePayload(body, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.UpdateGroup(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMGroupUpdate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}

// handleIAMRoleUpdate updates an IAM role, as gRPC UpdateRole.
func (h *QUICServiceHandler) handleIAMRoleUpdate(ctx context.Context, body []byte) *quicwire.Response {
	var pbReq platformv1.UpdateIAMRoleRequest
	if err := quicwire.DecodePayload(body, &pbReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.iamGRPC.UpdateRole(ctx, &pbReq)
	if err != nil {
		return h.grpcDelegateErrorToQUIC("IAMRoleUpdate", err)
	}
	return h.encodeGRPCDelegateResponse(resp)
}
