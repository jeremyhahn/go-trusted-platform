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

// quic_grpc_delegates.go wires the shared gRPC service delegates that the
// converged Tenant and IAM QUIC handlers dispatch to, and provides the
// gRPC-status -> QUIC-status translation and pb response encoding shared by
// both surfaces.
//
// The canonical QUIC wire contract for the Tenant and IAM surfaces is the
// platform.v1 protobuf request/response messages themselves: the SDK QUIC
// transport adapter hands the generated pb request struct straight to the
// payload codec (which keys on the exact Go field names of the message), and
// decodes daemon replies directly into the generated pb response struct.
// Decoding the payload into the same platform.v1 message types on the daemon
// side and delegating to the shared *TenantGRPCServer / *IAMGRPCService gives
// the QUIC transport identical semantics to gRPC by construction — the same
// bug class (silently dropped fields on a flat local struct whose Go field
// names diverge from the pb Go field names) can no longer occur.

package daemon

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// SetTenantGRPCServer wires the shared *TenantGRPCServer the converged Tenant
// QUIC handlers delegate to. It is invoked once during single-threaded daemon
// setup after the tenant manager has been attached to the gRPC server, so the
// QUIC transport and the gRPC transport share one manager instance and see
// identical per-tenant state (including barrier lifecycle).
func (h *QUICServiceHandler) SetTenantGRPCServer(s *TenantGRPCServer) {
	h.tenantGRPC = s
}

// SetIAMGRPCService wires the shared *IAMGRPCService the converged IAM QUIC
// handlers delegate to. It reuses the same instance registered on the gRPC
// servers so all transports share the QuicBaaS IAM SDK clients.
func (h *QUICServiceHandler) SetIAMGRPCService(s *IAMGRPCService) {
	h.iamGRPC = s
}

// grpcDelegateCodeToQUICStatus maps the gRPC status codes produced by the
// shared Tenant/IAM gRPC delegates onto QUIC status bytes. FailedPrecondition
// maps to StatusInvalidRequest (the QUIC status set has no precondition code);
// Unimplemented maps to StatusNotImplemented for OIDC token parity; unknown
// codes fall back to StatusInternalError.
var grpcDelegateCodeToQUICStatus = map[codes.Code]byte{
	codes.OK:                 quicwire.StatusOK,
	codes.InvalidArgument:    quicwire.StatusInvalidArgument,
	codes.NotFound:           quicwire.StatusNotFound,
	codes.AlreadyExists:      quicwire.StatusAlreadyExists,
	codes.PermissionDenied:   quicwire.StatusPermissionDenied,
	codes.Unauthenticated:    quicwire.StatusUnauthorized,
	codes.FailedPrecondition: quicwire.StatusInvalidRequest,
	codes.ResourceExhausted:  quicwire.StatusResourceExhausted,
	codes.Unavailable:        quicwire.StatusUnavailable,
	codes.Unimplemented:      quicwire.StatusNotImplemented,
	codes.DeadlineExceeded:   quicwire.StatusTimeout,
	codes.Internal:           quicwire.StatusInternalError,
}

// grpcDelegateErrorToQUIC converts a gRPC status error from a shared delegate
// into a QUIC error response, preserving the status-code semantics of the gRPC
// transport.
func (h *QUICServiceHandler) grpcDelegateErrorToQUIC(op string, err error) *quicwire.Response {
	quicStatus := quicwire.StatusInternalError
	if mapped, ok := grpcDelegateCodeToQUICStatus[status.Code(err)]; ok {
		quicStatus = mapped
	}
	return h.errorResponse(quicStatus, ErrQUICOperationFailed{Op: op, Cause: err})
}

// encodeGRPCDelegateResponse encodes v (a platform.v1 protobuf response) as a
// StatusOK QUIC response.
func (h *QUICServiceHandler) encodeGRPCDelegateResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}
