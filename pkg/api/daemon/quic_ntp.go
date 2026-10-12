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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Wire contract
// =============================================================================
//
// The SDK QUIC transport adapter routes every NTPService method to
// OpNTPCategory (0x50) with the sub-opcode in payload[0], and encodes the
// generated platform.v1 protobuf messages directly — the protobuf messages
// ARE the wire contract, exactly as for the switch and device surfaces. The
// daemon therefore decodes and encodes the same platform.v1 types, which is
// what keeps the MessagePack field names (which key on Go FIELD NAMES) in
// lockstep between client and server.
//
// All three NTP requests are empty messages, so the SDK sends only the
// sub-opcode byte; the handlers must tolerate a zero-length sub-payload.

// ntpQUICHandler is one NTP sub-operation handler (map-based dispatch for
// O(1) routing).
type ntpQUICHandler func(*QUICServiceHandler, context.Context) *quicwire.Response

// ntpQUICHandlers routes NTP sub-opcodes to their handlers.
var ntpQUICHandlers = map[byte]ntpQUICHandler{
	quicwire.NTPSubGetStatus:   (*QUICServiceHandler).handleNTPGetStatus,
	quicwire.NTPSubListSources: (*QUICServiceHandler).handleNTPListSources,
	quicwire.NTPSubStep:        (*QUICServiceHandler).handleNTPStep,
}

// SetNTPService wires the NTP gRPC service into the QUIC handler. The same
// instance backs REST, gRPC, MCP, and the Unix socket.
func (h *QUICServiceHandler) SetNTPService(service platformv1.NTPServiceServer) {
	h.ntpService = service
}

// WithQUICNTPService sets the NTP service at construction time.
func WithQUICNTPService(service platformv1.NTPServiceServer) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.ntpService = service
	}
}

// handleNTPCategory dispatches the NTP category opcode. payload[0] selects
// the sub-operation.
func (h *QUICServiceHandler) handleNTPCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.ntpService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "ntp"})
	}
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	handler, ok := ntpQUICHandlers[req.Payload[0]]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
	}
	return handler(h, ctx)
}

// ntpQUICStatus maps the service's gRPC codes onto QUIC wire statuses
// (map-based for O(1) lookup), so a QUIC caller sees the same failure class
// as a REST or gRPC caller.
var ntpQUICStatus = map[codes.Code]byte{
	codes.Unavailable:       quicwire.StatusUnavailable,
	codes.Aborted:           quicwire.StatusAlreadyExists,
	codes.InvalidArgument:   quicwire.StatusInvalidArgument,
	codes.DeadlineExceeded:  quicwire.StatusTimeout,
	codes.NotFound:          quicwire.StatusNotFound,
	codes.PermissionDenied:  quicwire.StatusPermissionDenied,
	codes.Unimplemented:     quicwire.StatusNotImplemented,
	codes.ResourceExhausted: quicwire.StatusResourceExhausted,
}

// ntpErrorResponse converts a service error into a QUIC error response.
func (h *QUICServiceHandler) ntpErrorResponse(err error) *quicwire.Response {
	wireStatus, ok := ntpQUICStatus[status.Code(err)]
	if !ok {
		wireStatus = quicwire.StatusInternalError
	}
	return h.errorResponse(wireStatus, err)
}

// encodeNTPResponse encodes a platform.v1 response message.
func (h *QUICServiceHandler) encodeNTPResponse(msg any) *quicwire.Response {
	payload, err := quicwire.EncodePayload(msg)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{Status: quicwire.StatusOK, Payload: payload}
}

// handleNTPGetStatus serves the get-status sub-operation.
func (h *QUICServiceHandler) handleNTPGetStatus(ctx context.Context) *quicwire.Response {
	resp, err := h.ntpService.GetStatus(ctx, &platformv1.GetNTPStatusRequest{})
	if err != nil {
		return h.ntpErrorResponse(err)
	}
	return h.encodeNTPResponse(resp)
}

// handleNTPListSources serves the list-sources sub-operation.
func (h *QUICServiceHandler) handleNTPListSources(ctx context.Context) *quicwire.Response {
	resp, err := h.ntpService.ListSources(ctx, &platformv1.ListNTPSourcesRequest{})
	if err != nil {
		return h.ntpErrorResponse(err)
	}
	return h.encodeNTPResponse(resp)
}

// handleNTPStep serves the step sub-operation. It answers StatusAlreadyExists
// (the wire's conflict status, mirroring REST 409) when no source is
// reachable.
func (h *QUICServiceHandler) handleNTPStep(ctx context.Context) *quicwire.Response {
	resp, err := h.ntpService.Step(ctx, &platformv1.StepNTPClockRequest{})
	if err != nil {
		return h.ntpErrorResponse(err)
	}
	return h.encodeNTPResponse(resp)
}
