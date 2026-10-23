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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Wire contract
// =============================================================================
//
// The SDK QUIC transport adapter routes every VPNService method to
// OpVPNCategory (0x52) with the sub-opcode in payload[0] and the
// MessagePack-encoded platform.v1 request in payload[1:]. The daemon decodes
// and encodes the same generated types, so the MessagePack field names stay in
// lockstep between client and server. A zero-length request body decodes to
// the empty message, which the service then validates.

// vpnQUICHandler is one VPN sub-operation handler (map-based dispatch for
// O(1) routing).
type vpnQUICHandler func(h *QUICServiceHandler, ctx context.Context, body []byte) *quicwire.Response

// vpnQUICHandlers routes VPN sub-opcodes to their handlers.
var vpnQUICHandlers = map[byte]vpnQUICHandler{
	quicwire.VPNSubEnrolPeer:           vpnQUICCall("VPNEnrolPeer", platformv1.VPNServiceServer.EnrolPeer),
	quicwire.VPNSubListPeers:           vpnQUICCall("VPNListPeers", platformv1.VPNServiceServer.ListPeers),
	quicwire.VPNSubRevokePeer:          vpnQUICCall("VPNRevokePeer", platformv1.VPNServiceServer.RevokePeer),
	quicwire.VPNSubGetStatus:           vpnQUICCall("VPNGetStatus", platformv1.VPNServiceServer.GetStatus),
	quicwire.VPNSubGetPosturePolicy:    vpnQUICCall("VPNGetPosturePolicy", platformv1.VPNServiceServer.GetPosturePolicy),
	quicwire.VPNSubSetPosturePolicy:    vpnQUICCall("VPNSetPosturePolicy", platformv1.VPNServiceServer.SetPosturePolicy),
	quicwire.VPNSubDeletePosturePolicy: vpnQUICCall("VPNDeletePosturePolicy", platformv1.VPNServiceServer.DeletePosturePolicy),
	quicwire.VPNSubListPosturePolicies: vpnQUICCall("VPNListPosturePolicies", platformv1.VPNServiceServer.ListPosturePolicies),
}

// vpnQUICCall builds the handler for one VPNService method: it decodes the
// sub-payload into the method's request message, runs the method on the
// shared server and encodes the reply, or maps the gRPC status to a QUIC
// status on failure.
func vpnQUICCall[Req any, Resp any](op string, method func(platformv1.VPNServiceServer, context.Context, *Req) (Resp, error)) vpnQUICHandler {
	return func(h *QUICServiceHandler, ctx context.Context, body []byte) *quicwire.Response {
		var request Req
		if err := quicwire.DecodePayload(body, &request); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}

		resp, err := method(h.vpnService, ctx, &request)
		if err != nil {
			return h.vpnErrorResponse(op, err)
		}
		return h.encodeGRPCDelegateResponse(resp)
	}
}

// vpnErrorResponse converts a VPN service error into a QUIC error response.
// A key collision is Aborted, which REST answers with 409 Conflict; QUIC's
// conflict status is StatusAlreadyExists, which the shared delegate map has
// no entry for. Every other code takes the shared mapping.
func (h *QUICServiceHandler) vpnErrorResponse(op string, err error) *quicwire.Response {
	if status.Code(err) == codes.Aborted {
		return h.errorResponse(quicwire.StatusAlreadyExists, ErrQUICOperationFailed{Op: op, Cause: err})
	}
	return h.grpcDelegateErrorToQUIC(op, err)
}

// SetVPNService wires the VPN control plane into the QUIC handler. The same
// instance backs REST, gRPC, MCP, and the Unix socket.
func (h *QUICServiceHandler) SetVPNService(service platformv1.VPNServiceServer) {
	h.vpnService = service
}

// handleVPNCategory dispatches the VPN category opcode. payload[0] selects
// the sub-operation and payload[1:] carries the request.
func (h *QUICServiceHandler) handleVPNCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.vpnService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: vpnServiceName})
	}
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	handler, ok := vpnQUICHandlers[req.Payload[0]]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
	}
	return handler(h, ctx, req.Payload[1:])
}
