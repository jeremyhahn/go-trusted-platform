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

// orchestratorServiceName names the orchestrator in transport errors.
const orchestratorServiceName = "orchestrator"

// orchestratorQUICHandler serves one orchestrator sub-operation; body is the
// MessagePack-encoded request that follows the sub-opcode.
type orchestratorQUICHandler func(h *QUICServiceHandler, ctx context.Context, body []byte) *quicwire.Response

// orchestratorQUICHandlers dispatches the OpOrchestratorCategory sub-opcodes.
var orchestratorQUICHandlers = map[byte]orchestratorQUICHandler{
	quicwire.OrchestratorSubHealth:       orchestratorQUICCall("OrchestratorHealth", platformv1.OrchestratorServiceServer.Health),
	quicwire.OrchestratorSubListAgents:   orchestratorQUICCall("OrchestratorListAgents", platformv1.OrchestratorServiceServer.ListAgents),
	quicwire.OrchestratorSubGetAgent:     orchestratorQUICCall("OrchestratorGetAgent", platformv1.OrchestratorServiceServer.GetAgent),
	quicwire.OrchestratorSubDisableAgent: orchestratorQUICCall("OrchestratorDisableAgent", platformv1.OrchestratorServiceServer.DisableAgent),
	quicwire.OrchestratorSubEnableAgent:  orchestratorQUICCall("OrchestratorEnableAgent", platformv1.OrchestratorServiceServer.EnableAgent),
	quicwire.OrchestratorSubListSessions: orchestratorQUICCall("OrchestratorListSessions", platformv1.OrchestratorServiceServer.ListSessions),
	quicwire.OrchestratorSubCloseSession: orchestratorQUICCall("OrchestratorCloseSession", platformv1.OrchestratorServiceServer.CloseSession),
	quicwire.OrchestratorSubListJobs:     orchestratorQUICCall("OrchestratorListJobs", platformv1.OrchestratorServiceServer.ListJobs),
	quicwire.OrchestratorSubGetJob:       orchestratorQUICCall("OrchestratorGetJob", platformv1.OrchestratorServiceServer.GetJob),
	quicwire.OrchestratorSubCancelJob:    orchestratorQUICCall("OrchestratorCancelJob", platformv1.OrchestratorServiceServer.CancelJob),
}

// orchestratorQUICCall decodes the request, calls the OrchestratorService
// method shared with the other transports and maps its gRPC status to the
// QUIC wire status.
func orchestratorQUICCall[Req any, Resp any](op string, method func(platformv1.OrchestratorServiceServer, context.Context, *Req) (Resp, error)) orchestratorQUICHandler {
	return func(h *QUICServiceHandler, ctx context.Context, body []byte) *quicwire.Response {
		var request Req
		if err := quicwire.DecodePayload(body, &request); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}

		resp, err := method(h.orchestratorService, ctx, &request)
		if err != nil {
			return h.grpcDelegateErrorToQUIC(op, err)
		}
		return h.encodeGRPCDelegateResponse(resp)
	}
}

// SetOrchestratorService wires the OrchestratorService the category opcode
// delegates to; it is the same instance gRPC, REST, MCP and the Unix socket
// use.
func (h *QUICServiceHandler) SetOrchestratorService(service platformv1.OrchestratorServiceServer) {
	h.orchestratorService = service
}

// handleOrchestratorCategory dispatches quicwire.OpOrchestratorCategory on
// the sub-opcode in payload[0].
func (h *QUICServiceHandler) handleOrchestratorCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestratorService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: orchestratorServiceName})
	}
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	handler, ok := orchestratorQUICHandlers[req.Payload[0]]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
	}
	return handler(h, ctx, req.Payload[1:])
}
