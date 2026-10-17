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
// Container QUIC wire contract
// =============================================================================
//
// The canonical QUIC wire contract for the container surface is the
// platform.v1 ComputeService protobuf request/response messages. The SDK
// QUIC transport adapter hands the generated pb request struct to the wire
// (the msgpack payload codec keys on exact Go field names), so the daemon
// MUST decode the payload into the SAME pb message the SDK sent and encode
// the pb response the SDK expects. Decoding into a flat local struct whose
// Go field names differ silently drops every field (e.g. the SDK sends
// CreateContainerRequest{Config:{Name,Image}} but a flat {Name,Image} decode
// leaves both empty because the config lives one level down under Config).
//
// The direct container opcodes collide with other top-level ranges (0xFC-0xFF
// are the PXE extended range, 0xEC/... overlap other reserved codes), so
// remote transports carry the unary container operations as sub-opcodes in
// payload[0] under the compute extended category opcode (quicwire.OpVMExtendedCategory,
// 0x69); see handleVMServiceOperation. The unary operations decode the pb
// message and delegate to the shared *ComputeGRPCService (the same business
// path the gRPC transport uses). Create/Start/Stop/Remove/Get/List, the
// operational Exec and Metrics verbs and Attest are all unary and converge
// here.
//
// AttachContainer and GetContainerLogs are server-streaming RPCs that the QUIC
// adapter does not carry (the QUIC request/response transport has no NewStream
// primitive for a fanned console/log stream); both remain daemon-native and
// are forwarded to the flat ContainerHandler exercised by the local CLI and the
// integration harness only.

// handleContainerOperation routes the direct container opcodes reachable at
// the top-level dispatcher (Get, List, Logs). The unary operations converge
// to pb and delegate; Logs is forwarded to the flat handler.
func (h *QUICServiceHandler) handleContainerOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if resp, handled := h.handleContainerPB(ctx, req.Opcode, req.Payload); handled {
		return resp
	}

	if h.containerHandler == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"})
	}
	return h.containerHandler.HandleRequest(ctx, req)
}

// handleContainerPB decodes the pb request for a converged unary container
// opcode and delegates to the shared *ComputeGRPCService, returning
// handled=true. For daemon-native opcodes (GetContainerLogs streaming,
// AttachContainer streaming) it returns (nil, false) so the caller forwards
// the request to the flat ContainerHandler. payload carries the
// marshalled pb request body (already stripped of any category sub-opcode
// prefix).
func (h *QUICServiceHandler) handleContainerPB(ctx context.Context, opcode byte, payload []byte) (*quicwire.Response, bool) {
	switch opcode {
	case quicwire.OpContainerCreate:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var createReq platformv1.CreateContainerRequest
		if err := quicwire.DecodePayload(payload, &createReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.CreateContainer(ctx, &createReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerCreate", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerStart:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var startReq platformv1.StartContainerRequest
		if err := quicwire.DecodePayload(payload, &startReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.StartContainer(ctx, &startReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerStart", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerStop:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var stopReq platformv1.StopContainerRequest
		if err := quicwire.DecodePayload(payload, &stopReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.StopContainer(ctx, &stopReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerStop", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerRemove:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var deleteReq platformv1.DeleteContainerRequest
		if err := quicwire.DecodePayload(payload, &deleteReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.DeleteContainer(ctx, &deleteReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerDelete", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerGet:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var getReq platformv1.GetContainerRequest
		if err := quicwire.DecodePayload(payload, &getReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.GetContainer(ctx, &getReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerGet", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerList:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var listReq platformv1.ListContainersRequest
		if len(payload) > 0 {
			if err := quicwire.DecodePayload(payload, &listReq); err != nil {
				return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
			}
		}
		resp, err := h.computeGRPC.ListContainers(ctx, &listReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerList", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerExec:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var execReq platformv1.ExecContainerRequest
		if err := quicwire.DecodePayload(payload, &execReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.ExecContainer(ctx, &execReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerExec", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerMetrics:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var metricsReq platformv1.GetContainerMetricsRequest
		if err := quicwire.DecodePayload(payload, &metricsReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.GetContainerMetrics(ctx, &metricsReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerMetrics", err), true
		}
		return h.encodeQUICOK(resp), true

	case quicwire.OpContainerAttest:
		if h.computeGRPC == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"}), true
		}
		var attestReq platformv1.AttestContainerRequest
		if err := quicwire.DecodePayload(payload, &attestReq); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.AttestContainer(ctx, &attestReq)
		if err != nil {
			return h.grpcStatusToQUICResponse("ContainerAttest", err), true
		}
		return h.encodeQUICOK(resp), true

	default:
		// GetContainerLogs and AttachContainer (server-streaming, not carried
		// over the unary QUIC transport) are daemon-native; the caller
		// forwards them to the flat ContainerHandler.
		return nil, false
	}
}

// =============================================================================
// Shared gRPC-delegate helpers (reused by the container, attestation, and DNS
// QUIC handlers that delegate to a shared *GRPCService).
// =============================================================================

// encodeQUICOK encodes v (a platform.v1 pb response or a daemon-native wire
// struct) as a StatusOK QUIC response.
func (h *QUICServiceHandler) encodeQUICOK(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// grpcStatusToQUICResponse converts a gRPC status error produced by a shared
// *GRPCService into a QUIC error response, preserving the gRPC transport's
// status-code semantics. It reuses the device code map and additionally maps
// Unimplemented (which the compute service returns for unsupported
// orchestrator features) onto StatusNotImplemented.
func (h *QUICServiceHandler) grpcStatusToQUICResponse(op string, err error) *quicwire.Response {
	quicStatus := quicwire.StatusInternalError
	if mapped, ok := deviceGRPCCodeToQUICStatus[status.Code(err)]; ok {
		quicStatus = mapped
	} else if status.Code(err) == codes.Unimplemented {
		quicStatus = quicwire.StatusNotImplemented
	}
	return h.errorResponse(quicStatus, ErrQUICOperationFailed{Op: op, Cause: err})
}
