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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Operational VM QUIC wire contract
// =============================================================================
//
// The operational VM verbs (GetVMMetrics, AttachDisk, DetachDisk, ResizeDisk,
// MigrateVM) share the same converged wire contract as the unary container
// verbs: the canonical QUIC payload is the platform.v1 ComputeService protobuf
// request/response message, and the daemon decodes the SAME pb message the SDK
// QUIC adapter sent and delegates to the shared *ComputeGRPCService — the same
// business path the gRPC transport uses. This keeps every transport at feature
// parity (see quic_container.go for the container analogue and the rationale
// behind decoding into the exact pb message rather than a flat local struct).
//
// These verbs collide with other top-level ranges (metrics/disk/migrate reuse
// the 0xCC-0xD0 bytes that are top-level category opcodes), so remote transports
// carry them as sub-opcodes in payload[0] under quic.OpVMExtendedCategory
// (0x69); see handleVMServiceOperation. The interactive AttachVMConsole /
// SendVMConsoleInput and the streaming GetVMLogs RPCs are server-streaming and
// are NOT carried over the unary QUIC transport — they remain gRPC/daemon-native
// (mirroring GetContainerLogs / AttachContainer).

// handleVMPB decodes the pb request for a converged unary operational VM
// opcode and delegates to the shared *ComputeGRPCService, returning
// handled=true. payload carries the marshalled pb request body (already
// stripped of the OpVMExtendedCategory sub-opcode prefix). Sub-opcodes that do
// not converge to pb return (nil, false) so the caller forwards them to the
// flat VMHandler.
func (h *QUICServiceHandler) handleVMPB(ctx context.Context, opcode byte, payload []byte) (*quic.Response, bool) {
	switch opcode {
	case quic.OpVMMetrics:
		if h.computeGRPC == nil {
			return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"}), true
		}
		var req platformv1.GetVMMetricsRequest
		if err := quic.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.GetVMMetrics(ctx, &req)
		if err != nil {
			return h.grpcStatusToQUICResponse("VMMetrics", err), true
		}
		return h.encodeQUICOK(resp), true

	case quic.OpVMAttachDisk:
		if h.computeGRPC == nil {
			return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"}), true
		}
		var req platformv1.AttachDiskRequest
		if err := quic.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.AttachDisk(ctx, &req)
		if err != nil {
			return h.grpcStatusToQUICResponse("VMAttachDisk", err), true
		}
		return h.encodeQUICOK(resp), true

	case quic.OpVMDetachDisk:
		if h.computeGRPC == nil {
			return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"}), true
		}
		var req platformv1.DetachDiskRequest
		if err := quic.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.DetachDisk(ctx, &req)
		if err != nil {
			return h.grpcStatusToQUICResponse("VMDetachDisk", err), true
		}
		return h.encodeQUICOK(resp), true

	case quic.OpVMResizeDisk:
		if h.computeGRPC == nil {
			return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"}), true
		}
		var req platformv1.ResizeDiskRequest
		if err := quic.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.ResizeDisk(ctx, &req)
		if err != nil {
			return h.grpcStatusToQUICResponse("VMResizeDisk", err), true
		}
		return h.encodeQUICOK(resp), true

	case quic.OpVMMigrate:
		if h.computeGRPC == nil {
			return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"}), true
		}
		var req platformv1.MigrateVMRequest
		if err := quic.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err}), true
		}
		resp, err := h.computeGRPC.MigrateVM(ctx, &req)
		if err != nil {
			return h.grpcStatusToQUICResponse("VMMigrate", err), true
		}
		return h.encodeQUICOK(resp), true

	default:
		return nil, false
	}
}
