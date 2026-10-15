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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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
// carry them as sub-opcodes in payload[0] under quicwire.OpVMExtendedCategory
// (0x69); see handleVMServiceOperation. The interactive AttachVMConsole /
// SendVMConsoleInput and the streaming GetVMLogs RPCs are server-streaming and
// are NOT carried over the unary QUIC transport — they remain gRPC/daemon-native
// (mirroring GetContainerLogs / AttachContainer).
//
// The CRUD and lifecycle verbs CreateVM, GetVM, ListVMs, StartVM, StopVM,
// DeleteVM (OpVMCreate..OpVMList, 0x60-0x65), RebootVM, SuspendVM and
// ResumeVM (OpVMRestart, OpVMSuspend, OpVMResume, 0xB6-0xB8), the snapshot
// verbs CreateSnapshot, RestoreSnapshot, DeleteSnapshot and ListSnapshots
// (OpVMSnapshotCreate..OpVMSnapshotList, 0xBB-0xBE), and AttestVM and
// VerifyVMAttestation (OpVMAttest 0xB9, OpVMVerifyAttest 0xBF) converge the
// same way, as sub-opcodes under OpVMExtendedCategory. Their errors take the
// shared errclass QUIC status, so a missing VM answers StatusNotFound and a
// VM in the wrong state answers StatusFailedPrecondition exactly as gRPC
// answers NotFound and FailedPrecondition.

// vmPBHandler answers one converged OpVMExtendedCategory sub-opcode.
// payload carries the marshalled pb request body.
type vmPBHandler func(h *QUICServiceHandler, ctx context.Context, payload []byte) *quicwire.Response

// vmPBFailure turns a ComputeGRPCService error into a QUIC error response.
type vmPBFailure func(h *QUICServiceHandler, op string, err error) *quicwire.Response

// vmPBHandlers maps each converged VM sub-opcode to its handler.
var vmPBHandlers = map[byte]vmPBHandler{
	quicwire.OpVMCreate:          vmPBUnary("VMCreate", (*ComputeGRPCService).CreateVM, vmPBClassFailure),
	quicwire.OpVMGet:             vmPBUnary("VMGet", (*ComputeGRPCService).GetVM, vmPBClassFailure),
	quicwire.OpVMList:            vmPBUnary("VMList", (*ComputeGRPCService).ListVMs, vmPBClassFailure),
	quicwire.OpVMStart:           vmPBUnary("VMStart", (*ComputeGRPCService).StartVM, vmPBClassFailure),
	quicwire.OpVMStop:            vmPBUnary("VMStop", (*ComputeGRPCService).StopVM, vmPBClassFailure),
	quicwire.OpVMDelete:          vmPBUnary("VMDelete", (*ComputeGRPCService).DeleteVM, vmPBClassFailure),
	quicwire.OpVMRestart:         vmPBUnary("VMRestart", (*ComputeGRPCService).RebootVM, vmPBClassFailure),
	quicwire.OpVMSuspend:         vmPBUnary("VMSuspend", (*ComputeGRPCService).SuspendVM, vmPBClassFailure),
	quicwire.OpVMResume:          vmPBUnary("VMResume", (*ComputeGRPCService).ResumeVM, vmPBClassFailure),
	quicwire.OpVMSnapshotCreate:  vmPBUnary("VMSnapshotCreate", (*ComputeGRPCService).CreateSnapshot, vmPBClassFailure),
	quicwire.OpVMSnapshotRestore: vmPBUnary("VMSnapshotRestore", (*ComputeGRPCService).RestoreSnapshot, vmPBClassFailure),
	quicwire.OpVMSnapshotDelete:  vmPBUnary("VMSnapshotDelete", (*ComputeGRPCService).DeleteSnapshot, vmPBClassFailure),
	quicwire.OpVMSnapshotList:    vmPBUnary("VMSnapshotList", (*ComputeGRPCService).ListSnapshots, vmPBClassFailure),
	quicwire.OpVMAttest:          vmPBUnary("VMAttest", (*ComputeGRPCService).AttestVM, vmPBClassFailure),
	quicwire.OpVMVerifyAttest:    vmPBUnary("VMVerifyAttest", (*ComputeGRPCService).VerifyVMAttestation, vmPBClassFailure),
	quicwire.OpVMMetrics:         vmPBUnary("VMMetrics", (*ComputeGRPCService).GetVMMetrics, (*QUICServiceHandler).grpcStatusToQUICResponse),
	quicwire.OpVMAttachDisk:      vmPBUnary("VMAttachDisk", (*ComputeGRPCService).AttachDisk, (*QUICServiceHandler).grpcStatusToQUICResponse),
	quicwire.OpVMDetachDisk:      vmPBUnary("VMDetachDisk", (*ComputeGRPCService).DetachDisk, (*QUICServiceHandler).grpcStatusToQUICResponse),
	quicwire.OpVMResizeDisk:      vmPBUnary("VMResizeDisk", (*ComputeGRPCService).ResizeDisk, (*QUICServiceHandler).grpcStatusToQUICResponse),
	quicwire.OpVMMigrate:         vmPBUnary("VMMigrate", (*ComputeGRPCService).MigrateVM, (*QUICServiceHandler).grpcStatusToQUICResponse),
}

// vmPBUnary builds the handler for one unary ComputeService VM method: it
// decodes the pb request into Req, calls the method on the shared
// *ComputeGRPCService and encodes the pb response.
func vmPBUnary[Req, Resp any](op string, call func(*ComputeGRPCService, context.Context, *Req) (Resp, error), fail vmPBFailure) vmPBHandler {
	return func(h *QUICServiceHandler, ctx context.Context, payload []byte) *quicwire.Response {
		var req Req
		if err := quicwire.DecodePayload(payload, &req); err != nil {
			return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
		resp, err := call(h.computeGRPC, ctx, &req)
		if err != nil {
			return fail(h, op, err)
		}
		return h.encodeQUICOK(resp)
	}
}

// vmPBClassFailure answers err with its shared errclass QUIC status.
func vmPBClassFailure(h *QUICServiceHandler, op string, err error) *quicwire.Response {
	return h.errorResponse(errclass.QUICStatus(err), ErrQUICOperationFailed{Op: op, Cause: err})
}

// handleVMPB decodes the pb request for a converged VM sub-opcode and
// delegates to the shared *ComputeGRPCService, returning handled=true.
// payload carries the marshalled pb request body (already stripped of the
// OpVMExtendedCategory sub-opcode prefix). Sub-opcodes that are not VM verbs
// return (nil, false).
func (h *QUICServiceHandler) handleVMPB(ctx context.Context, opcode byte, payload []byte) (*quicwire.Response, bool) {
	handler, ok := vmPBHandlers[opcode]
	if !ok {
		return nil, false
	}
	if h.computeGRPC == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"}), true
	}
	return handler(h, ctx, payload), true
}
