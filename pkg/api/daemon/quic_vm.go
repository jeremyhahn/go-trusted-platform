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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// handleVMServiceOperation routes the compute extended category
// (quicwire.OpVMExtendedCategory, 0x69), which carries a sub-opcode in
// payload[0]. Container sub-opcodes (create, start, stop, remove, get, list,
// logs, attest — whose direct opcodes are shadowed by the PXE ranges at the
// top-level dispatcher) are handled first; VM sub-opcodes go to handleVMPB.
// A sub-opcode neither answers is refused as unknown.
//
// The unary container sub-opcodes, attest included, converge to the
// platform.v1 ComputeService pb wire contract and delegate to the shared
// *ComputeGRPCService (see handleContainerPB); GetContainerLogs (streaming)
// has no converged pb path and is forwarded to the flat ContainerHandler.
func (h *QUICServiceHandler) handleVMServiceOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if len(req.Payload) == 0 {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICMissingField{Field: "sub_opcode"})
	}

	if quic.IsContainerSubOpcode(req.Payload[0]) {
		subOpcode := req.Payload[0]
		body := req.Payload[1:]

		if resp, handled := h.handleContainerPB(ctx, subOpcode, body); handled {
			return resp
		}

		if h.containerHandler == nil {
			return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"})
		}
		return h.containerHandler.HandleRequest(ctx, &quicwire.Request{
			Opcode:  subOpcode,
			Token:   req.Token,
			Payload: body,
		})
	}

	// The VM verbs and the operational VM sub-opcodes (metrics, disk
	// hotplug/unplug/resize, migrate) converge on the platform.v1 pb wire
	// contract and delegate to the shared *ComputeGRPCService, mirroring the
	// container sub-opcode path above.
	if resp, handled := h.handleVMPB(ctx, req.Payload[0], req.Payload[1:]); handled {
		return resp
	}
	return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Payload[0]})
}
