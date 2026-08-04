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
)

// handleVMOperation routes VM opcodes to the VM handler.
// This handles VM operations (0x60-0x6A range and extended codes).
//
// The compute extended category opcode (quic.OpVMExtendedCategory, 0x69)
// carries a sub-opcode in payload[0]. Container sub-opcodes (create, start,
// stop, remove, get, list, logs, attest — whose direct opcodes are shadowed
// by the PXE ranges at the top-level dispatcher) are handled first; every
// other sub-opcode falls through to the VM handler, which unwraps the
// extended VM sub-opcodes internally. This mirrors the provisioning category,
// where EAB sub-opcodes are routed ahead of the config delivery dispatcher.
//
// The six unary container sub-opcodes converge to the platform.v1
// ComputeService pb wire contract and delegate to the shared
// *ComputeGRPCService (see handleContainerPB); GetContainerLogs (streaming)
// and OpContainerAttest have no converged pb path and are forwarded to the
// flat ContainerHandler.
func (h *QUICServiceHandler) handleVMServiceOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if req.Opcode == quic.OpVMExtendedCategory && len(req.Payload) > 0 && quic.IsContainerSubOpcode(req.Payload[0]) {
		subOpcode := req.Payload[0]
		body := req.Payload[1:]

		if resp, handled := h.handleContainerPB(ctx, subOpcode, body); handled {
			return resp
		}

		if h.containerHandler == nil {
			return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "container"})
		}
		return h.containerHandler.HandleRequest(ctx, &quic.Request{
			Opcode:  subOpcode,
			Token:   req.Token,
			Payload: body,
		})
	}

	// Operational VM sub-opcodes (metrics, disk hotplug/unplug/resize, migrate)
	// converge on the platform.v1 pb wire contract and delegate to the shared
	// *ComputeGRPCService, mirroring the container sub-opcode path above.
	if req.Opcode == quic.OpVMExtendedCategory && len(req.Payload) > 0 && quic.IsVMSubOpcode(req.Payload[0]) {
		if resp, handled := h.handleVMPB(ctx, req.Payload[0], req.Payload[1:]); handled {
			return resp
		}
	}

	if h.vmHandler == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "vm"})
	}
	return h.vmHandler.HandleRequest(ctx, req)
}
