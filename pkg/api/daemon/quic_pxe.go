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

// =============================================================================
// QUIC PXE handlers
// =============================================================================
//
// Eight PXEService methods have their own opcodes (0xEC-0xEF, 0xFC-0xFF) and
// carry the method's request message as the whole payload. The other seven
// are PXESub* sub-opcodes of OpProvisioningCategory (0xCF): the first payload
// byte selects the method, the rest is its request message. Every opcode
// calls the same PXEService servicer the gRPC, REST, MCP and embedded
// transports use, so the QUIC path has no logic of its own.

// pxeQUICHandlers maps each direct PXE opcode to its PXEService method.
var pxeQUICHandlers = map[byte]appQUICHandler{
	quicwire.OpPXEListDevices:    appQUICCall("PXEListDevices", quicPXEServer, platformv1.PXEServiceServer.ListDevices),
	quicwire.OpPXEGetDevice:      appQUICCall("PXEGetDevice", quicPXEServer, platformv1.PXEServiceServer.GetDevice),
	quicwire.OpPXERegisterDevice: appQUICCall("PXERegisterDevice", quicPXEServer, platformv1.PXEServiceServer.RegisterDevice),
	quicwire.OpPXEUpdateState:    appQUICCall("PXEUpdateState", quicPXEServer, platformv1.PXEServiceServer.UpdateState),
	quicwire.OpPXEAuthorize:      appQUICCall("PXEAuthorize", quicPXEServer, platformv1.PXEServiceServer.Authorize),
	quicwire.OpPXEQuarantine:     appQUICCall("PXEQuarantine", quicPXEServer, platformv1.PXEServiceServer.Quarantine),
	quicwire.OpPXERetry:          appQUICCall("PXERetry", quicPXEServer, platformv1.PXEServiceServer.Retry),
	quicwire.OpPXERemoveDevice:   appQUICCall("PXERemoveDevice", quicPXEServer, platformv1.PXEServiceServer.RemoveDevice),
}

// pxeQUICSubHandlers maps each PXE sub-opcode of OpProvisioningCategory to
// its PXEService method.
var pxeQUICSubHandlers = map[byte]appQUICHandler{
	quicwire.PXESubGetDeviceByMAC:        appQUICCall("PXEGetDeviceByMAC", quicPXEServer, platformv1.PXEServiceServer.GetDeviceByMAC),
	quicwire.PXESubSetDeviceEnrolled:     appQUICCall("PXESetDeviceEnrolled", quicPXEServer, platformv1.PXEServiceServer.SetDeviceEnrolled),
	quicwire.PXESubBindDeviceCertificate: appQUICCall("PXEBindDeviceCertificate", quicPXEServer, platformv1.PXEServiceServer.BindDeviceCertificate),
	quicwire.PXESubGetEvents:             appQUICCall("PXEGetEvents", quicPXEServer, platformv1.PXEServiceServer.GetEvents),
	quicwire.PXESubGetStatus:             appQUICCall("PXEGetStatus", quicPXEServer, platformv1.PXEServiceServer.GetStatus),
	quicwire.PXESubStartService:          appQUICCall("PXEStartService", quicPXEServer, platformv1.PXEServiceServer.StartService),
	quicwire.PXESubStopService:           appQUICCall("PXEStopService", quicPXEServer, platformv1.PXEServiceServer.StopService),
	quicwire.PXESubWebhookComplete:       appQUICCall("PXEWebhookComplete", quicPXEServer, platformv1.PXEServiceServer.WebhookComplete),
}

func quicPXEServer(h *QUICServiceHandler) platformv1.PXEServiceServer {
	return h.pxeServer
}

// SetPXEServer wires the PXEService servicer the PXE opcodes delegate to.
// Until it is set every PXE opcode answers unavailable.
func (h *QUICServiceHandler) SetPXEServer(server platformv1.PXEServiceServer) {
	h.pxeServer = server
}

// handlePXEOperation handles the direct PXE opcodes (0xEC-0xEF, 0xFC-0xFF).
func (h *QUICServiceHandler) handlePXEOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.pxeServer == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "pxe"})
	}

	handler, ok := pxeQUICHandlers[req.Opcode]
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
	return handler(h, ctx, req.Payload)
}

// handlePXECategorySub handles the PXE sub-opcodes of OpProvisioningCategory
// (0xCF). It reports false for any other sub-opcode so the category's
// remaining dispatchers can take it.
func (h *QUICServiceHandler) handlePXECategorySub(ctx context.Context, req *quicwire.Request) (*quicwire.Response, bool) {
	if len(req.Payload) == 0 {
		return nil, false
	}
	handler, ok := pxeQUICSubHandlers[req.Payload[0]]
	if !ok {
		return nil, false
	}
	if h.pxeServer == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "pxe"}), true
	}
	return handler(h, ctx, req.Payload[1:]), true
}
