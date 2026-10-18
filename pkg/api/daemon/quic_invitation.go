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
// QUIC invitation handlers
// =============================================================================
//
// The invitation sub-opcodes (0x10-0x16) share OpIAMCategory (0x51) with the
// IAM tenant records: the first payload byte is the InvitationSub*
// sub-opcode, the rest is the method's request message. Each sub-opcode calls
// the same InvitationService servicer gRPC uses, so the QUIC path has no
// logic of its own.

// invitationQUICHandlers maps each invitation sub-opcode to its
// InvitationService method.
var invitationQUICHandlers = map[byte]appQUICHandler{
	quicwire.InvitationSubCreate:     appQUICCall("InvitationCreate", quicInvitationServer, platformv1.InvitationServiceServer.CreateInvitation),
	quicwire.InvitationSubGet:        appQUICCall("InvitationGet", quicInvitationServer, platformv1.InvitationServiceServer.GetInvitation),
	quicwire.InvitationSubGetByToken: appQUICCall("InvitationGetByToken", quicInvitationServer, platformv1.InvitationServiceServer.GetInvitationByToken),
	quicwire.InvitationSubList:       appQUICCall("InvitationList", quicInvitationServer, platformv1.InvitationServiceServer.ListInvitations),
	quicwire.InvitationSubRevoke:     appQUICCall("InvitationRevoke", quicInvitationServer, platformv1.InvitationServiceServer.RevokeInvitation),
	quicwire.InvitationSubAccept:     appQUICCall("InvitationAccept", quicInvitationServer, platformv1.InvitationServiceServer.AcceptInvitation),
	quicwire.InvitationSubDelete:     appQUICCall("InvitationDelete", quicInvitationServer, platformv1.InvitationServiceServer.DeleteInvitation),
}

func quicInvitationServer(h *QUICServiceHandler) platformv1.InvitationServiceServer {
	return h.invitationServer
}

// SetInvitationServer wires the InvitationService servicer the invitation
// sub-opcodes delegate to. Pass the instance registered on the gRPC servers.
func (h *QUICServiceHandler) SetInvitationServer(server platformv1.InvitationServiceServer) {
	h.invitationServer = server
}

// handleInvitationCategorySub routes an invitation sub-opcode when payload[0]
// belongs to the invitation range. It reports handled=false for anything
// else so the caller can fall through to the IAM tenant-record dispatcher.
func (h *QUICServiceHandler) handleInvitationCategorySub(ctx context.Context, req *quicwire.Request) (*quicwire.Response, bool) {
	if len(req.Payload) == 0 {
		// Empty payload is rejected by the IAM dispatcher's sub_opcode guard.
		return nil, false
	}
	handler, ok := invitationQUICHandlers[req.Payload[0]]
	if !ok {
		return nil, false
	}
	if h.invitationServer == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrQUICServiceUnavailable{Service: "invitation"}), true
	}
	return handler(h, ctx, req.Payload[1:]), true
}
