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

package quic

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// invitationSubOpcodes maps every InvitationService method to its sub-opcode
// under OpIAMCategory (0x51), which it shares with the IAM tenant records.
// The daemon dispatches each sub-opcode to the same servicer gRPC uses.
var invitationSubOpcodes = map[string]byte{
	platformv1.InvitationService_CreateInvitation_FullMethodName:     quicwire.InvitationSubCreate,
	platformv1.InvitationService_GetInvitation_FullMethodName:        quicwire.InvitationSubGet,
	platformv1.InvitationService_GetInvitationByToken_FullMethodName: quicwire.InvitationSubGetByToken,
	platformv1.InvitationService_ListInvitations_FullMethodName:      quicwire.InvitationSubList,
	platformv1.InvitationService_RevokeInvitation_FullMethodName:     quicwire.InvitationSubRevoke,
	platformv1.InvitationService_AcceptInvitation_FullMethodName:     quicwire.InvitationSubAccept,
	platformv1.InvitationService_DeleteInvitation_FullMethodName:     quicwire.InvitationSubDelete,
}

func init() {
	categoryOpcodes[quicwire.OpIAMCategory] = struct{}{}
	for method, sub := range invitationSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpIAMCategory
		categorySubOpcodeMap[method] = sub
	}
}
