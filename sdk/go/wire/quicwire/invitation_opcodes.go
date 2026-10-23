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

package quicwire

// Invitation sub-opcodes.
//
// The single-byte QUIC opcode space (0x00-0xFF) is fully allocated, so the
// InvitationService methods multiplex under the IAM category opcode
// OpIAMCategory (0x51): an invitation grants a user a role in a tenant. The
// first byte of the request payload selects the sub-operation and
// payload[1:] carries the MessagePack-encoded platform.v1 request.
//
// Sub-opcode ranges under 0x51:
//
//	0x01-0x05  IAM tenant records (iam_opcodes.go)
//	0x06-0x0F  reserved for IAM tenant-record growth
//	0x10-0x16  invitations (this file)
//
// The daemon dispatcher (pkg/api/daemon/quic_invitation.go) routes the
// invitation range before delegating the remainder to the IAM tenant-record
// handler, so the two sub-opcode families never collide.
const (
	// InvitationSubCreate creates an invitation to a tenant.
	InvitationSubCreate byte = 0x10
	// InvitationSubGet retrieves an invitation by ID.
	InvitationSubGet byte = 0x11
	// InvitationSubGetByToken retrieves an invitation by its token.
	InvitationSubGetByToken byte = 0x12
	// InvitationSubList lists a tenant's invitations.
	InvitationSubList byte = 0x13
	// InvitationSubRevoke revokes a pending invitation.
	InvitationSubRevoke byte = 0x14
	// InvitationSubAccept accepts an invitation by its token.
	InvitationSubAccept byte = 0x15
	// InvitationSubDelete permanently removes an invitation.
	InvitationSubDelete byte = 0x16
)
