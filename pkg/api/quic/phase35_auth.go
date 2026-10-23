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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Per-operation scopes for the ceremony, PIV and FIDO2 category opcodes. They
// are the operation catalog's entries (opcode_permissions.go), which
// GuardRequest already enforces for every request. The handlers enforce them
// a second time through AuthorizeSubOpcode, which also refuses a caller with
// no scoped AuthorizedContext: a bool-only token reaches none of these
// operations, as on gRPC.
//
// Ceremony init and status are scoped, not pre-auth: first boot has no token to
// present, so it runs over the Unix socket (not token-gated) or the pre-auth
// REST /init route, and an unauthenticated Init on a network listener would let
// a remote caller seize an uninitialized platform.

// CeremonySubOpcodePermissions maps each ceremony sub-opcode to its scope.
var CeremonySubOpcodePermissions = categoryPermissions[quicwire.OpCeremonyCategory]

// PIVSubOpcodePermissions maps each PIV sub-opcode to its scope.
var PIVSubOpcodePermissions = categoryPermissions[quicwire.OpPIVCategory]

// FIDO2SubOpcodePermissions maps each FIDO2 sub-opcode to its scope.
var FIDO2SubOpcodePermissions = categoryPermissions[quicwire.OpFIDO2Category]

// AuthorizeSubOpcode enforces the scope a category sub-operation requires
// against the AuthorizedContext that AuthenticateRequest stored in ctx. It
// returns nil when the operation is allowed, and a PermissionDenied response
// when the token lacks the scope.
//
// A request with no AuthorizedContext is refused: it carries no principal to
// hold a scope. AuthenticateRequest attaches one for a platform token (scp)
// and for an mTLS client certificate; a server without an auth middleware
// (SkipIAMValidation) or with only the legacy bool-only validator attaches
// none, so these operations are refused there. A sub-opcode absent from perms
// is left to the handler, which answers NotImplemented.
func AuthorizeSubOpcode(ctx context.Context, perms map[byte]OpcodePermission, sub byte) *quicwire.Response {
	perm, ok := perms[sub]
	if !ok {
		return nil
	}
	authCtx, ok := AuthorizedContextFromContext(ctx)
	if !ok {
		return &quicwire.Response{
			Status:  quicwire.StatusPermissionDenied,
			Payload: []byte(ErrPermissionDenied(perm).Error()),
		}
	}
	if err := authCtx.RequireScope(scopeForOperation(perm.Resource, perm.Action)); err != nil {
		return &quicwire.Response{
			Status:  quicwire.StatusPermissionDenied,
			Payload: []byte(ErrPermissionDenied(perm).Error()),
		}
	}
	return nil
}
