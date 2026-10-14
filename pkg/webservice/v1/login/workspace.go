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

package login

import "context"

// WorkspaceResolver names the workspace a backbone-authenticated principal
// belongs to: the user's own tenant, the one registration created or an
// invitation joined (#662).
//
// A browser login authenticates into that workspace, never into the
// operating tenant the ceremony ran in. The ceremony has to run in the
// operating tenant — that is where the relying party and the credential
// live — so the tenant the backbone reports is the wrong answer for the
// session, and the driver asks the resolver instead.
type WorkspaceResolver interface {
	// Workspace returns the workspace ID for the principal the backbone
	// names subject. It fails for a principal with no workspace; it never
	// answers with a fallback tenant.
	Workspace(ctx context.Context, subject string) (string, error)
}

// RoleResolver answers which roles a principal holds in one tenant. A
// session the driver lands in a workspace carries these roles and only
// these: the roles the backbone resolved belong to the operating tenant the
// ceremony ran in, and authorize nothing in the workspace (#662).
//
// The platform's implementation reads the go-quicbaas IAM tenant through
// the SDK (restiam.WorkspaceRoleResolver); the platform user store is never
// consulted.
type RoleResolver interface {
	// Roles returns the role names subject holds in tenantID. A principal
	// with no roles there answers an empty list, never an error.
	Roles(ctx context.Context, tenantID, subject string) ([]string, error)
}
