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

package iam

import (
	"context"

	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

// WorkspaceRoleResolver answers which roles a principal holds in a tenant
// by reading that tenant's go-quicbaas IAM user through the SDK. The login
// driver uses it to give a session landed in a workspace the workspace's
// roles, never the operating tenant's (#662).
//
// The principal is named by email, as the backbone names it and as the
// user mirror writes it. The roles are the names the mirror and the IAM
// role assignments store on the user ("admin" for a workspace owner), which
// are the names the session guards check.
type WorkspaceRoleResolver struct {
	client IAMClient
}

// NewWorkspaceRoleResolver returns a resolver over the IAM client the IAM
// router and the user mirror use, so all three read the same tenant store.
func NewWorkspaceRoleResolver(client IAMClient) (*WorkspaceRoleResolver, error) {
	if client == nil {
		return nil, ErrRoleResolverClientMissing{}
	}
	return &WorkspaceRoleResolver{client: client}, nil
}

// Roles returns the role names subject holds in tenantID.
//
// A principal the IAM tenant does not hold has no roles there: that is an
// empty answer, not an error, because an invited member is mirrored only by
// the startup reconcile and must still be able to sign in as a member. Any
// other failure is returned, so the caller refuses rather than guesses.
func (r *WorkspaceRoleResolver) Roles(ctx context.Context, tenantID, subject string) ([]string, error) {
	user, err := r.client.GetUserByEmail(ctx, tenantID, subject)
	if sdkerrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	return append([]string(nil), user.Roles...), nil
}

// Principal returns the roles subject holds in tenantID's IAM tenant, and
// whether that tenant holds subject at all. Unlike Roles it tells a user
// IAM no longer holds from one with no roles, so a session refresh can fail
// closed on the first (#646).
func (r *WorkspaceRoleResolver) Principal(ctx context.Context, tenantID, subject string) ([]string, bool, error) {
	user, err := r.client.GetUserByEmail(ctx, tenantID, subject)
	if sdkerrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if user == nil {
		return nil, false, nil
	}
	return append([]string(nil), user.Roles...), true, nil
}
