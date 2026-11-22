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

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

// WorkspaceRoleResolver answers which roles a principal holds in a tenant
// by reading that tenant's go-quicbaas IAM user through the SDK. The login
// driver uses it to give a session landed in a workspace the workspace's
// roles, never the operating tenant's (#662).
//
// The principal is named by email, as the backbone names it and as the
// user mirror writes it. IAM stores a user's roles as role IDs (the SDK's
// CreateUserRequest.Roles carries IDs, see role_ids.go), while the session
// guards check role names such as "admin", so the resolver names them from
// the tenant's roles.
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
	if user == nil || len(user.Roles) == 0 {
		return nil, nil
	}
	namesByID, err := r.roleNamesByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(user.Roles))
	for _, ref := range user.Roles {
		if name, ok := namesByID[ref]; ok {
			ref = name
		}
		roles = append(roles, ref)
	}
	return roles, nil
}

// roleNamesByID reads every role tenantID holds, system roles included, and
// maps each role's ID to its name. It pages the way tenantRoleIDs does.
func (r *WorkspaceRoleResolver) roleNamesByID(ctx context.Context, tenantID string) (map[string]string, error) {
	namesByID := make(map[string]string)
	req := &iamsdk.ListRolesRequest{PageSize: rolesPageSize, IncludeSystem: true}
	for {
		resp, err := r.client.ListRoles(ctx, tenantID, req)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return namesByID, nil
		}
		for _, role := range resp.Roles {
			namesByID[role.ID] = role.Name
		}
		next := resp.Pagination.NextPageToken
		if !resp.Pagination.HasMore || next == "" || next == req.PageToken {
			return namesByID, nil
		}
		req.PageToken = next
	}
}
