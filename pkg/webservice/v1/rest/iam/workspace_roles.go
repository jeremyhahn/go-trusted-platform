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

	qberrors "github.com/jeremyhahn/go-quicbaas/pkg/errors"
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
//
// Each of the user's role references is named, in order, with GetRole:
// a role GetRole finds gives its name, and a reference it does not find is
// kept unchanged (a role stored by name, or one since deleted). The embedded
// transport routes GetRole and answers a missing role with the server's own
// not-found error, which is kept like any other not-found. A transport that
// does not route GetRole answers the first call with an unknown-method error;
// the references are then named from the tenant's role list instead. Any
// other GetRole failure is returned.
//
// An account whose lifecycle is suspended, locked, disabled or deleting is
// refused with ErrWorkspaceAccountInactive before any role is named; an
// active, pending (invited) or unreported ("") lifecycle is admitted.
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
	if isInactiveLifecycle(user.Lifecycle) {
		return nil, ErrWorkspaceAccountInactive{TenantID: tenantID, Subject: subject, Lifecycle: user.Lifecycle}
	}
	if len(user.Roles) == 0 {
		return nil, nil
	}
	roles := make([]string, 0, len(user.Roles))
	for i, ref := range user.Roles {
		role, err := r.client.GetRole(ctx, tenantID, ref)
		switch {
		case err == nil:
			if role != nil && role.Name != "" {
				ref = role.Name
			}
		case isRoleNotFound(err):
		case i == 0 && isUnknownMethod(err):
			return r.namesFromRoleList(ctx, tenantID, user.Roles)
		default:
			return nil, err
		}
		roles = append(roles, ref)
	}
	return roles, nil
}

// isRoleNotFound reports whether a GetRole error means the role does not
// exist. The SDK transports answer a missing role with the SDK not-found
// error; the embedded transport passes the server's iam.ErrRoleNotFound (a
// go-quicbaas pkg/errors QBError with code ErrNotFound) through unchanged.
func isRoleNotFound(err error) bool {
	return sdkerrors.IsNotFound(err) || qberrors.IsNotFound(err)
}

// isInactiveLifecycle reports whether an IAM user lifecycle refuses the
// account its workspace roles.
func isInactiveLifecycle(lifecycle string) bool {
	switch lifecycle {
	case "suspended", "locked", "disabled", "deleting":
		return true
	}
	return false
}

// namesFromRoleList names refs from the tenant's role list, keeping a
// reference no role ID matches; it serves a transport without GetRole.
func (r *WorkspaceRoleResolver) namesFromRoleList(ctx context.Context, tenantID string, refs []string) ([]string, error) {
	namesByID, err := r.roleNamesByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	roles := make([]string, 0, len(refs))
	for _, ref := range refs {
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
