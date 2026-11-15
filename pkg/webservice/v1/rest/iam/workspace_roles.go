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
	"fmt"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/auth/iamuser"
)

// WorkspaceRoleResolver answers which roles a principal holds in a tenant
// by reading that tenant's go-quicbaas IAM user through the SDK. The login
// driver uses it to give a session landed in a workspace the workspace's
// roles, never the operating tenant's (#662).
//
// The principal is named by email, as the backbone names it and as the
// user mirror writes it. IAM stores the user's roles as canonical role IDs
// (built-in roles carry tenant-specific UUIDs), while the session guards
// check role names ("admin" for a workspace owner), so the resolver maps
// every stored reference to its role name through the tenant's role listing
// and refuses one the listing does not hold.
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
// the startup reconcile and must still be able to sign in as a member. A
// principal the tenant holds but not as an active account is refused with
// ErrInactiveAccount, as Principal refuses it at refresh (#646). Any other
// failure is returned, so the caller refuses rather than guesses.
func (r *WorkspaceRoleResolver) Roles(ctx context.Context, tenantID, subject string) ([]string, error) {
	user, active, err := r.activeUser(ctx, tenantID, subject)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, nil
	}
	if !active {
		return nil, ErrInactiveAccount{TenantID: tenantID, Subject: subject}
	}
	return r.roleNames(ctx, tenantID, user.Roles)
}

// roleNames maps the role references IAM stores on a user to the role
// names the session guards check. It pages the tenant's role listing, system
// roles included, maps every role ID to its name, keeps a reference that is
// already a role name, and returns an error for one the listing does not
// hold, never a guessed name. A user with no roles costs no listing.
func (r *WorkspaceRoleResolver) roleNames(ctx context.Context, tenantID string, refs []string) ([]string, error) {
	if len(refs) == 0 {
		return []string{}, nil
	}
	nameByID := make(map[string]string)
	names := make(map[string]struct{})
	req := &iamsdk.ListRolesRequest{PageSize: rolesPageSize, IncludeSystem: true}
	for {
		resp, err := r.client.ListRoles(ctx, tenantID, req)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			break
		}
		for _, role := range resp.Roles {
			nameByID[role.ID] = role.Name
			names[role.Name] = struct{}{}
		}
		next := resp.Pagination.NextPageToken
		if !resp.Pagination.HasMore || next == "" || next == req.PageToken {
			break
		}
		req.PageToken = next
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if name, ok := nameByID[ref]; ok {
			out = append(out, name)
			continue
		}
		if _, ok := names[ref]; ok {
			out = append(out, ref)
			continue
		}
		return nil, fmt.Errorf("iam: tenant %q holds no role %q", tenantID, ref)
	}
	return out, nil
}

// Principal returns the roles subject holds in tenantID's IAM tenant, and
// whether that tenant holds subject as an active account. Unlike Roles it
// tells a user IAM no longer admits from one with no roles, so a session
// refresh fails closed on the first (#646): a user IAM no longer holds, or
// holds as suspended, locked, disabled, pending or being deleted, is not
// found.
func (r *WorkspaceRoleResolver) Principal(ctx context.Context, tenantID, subject string) ([]string, bool, error) {
	user, active, err := r.activeUser(ctx, tenantID, subject)
	if err != nil {
		return nil, false, err
	}
	if !active {
		return nil, false, nil
	}
	roles, err := r.roleNames(ctx, tenantID, user.Roles)
	if err != nil {
		return nil, false, err
	}
	return roles, true, nil
}

// activeUser reads subject's user in tenantID and whether IAM holds it as
// an active account (iamuser.Active). It is the one lifecycle check Roles
// and Principal share, so login and refresh cannot disagree on who is
// admitted. A user the tenant does not hold is a nil user, not an error;
// any other lookup failure is returned.
func (r *WorkspaceRoleResolver) activeUser(ctx context.Context, tenantID, subject string) (*iamsdk.User, bool, error) {
	user, err := r.userByEmail(ctx, tenantID, subject)
	if sdkerrors.IsNotFound(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if user == nil {
		return nil, false, nil
	}
	return user, iamuser.Active(user), nil
}

// ErrInactiveAccount is Roles' refusal of a principal the workspace holds
// as suspended, locked, disabled, pending or being deleted. The login
// driver wraps it and aborts the login, so such an account gets no
// workspace session even when its operating-tenant credential is valid.
type ErrInactiveAccount struct {
	TenantID string
	Subject  string
}

func (e ErrInactiveAccount) Error() string {
	return "iam: account " + e.Subject + " is not active in tenant " + e.TenantID
}

// userByEmail reads the tenant's user named by email. The pinned SDK's
// embedded transport has no User/GetByEmail, so on it the lookup falls back
// to the tenant's user listing (see iamuser.Find).
func (r *WorkspaceRoleResolver) userByEmail(ctx context.Context, tenantID, email string) (*iamsdk.User, error) {
	return iamuser.Find(ctx,
		func(ctx context.Context) (*iamsdk.User, error) {
			return r.client.GetUserByEmail(ctx, tenantID, email)
		},
		func(ctx context.Context, req *iamsdk.ListUsersRequest) (*iamsdk.ListUsersResponse, error) {
			return r.client.ListUsers(ctx, tenantID, req)
		},
		iamuser.ByEmail(email))
}
