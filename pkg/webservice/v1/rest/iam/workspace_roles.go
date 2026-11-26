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

	"github.com/google/uuid"
	qberrors "github.com/jeremyhahn/go-quicbaas/pkg/errors"
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
//
// Each stored role ID is named with GetRole (see roleNames); a transport
// that does not route GetRole is named from the tenant's role list instead.
//
// An account whose lifecycle is suspended, locked, disabled or deleting is
// refused with ErrWorkspaceAccountInactive before any role is named; an
// active, pending (invited) or unreported ("") lifecycle is admitted.
func (r *WorkspaceRoleResolver) Roles(ctx context.Context, tenantID, subject string) ([]string, error) {
	user, active, err := r.activeUser(ctx, tenantID, subject)
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
	if !active {
		return nil, ErrInactiveAccount{TenantID: tenantID, Subject: subject}
	}
	return r.roleNames(ctx, tenantID, user.Roles)
}

// roleNames maps the role references IAM stores on a user to the role
// names the session guards check. It looks each stored role ID (a UUID) up
// with GetRole, since the role listing answers only its first page, keeps a
// reference that is already a role name, and returns an error for an ID the
// tenant does not hold, never a guessed name. A user with no roles costs no
// lookup. A transport that does not route GetRole answers with an
// unknown-method error; the references are then named from the tenant's
// role list, with the same refusal of an ID the list does not hold.
func (r *WorkspaceRoleResolver) roleNames(ctx context.Context, tenantID string, refs []string) ([]string, error) {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		// Role IDs are UUIDs; any other reference is already a role name.
		if uuid.Validate(ref) != nil {
			out = append(out, ref)
			continue
		}
		role, err := r.client.GetRole(ctx, tenantID, ref)
		switch {
		case isRoleNotFound(err) || (err == nil && role == nil):
			return nil, fmt.Errorf("iam: tenant %q holds no role %q", tenantID, ref)
		case err != nil && isUnknownMethod(err):
			return r.namesFromRoleList(ctx, tenantID, refs)
		case err != nil:
			return nil, err
		}
		out = append(out, role.Name)
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

// namesFromRoleList names refs from the tenant's role list for a transport
// without GetRole. A reference that is not a UUID is already a role name; a
// role ID the list does not hold is refused, as roleNames refuses it.
func (r *WorkspaceRoleResolver) namesFromRoleList(ctx context.Context, tenantID string, refs []string) ([]string, error) {
	namesByID, err := r.roleNamesByID(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if uuid.Validate(ref) != nil {
			out = append(out, ref)
			continue
		}
		name, ok := namesByID[ref]
		if !ok {
			return nil, fmt.Errorf("iam: tenant %q holds no role %q", tenantID, ref)
		}
		out = append(out, name)
	}
	return out, nil
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
