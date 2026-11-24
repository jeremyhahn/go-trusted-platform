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
	"errors"
	"strings"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/transport/embedded"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
// The user is read with GetUserByEmail. Only when the transport does not
// dispatch that method (the embedded transport answers an
// *embedded.UnknownMethodError, gRPC answers Unimplemented) is the user
// found by paging ListUsers and matching the email without regard to case,
// as MirroredEmails does (#2150).
//
// The roles stored on a go-quicbaas user are role IDs (CreateUser resolves
// names to IDs); the session guards check names. Every stored value that is
// the ID of one of the tenant's roles is replaced by that role's name; a
// value that is not a known ID is kept as it is. A role listing failure is
// returned as ErrRoleListFailed.
//
// A principal the IAM tenant does not hold has no roles there: that is an
// empty answer, not an error, because an invited member is mirrored only by
// the startup reconcile and must still be able to sign in as a member. Any
// lookup failure is returned, so the caller refuses rather than guesses.
// When the user is not in a listing that may be truncated (a page held
// mirroredEmailsPageSize users without a next page, or the reported total
// exceeds the users seen), Roles returns ErrWorkspaceUserListingIncomplete
// rather than "no roles". The embedded transport of the pinned go-quicbaas
// SDK drops ListUsers paging and always returns the first page, so a
// complete embedded lookup beyond the first 100 users needs the go-quicbaas
// upstream fix.
func (r *WorkspaceRoleResolver) Roles(ctx context.Context, tenantID, subject string) ([]string, error) {
	user, err := r.client.GetUserByEmail(ctx, tenantID, subject)
	switch {
	case err == nil && user == nil:
		return nil, nil
	case err == nil:
	case isNotFound(err):
		return nil, nil
	case isUndispatched(err):
		user, err = r.findUserByListing(ctx, tenantID, subject)
		if err != nil || user == nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return r.roleNames(ctx, tenantID, user.Roles)
}

// findUserByListing pages ListUsers for the user whose email is subject. It
// returns nil, nil when the complete listing holds no such user and
// ErrWorkspaceUserListingIncomplete when the listing may be truncated.
func (r *WorkspaceRoleResolver) findUserByListing(ctx context.Context, tenantID, subject string) (*iamsdk.User, error) {
	req := &iamsdk.ListUsersRequest{PageSize: mirroredEmailsPageSize}
	listed := 0
	truncated := false
	for {
		resp, err := r.client.ListUsers(ctx, tenantID, req)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			break
		}
		for i := range resp.Users {
			if strings.EqualFold(resp.Users[i].Email, subject) {
				user := resp.Users[i]
				return &user, nil
			}
		}
		listed += len(resp.Users)
		truncated = int(resp.Pagination.TotalCount) > listed
		next := resp.Pagination.NextPageToken
		if !resp.Pagination.HasMore || next == "" || next == req.PageToken {
			if len(resp.Users) >= int(mirroredEmailsPageSize) {
				truncated = true
			}
			break
		}
		req.PageToken = next
	}
	if truncated {
		return nil, ErrWorkspaceUserListingIncomplete{TenantID: tenantID, Listed: listed}
	}
	return nil, nil
}

// roleNames maps each stored role value that is the ID of one of the
// tenant's roles to the role's name and keeps any other value as it is.
func (r *WorkspaceRoleResolver) roleNames(ctx context.Context, tenantID string, stored []string) ([]string, error) {
	if len(stored) == 0 {
		return nil, nil
	}
	namesByID := make(map[string]string)
	req := &iamsdk.ListRolesRequest{PageSize: rolesPageSize, IncludeSystem: true}
	for {
		resp, err := r.client.ListRoles(ctx, tenantID, req)
		if err != nil {
			return nil, ErrRoleListFailed{TenantID: tenantID, Err: err}
		}
		if resp == nil {
			break
		}
		for _, role := range resp.Roles {
			if role.ID != "" && role.Name != "" {
				namesByID[role.ID] = role.Name
			}
		}
		next := resp.Pagination.NextPageToken
		if !resp.Pagination.HasMore || next == "" || next == req.PageToken {
			break
		}
		req.PageToken = next
	}
	names := make([]string, 0, len(stored))
	for _, value := range stored {
		if name, ok := namesByID[value]; ok {
			names = append(names, name)
			continue
		}
		names = append(names, value)
	}
	return names, nil
}

// isNotFound reports whether err says the user does not exist.
func isNotFound(err error) bool {
	return sdkerrors.Code(err) == sdkerrors.CodeNotFound || status.Code(err) == codes.NotFound
}

// isUndispatched reports whether err says the transport does not serve the
// method: the embedded transport's UnknownMethodError or Unimplemented.
func isUndispatched(err error) bool {
	var unknown *embedded.UnknownMethodError
	if errors.As(err, &unknown) {
		return true
	}
	return sdkerrors.Code(err) == sdkerrors.CodeUnimplemented || status.Code(err) == codes.Unimplemented
}
