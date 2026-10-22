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
)

// rolesPageSize is the page size ResolveRoleIDs reads the tenant's roles in.
const rolesPageSize = 100

// ResolveRoleIDs maps each role reference — a role name such as "admin", or a
// role ID — to the ID the tenant's role is stored under, in order.
//
// The platform's IAM surfaces name roles (`iam user create --roles admin`, the
// tenant-owner mirror), but the SDK's CreateUserRequest.Roles carries role IDs,
// and IAM refuses a name there with `iam.role: not_found`. A built-in role's ID
// cannot be derived from its name — a tenant seeded before go-qrdb moved off
// UUIDv5 keeps its legacy IDs — so the tenant's roles, built-in ones included,
// are read and matched: an ID first, then a name.
//
// No references returns nil without a read. An empty reference is
// ErrMissingRole, one the tenant does not hold is ErrRoleNotFound, and a failed
// read is ErrRoleListFailed.
func ResolveRoleIDs(ctx context.Context, roles iamsdk.RoleClient, tenantID string, refs []string) ([]string, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	if roles == nil {
		return nil, ErrRoleClientMissing{}
	}
	ids, idsByName, err := tenantRoleIDs(ctx, roles, tenantID)
	if err != nil {
		return nil, ErrRoleListFailed{TenantID: tenantID, Err: err}
	}

	resolved := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref == "" {
			return nil, ErrMissingRole{}
		}
		if _, ok := ids[ref]; ok {
			resolved = append(resolved, ref)
			continue
		}
		id, ok := idsByName[ref]
		if !ok {
			return nil, ErrRoleNotFound{TenantID: tenantID, RoleID: ref}
		}
		resolved = append(resolved, id)
	}
	return resolved, nil
}

// tenantRoleIDs reads every role of the tenant, system roles included, and
// returns the set of role IDs and the role ID of each role name.
func tenantRoleIDs(ctx context.Context, roles iamsdk.RoleClient, tenantID string) (map[string]struct{}, map[string]string, error) {
	ids := make(map[string]struct{})
	idsByName := make(map[string]string)
	req := &iamsdk.ListRolesRequest{PageSize: rolesPageSize, IncludeSystem: true}
	for {
		resp, err := roles.List(ctx, tenantID, req)
		if err != nil {
			return nil, nil, err
		}
		if resp == nil {
			return ids, idsByName, nil
		}
		for _, role := range resp.Roles {
			ids[role.ID] = struct{}{}
			idsByName[role.Name] = role.ID
		}
		next := resp.Pagination.NextPageToken
		if !resp.Pagination.HasMore || next == "" || next == req.PageToken {
			return ids, idsByName, nil
		}
		req.PageToken = next
	}
}
