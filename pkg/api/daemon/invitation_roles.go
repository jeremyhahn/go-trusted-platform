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

package daemon

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformservice "github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
)

// wireInvitationRoleLister gives the invitation service the tenant IAM role
// list its Create checks a role against (#1992). Without an IAM client the
// service keeps no lister and refuses every invitation, because no role can
// be checked.
func wireInvitationRoleLister(logger *logging.Logger, svc platformservice.InvitationServicer, client iam.Client) {
	settable, ok := svc.(interface {
		SetRoleLister(platformservice.InvitationRoleLister)
	})
	if !ok {
		return
	}
	if client == nil {
		if logger != nil {
			logger.Warn("IAM service disabled: invitation roles cannot be checked, invitations are refused")
		}
		return
	}
	settable.SetRoleLister(newInvitationRoleLister(client.Role()))
}

// invitationRolePageSize is the page size the role lister asks IAM for.
const invitationRolePageSize = 100

// invitationRoleMaxPageSize is the largest page size the role lister grows to
// when IAM returns a full page with no next-page token; a full page at this
// size may be truncated, so the lister fails closed.
const invitationRoleMaxPageSize = 10000

// roleListClient is the part of the QuicBaaS IAM role client the invitation
// role lister needs (iam.RoleClient satisfies it).
type roleListClient interface {
	List(ctx context.Context, tenantID string, req *iam.ListRolesRequest) (*iam.ListRolesResponse, error)
}

// invitationRoleLister names the roles in a tenant's IAM role list, the list
// an invitation's role is checked against (#1992). It satisfies
// platformservice.InvitationRoleLister.
type invitationRoleLister struct {
	roles roleListClient
}

func newInvitationRoleLister(roles roleListClient) *invitationRoleLister {
	return &invitationRoleLister{roles: roles}
}

// RoleNames returns the name of every role in the tenant's IAM role list,
// system roles included, reading every page. It stops on an empty response,
// or on an empty or repeated next-page token after a page shorter than the
// page size asked for. A full page with no usable token may hide more roles,
// so the listing restarts with the page size doubled, up to
// invitationRoleMaxPageSize; a full page at that size is an error, never a
// partial list.
func (l *invitationRoleLister) RoleNames(ctx context.Context, tenantID string) ([]string, error) {
	pageSize := invitationRolePageSize
	for {
		names, complete, err := l.listRoles(ctx, tenantID, pageSize)
		if err != nil {
			return nil, err
		}
		if complete {
			return names, nil
		}
		if pageSize >= invitationRoleMaxPageSize {
			return nil, fmt.Errorf("IAM role list for tenant %s may be truncated at %d roles", tenantID, len(names))
		}
		pageSize = min(pageSize*2, invitationRoleMaxPageSize)
	}
}

// listRoles reads the tenant's role list from the first page with the given
// page size, following next-page tokens. complete is false when the listing
// ended on a full page with an empty or repeated token and no TotalCount that
// matches: IAM may hold more roles than it returned (the embedded IAM path
// ignores page tokens and never sets one).
func (l *invitationRoleLister) listRoles(ctx context.Context, tenantID string, pageSize int) (names []string, complete bool, err error) {
	seen := map[string]bool{}
	token := ""
	for {
		seen[token] = true
		resp, err := l.roles.List(ctx, tenantID, &iam.ListRolesRequest{
			PageSize:      pageSize,
			PageToken:     token,
			IncludeSystem: true,
		})
		if err != nil {
			return nil, false, err
		}
		if resp == nil {
			return names, true, nil
		}
		for _, role := range resp.Roles {
			names = append(names, role.Name)
		}
		token = resp.Pagination.NextPageToken
		if token != "" && !seen[token] {
			continue
		}
		total := resp.Pagination.TotalCount
		if len(resp.Roles) < pageSize || (total > 0 && total == len(names)) {
			return names, true, nil
		}
		return names, false, nil
	}
}
