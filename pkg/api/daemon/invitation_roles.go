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
// an empty next-page token or a token it has already requested.
func (l *invitationRoleLister) RoleNames(ctx context.Context, tenantID string) ([]string, error) {
	var names []string
	seen := map[string]bool{}
	token := ""
	for {
		seen[token] = true
		resp, err := l.roles.List(ctx, tenantID, &iam.ListRolesRequest{
			PageSize:      invitationRolePageSize,
			PageToken:     token,
			IncludeSystem: true,
		})
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return names, nil
		}
		for _, role := range resp.Roles {
			names = append(names, role.Name)
		}
		token = resp.Pagination.NextPageToken
		if token == "" || seen[token] {
			return names, nil
		}
	}
}
