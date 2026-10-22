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
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// seedAdminRole gives the tenant the built-in admin role under an ID that is
// not its name, as go-qrdb stores it.
func seedAdminRole(t *testing.T, iam *memIAM, tenantID string) {
	t.Helper()
	_, err := iam.Role().Create(context.Background(), tenantID, &sdkiam.CreateRoleRequest{ID: "0b5e-admin", Name: "admin"})
	require.NoError(t, err)
}

func TestIAMGRPCService_CreateUserStoresRoleIDsForRoleNames(t *testing.T) {
	iam := newMemIAM()
	seedAdminRole(t, iam, "acme")
	svc := wiredIAMGRPCService(iam)
	ctx := context.Background()

	_, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
		TenantId: "acme", Email: "owner@acme.test", Roles: []string{"admin"},
	})
	require.NoError(t, err)

	stored, err := iam.User().Get(ctx, "acme", "owner@acme.test")
	require.NoError(t, err)
	assert.Equal(t, []string{"0b5e-admin"}, stored.Roles)
}

func TestIAMGRPCService_CreateUserWithUnknownRoleIsNotFound(t *testing.T) {
	iam := newMemIAM()
	seedAdminRole(t, iam, "acme")
	svc := wiredIAMGRPCService(iam)
	ctx := context.Background()

	_, err := svc.CreateUser(ctx, &platformv1.CreateIAMUserRequest{
		TenantId: "acme", Email: "owner@acme.test", Roles: []string{"owner"},
	})

	assert.Equal(t, codes.NotFound, status.Code(err))
	_, getErr := iam.User().Get(ctx, "acme", "owner@acme.test")
	assert.Error(t, getErr, "no user may be created with an unresolved role")
}

func TestIAMGRPCService_RoleResolveError(t *testing.T) {
	svc := wiredIAMGRPCService(newMemIAM())
	cases := map[string]struct {
		err  error
		want codes.Code
	}{
		"unknown role":   {restiam.ErrRoleNotFound{TenantID: "acme", RoleID: "owner"}, codes.NotFound},
		"empty role":     {restiam.ErrMissingRole{}, codes.InvalidArgument},
		"list failed":    {restiam.ErrRoleListFailed{TenantID: "acme", Err: status.Error(codes.Unavailable, "down")}, codes.Unavailable},
		"no role client": {restiam.ErrRoleClientMissing{}, codes.Internal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, status.Code(svc.roleResolveError(tc.err)))
		})
	}
}
