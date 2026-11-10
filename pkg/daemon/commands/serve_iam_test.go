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

package commands

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
)

// wiringRoleClient lists a tenant's two built-in roles in one page.
type wiringRoleClient struct {
	iam.RoleClient
}

func (wiringRoleClient) List(_ context.Context, _ string, _ *iam.ListRolesRequest) (*iam.ListRolesResponse, error) {
	return &iam.ListRolesResponse{Roles: []iam.Role{
		{ID: "0b5e-admin", Name: "admin", IsSystem: true},
		{ID: "0b5e-operator", Name: "operator", IsSystem: true},
	}}, nil
}

// wiringUserClient holds one user with the admin role and records the role
// assignments and revocations sent to it.
type wiringUserClient struct {
	iam.UserClient
	assigned []string
	revoked  []string
}

func (c *wiringUserClient) Get(_ context.Context, tenantID, userID string) (*iam.User, error) {
	return &iam.User{ID: userID, TenantID: tenantID, Roles: []string{"0b5e-admin"}}, nil
}

func (c *wiringUserClient) AssignRole(_ context.Context, _, _, roleID string) error {
	c.assigned = append(c.assigned, roleID)
	return nil
}

func (c *wiringUserClient) RevokeRole(_ context.Context, _, _, roleID string) error {
	c.revoked = append(c.revoked, roleID)
	return nil
}

// wiringSDKClient is an SDK IAM client with only the user and role clients.
type wiringSDKClient struct {
	iam.Client
	users *wiringUserClient
}

func (c *wiringSDKClient) User() iam.UserClient { return c.users }
func (c *wiringSDKClient) Role() iam.RoleClient { return wiringRoleClient{} }

// On a gRPC or Unix QuicBaaS backend the web service's IAM client changes a
// user's roles: the backend supports it.
func TestWebserviceIAMClient_RemoteBackendSetsChangedRoles(t *testing.T) {
	for name, cfg := range map[string]*platformquicbaas.Config{
		"grpc": {Transport: platformquicbaas.TransportGRPC},
		"unix": {Transport: platformquicbaas.TransportUnix},
	} {
		t.Run(name, func(t *testing.T) {
			client := &wiringSDKClient{users: &wiringUserClient{}}

			err := webserviceIAMClient(client, cfg).SetUserRoles(context.Background(), "tenant-a", "user-1", []string{"operator"})

			require.NoError(t, err)
			assert.Equal(t, []string{"0b5e-operator"}, client.users.assigned)
			assert.Equal(t, []string{"0b5e-admin"}, client.users.revoked)
		})
	}
}

// On the embedded backend, which is also what a missing QuicBaaS
// configuration means, a role change is refused and nothing is sent.
func TestWebserviceIAMClient_EmbeddedBackendRefusesARoleChange(t *testing.T) {
	for name, cfg := range map[string]*platformquicbaas.Config{
		"no configuration": nil,
		"zero value":       {},
	} {
		t.Run(name, func(t *testing.T) {
			client := &wiringSDKClient{users: &wiringUserClient{}}

			err := webserviceIAMClient(client, cfg).SetUserRoles(context.Background(), "tenant-a", "user-1", []string{"operator"})

			require.ErrorIs(t, err, restiam.ErrRoleChangeUnsupported{})
			assert.Empty(t, client.users.assigned)
			assert.Empty(t, client.users.revoked)
		})
	}
}
