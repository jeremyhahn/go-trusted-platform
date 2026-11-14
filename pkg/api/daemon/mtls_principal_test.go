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
	"errors"
	"testing"

	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #1107: a verified client certificate acts as its IAM principal, with that
// principal's permissions, not with *:*.

// stubCertificatePrincipals is a CertificatePrincipalResolver that answers
// with a fixed principal or error and records the identity it was asked for.
type stubCertificatePrincipals struct {
	principal *CertificatePrincipal
	err       error
	asked     []*auth.Identity
	// echo resolves the certificate's own identity and tenant as the
	// principal, granting principal.Scopes and principal.Roles.
	echo bool
}

func (s *stubCertificatePrincipals) ResolveCertificatePrincipal(_ context.Context, identity *auth.Identity) (*CertificatePrincipal, error) {
	s.asked = append(s.asked, identity)
	if s.err != nil {
		return nil, s.err
	}
	if s.echo {
		return &CertificatePrincipal{Subject: identity.ID, TenantID: identity.TenantID,
			Roles: s.principal.Roles, Scopes: s.principal.Scopes}, nil
	}
	return s.principal, nil
}

// operatorPrincipals resolves every certificate to itself as an operator
// principal whose role carries the full wildcard, as an IAM admin role does.
func operatorPrincipals() *stubCertificatePrincipals {
	return &stubCertificatePrincipals{echo: true, principal: &CertificatePrincipal{
		Roles: []string{"admin"}, Scopes: []string{"*:*"},
	}}
}

// certPrincipalUsers is the IAM user client the resolver reads.
type certPrincipalUsers struct {
	sdkiam.UserClient
	users        map[string]*sdkiam.User // tenant + "/" + username or id
	err          error
	byUsername   int
	byID         int
	lastTenantID string
}

func (u *certPrincipalUsers) FindByUsername(_ context.Context, tenantID, username string) (*sdkiam.User, error) {
	u.byUsername++
	u.lastTenantID = tenantID
	if u.err != nil {
		return nil, u.err
	}
	if user, ok := u.users[tenantID+"/"+username]; ok {
		return user, nil
	}
	return nil, errors.New("iam.user: not_found")
}

func (u *certPrincipalUsers) Get(_ context.Context, tenantID, userID string) (*sdkiam.User, error) {
	u.byID++
	u.lastTenantID = tenantID
	if user, ok := u.users[tenantID+"/"+userID]; ok {
		return user, nil
	}
	return nil, errors.New("iam.user: not_found")
}

// certPrincipalRoles is the IAM role client the resolver reads.
type certPrincipalRoles struct {
	sdkiam.RoleClient
	roles map[string]*sdkiam.Role
	err   error
}

func (r *certPrincipalRoles) Get(_ context.Context, _ string, roleID string) (*sdkiam.Role, error) {
	if r.err != nil {
		return nil, r.err
	}
	if role, ok := r.roles[roleID]; ok {
		return role, nil
	}
	return nil, errors.New("iam.role: not_found")
}

func newCertPrincipalDirectory() (*certPrincipalUsers, *certPrincipalRoles) {
	users := &certPrincipalUsers{users: map[string]*sdkiam.User{
		"tenant-a/device-01": {ID: "u-device", TenantID: "tenant-a", Username: "device-01",
			Lifecycle: "active", Roles: []string{"device", "reader"}},
		"tenant-a/u-device": {ID: "u-device", TenantID: "tenant-a", Username: "device-01",
			Lifecycle: "active", Roles: []string{"device"}},
		"tenant-a/suspended": {ID: "u-suspended", TenantID: "tenant-a", Username: "suspended",
			Lifecycle: "suspended", Roles: []string{"device"}},
	}}
	roles := &certPrincipalRoles{roles: map[string]*sdkiam.Role{
		"device": {ID: "device", Permissions: []string{"device:read", "attestation:submit"}},
		"reader": {ID: "reader", Permissions: []string{"device:read", "tenant:read"}},
	}}
	return users, roles
}

func newTestIAMCertificatePrincipals(t *testing.T, users *certPrincipalUsers, roles *certPrincipalRoles) *iamCertificatePrincipals {
	t.Helper()
	resolver, err := newIAMCertificatePrincipals(users, roles)
	require.NoError(t, err)
	return resolver
}

func TestIAMCertificatePrincipals_GrantsThePrincipalsRolePermissions(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	resolver := newTestIAMCertificatePrincipals(t, users, roles)

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})

	require.NoError(t, err)
	assert.Equal(t, "u-device", principal.Subject, "the subject is the IAM principal")
	assert.Equal(t, "tenant-a", principal.TenantID)
	assert.Equal(t, []string{"device", "reader"}, principal.Roles)
	assert.Equal(t, []string{"device:read", "attestation:submit", "tenant:read"}, principal.Scopes,
		"the union of the principal's role permissions, each once")
	assert.Equal(t, "tenant-a", users.lastTenantID, "the principal is looked up in the certificate's tenant")
}

func TestIAMCertificatePrincipals_PrefersTheIAMUserID(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	resolver := newTestIAMCertificatePrincipals(t, users, roles)

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", UserID: "u-device", TenantID: "tenant-a"})

	require.NoError(t, err)
	assert.Equal(t, 1, users.byID)
	assert.Zero(t, users.byUsername)
	assert.Equal(t, []string{"device:read", "attestation:submit"}, principal.Scopes)
}

func TestIAMCertificatePrincipals_RefusesWhatIAMCannotResolve(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		identity *auth.Identity
		mutate   func(*certPrincipalUsers, *certPrincipalRoles)
		askIAM   bool
	}{
		"no identity":       {identity: nil},
		"no tenant":         {identity: &auth.Identity{ID: "device-01"}},
		"no principal":      {identity: &auth.Identity{TenantID: "tenant-a"}},
		"unknown principal": {identity: &auth.Identity{ID: "nobody", TenantID: "tenant-a"}, askIAM: true},
		"another tenant":    {identity: &auth.Identity{ID: "device-01", TenantID: "tenant-b"}, askIAM: true},
		"inactive":          {identity: &auth.Identity{ID: "suspended", TenantID: "tenant-a"}, askIAM: true},
		"IAM unavailable": {identity: &auth.Identity{ID: "device-01", TenantID: "tenant-a"}, askIAM: true,
			mutate: func(u *certPrincipalUsers, _ *certPrincipalRoles) { u.err = errors.New("iam: unavailable") }},
		"role unreadable": {identity: &auth.Identity{ID: "device-01", TenantID: "tenant-a"}, askIAM: true,
			mutate: func(_ *certPrincipalUsers, r *certPrincipalRoles) { r.err = errors.New("iam: unavailable") }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			users, roles := newCertPrincipalDirectory()
			if tc.mutate != nil {
				tc.mutate(users, roles)
			}
			resolver := newTestIAMCertificatePrincipals(t, users, roles)

			principal, err := resolver.ResolveCertificatePrincipal(context.Background(), tc.identity)

			require.Error(t, err)
			assert.Nil(t, principal)
			var want ErrCertificatePrincipalUnresolved
			assert.True(t, errors.As(err, &want), "error is %T", err)
			assert.Equal(t, tc.askIAM, users.byUsername+users.byID > 0)
		})
	}
}

func TestNewIAMCertificatePrincipals_RequiresBothClients(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	_, err := newIAMCertificatePrincipals(nil, roles)
	assert.Error(t, err)
	_, err = newIAMCertificatePrincipals(users, nil)
	assert.Error(t, err)
}
