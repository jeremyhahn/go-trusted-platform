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
	"fmt"
	"slices"
	"testing"

	quiciam "github.com/jeremyhahn/go-quicbaas/pkg/iam"
	sdkiam "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	apiquic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth/iamuser"
	"github.com/jeremyhahn/go-trusted-platform/pkg/auth/iamuser/iamusertest"
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

func newTestIAMCertificatePrincipals(t *testing.T, users *certPrincipalUsers, roles *certPrincipalRoles, pep sdkiam.PEPClient) *iamCertificatePrincipals {
	t.Helper()
	resolver, err := newIAMCertificatePrincipals(users, roles, pep)
	require.NoError(t, err)
	return resolver
}

// allowAllPEP is a policy decision point that allows every permission it is asked.
func allowAllPEP() *mockSDKPEPClient {
	return &mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		return &sdkiam.CheckResponse{Allowed: true}, nil
	}}
}

func TestIAMCertificatePrincipals_GrantsThePrincipalsRolePermissions(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	resolver := newTestIAMCertificatePrincipals(t, users, roles, allowAllPEP())

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

// TestIAMCertificatePrincipals_ResolvesOnTheEmbeddedTransport drives the
// resolver through the real SDK client over the pinned embedded transport,
// which registers neither User/FindByUsername nor User/GetByEmail: a CN and
// an email-SAN principal still resolve, and an unknown one is refused.
func TestIAMCertificatePrincipals_ResolvesOnTheEmbeddedTransport(t *testing.T) {
	t.Parallel()
	e := iamusertest.NewEmbedded(t)
	e.AddRole(t, "tenant-a", "device")
	deviceID := e.AddUser(t, "tenant-a", "device-01@example.com", "device-01", quiciam.LifecycleActive, "device")
	resolver, err := newIAMCertificatePrincipals(e.Client.User(), e.Client.Role(), &mockSDKPEPClient{})
	require.NoError(t, err)

	t.Run("a CN principal", func(t *testing.T) {
		principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
			&auth.Identity{ID: "device-01", TenantID: "tenant-a"})
		require.NoError(t, err)
		assert.Equal(t, deviceID, principal.Subject)
		assert.Equal(t, []string{"device"}, principal.Roles)
	})
	t.Run("an email-SAN principal", func(t *testing.T) {
		principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
			&auth.Identity{ID: "Device-01@Example.com", Email: "Device-01@Example.com", TenantID: "tenant-a"})
		require.NoError(t, err)
		assert.Equal(t, deviceID, principal.Subject)
	})
	t.Run("an unknown principal is refused", func(t *testing.T) {
		_, err := resolver.ResolveCertificatePrincipal(context.Background(),
			&auth.Identity{ID: "nobody", TenantID: "tenant-a"})
		var unresolved ErrCertificatePrincipalUnresolved
		require.ErrorAs(t, err, &unresolved)
	})
}

// TestIAMCertificatePrincipals_RefusesATruncatedListing seeds more users than
// the embedded User/List returns in its one page: a principal not on it is
// refused as a truncated listing, never as "IAM holds no principal".
func TestIAMCertificatePrincipals_RefusesATruncatedListing(t *testing.T) {
	t.Parallel()
	e := iamusertest.NewEmbedded(t)
	for i := 0; i < iamuser.ListPageSize+20; i++ {
		e.AddUser(t, "tenant-a", fmt.Sprintf("d%03d@example.com", i), fmt.Sprintf("d%03d", i), quiciam.LifecycleActive)
	}
	resolver, err := newIAMCertificatePrincipals(e.Client.User(), e.Client.Role(), &mockSDKPEPClient{})
	require.NoError(t, err)

	_, err = resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "nobody", TenantID: "tenant-a"})
	require.ErrorIs(t, err, iamuser.ErrTruncated)
	var unresolved ErrCertificatePrincipalUnresolved
	require.ErrorAs(t, err, &unresolved)
	assert.Contains(t, unresolved.Reason, "truncated")
}

func TestIAMCertificatePrincipals_PrefersTheIAMUserID(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	resolver := newTestIAMCertificatePrincipals(t, users, roles, allowAllPEP())

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
			resolver := newTestIAMCertificatePrincipals(t, users, roles, allowAllPEP())

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
	_, err := newIAMCertificatePrincipals(nil, roles, allowAllPEP())
	assert.Error(t, err)
	_, err = newIAMCertificatePrincipals(users, nil, allowAllPEP())
	assert.Error(t, err)
	_, err = newIAMCertificatePrincipals(users, roles, nil)
	assert.Error(t, err, "no policy decision point, no certificate principals")
}

func TestIAMCertificatePrincipals_ThePEPDecidesEachScope(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	var asked []*sdkiam.CheckRequest
	pep := &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		asked = append(asked, req)
		return &sdkiam.CheckResponse{Allowed: req.Resource != "attestation" || req.Action != "submit"}, nil
	}}
	resolver := newTestIAMCertificatePrincipals(t, users, roles, pep)

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})

	require.NoError(t, err)
	assert.Equal(t, []string{"device:read", "tenant:read"}, principal.Scopes,
		"only the permissions the PEP allows become scopes")
	require.Len(t, asked, 3, "each role permission is asked once")
	got := make([][2]string, 0, len(asked))
	for _, req := range asked {
		assert.Equal(t, sdkiam.CheckSubject{ID: "u-device", TenantID: "tenant-a", Roles: []string{"device", "reader"}}, req.Subject)
		got = append(got, [2]string{req.Resource, req.Action})
	}
	assert.Equal(t, [][2]string{{"device", "read"}, {"attestation", "submit"}, {"tenant", "read"}}, got)
}

// TestIAMCertificatePrincipals_AnABACOnlyAllowBecomesAScope pins #1906
// Codex P1: go-qrdb decides every request (docs/SPEC.md), so an explicit
// ABAC allow with no matching role permission, here for a principal with
// no roles at all, still grants its scope; a principal the PEP allows
// nothing gets no scope.
func TestIAMCertificatePrincipals_AnABACOnlyAllowBecomesAScope(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	users.users["tenant-a/abac-01"] = &sdkiam.User{ID: "u-abac", TenantID: "tenant-a",
		Username: "abac-01", Lifecycle: "active"}
	users.users["tenant-a/nobody-01"] = &sdkiam.User{ID: "u-nobody", TenantID: "tenant-a",
		Username: "nobody-01", Lifecycle: "active"}
	pep := &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		return &sdkiam.CheckResponse{Allowed: req.Subject.ID == "u-abac" &&
			req.Resource == "device" && req.Action == "read"}, nil
	}}
	resolver := newTestIAMCertificatePrincipals(t, users, roles, pep)

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "abac-01", TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.Equal(t, []string{"device:read"}, principal.Scopes,
		"an explicit ABAC allow is a scope even with no role permission")

	principal, err = resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "nobody-01", TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.Empty(t, principal.Scopes, "a principal the PEP allows nothing has no scope")
}

// A role permission holding a wildcard never becomes a certificate
// principal's scope: RequireScope matches a wildcard scope against any
// concrete operation, so copying "*:*" would admit "device:write" without
// the PEP ever deciding it (docs/SPEC.md: the decision point decides every
// request). Only concrete permissions the PEP allows become scopes.
func TestIAMCertificatePrincipals_AWildcardIsDecidedPerConcretePermission(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	roles.roles["device"] = &sdkiam.Role{ID: "device", Permissions: []string{"*:*", "device:read"}}
	roles.roles["reader"] = &sdkiam.Role{ID: "reader", Permissions: []string{"device:*", "*:read"}}
	var asked []*sdkiam.CheckRequest
	pep := &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		asked = append(asked, req)
		return &sdkiam.CheckResponse{Allowed: req.Resource != "device" || req.Action != "write"}, nil
	}}
	resolver := newTestIAMCertificatePrincipals(t, users, roles, pep)
	resolver.catalog = []string{"attestation:submit", "device:read", "device:write", "tenant:read"}

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})

	require.NoError(t, err)
	assert.Equal(t, []string{"attestation:submit", "device:read", "tenant:read"}, principal.Scopes,
		"a wildcard grants the concrete permissions it covers that the PEP allows")
	for _, scope := range principal.Scopes {
		assert.NotContains(t, scope, "*", "a wildcard pattern is never a certificate principal's scope")
	}
	for _, req := range asked {
		assert.NotContains(t, req.Resource+":"+req.Action, "*", "the PEP is never asked about a wildcard pattern")
	}
	assert.Len(t, asked, 4, "each concrete permission is asked once")
}

func TestIAMCertificatePrincipals_AResourceWildcardGrantsTheConcretePermissionsThePEPAllows(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	roles.roles["device"] = &sdkiam.Role{ID: "device", Permissions: []string{"piv:*", "pi*:use"}}
	roles.roles["reader"] = &sdkiam.Role{ID: "reader", Permissions: []string{"*:read"}}
	type pair struct{ resource, action string }
	var asked []pair
	pep := &mockSDKPEPClient{checkFunc: func(_ context.Context, req *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		asked = append(asked, pair{req.Resource, req.Action})
		return &sdkiam.CheckResponse{Allowed: req.Resource != "piv" || req.Action != "read"}, nil
	}}
	resolver := newTestIAMCertificatePrincipals(t, users, roles, pep)
	resolver.catalog = []string{"device:read", "piv:read", "piv:use", "tenant:write"}

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})

	require.NoError(t, err)
	assert.Equal(t, []string{"piv:use", "device:read"}, principal.Scopes,
		"piv:* grants piv:use, which the PEP allows, and not piv:read, which it denies")
	assert.Equal(t, []pair{{"piv", "read"}, {"piv", "use"}, {"device", "read"}}, asked,
		"a partial glob is never expanded, and a permission no grant covers is never asked")
}

func TestConcretePermissionCatalog_HoldsEveryTransportsConcretePermissions(t *testing.T) {
	t.Parallel()
	catalog := concretePermissionCatalog()

	require.NotEmpty(t, catalog)
	assert.True(t, slices.IsSorted(catalog), "the catalog is sorted")
	assert.Len(t, slices.Compact(slices.Clone(catalog)), len(catalog), "the catalog is distinct")
	for _, permission := range catalog {
		assert.NotContains(t, permission, "*", "the catalog holds concrete permissions only")
	}
	assert.Contains(t, catalog, "piv:use")
	for _, source := range [][]string{grpcapi.Scopes(), apiquic.OperationScopes(), mcp.SupportedScopes()} {
		for _, scope := range source {
			assert.Contains(t, catalog, scope)
		}
	}
}

func TestIAMCertificatePrincipals_APEPThatDeniesAllGrantsNoScopes(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	resolver := newTestIAMCertificatePrincipals(t, users, roles, &mockSDKPEPClient{})

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})

	require.NoError(t, err)
	require.NotNil(t, principal)
	assert.Empty(t, principal.Scopes)
}

func TestIAMCertificatePrincipals_RefusesWhenThePEPCannotDecide(t *testing.T) {
	t.Parallel()
	users, roles := newCertPrincipalDirectory()
	pep := &mockSDKPEPClient{checkFunc: func(context.Context, *sdkiam.CheckRequest) (*sdkiam.CheckResponse, error) {
		return nil, assert.AnError
	}}
	resolver := newTestIAMCertificatePrincipals(t, users, roles, pep)

	principal, err := resolver.ResolveCertificatePrincipal(context.Background(),
		&auth.Identity{ID: "device-01", TenantID: "tenant-a"})

	assert.Nil(t, principal, "fail closed, never a partial grant")
	var unresolved ErrCertificatePrincipalUnresolved
	assert.ErrorAs(t, err, &unresolved)
}
