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

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// fakeUserPager serves users one per page so the reconcile has to page.
type fakeUserPager struct {
	users []*entities.User
	err   error
}

func (f *fakeUserPager) Page(_ context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.User], error) {
	if query.Page < 1 || query.Page > len(f.users) {
		return datastore.PageResult[*entities.User]{Page: query.Page, PageSize: 1}, nil
	}
	return datastore.PageResult[*entities.User]{
		Entities: f.users[query.Page-1 : query.Page],
		Page:     query.Page,
		PageSize: 1,
		HasMore:  query.Page < len(f.users),
	}, nil
}

func (f *fakeUserPager) ForEachPage(ctx context.Context, query datastore.PageQuery, fn datastore.PagerFunc[*entities.User]) error {
	if f.err != nil {
		return f.err
	}
	for page := 1; ; page++ {
		query.Page = page
		result, err := f.Page(ctx, query)
		if err != nil {
			return err
		}
		if err := fn(result); err != nil {
			return err
		}
		if !result.HasMore {
			return nil
		}
	}
}

// fakeIAMDirectory serves fixed IAM tenant memberships.
type fakeIAMDirectory struct {
	emails map[string]map[string]struct{}
	errFor map[string]error
}

func (f *fakeIAMDirectory) MirroredEmails(_ context.Context, tenantID string) (map[string]struct{}, error) {
	if err := f.errFor[tenantID]; err != nil {
		return nil, err
	}
	return f.emails[tenantID], nil
}

// fakeRoleProvisioner records EnsureDefaultRoles calls.
type fakeRoleProvisioner struct {
	tenants []string
	err     error
}

func (f *fakeRoleProvisioner) EnsureDefaultRoles(_ context.Context, tenantID string) error {
	f.tenants = append(f.tenants, tenantID)
	return f.err
}

// reconcileFixture is the dependency set of one reconciler under test.
type reconcileFixture struct {
	users     *fakeUserPager
	mirror    *fakeIAMMirror
	directory *fakeIAMDirectory
	roles     *fakeRoleProvisioner
}

func newReconcileFixture(users ...*entities.User) *reconcileFixture {
	return &reconcileFixture{
		users:     &fakeUserPager{users: users},
		mirror:    &fakeIAMMirror{},
		directory: &fakeIAMDirectory{},
		roles:     &fakeRoleProvisioner{},
	}
}

func (f *reconcileFixture) config() *IAMUserReconcilerConfig {
	return &IAMUserReconcilerConfig{
		Logger:    newTestLogger(),
		Users:     f.users,
		Mirror:    f.mirror,
		Directory: f.directory,
		Roles:     f.roles,
	}
}

func (f *reconcileFixture) reconcile(t *testing.T) (*IAMUserReconcileReport, error) {
	t.Helper()
	reconciler, err := NewIAMUserReconciler(f.config())
	require.NoError(t, err)
	return reconciler.Reconcile(context.Background())
}

func reconcileUser(id uint64, tenantID, email string, owner bool) *entities.User {
	return &entities.User{ID: id, TenantID: tenantID, Email: email, IsTenantOwner: owner}
}

func TestIAMUserReconcile_MirrorsMissingUserAndSkipsPresentOne(t *testing.T) {
	owner := reconcileUser(1, "t1", "Owner@Example.com", true)
	member := reconcileUser(2, "t1", "member@example.com", false)
	fixture := newReconcileFixture(owner, member)
	fixture.directory.emails = map[string]map[string]struct{}{
		"t1": {"owner@example.com": {}},
	}

	report, err := fixture.reconcile(t)

	require.NoError(t, err)
	assert.Equal(t, &IAMUserReconcileReport{Scanned: 2, Present: 1, Mirrored: 1}, report)
	assert.Equal(t, []mirroredUser{{TenantID: "t1", Email: member.Email}}, fixture.mirror.calls,
		"only the missing user is mirrored; the present one is matched case-insensitively")
	assert.Equal(t, []string{"t1"}, fixture.roles.tenants)
}

func TestIAMUserReconcile_MirrorsOwnerWithOwnerRole(t *testing.T) {
	owner := reconcileUser(1, "t1", "owner@example.com", true)
	fixture := newReconcileFixture(owner)

	report, err := fixture.reconcile(t)

	require.NoError(t, err)
	assert.Equal(t, 1, report.Mirrored)
	assert.Equal(t, []mirroredUser{{TenantID: "t1", Email: owner.Email, Roles: []string{DefaultTenantOwnerRole}}}, fixture.mirror.calls)
}

func TestIAMUserReconcile_NothingMissingTouchesNothing(t *testing.T) {
	fixture := newReconcileFixture(
		reconcileUser(1, "t1", "a@example.com", true),
		reconcileUser(2, "", "orphan@example.com", false),
	)
	fixture.directory.emails = map[string]map[string]struct{}{"t1": {"a@example.com": {}}}

	report, err := fixture.reconcile(t)

	require.NoError(t, err)
	assert.Equal(t, &IAMUserReconcileReport{Scanned: 2, Skipped: 1, Present: 1}, report)
	assert.Empty(t, fixture.mirror.calls)
	assert.Empty(t, fixture.roles.tenants, "roles are provisioned only when a user is missing")
}

func TestIAMUserReconcile_FailuresAreCountedNotFatal(t *testing.T) {
	fails := reconcileUser(1, "t1", "fails@example.com", false)
	works := reconcileUser(2, "t1", "works@example.com", false)
	unlisted := reconcileUser(3, "t2", "unlisted@example.com", false)
	fixture := newReconcileFixture(fails, works, unlisted)
	fixture.mirror.failFor = map[string]error{fails.Email: errors.New("iam.role: not_found")}
	fixture.directory.errFor = map[string]error{"t2": errors.New("iam unavailable")}
	fixture.roles.err = errors.New("reconcile roles failed")

	report, err := fixture.reconcile(t)

	require.NoError(t, err)
	assert.Equal(t, &IAMUserReconcileReport{Scanned: 3, Mirrored: 1, Failed: 2}, report)
	assert.Len(t, fixture.mirror.calls, 2, "a role provisioning failure does not stop the mirror")
	assert.Equal(t, []string{"t1"}, fixture.roles.tenants, "an unlistable tenant is not touched")
}

func TestIAMUserReconcile_UserStoreFailureIsTyped(t *testing.T) {
	storeErr := errors.New("store unavailable")
	fixture := newReconcileFixture()
	fixture.users.err = storeErr

	report, err := fixture.reconcile(t)

	var failed ErrIAMReconcileFailed
	require.ErrorAs(t, err, &failed)
	assert.ErrorIs(t, err, storeErr)
	assert.NotNil(t, report)
	assert.Empty(t, fixture.mirror.calls)
}

func TestNewIAMUserReconciler_RequiresEveryDependency(t *testing.T) {
	_, err := NewIAMUserReconciler(nil)
	assert.Equal(t, ErrIAMReconcilerConfig{Field: "config"}, err)

	cases := map[string]func(*IAMUserReconcilerConfig){
		"Logger":    func(c *IAMUserReconcilerConfig) { c.Logger = nil },
		"Users":     func(c *IAMUserReconcilerConfig) { c.Users = nil },
		"Mirror":    func(c *IAMUserReconcilerConfig) { c.Mirror = nil },
		"Directory": func(c *IAMUserReconcilerConfig) { c.Directory = nil },
		"Roles":     func(c *IAMUserReconcilerConfig) { c.Roles = nil },
	}
	for field, unset := range cases {
		t.Run(field, func(t *testing.T) {
			config := newReconcileFixture().config()
			unset(config)

			reconciler, err := NewIAMUserReconciler(config)

			assert.Nil(t, reconciler)
			assert.Equal(t, ErrIAMReconcilerConfig{Field: field}, err)
		})
	}
}

func TestIAMReconcileErrors(t *testing.T) {
	cause := errors.New("boom")
	failed := ErrIAMReconcileFailed{Cause: cause}
	assert.Equal(t, "IAM user reconcile failed to read platform users: boom", failed.Error())
	assert.Equal(t, cause, failed.Unwrap())

	assert.Equal(t, "IAM user reconciler: Users is required", ErrIAMReconcilerConfig{Field: "Users"}.Error())
}
