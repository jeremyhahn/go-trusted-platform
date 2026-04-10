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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// noCtxFlags returns CommonFlags with nil GetContext.
func noCtxFlags() *cli.CommonFlags {
	return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
}

// assertNoCtxErr checks the error is cli.ErrNoContextSet.
func assertNoCtxErr(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.IsType(t, cli.ErrNoContextSet{}, err)
}

// =============================================================================
// Group run* — validation + no-context paths
// =============================================================================

func TestRunGroupCreate_MissingTenant(t *testing.T) {
	err := runGroupCreate(noCtxFlags(), "", "grp-1", "name", "desc")
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunGroupCreate_NoContext(t *testing.T) {
	err := runGroupCreate(noCtxFlags(), "tenant-1", "grp-1", "name", "desc")
	assertNoCtxErr(t, err)
}

func TestRunGroupGet_MissingTenant(t *testing.T) {
	err := runGroupGet(noCtxFlags(), "", "grp-1")
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunGroupGet_MissingGroupID(t *testing.T) {
	err := runGroupGet(noCtxFlags(), "tenant-1", "")
	require.Error(t, err)
	assert.IsType(t, ErrMissingGroupID{}, err)
}

func TestRunGroupGet_NoContext(t *testing.T) {
	err := runGroupGet(noCtxFlags(), "tenant-1", "grp-1")
	assertNoCtxErr(t, err)
}

func TestRunGroupList_MissingTenant(t *testing.T) {
	err := runGroupList(noCtxFlags(), "", 1, 50)
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunGroupList_NoContext(t *testing.T) {
	err := runGroupList(noCtxFlags(), "tenant-1", 1, 50)
	assertNoCtxErr(t, err)
}

func TestRunGroupUpdate_MissingTenant(t *testing.T) {
	err := runGroupUpdate(noCtxFlags(), "", "grp-1", "name", "desc")
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunGroupUpdate_MissingGroupID(t *testing.T) {
	err := runGroupUpdate(noCtxFlags(), "tenant-1", "", "name", "desc")
	require.Error(t, err)
	assert.IsType(t, ErrMissingGroupID{}, err)
}

func TestRunGroupUpdate_NoContext(t *testing.T) {
	err := runGroupUpdate(noCtxFlags(), "tenant-1", "grp-1", "name", "desc")
	assertNoCtxErr(t, err)
}

func TestRunGroupDelete_MissingTenant(t *testing.T) {
	err := runGroupDelete(noCtxFlags(), "", "grp-1")
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunGroupDelete_MissingGroupID(t *testing.T) {
	err := runGroupDelete(noCtxFlags(), "tenant-1", "")
	require.Error(t, err)
	assert.IsType(t, ErrMissingGroupID{}, err)
}

func TestRunGroupDelete_NoContext(t *testing.T) {
	err := runGroupDelete(noCtxFlags(), "tenant-1", "grp-1")
	assertNoCtxErr(t, err)
}

// =============================================================================
// Group command construction — RunE invocation
// =============================================================================

func TestGroupCreateCommand_RunE_NoContext(t *testing.T) {
	cmd := newGroupCreateCommand(func() *cli.CommonFlags { return noCtxFlags() })
	cmd.SetArgs([]string{"grp-1", "--tenant", "t-1"})
	err := cmd.Execute()
	assertNoCtxErr(t, err)
}

func TestGroupGetCommand_RunE_NoContext(t *testing.T) {
	cmd := newGroupGetCommand(func() *cli.CommonFlags { return noCtxFlags() })
	cmd.SetArgs([]string{"tenant-1", "grp-1"})
	err := cmd.Execute()
	assertNoCtxErr(t, err)
}

func TestGroupListCommand_RunE_NoContext(t *testing.T) {
	cmd := newGroupListCommand(func() *cli.CommonFlags { return noCtxFlags() })
	cmd.SetArgs([]string{"--tenant", "t-1"})
	err := cmd.Execute()
	assertNoCtxErr(t, err)
}

func TestGroupUpdateCommand_RunE_NoContext(t *testing.T) {
	cmd := newGroupUpdateCommand(func() *cli.CommonFlags { return noCtxFlags() })
	cmd.SetArgs([]string{"grp-1", "--tenant", "t-1"})
	err := cmd.Execute()
	assertNoCtxErr(t, err)
}

func TestGroupDeleteCommand_RunE_NoContext(t *testing.T) {
	cmd := newGroupDeleteCommand(func() *cli.CommonFlags { return noCtxFlags() })
	cmd.SetArgs([]string{"tenant-1", "grp-1"})
	err := cmd.Execute()
	assertNoCtxErr(t, err)
}

// =============================================================================
// Role run* — validation + no-context paths
// =============================================================================

func TestRunRoleCreate_MissingTenant(t *testing.T) {
	err := runRoleCreate(noCtxFlags(), "", "role-1", "name", "desc", nil)
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunRoleCreate_NoContext(t *testing.T) {
	err := runRoleCreate(noCtxFlags(), "t-1", "role-1", "name", "desc", []string{"read", "write"})
	assertNoCtxErr(t, err)
}

func TestRunRoleGet_MissingTenant(t *testing.T) {
	err := runRoleGet(noCtxFlags(), "", "role-1")
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunRoleGet_MissingRoleID(t *testing.T) {
	err := runRoleGet(noCtxFlags(), "t-1", "")
	require.Error(t, err)
	assert.IsType(t, ErrMissingRoleID{}, err)
}

func TestRunRoleGet_NoContext(t *testing.T) {
	err := runRoleGet(noCtxFlags(), "t-1", "role-1")
	assertNoCtxErr(t, err)
}

func TestRunRoleList_MissingTenant(t *testing.T) {
	err := runRoleList(noCtxFlags(), "", 1, 50)
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunRoleList_NoContext(t *testing.T) {
	err := runRoleList(noCtxFlags(), "t-1", 1, 50)
	assertNoCtxErr(t, err)
}

func TestRunRoleUpdate_MissingTenant(t *testing.T) {
	err := runRoleUpdate(noCtxFlags(), "", "role-1", "name", "desc", nil)
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunRoleUpdate_MissingRoleID(t *testing.T) {
	err := runRoleUpdate(noCtxFlags(), "t-1", "", "name", "desc", nil)
	require.Error(t, err)
	assert.IsType(t, ErrMissingRoleID{}, err)
}

func TestRunRoleUpdate_NoContext(t *testing.T) {
	err := runRoleUpdate(noCtxFlags(), "t-1", "role-1", "name", "desc", []string{"admin"})
	assertNoCtxErr(t, err)
}

func TestRunRoleDelete_MissingTenant(t *testing.T) {
	err := runRoleDelete(noCtxFlags(), "", "role-1")
	require.Error(t, err)
	assert.IsType(t, ErrMissingTenantID{}, err)
}

func TestRunRoleDelete_MissingRoleID(t *testing.T) {
	err := runRoleDelete(noCtxFlags(), "t-1", "")
	require.Error(t, err)
	assert.IsType(t, ErrMissingRoleID{}, err)
}

func TestRunRoleDelete_NoContext(t *testing.T) {
	err := runRoleDelete(noCtxFlags(), "t-1", "role-1")
	assertNoCtxErr(t, err)
}

// =============================================================================
// Tenant run* — no-context paths (no early validation)
// =============================================================================

func TestRunTenantCreate_NoContext(t *testing.T) {
	err := runTenantCreate(noCtxFlags(), "t-1", "Test Tenant", 100, true)
	assertNoCtxErr(t, err)
}

func TestRunTenantGet_NoContext(t *testing.T) {
	err := runTenantGet(noCtxFlags(), "t-1")
	assertNoCtxErr(t, err)
}

func TestRunTenantList_NoContext(t *testing.T) {
	err := runTenantList(noCtxFlags(), 1, 50)
	assertNoCtxErr(t, err)
}

func TestRunTenantUpdate_NoContext(t *testing.T) {
	err := runTenantUpdate(noCtxFlags(), "t-1", "Updated", 200, false, false)
	assertNoCtxErr(t, err)
}

func TestRunTenantDelete_NoContext(t *testing.T) {
	err := runTenantDelete(noCtxFlags(), "t-1")
	assertNoCtxErr(t, err)
}

// =============================================================================
// User run* — no-context paths (no early validation)
// =============================================================================

func TestRunUserCreate_NoContext(t *testing.T) {
	err := runUserCreate(noCtxFlags(), "t-1", "user@test.com", "Test User", "admin", "grp-1", "key=val")
	assertNoCtxErr(t, err)
}

func TestRunUserGet_NoContext(t *testing.T) {
	err := runUserGet(noCtxFlags(), "t-1", "user-1")
	assertNoCtxErr(t, err)
}

func TestRunUserList_NoContext(t *testing.T) {
	err := runUserList(noCtxFlags(), "t-1", 1, 50)
	assertNoCtxErr(t, err)
}

func TestRunUserUpdate_NoContext(t *testing.T) {
	err := runUserUpdate(noCtxFlags(), "t-1", "user-1", "user@test.com", "Updated", "admin", "grp-1", "k=v")
	assertNoCtxErr(t, err)
}

func TestRunUserDelete_NoContext(t *testing.T) {
	err := runUserDelete(noCtxFlags(), "t-1", "user-1")
	assertNoCtxErr(t, err)
}

func TestRunUserAssignRole_NoContext(t *testing.T) {
	err := runUserAssignRole(noCtxFlags(), "t-1", "user-1", "admin")
	assertNoCtxErr(t, err)
}

func TestRunUserRevokeRole_NoContext(t *testing.T) {
	err := runUserRevokeRole(noCtxFlags(), "t-1", "user-1", "admin")
	assertNoCtxErr(t, err)
}

// =============================================================================
// Policy run* — no-context paths (no early validation)
// =============================================================================

func TestRunPolicyCreate_NoContext(t *testing.T) {
	err := runPolicyCreate(noCtxFlags(), "t-1", "test-policy", "desc", 10, "/tmp/nonexistent.yaml", "env=test")
	assertNoCtxErr(t, err)
}

func TestRunPolicyGet_NoContext(t *testing.T) {
	err := runPolicyGet(noCtxFlags(), "t-1", "test-policy")
	assertNoCtxErr(t, err)
}

func TestRunPolicyList_NoContext(t *testing.T) {
	err := runPolicyList(noCtxFlags(), "t-1", 1, 50)
	assertNoCtxErr(t, err)
}

func TestRunPolicyUpdate_NoContext(t *testing.T) {
	err := runPolicyUpdate(noCtxFlags(), "t-1", "test-policy", "updated desc", 20, "/tmp/nonexistent.yaml", "env=prod")
	assertNoCtxErr(t, err)
}

func TestRunPolicyDelete_NoContext(t *testing.T) {
	err := runPolicyDelete(noCtxFlags(), "t-1", "test-policy")
	assertNoCtxErr(t, err)
}

func TestRunPolicyValidate_NoContext(t *testing.T) {
	err := runPolicyValidate(noCtxFlags(), "t-1", "/tmp/nonexistent.yaml")
	assertNoCtxErr(t, err)
}

func TestRunPolicyTest_NoContext(t *testing.T) {
	err := runPolicyTest(noCtxFlags(), "t-1", "user-1", "admin", "grp-1", "read", "/api/v1/data", "{}")
	assertNoCtxErr(t, err)
}

// =============================================================================
// App run* — no-context paths (no early validation)
// =============================================================================

func TestRunAppRegister_NoContext(t *testing.T) {
	err := runAppRegister(noCtxFlags(), "t-1", "my-app", "https://localhost/callback", "authorization_code", "code", "app")
	assertNoCtxErr(t, err)
}

func TestRunAppGet_NoContext(t *testing.T) {
	err := runAppGet(noCtxFlags(), "t-1", "client-1")
	assertNoCtxErr(t, err)
}

func TestRunAppList_NoContext(t *testing.T) {
	err := runAppList(noCtxFlags(), "t-1", 1, 50)
	assertNoCtxErr(t, err)
}

func TestRunAppUpdate_NoContext(t *testing.T) {
	err := runAppUpdate(noCtxFlags(), "t-1", "client-1", "updated-app", "https://localhost/cb", "authorization_code", "code", "app")
	assertNoCtxErr(t, err)
}

func TestRunAppDelete_NoContext(t *testing.T) {
	err := runAppDelete(noCtxFlags(), "t-1", "client-1")
	assertNoCtxErr(t, err)
}

func TestRunAppRotateSecret_NoContext(t *testing.T) {
	err := runAppRotateSecret(noCtxFlags(), "t-1", "client-1")
	assertNoCtxErr(t, err)
}
