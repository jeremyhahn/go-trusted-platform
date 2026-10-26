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

package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// fakeUserManager is an in-memory bmc.ManagedUserManager. It records every
// mutation; the password is copied out of the enclave during the call because
// the command destroys the enclave afterwards.
type fakeUserManager struct {
	users []bmc.User

	listErr, createErr, deleteErr, passwordErr, privErr error

	created     *bmc.User
	createdPass string
	deletedSlot uint8
	passSlot    uint8
	newPass     string
	privSlot    uint8
	privChannel uint8
	priv        bmc.Privilege
	closed      int
}

func (f *fakeUserManager) ListUsers(context.Context) ([]bmc.User, error) {
	return f.users, f.listErr
}

func (f *fakeUserManager) CreateUser(_ context.Context, u bmc.User, pw *memguard.MemoryEnclave) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = &u
	f.createdPass = string(pw.Bytes())
	return nil
}

func (f *fakeUserManager) SetUserPassword(_ context.Context, slot uint8, pw *memguard.MemoryEnclave) error {
	if f.passwordErr != nil {
		return f.passwordErr
	}
	f.passSlot = slot
	f.newPass = string(pw.Bytes())
	return nil
}

func (f *fakeUserManager) SetUserPrivilege(_ context.Context, slot, channel uint8, priv bmc.Privilege) error {
	if f.privErr != nil {
		return f.privErr
	}
	f.privSlot, f.privChannel, f.priv = slot, channel, priv
	return nil
}

func (f *fakeUserManager) DeleteUser(_ context.Context, slot uint8) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletedSlot = slot
	return nil
}

func (f *fakeUserManager) MaxUsers(context.Context) (uint8, error) {
	return 16, nil
}

func (f *fakeUserManager) Close() error {
	f.closed++
	return nil
}

// withFakeUserManager routes both standalone protocols to mgr and returns a
// pointer to the config the command dialled with.
func withFakeUserManager(t *testing.T, mgr *fakeUserManager, newErr error) **bmc.Config {
	t.Helper()
	var got *bmc.Config
	open := func(_ context.Context, cfg *bmc.Config, _ *slog.Logger) (bmc.ManagedUserManager, error) {
		got = cfg
		if newErr != nil {
			return nil, newErr
		}
		return mgr, nil
	}
	orig := standaloneUserManagers
	standaloneUserManagers = map[bmc.Protocol]standaloneUserManagerFunc{
		bmc.ProtocolIPMI:    open,
		bmc.ProtocolRedfish: open,
	}
	t.Cleanup(func() { standaloneUserManagers = orig })
	return &got
}

// withPassword answers the password prompt with answer, or fails it with err.
func withPassword(t *testing.T, answer string, err error) {
	t.Helper()
	orig := readPassword
	readPassword = func(int) ([]byte, error) { return []byte(answer), err }
	t.Cleanup(func() { readPassword = orig })
}

func twoBMCUsers() []bmc.User {
	return []bmc.User{
		{Slot: 2, Username: "admin", Enabled: true, Privilege: bmc.PrivilegeAdministrator, Channel: 1},
		{Slot: 3, Username: "ops", Enabled: false, Privilege: bmc.PrivilegeOperator, Channel: 1},
	}
}

const wantUserTable = "" +
	"SLOT   USERNAME             ENABLED   PRIVILEGE        CHANNEL \n" +
	"----   --------             -------   ---------        ------- \n" +
	"2      admin                yes       administrator    1       \n" +
	"3      ops                  no        operator         1       \n"

// --- standalone mode -------------------------------------------------------

func TestStandaloneUserList(t *testing.T) {
	mgr := &fakeUserManager{users: twoBMCUsers()}
	withFakeUserManager(t, mgr, nil)

	out, err := runBMC(t, tableGetFlags(), withArgs([]string{"user", "list"}, standaloneIPMIArgs...)...)
	require.NoError(t, err)
	assert.Equal(t, wantUserTable, out)
	assert.Equal(t, 1, mgr.closed)

	out, err = runBMC(t, jsonGetFlags(), withArgs([]string{"user", "list"}, standaloneIPMIArgs...)...)
	require.NoError(t, err)
	var users []bmcsvc.User
	require.NoError(t, json.Unmarshal([]byte(out), &users))
	assert.Equal(t, []bmcsvc.User{
		{Slot: 2, Username: "admin", Enabled: true, Privilege: bmcsvc.PrivilegeAdministrator, Channel: 1},
		{Slot: 3, Username: "ops", Enabled: false, Privilege: bmcsvc.PrivilegeOperator, Channel: 1},
	}, users)
}

func TestStandaloneUserList_Empty(t *testing.T) {
	withFakeUserManager(t, &fakeUserManager{}, nil)
	out, err := runBMC(t, tableGetFlags(), withArgs([]string{"user", "list"}, standaloneIPMIArgs...)...)
	require.NoError(t, err)
	assert.Equal(t, "No users found\n", out)
}

func TestStandaloneUserCreate(t *testing.T) {
	mgr := &fakeUserManager{}
	withFakeUserManager(t, mgr, nil)
	withPassword(t, "n3w-pass", nil)

	out, err := runBMC(t, tableGetFlags(), withArgs(
		[]string{"user", "create", "--username", "alice", "--role", "operator", "--slot", "5", "--channel", "2"},
		standaloneIPMIArgs...)...)
	require.NoError(t, err)
	assert.Equal(t, "Host:     192.0.2.10\nAction:   create\nUsername: alice\nSlot:     5\nStatus:   success\n", out)
	require.NotNil(t, mgr.created)
	assert.Equal(t, bmc.User{Slot: 5, Username: "alice", Enabled: true, Privilege: bmc.PrivilegeOperator, Channel: 2}, *mgr.created)
	assert.Equal(t, "n3w-pass", mgr.createdPass)
	assert.Equal(t, 1, mgr.closed)
}

func TestStandaloneUserCreate_JSON(t *testing.T) {
	withFakeUserManager(t, &fakeUserManager{}, nil)
	withPassword(t, "pw", nil)

	out, err := runBMC(t, jsonGetFlags(), withArgs(
		[]string{"user", "create", "--username", "alice", "--role", "user", "--slot", "4"},
		standaloneIPMIArgs...)...)
	require.NoError(t, err)
	var resp userActionResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, userActionResponse{ProfileID: "192.0.2.10", Action: "create", Username: "alice", Slot: 4, Status: "success"}, resp)
}

func TestStandaloneUserDelete(t *testing.T) {
	mgr := &fakeUserManager{users: twoBMCUsers()}
	withFakeUserManager(t, mgr, nil)

	out, err := runBMC(t, tableGetFlags(), withArgs([]string{"user", "delete", "--username", "ops"}, standaloneIPMIArgs...)...)
	require.NoError(t, err)
	assert.Equal(t, "Host:     192.0.2.10\nAction:   delete\nUsername: ops\nSlot:     3\nStatus:   success\n", out)
	assert.Equal(t, uint8(3), mgr.deletedSlot)
}

func TestStandaloneUserUpdatePassword(t *testing.T) {
	mgr := &fakeUserManager{users: twoBMCUsers()}
	withFakeUserManager(t, mgr, nil)
	withPassword(t, "rotated", nil)

	out, err := runBMC(t, tableGetFlags(), withArgs([]string{"user", "update-password", "--username", "admin"}, standaloneIPMIArgs...)...)
	require.NoError(t, err)
	assert.Equal(t, "Host:     192.0.2.10\nAction:   update-password\nUsername: admin\nSlot:     2\nStatus:   success\n", out)
	assert.Equal(t, uint8(2), mgr.passSlot)
	assert.Equal(t, "rotated", mgr.newPass)
}

func TestStandaloneUserUpdateAccess(t *testing.T) {
	mgr := &fakeUserManager{users: twoBMCUsers()}
	withFakeUserManager(t, mgr, nil)

	out, err := runBMC(t, tableGetFlags(), withArgs(
		[]string{"user", "update-access", "--username", "ops", "--role", "no_access", "--channel", "3"},
		standaloneIPMIArgs...)...)
	require.NoError(t, err)
	assert.Equal(t, "Host:     192.0.2.10\nAction:   update-access\nUsername: ops\nSlot:     3\nRole:     no_access\nStatus:   success\n", out)
	assert.Equal(t, uint8(3), mgr.privSlot)
	assert.Equal(t, uint8(3), mgr.privChannel)
	assert.Equal(t, bmc.PrivilegeNoAccess, mgr.priv)

	out, err = runBMC(t, jsonGetFlags(), withArgs(
		[]string{"user", "update-access", "--username", "ops", "--role", "administrator"},
		standaloneIPMIArgs...)...)
	require.NoError(t, err)
	var resp userActionResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, "privilege changed to administrator", resp.Message)
	assert.Equal(t, uint8(1), mgr.privChannel, "--channel defaults to 1")
}

func TestStandaloneUser_ManagerErrorsPropagate(t *testing.T) {
	boom := errors.New("bmc rejected")
	tests := []struct {
		name string
		mgr  *fakeUserManager
		args []string
	}{
		{"list", &fakeUserManager{listErr: boom}, []string{"user", "list"}},
		{"create", &fakeUserManager{createErr: boom}, []string{"user", "create", "--username", "a", "--role", "user"}},
		{"delete lookup", &fakeUserManager{listErr: boom}, []string{"user", "delete", "--username", "admin"}},
		{"delete", &fakeUserManager{users: twoBMCUsers(), deleteErr: boom}, []string{"user", "delete", "--username", "admin"}},
		{"update-password lookup", &fakeUserManager{listErr: boom}, []string{"user", "update-password", "--username", "admin"}},
		{"update-password", &fakeUserManager{users: twoBMCUsers(), passwordErr: boom}, []string{"user", "update-password", "--username", "admin"}},
		{"update-access lookup", &fakeUserManager{listErr: boom}, []string{"user", "update-access", "--username", "admin", "--role", "user"}},
		{"update-access", &fakeUserManager{users: twoBMCUsers(), privErr: boom}, []string{"user", "update-access", "--username", "admin", "--role", "user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFakeUserManager(t, tt.mgr, nil)
			withPassword(t, "pw", nil)
			out, err := runBMC(t, tableGetFlags(), withArgs(tt.args, standaloneIPMIArgs...)...)
			require.ErrorIs(t, err, boom)
			assert.Empty(t, out)
			assert.Equal(t, 1, tt.mgr.closed)
		})
	}
}

func TestStandaloneUser_UnknownUsername(t *testing.T) {
	for _, args := range [][]string{
		{"user", "delete", "--username", "ghost"},
		{"user", "update-password", "--username", "ghost"},
		{"user", "update-access", "--username", "ghost", "--role", "user"},
	} {
		t.Run(args[1], func(t *testing.T) {
			withFakeUserManager(t, &fakeUserManager{users: twoBMCUsers()}, nil)
			withPassword(t, "pw", nil)
			_, err := runBMC(t, tableGetFlags(), withArgs(args, standaloneIPMIArgs...)...)
			var notFound ErrUserNotFound
			require.ErrorAs(t, err, &notFound)
			assert.Equal(t, "ghost", notFound.Username)
			assert.Equal(t, `bmc: no BMC user named "ghost"`, err.Error())
		})
	}
}

func TestStandaloneUser_ManagerConstructionError(t *testing.T) {
	boom := errors.New("rmcp session refused")
	withFakeUserManager(t, nil, boom)
	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"user", "list"}, standaloneIPMIArgs...)...)
	require.ErrorIs(t, err, boom)
}

func TestStandaloneUser_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want error
	}{
		{"create no username", []string{"user", "create", "--role", "user"}, ErrUsernameRequired{}},
		{"create no role", []string{"user", "create", "--username", "a"}, ErrRoleRequired{}},
		{"create bad role", []string{"user", "create", "--username", "a", "--role", "root"}, ErrInvalidRole{Role: "root"}},
		{"delete no username", []string{"user", "delete"}, ErrUsernameRequired{}},
		{"update-password no username", []string{"user", "update-password"}, ErrUsernameRequired{}},
		{"update-access no username", []string{"user", "update-access", "--role", "user"}, ErrUsernameRequired{}},
		{"update-access no role", []string{"user", "update-access", "--username", "a"}, ErrRoleRequired{}},
		{"update-access bad role", []string{"user", "update-access", "--username", "a", "--role", "root"}, ErrInvalidRole{Role: "root"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &fakeUserManager{users: twoBMCUsers()}
			withFakeUserManager(t, mgr, nil)
			_, err := runBMC(t, tableGetFlags(), withArgs(tt.args, standaloneIPMIArgs...)...)
			require.ErrorIs(t, err, tt.want)
			assert.Zero(t, mgr.closed, "validation must fail before dialling the BMC")
		})
	}
}

func TestStandaloneUser_PasswordPromptErrors(t *testing.T) {
	ttyErr := errors.New("inappropriate ioctl for device")
	for _, args := range [][]string{
		{"user", "create", "--username", "a", "--role", "user"},
		{"user", "update-password", "--username", "admin"},
	} {
		t.Run(args[1]+" read error", func(t *testing.T) {
			mgr := &fakeUserManager{users: twoBMCUsers()}
			withFakeUserManager(t, mgr, nil)
			withPassword(t, "", ttyErr)
			_, err := runBMC(t, tableGetFlags(), withArgs(args, standaloneIPMIArgs...)...)
			var pwErr ErrPasswordRequired
			require.ErrorAs(t, err, &pwErr)
			require.ErrorIs(t, err, ttyErr)
			assert.Zero(t, mgr.closed)
		})
		t.Run(args[1]+" empty", func(t *testing.T) {
			withFakeUserManager(t, &fakeUserManager{users: twoBMCUsers()}, nil)
			withPassword(t, "", nil)
			_, err := runBMC(t, tableGetFlags(), withArgs(args, standaloneIPMIArgs...)...)
			require.ErrorIs(t, err, ErrPasswordRequired{})
		})
	}
}

// Regression: user management used to receive the raw "--bmc-protocol" value
// and port 443 for every protocol, and demanded HTTPS trust flags for IPMI.
func TestStandaloneUser_ConfigFollowsProtocol(t *testing.T) {
	t.Run("ipmi", func(t *testing.T) {
		cfg := withFakeUserManager(t, &fakeUserManager{}, nil)
		_, err := runBMC(t, tableGetFlags(), withArgs([]string{"user", "list"}, standaloneIPMIArgs...)...)
		require.NoError(t, err)
		require.NotNil(t, *cfg)
		assert.Equal(t, bmc.ProtocolIPMI, (*cfg).Protocol)
		assert.Equal(t, 623, (*cfg).Port)
		assert.Nil(t, (*cfg).TLS)
		assert.NoError(t, (*cfg).Validate())
	})
	t.Run("redfish", func(t *testing.T) {
		cfg := withFakeUserManager(t, &fakeUserManager{}, nil)
		_, err := runBMC(t, tableGetFlags(), "user", "list",
			"--bmc-host", "192.0.2.10", "--bmc-user", "admin", "--bmc-pass", "secret",
			"--bmc-protocol", "redfish", "--bmc-pin", strings.Repeat("ab", 32))
		require.NoError(t, err)
		require.NotNil(t, *cfg)
		assert.Equal(t, bmc.ProtocolRedfish, (*cfg).Protocol)
		assert.Equal(t, 443, (*cfg).Port)
		assert.NotNil(t, (*cfg).TLS)
		assert.NoError(t, (*cfg).Validate())
	})
}

func TestStandaloneUser_NoManagerForProtocol(t *testing.T) {
	orig := standaloneUserManagers
	standaloneUserManagers = map[bmc.Protocol]standaloneUserManagerFunc{}
	t.Cleanup(func() { standaloneUserManagers = orig })

	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"user", "list"}, standaloneIPMIArgs...)...)
	var invalid ErrBMCInvalidProtocol
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "ipmi", invalid.Value)
}

func TestStandaloneUserManagers_CoverBothProtocols(t *testing.T) {
	assert.Len(t, standaloneUserManagers, 2)
	assert.Contains(t, standaloneUserManagers, bmc.ProtocolIPMI)
	assert.Contains(t, standaloneUserManagers, bmc.ProtocolRedfish)
}

// --- daemon mode -----------------------------------------------------------

func daemonUsers() []*platformv1.BMCUser {
	return []*platformv1.BMCUser{
		{Slot: 2, Username: "admin", Enabled: true, Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR, Channel: 1},
		{Slot: 3, Username: "ops", Enabled: false, Privilege: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR, Channel: 1},
	}
}

func TestDaemonUserList(t *testing.T) {
	srv := &inProcBMCServer{users: daemonUsers()}
	table, jsonFlags := serveInProcBMC(t, srv)

	out, err := runBMC(t, table, "user", "list", "--profile-id", "7")
	require.NoError(t, err)
	assert.Equal(t, wantUserTable, out)
	assert.Equal(t, uint64(7), srv.listReq.GetProfileId())

	out, err = runBMC(t, jsonFlags, "user", "list", "--profile-id", "7")
	require.NoError(t, err)
	var users []bmcsvc.User
	require.NoError(t, json.Unmarshal([]byte(out), &users))
	require.Len(t, users, 2)
	assert.Equal(t, bmcsvc.PrivilegeAdministrator, users[0].Privilege)
}

func TestDaemonUserList_Empty(t *testing.T) {
	table, _ := serveInProcBMC(t, &inProcBMCServer{})
	out, err := runBMC(t, table, "user", "list", "--profile-id", "7")
	require.NoError(t, err)
	assert.Equal(t, "No users found\n", out)
}

func TestDaemonUserCreate(t *testing.T) {
	srv := &inProcBMCServer{createSlot: 6}
	table, jsonFlags := serveInProcBMC(t, srv)
	withPassword(t, "s3cret", nil)

	out, err := runBMC(t, table, "user", "create", "--profile-id", "7", "--username", "alice", "--role", "operator", "--channel", "2")
	require.NoError(t, err)
	assert.Equal(t, "Profile:  7\nAction:   create\nUsername: alice\nSlot:     6\nStatus:   success\n", out)
	require.NotNil(t, srv.createReq)
	assert.Equal(t, uint64(7), srv.createReq.GetProfileId())
	assert.Equal(t, "s3cret", srv.createReq.GetPassword())
	assert.Equal(t, "alice", srv.createReq.GetUser().GetUsername())
	assert.Equal(t, platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR, srv.createReq.GetUser().GetPrivilege())
	assert.Equal(t, uint32(2), srv.createReq.GetUser().GetChannel())
	assert.True(t, srv.createReq.GetUser().GetEnabled())

	out, err = runBMC(t, jsonFlags, "user", "create", "--profile-id", "7", "--username", "alice", "--role", "user")
	require.NoError(t, err)
	var resp userActionResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, userActionResponse{ProfileID: "7", Action: "create", Username: "alice", Slot: 6, Status: "success"}, resp)
}

func TestDaemonUserDelete(t *testing.T) {
	srv := &inProcBMCServer{users: daemonUsers()}
	table, _ := serveInProcBMC(t, srv)

	out, err := runBMC(t, table, "user", "delete", "--profile-id", "7", "--username", "ops")
	require.NoError(t, err)
	assert.Equal(t, "Profile:  7\nAction:   delete\nUsername: ops\nSlot:     3\nStatus:   success\n", out)
	assert.Equal(t, uint32(3), srv.deleteReq.GetSlot())
}

func TestDaemonUserUpdatePassword(t *testing.T) {
	srv := &inProcBMCServer{users: daemonUsers()}
	table, _ := serveInProcBMC(t, srv)
	withPassword(t, "rotated", nil)

	out, err := runBMC(t, table, "user", "update-password", "--profile-id", "7", "--username", "admin")
	require.NoError(t, err)
	assert.Equal(t, "Profile:  7\nAction:   update-password\nUsername: admin\nSlot:     2\nStatus:   success\n", out)
	assert.Equal(t, uint32(2), srv.passwordReq.GetSlot())
	assert.Equal(t, "rotated", srv.passwordReq.GetPassword())
}

func TestDaemonUserUpdateAccess(t *testing.T) {
	srv := &inProcBMCServer{users: daemonUsers()}
	table, jsonFlags := serveInProcBMC(t, srv)

	out, err := runBMC(t, table, "user", "update-access", "--profile-id", "7", "--username", "ops", "--role", "callback", "--channel", "4")
	require.NoError(t, err)
	assert.Equal(t, "Profile:  7\nAction:   update-access\nUsername: ops\nSlot:     3\nRole:     callback\nStatus:   success\n", out)
	assert.Equal(t, uint32(3), srv.privReq.GetSlot())
	assert.Equal(t, uint32(4), srv.privReq.GetChannel())
	assert.Equal(t, platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_CALLBACK, srv.privReq.GetPrivilege())

	out, err = runBMC(t, jsonFlags, "user", "update-access", "--profile-id", "7", "--username", "ops", "--role", "no-access")
	require.NoError(t, err)
	var resp userActionResponse
	require.NoError(t, json.Unmarshal([]byte(out), &resp))
	assert.Equal(t, userActionResponse{ProfileID: "7", Action: "update-access", Username: "ops", Slot: 3, Status: "success", Message: "privilege changed to no-access"}, resp)
}

func TestDaemonUser_ServerErrors(t *testing.T) {
	tests := []struct {
		args   []string
		action string
	}{
		{[]string{"user", "list", "--profile-id", "7"}, "list"},
		{[]string{"user", "create", "--profile-id", "7", "--username", "a", "--role", "user"}, "create"},
		{[]string{"user", "delete", "--profile-id", "7", "--username", "admin"}, "list"},
		{[]string{"user", "update-password", "--profile-id", "7", "--username", "admin"}, "list"},
		{[]string{"user", "update-access", "--profile-id", "7", "--username", "admin", "--role", "user"}, "list"},
	}
	for _, tt := range tests {
		t.Run(tt.args[1], func(t *testing.T) {
			table, _ := serveInProcBMC(t, &inProcBMCServer{err: status.Error(codes.Unavailable, "bmc offline")})
			withPassword(t, "pw", nil)
			out, err := runBMC(t, table, tt.args...)
			var failed *bmcsvc.ErrUserFailed
			require.ErrorAs(t, err, &failed)
			assert.Equal(t, tt.action, failed.Action)
			assert.Equal(t, uint64(7), failed.ProfileID)
			assert.Empty(t, out)
		})
	}
}

func TestDaemonUser_MutationErrors(t *testing.T) {
	tests := []struct {
		args   []string
		action string
	}{
		{[]string{"user", "delete", "--profile-id", "7", "--username", "admin"}, "delete"},
		{[]string{"user", "update-password", "--profile-id", "7", "--username", "admin"}, "set-password"},
		{[]string{"user", "update-access", "--profile-id", "7", "--username", "admin", "--role", "user"}, "set-privilege"},
	}
	for _, tt := range tests {
		t.Run(tt.args[1], func(t *testing.T) {
			srv := &inProcBMCServer{users: daemonUsers(), mutateErr: status.Error(codes.Internal, "bmc refused")}
			table, _ := serveInProcBMC(t, srv)
			withPassword(t, "pw", nil)
			_, err := runBMC(t, table, tt.args...)
			var failed *bmcsvc.ErrUserFailed
			require.ErrorAs(t, err, &failed)
			assert.Equal(t, tt.action, failed.Action)
		})
	}
}

func TestDaemonUser_UnknownUsername(t *testing.T) {
	for _, args := range [][]string{
		{"user", "delete", "--profile-id", "7", "--username", "ghost"},
		{"user", "update-password", "--profile-id", "7", "--username", "ghost"},
		{"user", "update-access", "--profile-id", "7", "--username", "ghost", "--role", "user"},
	} {
		t.Run(args[1], func(t *testing.T) {
			srv := &inProcBMCServer{users: daemonUsers()}
			table, _ := serveInProcBMC(t, srv)
			withPassword(t, "pw", nil)
			_, err := runBMC(t, table, args...)
			require.ErrorIs(t, err, ErrUserNotFound{Username: "ghost"})
			assert.Nil(t, srv.deleteReq)
			assert.Nil(t, srv.passwordReq)
			assert.Nil(t, srv.privReq)
		})
	}
}

func TestDaemonUser_ValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want error
	}{
		{"list no profile", []string{"user", "list"}, ErrProfileIDRequired{}},
		{"create no profile", []string{"user", "create", "--username", "a", "--role", "user"}, ErrProfileIDRequired{}},
		{"create no username", []string{"user", "create", "--profile-id", "7", "--role", "user"}, ErrUsernameRequired{}},
		{"create no role", []string{"user", "create", "--profile-id", "7", "--username", "a"}, ErrRoleRequired{}},
		{"create bad role", []string{"user", "create", "--profile-id", "7", "--username", "a", "--role", "root"}, ErrInvalidRole{Role: "root"}},
		{"delete no profile", []string{"user", "delete", "--username", "a"}, ErrProfileIDRequired{}},
		{"delete no username", []string{"user", "delete", "--profile-id", "7"}, ErrUsernameRequired{}},
		{"update-password no profile", []string{"user", "update-password", "--username", "a"}, ErrProfileIDRequired{}},
		{"update-password no username", []string{"user", "update-password", "--profile-id", "7"}, ErrUsernameRequired{}},
		{"update-access no profile", []string{"user", "update-access", "--username", "a", "--role", "user"}, ErrProfileIDRequired{}},
		{"update-access no username", []string{"user", "update-access", "--profile-id", "7", "--role", "user"}, ErrUsernameRequired{}},
		{"update-access no role", []string{"user", "update-access", "--profile-id", "7", "--username", "a"}, ErrRoleRequired{}},
		{"update-access bad role", []string{"user", "update-access", "--profile-id", "7", "--username", "a", "--role", "root"}, ErrInvalidRole{Role: "root"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runBMC(t, tableGetFlags(), tt.args...)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestDaemonUser_ProfileIDParseErrors(t *testing.T) {
	for _, args := range [][]string{
		{"user", "list"},
		{"user", "create", "--username", "a", "--role", "user"},
		{"user", "delete", "--username", "a"},
		{"user", "update-password", "--username", "a"},
		{"user", "update-access", "--username", "a", "--role", "user"},
	} {
		t.Run(args[1], func(t *testing.T) {
			_, err := runBMC(t, tableGetFlags(), withArgs(args, "--profile-id", "seven")...)
			var parseErr ErrProfileIDParseFailed
			require.ErrorAs(t, err, &parseErr)
			assert.Equal(t, "seven", parseErr.Value)
		})
	}
}

func TestDaemonUser_PasswordPromptErrors(t *testing.T) {
	for _, args := range [][]string{
		{"user", "create", "--profile-id", "7", "--username", "a", "--role", "user"},
		{"user", "update-password", "--profile-id", "7", "--username", "admin"},
	} {
		t.Run(args[1], func(t *testing.T) {
			srv := &inProcBMCServer{users: daemonUsers()}
			table, _ := serveInProcBMC(t, srv)
			withPassword(t, "", nil)
			_, err := runBMC(t, table, args...)
			require.ErrorIs(t, err, ErrPasswordRequired{})
			assert.Nil(t, srv.createReq)
			assert.Nil(t, srv.passwordReq)
		})
	}
}

// --- helpers ---------------------------------------------------------------

func TestParseRole(t *testing.T) {
	tests := []struct {
		in       string
		wantSDK  bmcsvc.Privilege
		wantBMC  bmc.Privilege
		accepted bool
	}{
		{"administrator", bmcsvc.PrivilegeAdministrator, bmc.PrivilegeAdministrator, true},
		{" Operator ", bmcsvc.PrivilegeOperator, bmc.PrivilegeOperator, true},
		{"USER", bmcsvc.PrivilegeUser, bmc.PrivilegeUser, true},
		{"callback", bmcsvc.PrivilegeCallback, bmc.PrivilegeCallback, true},
		{"no-access", bmcsvc.PrivilegeNoAccess, bmc.PrivilegeNoAccess, true},
		// Regression: standalone mode rejected no_access while daemon mode took it.
		{"no_access", bmcsvc.PrivilegeNoAccess, bmc.PrivilegeNoAccess, true},
		{"root", "", 0, false},
		{"", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			sdkPriv, ok := parseRole(tt.in)
			assert.Equal(t, tt.accepted, ok)
			assert.Equal(t, tt.wantSDK, sdkPriv)

			bmcPriv, ok := parseRoleToBMCPrivilege(tt.in)
			assert.Equal(t, tt.accepted, ok)
			assert.Equal(t, tt.wantBMC, bmcPriv)
		})
	}
}

func TestBMCUsersToSDK(t *testing.T) {
	assert.Nil(t, bmcUsersToSDK(nil))

	got := bmcUsersToSDK([]bmc.User{
		{Slot: 1, Username: "cb", Enabled: true, Privilege: bmc.PrivilegeCallback, Channel: 2},
		{Slot: 2, Username: "u", Privilege: bmc.PrivilegeUser, Channel: 1},
		{Slot: 3, Username: "none", Privilege: bmc.PrivilegeNoAccess, Channel: 1},
		{Slot: 4, Username: "odd", Privilege: bmc.Privilege(0x09), Channel: 1},
	})
	assert.Equal(t, []bmcsvc.User{
		{Slot: 1, Username: "cb", Enabled: true, Privilege: bmcsvc.PrivilegeCallback, Channel: 2},
		{Slot: 2, Username: "u", Privilege: bmcsvc.PrivilegeUser, Channel: 1},
		{Slot: 3, Username: "none", Privilege: bmcsvc.PrivilegeNoAccess, Channel: 1},
		{Slot: 4, Username: "odd", Privilege: bmcsvc.PrivilegeUnspecified, Channel: 1},
	}, got)
}

func TestPromptPassword(t *testing.T) {
	withPassword(t, "hunter2", nil)
	got, err := promptPassword("pw: ")
	require.NoError(t, err)
	assert.Equal(t, "hunter2", got)
}
