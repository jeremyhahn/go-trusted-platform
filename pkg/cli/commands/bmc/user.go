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
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// userFlags holds flags for user subcommands.
type userFlags struct {
	profileID string
	username  string
	role      string
	slot      uint32
	channel   uint32
}

// newUserCommand creates the user subcommand group for BMC user management.
func newUserCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage BMC user accounts",
		Long: `Manage BMC user accounts via IPMI or Redfish.

Provides commands to list, create, delete, and modify BMC user accounts
and their access privileges.

Examples:
  # List all BMC users
  platformctl bmc user list --profile-id 1

  # Create a new user
  platformctl bmc user create --profile-id 1 \
    --username operator1 --role operator

  # Delete a user
  platformctl bmc user delete --profile-id 1 --username operator1

  # Update a user's password
  platformctl bmc user update-password --profile-id 1 --username operator1

  # Update a user's access level
  platformctl bmc user update-access --profile-id 1 \
    --username operator1 --role administrator`,
	}

	cmd.AddCommand(newUserListCommand(getFlags))
	cmd.AddCommand(newUserCreateCommand(getFlags))
	cmd.AddCommand(newUserDeleteCommand(getFlags))
	cmd.AddCommand(newUserUpdatePasswordCommand(getFlags))
	cmd.AddCommand(newUserUpdateAccessCommand(getFlags))

	return cmd
}

// newUserListCommand creates the user list subcommand.
func newUserListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags userFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List BMC users",
		Long: `List all populated BMC user account slots.

Examples:
  # Via platformd
  platformctl bmc user list --profile-id 1

  # Direct standalone
  platformctl bmc user list \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneUserList(cmd, &standalone, getFlags)
			}
			return runUserList(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newUserCreateCommand creates the user create subcommand.
func newUserCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags userFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a BMC user",
		Long: `Create a new BMC user account. The password will be prompted securely.

Valid roles: administrator, operator, user, callback, no-access

Examples:
  # Via platformd
  platformctl bmc user create --profile-id 1 \
    --username operator1 --role operator

  # Direct standalone with specific slot
  platformctl bmc user create \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass \
    --username operator1 --role operator --slot 5`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneUserCreate(cmd, &standalone, &flags, getFlags)
			}
			return runUserCreate(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	cmd.Flags().StringVar(&flags.username, "username", "", "BMC username (required)")
	cmd.Flags().StringVar(&flags.role, "role", "", "User role: administrator, operator, user, callback, no-access (required)")
	cmd.Flags().Uint32Var(&flags.slot, "slot", 0, "IPMI user slot (0 = auto-assign)")
	cmd.Flags().Uint32Var(&flags.channel, "channel", 1, "IPMI channel index")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newUserDeleteCommand creates the user delete subcommand.
func newUserDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags userFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a BMC user",
		Long: `Delete a BMC user account by username. The user slot is resolved
from the username by listing accounts first.

Examples:
  # Via platformd
  platformctl bmc user delete --profile-id 1 --username operator1

  # Direct standalone
  platformctl bmc user delete \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass \
    --username operator1`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneUserDelete(cmd, &standalone, &flags, getFlags)
			}
			return runUserDelete(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	cmd.Flags().StringVar(&flags.username, "username", "", "BMC username to delete (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newUserUpdatePasswordCommand creates the user update-password subcommand.
func newUserUpdatePasswordCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags userFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "update-password",
		Short: "Update a BMC user password",
		Long: `Update the password for a BMC user account. The new password will be
prompted securely via the terminal.

Examples:
  # Via platformd
  platformctl bmc user update-password --profile-id 1 --username operator1

  # Direct standalone
  platformctl bmc user update-password \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass \
    --username operator1`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneUserUpdatePassword(cmd, &standalone, &flags, getFlags)
			}
			return runUserUpdatePassword(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	cmd.Flags().StringVar(&flags.username, "username", "", "BMC username (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newUserUpdateAccessCommand creates the user update-access subcommand.
func newUserUpdateAccessCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags userFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "update-access",
		Short: "Update a BMC user access level",
		Long: `Update the privilege level for a BMC user account.

Valid roles: administrator, operator, user, callback, no-access

Examples:
  # Via platformd
  platformctl bmc user update-access --profile-id 1 \
    --username operator1 --role administrator

  # Direct standalone
  platformctl bmc user update-access \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass \
    --username operator1 --role administrator`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneUserUpdateAccess(cmd, &standalone, &flags, getFlags)
			}
			return runUserUpdateAccess(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	cmd.Flags().StringVar(&flags.username, "username", "", "BMC username (required)")
	cmd.Flags().StringVar(&flags.role, "role", "", "New role: administrator, operator, user, callback, no-access (required)")
	cmd.Flags().Uint32Var(&flags.channel, "channel", 1, "IPMI channel index")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// =============================================================================
// Daemon-mode implementations (SDK client via gRPC)
// =============================================================================

// runUserList lists BMC users via the SDK.
func runUserList(flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	commonFlags := getFlags()
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().BMC()
	if grpcClient == nil {
		return ErrBMCClientNotInitialized{}
	}

	sdkClient := bmcsvc.NewClientFromGRPC(grpcClient)

	ctx := base.Context()
	users, err := sdkClient.ListUsers(ctx, profileID)
	if err != nil {
		return err
	}

	return printUserList(commonFlags, users)
}

// runUserCreate creates a BMC user via the SDK.
func runUserCreate(flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	if flags.username == "" {
		return ErrUsernameRequired{}
	}
	if flags.role == "" {
		return ErrRoleRequired{}
	}

	priv, ok := parseRole(flags.role)
	if !ok {
		return ErrInvalidRole{Role: flags.role}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	password, err := promptPassword("New BMC password: ")
	if err != nil {
		return err
	}

	commonFlags := getFlags()
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().BMC()
	if grpcClient == nil {
		return ErrBMCClientNotInitialized{}
	}

	sdkClient := bmcsvc.NewClientFromGRPC(grpcClient)

	user := &bmcsvc.User{
		Slot:      flags.slot,
		Username:  flags.username,
		Enabled:   true,
		Privilege: priv,
		Channel:   flags.channel,
	}

	ctx := base.Context()
	slot, err := sdkClient.CreateUser(ctx, profileID, user, password)
	if err != nil {
		return err
	}

	resp := userActionResponse{
		ProfileID: flags.profileID,
		Action:    "create",
		Username:  flags.username,
		Slot:      slot,
		Status:    "success",
	}

	done, emitErr := emitJSON(getFlags, resp)
	if emitErr != nil || done {
		return emitErr
	}

	fmt.Fprintf(os.Stdout, "Profile:  %s\nAction:   create\nUsername: %s\nSlot:     %d\nStatus:   success\n",
		resp.ProfileID, resp.Username, resp.Slot)
	return nil
}

// runUserDelete deletes a BMC user via the SDK.
func runUserDelete(flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	if flags.username == "" {
		return ErrUsernameRequired{}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	commonFlags := getFlags()
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().BMC()
	if grpcClient == nil {
		return ErrBMCClientNotInitialized{}
	}

	sdkClient := bmcsvc.NewClientFromGRPC(grpcClient)
	ctx := base.Context()

	// Resolve username to slot
	slot, err := resolveUserSlot(ctx, sdkClient, profileID, flags.username)
	if err != nil {
		return err
	}

	if err := sdkClient.DeleteUser(ctx, profileID, slot); err != nil {
		return err
	}

	resp := userActionResponse{
		ProfileID: flags.profileID,
		Action:    "delete",
		Username:  flags.username,
		Slot:      slot,
		Status:    "success",
	}

	done, emitErr := emitJSON(getFlags, resp)
	if emitErr != nil || done {
		return emitErr
	}

	fmt.Fprintf(os.Stdout, "Profile:  %s\nAction:   delete\nUsername: %s\nSlot:     %d\nStatus:   success\n",
		resp.ProfileID, resp.Username, resp.Slot)
	return nil
}

// runUserUpdatePassword updates a BMC user password via the SDK.
func runUserUpdatePassword(flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	if flags.username == "" {
		return ErrUsernameRequired{}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	password, err := promptPassword("New BMC password: ")
	if err != nil {
		return err
	}

	commonFlags := getFlags()
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().BMC()
	if grpcClient == nil {
		return ErrBMCClientNotInitialized{}
	}

	sdkClient := bmcsvc.NewClientFromGRPC(grpcClient)
	ctx := base.Context()

	slot, err := resolveUserSlot(ctx, sdkClient, profileID, flags.username)
	if err != nil {
		return err
	}

	if err := sdkClient.SetUserPassword(ctx, profileID, slot, password); err != nil {
		return err
	}

	resp := userActionResponse{
		ProfileID: flags.profileID,
		Action:    "update-password",
		Username:  flags.username,
		Slot:      slot,
		Status:    "success",
	}

	done, emitErr := emitJSON(getFlags, resp)
	if emitErr != nil || done {
		return emitErr
	}

	fmt.Fprintf(os.Stdout, "Profile:  %s\nAction:   update-password\nUsername: %s\nSlot:     %d\nStatus:   success\n",
		resp.ProfileID, resp.Username, resp.Slot)
	return nil
}

// runUserUpdateAccess updates a BMC user privilege via the SDK.
func runUserUpdateAccess(flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	if flags.username == "" {
		return ErrUsernameRequired{}
	}
	if flags.role == "" {
		return ErrRoleRequired{}
	}

	priv, ok := parseRole(flags.role)
	if !ok {
		return ErrInvalidRole{Role: flags.role}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	commonFlags := getFlags()
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().BMC()
	if grpcClient == nil {
		return ErrBMCClientNotInitialized{}
	}

	sdkClient := bmcsvc.NewClientFromGRPC(grpcClient)
	ctx := base.Context()

	slot, err := resolveUserSlot(ctx, sdkClient, profileID, flags.username)
	if err != nil {
		return err
	}

	if err := sdkClient.SetUserPrivilege(ctx, profileID, slot, flags.channel, priv); err != nil {
		return err
	}

	resp := userActionResponse{
		ProfileID: flags.profileID,
		Action:    "update-access",
		Username:  flags.username,
		Slot:      slot,
		Status:    "success",
		Message:   "privilege changed to " + flags.role,
	}

	done, emitErr := emitJSON(getFlags, resp)
	if emitErr != nil || done {
		return emitErr
	}

	fmt.Fprintf(os.Stdout, "Profile:  %s\nAction:   update-access\nUsername: %s\nSlot:     %d\nRole:     %s\nStatus:   success\n",
		resp.ProfileID, resp.Username, resp.Slot, flags.role)
	return nil
}

// =============================================================================
// Standalone-mode implementations (direct BMC client)
// =============================================================================

// runStandaloneUserList lists BMC users via standalone mode.
func runStandaloneUserList(cmd *cobra.Command, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneUserManager(cmd, standalone, func(mgr bmc.UserManager) error {
		ctx := cmd.Context()
		users, err := mgr.ListUsers(ctx)
		if err != nil {
			return err
		}

		sdkUsers := bmcUsersToSDK(users)
		return printUserList(getFlags(), sdkUsers)
	})
}

// runStandaloneUserCreate creates a BMC user via standalone mode.
func runStandaloneUserCreate(cmd *cobra.Command, standalone *standaloneBMCFlags, flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.username == "" {
		return ErrUsernameRequired{}
	}
	if flags.role == "" {
		return ErrRoleRequired{}
	}

	bmcPriv, ok := parseRoleToBMCPrivilege(flags.role)
	if !ok {
		return ErrInvalidRole{Role: flags.role}
	}

	passwordStr, err := promptPassword("New BMC password: ")
	if err != nil {
		return err
	}

	return withStandaloneUserManager(cmd, standalone, func(mgr bmc.UserManager) error {
		ctx := cmd.Context()

		pw := memguard.NewFromString(passwordStr)
		defer pw.Destroy()

		user := bmc.User{
			Slot:      uint8(flags.slot),
			Username:  flags.username,
			Enabled:   true,
			Privilege: bmcPriv,
			Channel:   uint8(flags.channel),
		}

		if err := mgr.CreateUser(ctx, user, pw); err != nil {
			return err
		}

		resp := userActionResponse{
			ProfileID: standalone.host,
			Action:    "create",
			Username:  flags.username,
			Slot:      flags.slot,
			Status:    "success",
		}

		done, emitErr := emitJSON(getFlags, resp)
		if emitErr != nil || done {
			return emitErr
		}

		fmt.Fprintf(os.Stdout, "Host:     %s\nAction:   create\nUsername: %s\nSlot:     %d\nStatus:   success\n",
			resp.ProfileID, resp.Username, resp.Slot)
		return nil
	})
}

// runStandaloneUserDelete deletes a BMC user via standalone mode.
func runStandaloneUserDelete(cmd *cobra.Command, standalone *standaloneBMCFlags, flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.username == "" {
		return ErrUsernameRequired{}
	}

	return withStandaloneUserManager(cmd, standalone, func(mgr bmc.UserManager) error {
		ctx := cmd.Context()

		slot, err := resolveStandaloneUserSlot(ctx, mgr, flags.username)
		if err != nil {
			return err
		}

		if err := mgr.DeleteUser(ctx, slot); err != nil {
			return err
		}

		resp := userActionResponse{
			ProfileID: standalone.host,
			Action:    "delete",
			Username:  flags.username,
			Slot:      uint32(slot),
			Status:    "success",
		}

		done, emitErr := emitJSON(getFlags, resp)
		if emitErr != nil || done {
			return emitErr
		}

		fmt.Fprintf(os.Stdout, "Host:     %s\nAction:   delete\nUsername: %s\nSlot:     %d\nStatus:   success\n",
			resp.ProfileID, resp.Username, resp.Slot)
		return nil
	})
}

// runStandaloneUserUpdatePassword updates a BMC user password via standalone mode.
func runStandaloneUserUpdatePassword(cmd *cobra.Command, standalone *standaloneBMCFlags, flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.username == "" {
		return ErrUsernameRequired{}
	}

	passwordStr, err := promptPassword("New BMC password: ")
	if err != nil {
		return err
	}

	return withStandaloneUserManager(cmd, standalone, func(mgr bmc.UserManager) error {
		ctx := cmd.Context()

		slot, err := resolveStandaloneUserSlot(ctx, mgr, flags.username)
		if err != nil {
			return err
		}

		pw := memguard.NewFromString(passwordStr)
		defer pw.Destroy()

		if err := mgr.SetUserPassword(ctx, slot, pw); err != nil {
			return err
		}

		resp := userActionResponse{
			ProfileID: standalone.host,
			Action:    "update-password",
			Username:  flags.username,
			Slot:      uint32(slot),
			Status:    "success",
		}

		done, emitErr := emitJSON(getFlags, resp)
		if emitErr != nil || done {
			return emitErr
		}

		fmt.Fprintf(os.Stdout, "Host:     %s\nAction:   update-password\nUsername: %s\nSlot:     %d\nStatus:   success\n",
			resp.ProfileID, resp.Username, resp.Slot)
		return nil
	})
}

// runStandaloneUserUpdateAccess updates a BMC user privilege via standalone mode.
func runStandaloneUserUpdateAccess(cmd *cobra.Command, standalone *standaloneBMCFlags, flags *userFlags, getFlags func() *cli.CommonFlags) error {
	if flags.username == "" {
		return ErrUsernameRequired{}
	}
	if flags.role == "" {
		return ErrRoleRequired{}
	}

	bmcPriv, ok := parseRoleToBMCPrivilege(flags.role)
	if !ok {
		return ErrInvalidRole{Role: flags.role}
	}

	return withStandaloneUserManager(cmd, standalone, func(mgr bmc.UserManager) error {
		ctx := cmd.Context()

		slot, err := resolveStandaloneUserSlot(ctx, mgr, flags.username)
		if err != nil {
			return err
		}

		if err := mgr.SetUserPrivilege(ctx, slot, uint8(flags.channel), bmcPriv); err != nil {
			return err
		}

		resp := userActionResponse{
			ProfileID: standalone.host,
			Action:    "update-access",
			Username:  flags.username,
			Slot:      uint32(slot),
			Status:    "success",
			Message:   "privilege changed to " + flags.role,
		}

		done, emitErr := emitJSON(getFlags, resp)
		if emitErr != nil || done {
			return emitErr
		}

		fmt.Fprintf(os.Stdout, "Host:     %s\nAction:   update-access\nUsername: %s\nSlot:     %d\nRole:     %s\nStatus:   success\n",
			resp.ProfileID, resp.Username, resp.Slot, flags.role)
		return nil
	})
}

// =============================================================================
// Shared helpers
// =============================================================================

// withStandaloneUserManager creates a standalone UserManager and runs fn.
func withStandaloneUserManager(cmd *cobra.Command, standalone *standaloneBMCFlags, fn func(bmc.UserManager) error) error {
	pw, err := loadStandalonePassword(standalone)
	if err != nil {
		return err
	}

	if standalone.user == "" {
		return ErrBMCMissingCredential{Field: "username (set --bmc-user)"}
	}

	cfg := &bmc.Config{
		Address:       standalone.host,
		Port:          standalone.port,
		Protocol:      bmc.Protocol(standalone.protocol),
		Username:      standalone.user,
		Password:      pw,
		SkipTLSVerify: standalone.skipTLSVerify,
	}

	mgr, err := bmc.NewUserManager(cmd.Context(), cfg, standaloneLogger())
	if err != nil {
		return err
	}
	defer mgr.Close()

	return fn(mgr)
}

// resolveUserSlot finds the IPMI slot for a username by listing users.
func resolveUserSlot(ctx context.Context, client *bmcsvc.Client, profileID uint64, username string) (uint32, error) {
	users, err := client.ListUsers(ctx, profileID)
	if err != nil {
		return 0, err
	}
	for _, u := range users {
		if u.Username == username {
			return u.Slot, nil
		}
	}
	return 0, ErrBMCMissingCredential{Field: "user " + username + " not found"}
}

// resolveStandaloneUserSlot finds the IPMI slot for a username via standalone UserManager.
func resolveStandaloneUserSlot(ctx context.Context, mgr bmc.UserManager, username string) (uint8, error) {
	users, err := mgr.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	for _, u := range users {
		if u.Username == username {
			return u.Slot, nil
		}
	}
	return 0, ErrBMCMissingCredential{Field: "user " + username + " not found"}
}

// parseRole maps a CLI role name to an SDK Privilege.
func parseRole(role string) (bmcsvc.Privilege, bool) {
	normalized := strings.ToUpper(strings.TrimSpace(role))
	// Map CLI-friendly names to SDK privilege values
	roleMap := map[string]bmcsvc.Privilege{
		"ADMINISTRATOR": bmcsvc.PrivilegeAdministrator,
		"OPERATOR":      bmcsvc.PrivilegeOperator,
		"USER":          bmcsvc.PrivilegeUser,
		"CALLBACK":      bmcsvc.PrivilegeCallback,
		"NO-ACCESS":     bmcsvc.PrivilegeNoAccess,
		"NO_ACCESS":     bmcsvc.PrivilegeNoAccess,
	}
	priv, ok := roleMap[normalized]
	return priv, ok
}

// parseRoleToBMCPrivilege maps a CLI role name to a bmc.Privilege.
func parseRoleToBMCPrivilege(role string) (bmc.Privilege, bool) {
	normalized := strings.ToLower(strings.TrimSpace(role))
	roleMap := map[string]bmc.Privilege{
		"administrator": bmc.PrivilegeAdministrator,
		"operator":      bmc.PrivilegeOperator,
		"user":          bmc.PrivilegeUser,
		"callback":      bmc.PrivilegeCallback,
		"no-access":     bmc.PrivilegeNoAccess,
	}
	priv, ok := roleMap[normalized]
	return priv, ok
}

// bmcUsersToSDK converts bmc.User slice to SDK User slice.
func bmcUsersToSDK(users []bmc.User) []bmcsvc.User {
	if len(users) == 0 {
		return nil
	}
	result := make([]bmcsvc.User, len(users))
	privMap := map[bmc.Privilege]bmcsvc.Privilege{
		bmc.PrivilegeAdministrator: bmcsvc.PrivilegeAdministrator,
		bmc.PrivilegeOperator:      bmcsvc.PrivilegeOperator,
		bmc.PrivilegeUser:          bmcsvc.PrivilegeUser,
		bmc.PrivilegeCallback:      bmcsvc.PrivilegeCallback,
		bmc.PrivilegeNoAccess:      bmcsvc.PrivilegeNoAccess,
	}
	for i, u := range users {
		priv := bmcsvc.PrivilegeUnspecified
		if p, ok := privMap[u.Privilege]; ok {
			priv = p
		}
		result[i] = bmcsvc.User{
			Slot:      uint32(u.Slot),
			Username:  u.Username,
			Enabled:   u.Enabled,
			Privilege: priv,
			Channel:   uint32(u.Channel),
		}
	}
	return result
}

// printUserList prints the user list in the appropriate format.
func printUserList(flags *cli.CommonFlags, users []bmcsvc.User) error {
	if flags != nil && flags.OutputFormat == cli.OutputFormatJSON {
		return encodeJSON(os.Stdout, users)
	}

	if len(users) == 0 {
		fmt.Fprintln(os.Stdout, "No users found")
		return nil
	}

	fmt.Fprintf(os.Stdout, "%-6s %-20s %-9s %-16s %-8s\n", "SLOT", "USERNAME", "ENABLED", "PRIVILEGE", "CHANNEL")
	fmt.Fprintf(os.Stdout, "%-6s %-20s %-9s %-16s %-8s\n", "----", "--------", "-------", "---------", "-------")
	for _, u := range users {
		enabled := "yes"
		if !u.Enabled {
			enabled = "no"
		}
		fmt.Fprintf(os.Stdout, "%-6d %-20s %-9s %-16s %-8d\n",
			u.Slot, u.Username, enabled, strings.ToLower(string(u.Privilege)), u.Channel)
	}
	return nil
}

// promptPassword prompts the user for a password securely via the terminal.
func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", ErrPasswordRequired{}
	}
	return string(raw), nil
}
