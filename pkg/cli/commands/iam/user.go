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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
)

// NewUserCommand creates the user management command group
func NewUserCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage users",
		Long: `Manage users including creation, retrieval, updates, and role assignments.

Supported operations:
  - create: Create a new user
  - get: Retrieve user details
  - list: List users in a tenant
  - update: Update user properties
  - delete: Delete a user
  - assign-role: Assign a role to a user
  - revoke-role: Revoke a role from a user`,
	}

	cmd.AddCommand(newUserCreateCommand(getFlags))
	cmd.AddCommand(newUserGetCommand(getFlags))
	cmd.AddCommand(newUserListCommand(getFlags))
	cmd.AddCommand(newUserUpdateCommand(getFlags))
	cmd.AddCommand(newUserDeleteCommand(getFlags))
	cmd.AddCommand(newUserAssignRoleCommand(getFlags))
	cmd.AddCommand(newUserRevokeRoleCommand(getFlags))

	return cmd
}

// newUserCreateCommand creates the user create subcommand
func newUserCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var email string
	var name string
	var roles string
	var attributes string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new user",
		Long: `Create a new user in the specified tenant.

Examples:
  # Create a basic user
  platformctl iam user create --tenant my-tenant --email user@example.com --name "John Doe"

  # Create a user with roles
  platformctl iam user create --tenant my-tenant --email admin@example.com --name "Admin User" --roles "admin,viewer"

  # Create a user with custom attributes
  platformctl iam user create --tenant my-tenant --email user@example.com --name "Jane Doe" --attributes "department=engineering,level=senior"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if email == "" {
				return ErrMissingEmail{}
			}
			flags := getFlags()
			return runUserCreate(flags, tenantID, email, name, roles, attributes)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&email, "email", "", "user email address (required)")
	cmd.Flags().StringVar(&name, "name", "", "user display name")
	cmd.Flags().StringVar(&roles, "roles", "", "comma-separated list of roles to assign")
	cmd.Flags().StringVar(&attributes, "attributes", "", "comma-separated key=value pairs for custom attributes")

	return cmd
}

// newUserGetCommand creates the user get subcommand
func newUserGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant-id> <user-id>",
		Short: "Get user information",
		Long:  "Retrieve detailed information about a specific user by tenant ID and user ID",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUserGet(flags, args[0], args[1])
		},
	}

	return cmd
}

// newUserListCommand creates the user list subcommand
func newUserListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var page uint32
	var pageSize uint32

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List users",
		Long: `List users in a tenant with optional filtering and pagination.

Examples:
  # List all users in a tenant
  platformctl iam user list --tenant my-tenant

  # List users with pagination
  platformctl iam user list --tenant my-tenant --page 1 --page-size 20`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			flags := getFlags()
			return runUserList(flags, tenantID, page, pageSize)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().Uint32VarP(&page, "page", "p", 1, "page number")
	cmd.Flags().Uint32VarP(&pageSize, "page-size", "s", 50, "maximum number of users per page")

	return cmd
}

// newUserUpdateCommand creates the user update subcommand
func newUserUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var userID string
	var email string
	var name string
	var roles string
	var attributes string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a user",
		Long: `Update an existing user's properties.

Examples:
  # Update user name
  platformctl iam user update --tenant my-tenant --user-id user-123 --name "Updated Name"

  # Update user roles
  platformctl iam user update --tenant my-tenant --user-id user-123 --roles "admin,editor"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if userID == "" {
				return ErrMissingUserID{}
			}
			flags := getFlags()
			return runUserUpdate(flags, tenantID, userID, email, name, roles, attributes)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&userID, "user-id", "", "user ID to update (required)")
	cmd.Flags().StringVar(&email, "email", "", "new email address")
	cmd.Flags().StringVar(&name, "name", "", "new display name")
	cmd.Flags().StringVar(&roles, "roles", "", "comma-separated list of roles (replaces existing)")
	cmd.Flags().StringVar(&attributes, "attributes", "", "comma-separated key=value pairs (replaces existing)")

	return cmd
}

// newUserDeleteCommand creates the user delete subcommand
func newUserDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <tenant-id> <user-id>",
		Short: "Delete a user",
		Long:  "Delete a user from the specified tenant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUserDelete(flags, args[0], args[1])
		},
	}

	return cmd
}

// newUserAssignRoleCommand creates the user assign-role subcommand
func newUserAssignRoleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "assign-role <tenant-id> <user-id> <role>",
		Short: "Assign a role to a user",
		Long: `Assign a role to an existing user.

Examples:
  # Assign admin role to a user
  platformctl iam user assign-role my-tenant user-123 admin`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUserAssignRole(flags, args[0], args[1], args[2])
		},
	}

	return cmd
}

// newUserRevokeRoleCommand creates the user revoke-role subcommand
func newUserRevokeRoleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke-role <tenant-id> <user-id> <role>",
		Short: "Revoke a role from a user",
		Long: `Revoke a previously assigned role from a user.

Examples:
  # Revoke admin role from a user
  platformctl iam user revoke-role my-tenant user-123 admin`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUserRevokeRole(flags, args[0], args[1], args[2])
		},
	}

	return cmd
}

func runUserCreate(flags *cli.CommonFlags, tenantID, email, name, roles, attributes string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	user, err := sdkClient.CreateUserDomain(ctx, tenantID, email, name,
		parseStringSlice(roles), parseAttributes(attributes))
	if err != nil {
		return &WrappedError{Msg: "failed to create user", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(user)

	case cli.OutputFormatTable:
		if user != nil {
			printer.PrintSuccess(fmt.Sprintf("User created successfully: %s", user.ID))
			fmt.Println()
			printUserDetails(printer, user)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runUserGet(flags *cli.CommonFlags, tenantID, userID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	user, err := sdkClient.GetUserDomain(ctx, tenantID, userID)
	if err != nil {
		return &WrappedError{Msg: "failed to get user", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(user)

	case cli.OutputFormatTable:
		if user != nil {
			printUserDetails(printer, user)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runUserList(flags *cli.CommonFlags, tenantID string, page, pageSize uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.ListUsersDomain(ctx, tenantID, page, pageSize)
	if err != nil {
		return &WrappedError{Msg: "failed to list users", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if len(result.Users) == 0 {
			printer.PrintInfo("No users found")
			return nil
		}

		table := cli.NewTableData("ID", "Email", "Name", "Roles", "MFA", "Created At")
		for _, user := range result.Users {
			table.AddRow(
				user.ID,
				user.Email,
				truncateString(user.Name, 25),
				truncateString(formatStringSlice(user.Roles), 30),
				formatBool(user.MfaVerified),
				formatTimestamp(user.CreatedAt),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total Count", fmt.Sprintf("%d", result.Total))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runUserUpdate(flags *cli.CommonFlags, tenantID, userID, email, name, roles, attributes string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	user, err := sdkClient.UpdateUserDomain(ctx, tenantID, userID, email, name,
		parseStringSlice(roles), parseAttributes(attributes))
	if err != nil {
		return &WrappedError{Msg: "failed to update user", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(user)

	case cli.OutputFormatTable:
		if user != nil {
			printer.PrintSuccess(fmt.Sprintf("User updated successfully: %s", user.ID))
			fmt.Println()
			printUserDetails(printer, user)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runUserDelete(flags *cli.CommonFlags, tenantID, userID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	status, err := sdkClient.DeleteUserDomain(ctx, tenantID, userID)
	if err != nil {
		return &WrappedError{Msg: "failed to delete user", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("User %s deleted successfully", userID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to delete user %s", userID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runUserAssignRole(flags *cli.CommonFlags, tenantID, userID, role string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	status, err := sdkClient.AssignRoleDomain(ctx, tenantID, userID, role)
	if err != nil {
		return &WrappedError{Msg: "failed to assign role", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("Role '%s' assigned to user %s", role, userID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to assign role '%s' to user %s", role, userID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runUserRevokeRole(flags *cli.CommonFlags, tenantID, userID, role string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	status, err := sdkClient.RevokeRoleDomain(ctx, tenantID, userID, role)
	if err != nil {
		return &WrappedError{Msg: "failed to revoke role", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("Role '%s' revoked from user %s", role, userID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to revoke role '%s' from user %s", role, userID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printUserDetails(printer *cli.Printer, user *iamsvc.User) {
	printer.PrintKeyValue("User ID", user.ID)
	printer.PrintKeyValue("Tenant ID", user.TenantID)
	printer.PrintKeyValue("Email", user.Email)
	if user.Name != "" {
		printer.PrintKeyValue("Name", user.Name)
	}
	printer.PrintKeyValue("Roles", formatStringSlice(user.Roles))
	if len(user.Attributes) > 0 {
		printer.PrintKeyValue("Attributes", formatAttributes(user.Attributes))
	}
	printer.PrintKeyValue("MFA Verified", formatBool(user.MfaVerified))
	printer.PrintKeyValue("Created At", formatTimestamp(user.CreatedAt))
	if user.UpdatedAt != nil {
		printer.PrintKeyValue("Updated At", formatTimestampPtr(user.UpdatedAt))
	}
	if user.LastAuth != nil {
		printer.PrintKeyValue("Last Auth", formatTimestampPtr(user.LastAuth))
	}
}
