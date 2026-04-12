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
	"strings"

	"github.com/spf13/cobra"

	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewRoleCommand creates the role management command group
func NewRoleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Manage roles",
		Long: `Manage roles including creation, listing, and permission assignment.

Supported operations:
  - create: Create a new role
  - get: Retrieve role details
  - list: List all roles in a tenant
  - update: Update role properties
  - delete: Delete a role`,
	}

	cmd.AddCommand(newRoleCreateCommand(getFlags))
	cmd.AddCommand(newRoleGetCommand(getFlags))
	cmd.AddCommand(newRoleListCommand(getFlags))
	cmd.AddCommand(newRoleUpdateCommand(getFlags))
	cmd.AddCommand(newRoleDeleteCommand(getFlags))

	return cmd
}

// newRoleCreateCommand creates the role create subcommand
func newRoleCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var name string
	var description string
	var permissions []string

	cmd := &cobra.Command{
		Use:   "create <role-id>",
		Short: "Create a new role",
		Long: `Create a new role within a tenant.

The role ID must be unique within the tenant. Permissions are specified as a
comma-separated list of permission strings.

Examples:
  platformctl iam role create admin --tenant my-tenant --name "Administrator" --permissions "read,write,delete"
  platformctl iam role create viewer --tenant my-tenant --name "Viewer" --permissions "read"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRoleCreate(flags, tenantID, args[0], name, description, permissions)
		},
	}

	cmd.Flags().StringVarP(&tenantID, "tenant", "t", "", "tenant ID (required)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "role display name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "role description")
	cmd.Flags().StringSliceVarP(&permissions, "permissions", "p", nil, "comma-separated list of permissions")

	if err := cmd.MarkFlagRequired("tenant"); err != nil {
		panic(fmt.Sprintf("failed to mark tenant flag required: %v", err))
	}

	return cmd
}

// newRoleGetCommand creates the role get subcommand
func newRoleGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant-id> <role-id>",
		Short: "Get role details",
		Long:  "Retrieve detailed information about a specific role",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRoleGet(flags, args[0], args[1])
		},
	}

	return cmd
}

// newRoleListCommand creates the role list subcommand
func newRoleListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var page uint32
	var pageSize uint32

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all roles",
		Long:  "Display a list of all roles within a tenant with pagination support",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRoleList(flags, tenantID, page, pageSize)
		},
	}

	cmd.Flags().StringVarP(&tenantID, "tenant", "t", "", "tenant ID (required)")
	cmd.Flags().Uint32VarP(&page, "page", "p", 1, "page number")
	cmd.Flags().Uint32VarP(&pageSize, "page-size", "s", 50, "maximum number of roles per page")

	if err := cmd.MarkFlagRequired("tenant"); err != nil {
		panic(fmt.Sprintf("failed to mark tenant flag required: %v", err))
	}

	return cmd
}

// newRoleUpdateCommand creates the role update subcommand
func newRoleUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var name string
	var description string
	var permissions []string

	cmd := &cobra.Command{
		Use:   "update <role-id>",
		Short: "Update a role",
		Long: `Update an existing role's properties.

Examples:
  platformctl iam role update admin --tenant my-tenant --name "Super Admin" --permissions "read,write,delete,admin"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRoleUpdate(flags, tenantID, args[0], name, description, permissions)
		},
	}

	cmd.Flags().StringVarP(&tenantID, "tenant", "t", "", "tenant ID (required)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "new role display name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "new role description")
	cmd.Flags().StringSliceVarP(&permissions, "permissions", "p", nil, "comma-separated list of permissions")

	if err := cmd.MarkFlagRequired("tenant"); err != nil {
		panic(fmt.Sprintf("failed to mark tenant flag required: %v", err))
	}

	return cmd
}

// newRoleDeleteCommand creates the role delete subcommand
func newRoleDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <tenant-id> <role-id>",
		Short: "Delete a role",
		Long:  "Delete an existing role from a tenant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRoleDelete(flags, args[0], args[1])
		},
	}

	return cmd
}

func runRoleCreate(flags *cli.CommonFlags, tenantID, roleID, name, description string, permissions []string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	role, err := sdkClient.CreateRoleDomain(ctx, tenantID, roleID, name, description, permissions)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(role)

	case cli.OutputFormatTable:
		if role != nil {
			printer.PrintSuccess(fmt.Sprintf("Role created successfully: %s", role.ID))
			fmt.Println()
			printRoleDetails(printer, role)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runRoleGet(flags *cli.CommonFlags, tenantID, roleID string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}
	if roleID == "" {
		return ErrMissingRoleID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	role, err := sdkClient.GetRoleDomain(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(role)

	case cli.OutputFormatTable:
		if role != nil {
			printRoleDetails(printer, role)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runRoleList(flags *cli.CommonFlags, tenantID string, page, pageSize uint32) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.ListRolesDomain(ctx, tenantID, page, pageSize)
	if err != nil {
		return fmt.Errorf("failed to list roles: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if len(result.Roles) == 0 {
			printer.PrintInfo("No roles found")
			return nil
		}

		table := cli.NewTableData("Role ID", "Name", "Description", "Permissions", "Created At")
		for _, role := range result.Roles {
			permDisplay := formatPermissions(role.Permissions)
			table.AddRow(
				role.ID,
				role.Name,
				truncateString(role.Description, 30),
				permDisplay,
				formatTimestamp(role.CreatedAt),
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

func runRoleUpdate(flags *cli.CommonFlags, tenantID, roleID, name, description string, permissions []string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}
	if roleID == "" {
		return ErrMissingRoleID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	role, err := sdkClient.UpdateRoleDomain(ctx, tenantID, roleID, name, description, permissions)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(role)

	case cli.OutputFormatTable:
		if role != nil {
			printer.PrintSuccess(fmt.Sprintf("Role updated successfully: %s", role.ID))
			fmt.Println()
			printRoleDetails(printer, role)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runRoleDelete(flags *cli.CommonFlags, tenantID, roleID string) error {
	if tenantID == "" {
		return ErrMissingTenantID{}
	}
	if roleID == "" {
		return ErrMissingRoleID{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	status, err := sdkClient.DeleteRoleDomain(ctx, tenantID, roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("Role deleted successfully: %s", roleID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to delete role: %s", roleID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printRoleDetails prints detailed information about a role
func printRoleDetails(printer *cli.Printer, role *iamsvc.Role) {
	printer.PrintKeyValue("Role ID", role.ID)
	printer.PrintKeyValue("Tenant ID", role.TenantID)
	if role.Name != "" {
		printer.PrintKeyValue("Name", role.Name)
	}
	if role.Description != "" {
		printer.PrintKeyValue("Description", role.Description)
	}
	if len(role.Permissions) > 0 {
		printer.PrintKeyValue("Permissions", strings.Join(role.Permissions, ", "))
	} else {
		printer.PrintKeyValue("Permissions", "(none)")
	}
	printer.PrintKeyValue("Created At", formatTimestamp(role.CreatedAt))
	if role.UpdatedAt != nil {
		printer.PrintKeyValue("Updated At", formatTimestampPtr(role.UpdatedAt))
	}
}

// formatPermissions formats permissions for table display
func formatPermissions(permissions []string) string {
	if len(permissions) == 0 {
		return "(none)"
	}
	if len(permissions) <= 3 {
		return strings.Join(permissions, ", ")
	}
	return strings.Join(permissions[:3], ", ") + fmt.Sprintf(" (+%d more)", len(permissions)-3)
}
