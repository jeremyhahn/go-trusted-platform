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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewTenantCommand creates the tenant management command group
func NewTenantCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Manage tenants",
		Long: `Manage tenants in the Identity and Access Management system.

Tenants provide multi-tenancy isolation for users, groups, roles, and policies.
Each tenant can have its own settings including maximum user count and MFA requirements.

Supported operations:
  - create: Create a new tenant
  - get: Retrieve tenant details
  - list: List all tenants
  - update: Update tenant settings
  - delete: Delete a tenant`,
	}

	cmd.AddCommand(newTenantCreateCommand(getFlags))
	cmd.AddCommand(newTenantGetCommand(getFlags))
	cmd.AddCommand(newTenantListCommand(getFlags))
	cmd.AddCommand(newTenantUpdateCommand(getFlags))
	cmd.AddCommand(newTenantDeleteCommand(getFlags))

	return cmd
}

// newTenantCreateCommand creates the tenant create subcommand
func newTenantCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var id string
	var name string
	var maxUsers int32
	var mfaRequired bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new tenant",
		Long: `Create a new tenant with the specified settings.

The tenant ID must be unique and will be used to reference this tenant
in all subsequent operations. The name is a human-readable display name.

Example:
  platformctl iam tenant create --id acme --name "Acme Corporation" --max-users 100 --mfa-required`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return ErrMissingTenantID{}
			}
			flags := getFlags()
			return runTenantCreate(flags, id, name, maxUsers, mfaRequired)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "unique tenant identifier (required)")
	cmd.Flags().StringVar(&name, "name", "", "human-readable tenant name")
	cmd.Flags().Int32Var(&maxUsers, "max-users", 0, "maximum number of users allowed (0 = unlimited)")
	cmd.Flags().BoolVar(&mfaRequired, "mfa-required", false, "require MFA for all users")

	return cmd
}

// newTenantGetCommand creates the tenant get subcommand
func newTenantGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant-id>",
		Short: "Get tenant information",
		Long: `Retrieve information about a specific tenant by its ID.

Example:
  platformctl iam tenant get acme`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantGet(flags, args[0])
		},
	}

	return cmd
}

// newTenantListCommand creates the tenant list subcommand
func newTenantListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var page uint32
	var pageSize uint32

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all tenants",
		Long: `Display a list of all tenants with pagination support.

Example:
  platformctl iam tenant list --page-size 50`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantList(flags, page, pageSize)
		},
	}

	cmd.Flags().Uint32VarP(&page, "page", "p", 1, "page number")
	cmd.Flags().Uint32VarP(&pageSize, "page-size", "s", 50, "maximum number of tenants per page")

	return cmd
}

// newTenantUpdateCommand creates the tenant update subcommand
func newTenantUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var id string
	var name string
	var maxUsers int32
	var mfaRequired bool
	var setMfaRequired bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a tenant",
		Long: `Update an existing tenant's settings.

Only the specified fields will be updated. Use --mfa-required or --no-mfa-required
to explicitly set the MFA requirement.

Example:
  platformctl iam tenant update --id acme --name "Acme Corp Inc" --max-users 200 --mfa-required`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if id == "" {
				return ErrMissingTenantID{}
			}
			// Check if mfa-required flag was explicitly set
			setMfaRequired = cmd.Flags().Changed("mfa-required")
			flags := getFlags()
			return runTenantUpdate(flags, id, name, maxUsers, mfaRequired, setMfaRequired)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "tenant ID to update (required)")
	cmd.Flags().StringVar(&name, "name", "", "new tenant name")
	cmd.Flags().Int32Var(&maxUsers, "max-users", 0, "new maximum user count")
	cmd.Flags().BoolVar(&mfaRequired, "mfa-required", false, "require MFA for all users")

	return cmd
}

// newTenantDeleteCommand creates the tenant delete subcommand
func newTenantDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <tenant-id>",
		Short: "Delete a tenant",
		Long: `Delete a tenant and all associated resources.

WARNING: This operation is destructive and cannot be undone.
All users, groups, roles, and policies associated with this tenant will be deleted.

Example:
  platformctl iam tenant delete acme`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantDelete(flags, args[0])
		},
	}

	return cmd
}

func runTenantCreate(flags *cli.CommonFlags, id, name string, maxUsers int32, mfaRequired bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	settings := &platformv1.IAMTenantSettings{
		MaxUsers:    maxUsers,
		MfaRequired: mfaRequired,
	}

	req := &platformv1.CreateIAMTenantRequest{
		Id:       id,
		Name:     name,
		Settings: settings,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().CreateTenant(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Tenant != nil {
			printer.PrintSuccess(fmt.Sprintf("Tenant created successfully: %s", resp.Tenant.Id))
			fmt.Println()
			printTenantDetails(printer, resp.Tenant)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runTenantGet(flags *cli.CommonFlags, tenantID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.GetIAMTenantRequest{
		TenantId: tenantID,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().GetTenant(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get tenant: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Tenant != nil {
			printTenantDetails(printer, resp.Tenant)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runTenantList(flags *cli.CommonFlags, page, pageSize uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.ListIAMTenantsRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().ListTenants(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to list tenants: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Tenants) == 0 {
			printer.PrintInfo("No tenants found")
			return nil
		}

		table := cli.NewTableData("ID", "Name", "Max Users", "MFA Required", "Created At")
		for _, tenant := range resp.Tenants {
			maxUsersStr := "unlimited"
			mfaStr := "No"
			if tenant.Settings != nil {
				if tenant.Settings.MaxUsers > 0 {
					maxUsersStr = fmt.Sprintf("%d", tenant.Settings.MaxUsers)
				}
				if tenant.Settings.MfaRequired {
					mfaStr = "Yes"
				}
			}
			table.AddRow(
				tenant.Id,
				tenant.Name,
				maxUsersStr,
				mfaStr,
				formatTimestamp(tenant.CreatedAt),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total Count", fmt.Sprintf("%d", resp.Total))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runTenantUpdate(flags *cli.CommonFlags, id, name string, maxUsers int32, mfaRequired, setMfaRequired bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// First get the current tenant to preserve existing settings
	getReq := &platformv1.GetIAMTenantRequest{TenantId: id}
	ctx := base.Context()
	current, err := base.Client().IAM().GetTenant(ctx, getReq)
	if err != nil {
		return fmt.Errorf("failed to get tenant for update: %w", err)
	}

	if current.Tenant == nil {
		return fmt.Errorf("tenant not found: %s", id)
	}

	// Build settings with current values as base
	settings := &platformv1.IAMTenantSettings{}
	if current.Tenant.Settings != nil {
		settings.MaxUsers = current.Tenant.Settings.MaxUsers
		settings.MfaRequired = current.Tenant.Settings.MfaRequired
	}

	// Update only specified fields
	if maxUsers > 0 {
		settings.MaxUsers = maxUsers
	}
	if setMfaRequired {
		settings.MfaRequired = mfaRequired
	}

	// Use current name if not specified
	updateName := current.Tenant.Name
	if name != "" {
		updateName = name
	}

	req := &platformv1.UpdateIAMTenantRequest{
		TenantId: id,
		Name:     updateName,
		Settings: settings,
	}

	resp, err := base.Client().IAM().UpdateTenant(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Tenant != nil {
			printer.PrintSuccess(fmt.Sprintf("Tenant updated successfully: %s", resp.Tenant.Id))
			fmt.Println()
			printTenantDetails(printer, resp.Tenant)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func runTenantDelete(flags *cli.CommonFlags, tenantID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.DeleteIAMTenantRequest{
		TenantId: tenantID,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().DeleteTenant(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("Tenant %s deleted successfully", tenantID))
		} else {
			printer.PrintError(fmt.Sprintf("Failed to delete tenant %s", tenantID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printTenantDetails prints tenant details in a formatted way
func printTenantDetails(printer *cli.Printer, tenant *platformv1.IAMTenant) {
	printer.PrintKeyValue("ID", tenant.Id)
	printer.PrintKeyValue("Name", tenant.Name)
	if tenant.Settings != nil {
		if tenant.Settings.MaxUsers > 0 {
			printer.PrintKeyValue("Max Users", fmt.Sprintf("%d", tenant.Settings.MaxUsers))
		} else {
			printer.PrintKeyValue("Max Users", "unlimited")
		}
		printer.PrintKeyValue("MFA Required", formatBool(tenant.Settings.MfaRequired))
	}
	printer.PrintKeyValue("Created At", formatTimestamp(tenant.CreatedAt))
	if tenant.UpdatedAt != nil {
		printer.PrintKeyValue("Updated At", formatTimestamp(tenant.UpdatedAt))
	}
}
