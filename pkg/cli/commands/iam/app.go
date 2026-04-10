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
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewAppCommand creates the application (OAuth client) management command group
func NewAppCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Manage OAuth applications",
		Long: `Manage OAuth applications (clients) including registration, updates, and secret rotation.

Supported operations:
  - register: Register a new OAuth application
  - get: Retrieve application details
  - list: List applications in a tenant
  - update: Update application properties
  - delete: Delete an application
  - rotate-secret: Rotate an application's client secret`,
	}

	cmd.AddCommand(newAppRegisterCommand(getFlags))
	cmd.AddCommand(newAppGetCommand(getFlags))
	cmd.AddCommand(newAppListCommand(getFlags))
	cmd.AddCommand(newAppUpdateCommand(getFlags))
	cmd.AddCommand(newAppDeleteCommand(getFlags))
	cmd.AddCommand(newAppRotateSecretCommand(getFlags))

	return cmd
}

// newAppRegisterCommand creates the app register subcommand
func newAppRegisterCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var name string
	var redirectURIs string
	var grantTypes string
	var responseTypes string
	var resourcePrefix string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new OAuth application",
		Long: `Register a new OAuth application (client) in the specified tenant.

Grant types specify the OAuth 2.0 flows the application can use:
  - authorization_code: Standard web application flow
  - client_credentials: Machine-to-machine authentication
  - refresh_token: Allow token refresh
  - implicit: Browser-based applications (not recommended)
  - password: Resource owner password grant (not recommended)

Response types specify what the authorization endpoint returns:
  - code: Authorization code (for authorization_code grant)
  - token: Access token (for implicit grant)
  - id_token: OpenID Connect ID token

Examples:
  # Register a web application
  platformctl iam app register --tenant my-tenant --name "My Web App" \
    --redirect-uris "https://app.example.com/callback" \
    --grant-types "authorization_code,refresh_token"

  # Register a machine-to-machine application
  platformctl iam app register --tenant my-tenant --name "API Service" \
    --grant-types "client_credentials" \
    --resource-prefix "api"

  # Register with multiple redirect URIs
  platformctl iam app register --tenant my-tenant --name "Multi-Env App" \
    --redirect-uris "https://app.example.com/callback,https://staging.example.com/callback"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if name == "" {
				return ErrMissingAppName{}
			}
			flags := getFlags()
			return runAppRegister(flags, tenantID, name, redirectURIs, grantTypes, responseTypes, resourcePrefix)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "application name (required)")
	cmd.Flags().StringVar(&redirectURIs, "redirect-uris", "", "comma-separated list of redirect URIs")
	cmd.Flags().StringVar(&grantTypes, "grant-types", "authorization_code", "comma-separated list of grant types")
	cmd.Flags().StringVar(&responseTypes, "response-types", "code", "comma-separated list of response types")
	cmd.Flags().StringVar(&resourcePrefix, "resource-prefix", "", "resource prefix for policy matching")

	return cmd
}

// newAppGetCommand creates the app get subcommand
func newAppGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant-id> <client-id>",
		Short: "Get application information",
		Long: `Retrieve detailed information about a specific OAuth application by tenant ID and client ID.

Examples:
  platformctl iam app get my-tenant abc123-client-id`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runAppGet(flags, args[0], args[1])
		},
	}

	return cmd
}

// newAppListCommand creates the app list subcommand
func newAppListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var page uint32
	var pageSize uint32

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List applications",
		Long: `List OAuth applications in a tenant with optional pagination.

Examples:
  # List all applications in a tenant
  platformctl iam app list --tenant my-tenant

  # List applications with pagination
  platformctl iam app list --tenant my-tenant --page-size 20 --page 1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			flags := getFlags()
			return runAppList(flags, tenantID, page, pageSize)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().Uint32Var(&pageSize, "page-size", 50, "maximum number of applications to return")
	cmd.Flags().Uint32Var(&page, "page", 1, "page number")

	return cmd
}

// newAppUpdateCommand creates the app update subcommand
func newAppUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var tenantID string
	var clientID string
	var name string
	var redirectURIs string
	var grantTypes string
	var responseTypes string
	var resourcePrefix string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an application",
		Long: `Update an existing OAuth application's properties.

Examples:
  # Update application name
  platformctl iam app update --tenant my-tenant --client-id abc123 --name "New Name"

  # Update redirect URIs
  platformctl iam app update --tenant my-tenant --client-id abc123 \
    --redirect-uris "https://new.example.com/callback"

  # Update grant types
  platformctl iam app update --tenant my-tenant --client-id abc123 \
    --grant-types "authorization_code,client_credentials,refresh_token"`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				return ErrMissingTenantID{}
			}
			if clientID == "" {
				return ErrMissingClientID{}
			}
			flags := getFlags()
			return runAppUpdate(flags, tenantID, clientID, name, redirectURIs, grantTypes, responseTypes, resourcePrefix)
		},
	}

	cmd.Flags().StringVar(&tenantID, "tenant", "", "tenant ID (required)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "client ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "new application name")
	cmd.Flags().StringVar(&redirectURIs, "redirect-uris", "", "comma-separated list of redirect URIs")
	cmd.Flags().StringVar(&grantTypes, "grant-types", "", "comma-separated list of grant types")
	cmd.Flags().StringVar(&responseTypes, "response-types", "", "comma-separated list of response types")
	cmd.Flags().StringVar(&resourcePrefix, "resource-prefix", "", "resource prefix for policy matching")

	return cmd
}

// newAppDeleteCommand creates the app delete subcommand
func newAppDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <tenant-id> <client-id>",
		Short: "Delete an application",
		Long: `Delete an OAuth application from the specified tenant.

WARNING: This operation cannot be undone. All tokens issued for this application
will be invalidated.

Examples:
  platformctl iam app delete my-tenant abc123-client-id`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runAppDelete(flags, args[0], args[1])
		},
	}

	return cmd
}

// newAppRotateSecretCommand creates the app rotate-secret subcommand
func newAppRotateSecretCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-secret <tenant-id> <client-id>",
		Short: "Rotate an application's client secret",
		Long: `Rotate the client secret for an OAuth application.

The new secret will be displayed once. Make sure to save it securely as it
cannot be retrieved again.

Examples:
  platformctl iam app rotate-secret my-tenant abc123-client-id`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runAppRotateSecret(flags, args[0], args[1])
		},
	}

	return cmd
}

// runAppRegister executes the app register command
func runAppRegister(flags *cli.CommonFlags, tenantID, name, redirectURIs, grantTypes, responseTypes, resourcePrefix string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.RegisterIAMAppRequest{
		TenantId:       tenantID,
		Name:           name,
		RedirectUris:   parseStringSlice(redirectURIs),
		GrantTypes:     parseStringSlice(grantTypes),
		ResponseTypes:  parseStringSlice(responseTypes),
		ResourcePrefix: resourcePrefix,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().RegisterApp(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to register application: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.App != nil {
			printer.PrintSuccess(fmt.Sprintf("Application registered successfully: %s", resp.App.Name))
			fmt.Println()
			printAppDetails(printer, resp.App)
			// Show client secret prominently since it's only shown once
			if resp.App.ClientSecret != "" {
				fmt.Println()
				printer.PrintWarning("IMPORTANT: Save this client secret securely. It will not be shown again.")
				printer.PrintKeyValue("Client Secret", resp.App.ClientSecret)
			}
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runAppGet executes the app get command
func runAppGet(flags *cli.CommonFlags, tenantID, clientID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.GetIAMAppRequest{
		TenantId: tenantID,
		ClientId: clientID,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().GetApp(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to get application: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.App != nil {
			printAppDetails(printer, resp.App)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runAppList executes the app list command
func runAppList(flags *cli.CommonFlags, tenantID string, page, pageSize uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.ListIAMAppsRequest{
		TenantId: tenantID,
		Pagination: &platformv1.PaginationRequest{
			Page:     page,
			PageSize: pageSize,
		},
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().ListApps(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to list applications: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if len(resp.Apps) == 0 {
			printer.PrintInfo("No applications found")
			return nil
		}

		table := cli.NewTableData("Client ID", "Name", "Grant Types", "Redirect URIs", "Created At")
		for _, app := range resp.Apps {
			table.AddRow(
				truncateString(app.ClientId, 20),
				truncateString(app.Name, 25),
				truncateString(formatStringSlice(app.GrantTypes), 30),
				truncateString(formatStringSlice(app.RedirectUris), 40),
				formatAppTimestamp(app.CreatedAt),
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

// runAppUpdate executes the app update command
func runAppUpdate(flags *cli.CommonFlags, tenantID, clientID, name, redirectURIs, grantTypes, responseTypes, resourcePrefix string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.UpdateIAMAppRequest{
		TenantId:       tenantID,
		ClientId:       clientID,
		Name:           name,
		RedirectUris:   parseStringSlice(redirectURIs),
		GrantTypes:     parseStringSlice(grantTypes),
		ResponseTypes:  parseStringSlice(responseTypes),
		ResourcePrefix: resourcePrefix,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().UpdateApp(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update application: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.App != nil {
			printer.PrintSuccess(fmt.Sprintf("Application updated successfully: %s", resp.App.Name))
			fmt.Println()
			printAppDetails(printer, resp.App)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runAppDelete executes the app delete command
func runAppDelete(flags *cli.CommonFlags, tenantID, clientID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.DeleteIAMAppRequest{
		TenantId: tenantID,
		ClientId: clientID,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().DeleteApp(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to delete application: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("Application deleted successfully: %s", clientID))
		} else {
			printer.PrintWarning(fmt.Sprintf("Application deletion may not have completed: %s", clientID))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runAppRotateSecret executes the app rotate-secret command
func runAppRotateSecret(flags *cli.CommonFlags, tenantID, clientID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	req := &platformv1.RotateIAMAppSecretRequest{
		TenantId: tenantID,
		ClientId: clientID,
	}

	ctx := base.Context()
	resp, err := base.Client().IAM().RotateAppSecret(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to rotate application secret: %w", err)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Client secret rotated successfully for: %s", resp.Name))
		fmt.Println()
		printer.PrintKeyValue("Client ID", resp.ClientId)
		printer.PrintKeyValue("Name", resp.Name)
		if resp.ClientSecret != "" {
			fmt.Println()
			printer.PrintWarning("IMPORTANT: Save this new client secret securely. It will not be shown again.")
			printer.PrintKeyValue("New Client Secret", resp.ClientSecret)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printAppDetails prints detailed application information in table format
func printAppDetails(printer *cli.Printer, app *platformv1.IAMApp) {
	printer.PrintKeyValue("Client ID", app.ClientId)
	printer.PrintKeyValue("Name", app.Name)
	printer.PrintKeyValue("Tenant ID", app.TenantId)
	printer.PrintKeyValue("Redirect URIs", formatStringSlice(app.RedirectUris))
	printer.PrintKeyValue("Grant Types", formatStringSlice(app.GrantTypes))
	printer.PrintKeyValue("Response Types", formatStringSlice(app.ResponseTypes))
	if app.ResourcePrefix != "" {
		printer.PrintKeyValue("Resource Prefix", app.ResourcePrefix)
	}
	printer.PrintKeyValue("Created At", formatAppTimestamp(app.CreatedAt))
	printer.PrintKeyValue("Updated At", formatAppTimestamp(app.UpdatedAt))
}

// formatAppTimestamp formats a timestamp for display
func formatAppTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "-"
	}
	return ts.AsTime().Format(time.RFC3339)
}
