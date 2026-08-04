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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	iamsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/iam"
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

Examples:
  # Register a web application
  platformctl iam app register --tenant my-tenant --name "My Web App" \
    --redirect-uris "https://app.example.com/callback" \
    --grant-types "authorization_code,refresh_token"

  # Register a machine-to-machine application
  platformctl iam app register --tenant my-tenant --name "API Service" \
    --grant-types "client_credentials" \
    --resource-prefix "api"`,
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
		Args:  cobra.ExactArgs(2),
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
		Args:  cobra.ExactArgs(2),
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
		Args:  cobra.ExactArgs(2),
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

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	app, err := sdkClient.RegisterAppDomain(ctx, tenantID, name,
		parseStringSlice(redirectURIs), parseStringSlice(grantTypes),
		parseStringSlice(responseTypes), resourcePrefix)
	if err != nil {
		return &WrappedError{Msg: "failed to register application", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(app)

	case cli.OutputFormatTable:
		if app != nil {
			printer.PrintSuccess(fmt.Sprintf("Application registered successfully: %s", app.Name))
			fmt.Println()
			printAppDetails(printer, app)
			// Show client secret prominently since it's only shown once
			if app.ClientSecret != "" {
				fmt.Println()
				printer.PrintWarning("IMPORTANT: Save this client secret securely. It will not be shown again.")
				printer.PrintKeyValue("Client Secret", app.ClientSecret)
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

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	app, err := sdkClient.GetAppDomain(ctx, tenantID, clientID)
	if err != nil {
		return &WrappedError{Msg: "failed to get application", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(app)

	case cli.OutputFormatTable:
		if app != nil {
			printAppDetails(printer, app)
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

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.ListAppsDomain(ctx, tenantID, page, pageSize)
	if err != nil {
		return &WrappedError{Msg: "failed to list applications", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if len(result.Apps) == 0 {
			printer.PrintInfo("No applications found")
			return nil
		}

		table := cli.NewTableData("Client ID", "Name", "Grant Types", "Redirect URIs", "Created At")
		for _, app := range result.Apps {
			table.AddRow(
				truncateString(app.ClientID, 20),
				truncateString(app.Name, 25),
				truncateString(formatStringSlice(app.GrantTypes), 30),
				truncateString(formatStringSlice(app.RedirectURIs), 40),
				formatAppTimestamp(app.CreatedAt),
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

// runAppUpdate executes the app update command
func runAppUpdate(flags *cli.CommonFlags, tenantID, clientID, name, redirectURIs, grantTypes, responseTypes, resourcePrefix string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	app, err := sdkClient.UpdateAppDomain(ctx, tenantID, clientID, name,
		parseStringSlice(redirectURIs), parseStringSlice(grantTypes),
		parseStringSlice(responseTypes), resourcePrefix)
	if err != nil {
		return &WrappedError{Msg: "failed to update application", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(app)

	case cli.OutputFormatTable:
		if app != nil {
			printer.PrintSuccess(fmt.Sprintf("Application updated successfully: %s", app.Name))
			fmt.Println()
			printAppDetails(printer, app)
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

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	status, err := sdkClient.DeleteAppDomain(ctx, tenantID, clientID)
	if err != nil {
		return &WrappedError{Msg: "failed to delete application", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
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

	sdkClient := iamsvc.NewClientFromGRPC(base.Client().IAM())
	ctx := base.Context()

	result, err := sdkClient.RotateAppSecretDomain(ctx, tenantID, clientID)
	if err != nil {
		return &WrappedError{Msg: "failed to rotate application secret", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Client secret rotated successfully for: %s", result.Name))
		fmt.Println()
		printer.PrintKeyValue("Client ID", result.ClientID)
		printer.PrintKeyValue("Name", result.Name)
		if result.ClientSecret != "" {
			fmt.Println()
			printer.PrintWarning("IMPORTANT: Save this new client secret securely. It will not be shown again.")
			printer.PrintKeyValue("New Client Secret", result.ClientSecret)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printAppDetails prints detailed application information in table format
func printAppDetails(printer *cli.Printer, app *iamsvc.App) {
	printer.PrintKeyValue("Client ID", app.ClientID)
	printer.PrintKeyValue("Name", app.Name)
	printer.PrintKeyValue("Tenant ID", app.TenantID)
	printer.PrintKeyValue("Redirect URIs", formatStringSlice(app.RedirectURIs))
	printer.PrintKeyValue("Grant Types", formatStringSlice(app.GrantTypes))
	printer.PrintKeyValue("Response Types", formatStringSlice(app.ResponseTypes))
	if app.ResourcePrefix != "" {
		printer.PrintKeyValue("Resource Prefix", app.ResourcePrefix)
	}
	printer.PrintKeyValue("Created At", formatAppTimestamp(app.CreatedAt))
	if app.UpdatedAt != nil {
		printer.PrintKeyValue("Updated At", formatTimestampPtr(app.UpdatedAt))
	}
}

// formatAppTimestamp formats a time.Time for display
func formatAppTimestamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}
