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

package tenant

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// NewSuspendCommand creates the tenant suspend subcommand
func NewSuspendCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suspend <tenant-name>",
		Short: "Suspend a tenant",
		Long: `Suspend a tenant, blocking all network traffic and resource operations.

When a tenant is suspended:
  - All network traffic through the OVS bridge is blocked
  - No new resources can be created
  - Existing resources remain but become inaccessible
  - The tenant can be resumed to restore access

Use this command for:
  - Temporary maintenance
  - Security incidents
  - Billing issues

Examples:
  # Suspend a tenant
  platformctl tenant suspend my-tenant

  # Output as JSON
  platformctl tenant suspend my-tenant -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantSuspend(flags, args[0])
		},
	}

	return cmd
}

func runTenantSuspend(flags *cli.CommonFlags, tenantName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create tenant service client from the platform client
	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	ctx := context.Background()

	// First get the tenant by name to get the ID using domain-typed method
	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	// Suspend the tenant
	if err := tenantClient.Suspend(ctx, t.ID); err != nil {
		return ErrOperationFailed{
			Operation: "suspend",
			TenantID:  t.ID,
			Err:       err,
		}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := &SuspendTenantResponse{
			TenantID:   t.ID,
			TenantName: tenantName,
			State:      "suspended",
			Success:    true,
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant %s suspended successfully", tenantName))
		printer.PrintInfo("All network traffic has been blocked")
		printer.PrintInfo("Use 'platformctl tenant resume' to restore access")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// SuspendTenantResponse represents the suspend response
type SuspendTenantResponse struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	State      string `json:"state" yaml:"state"`
	Success    bool   `json:"success" yaml:"success"`
}
