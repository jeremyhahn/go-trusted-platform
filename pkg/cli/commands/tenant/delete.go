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

// NewDeleteCommand creates the tenant delete subcommand
func NewDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <tenant-name>",
		Short: "Delete a tenant",
		Long: `Delete a tenant and all associated resources.

WARNING: This operation is destructive and cannot be undone.
All resources associated with this tenant will be deleted, including:
  - VLAN allocations
  - OVS bridges and network configurations
  - Resource quotas and usage data

Examples:
  # Delete a tenant
  platformctl tenant delete my-tenant

  # Force delete without confirmation (for scripting)
  platformctl tenant delete my-tenant --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantDelete(flags, args[0], force)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "skip confirmation prompt")

	return cmd
}

func runTenantDelete(flags *cli.CommonFlags, tenantName string, force bool) error {
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

	// Delete the tenant
	if err := tenantClient.Delete(ctx, t.ID); err != nil {
		return ErrOperationFailed{
			Operation: "delete",
			TenantID:  t.ID,
			Err:       err,
		}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := &DeleteTenantResponse{
			TenantID:   t.ID,
			TenantName: tenantName,
			Success:    true,
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant %s deleted successfully", tenantName))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// DeleteTenantResponse represents the delete response
type DeleteTenantResponse struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	Success    bool   `json:"success" yaml:"success"`
}
