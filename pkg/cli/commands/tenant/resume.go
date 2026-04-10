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

// NewResumeCommand creates the tenant resume subcommand
func NewResumeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "resume <tenant-name>",
		Short: "Resume a suspended tenant",
		Long: `Resume a suspended tenant, restoring network traffic and resource operations.

When a tenant is resumed:
  - Network traffic through the OVS bridge is restored
  - Resource creation is re-enabled
  - All existing resources become accessible again

Examples:
  # Resume a suspended tenant
  platformctl tenant resume my-tenant

  # Output as JSON
  platformctl tenant resume my-tenant -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantResume(flags, args[0])
		},
	}

	return cmd
}

func runTenantResume(flags *cli.CommonFlags, tenantName string) error {
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

	// Resume the tenant
	if err := tenantClient.Resume(ctx, t.ID); err != nil {
		return ErrOperationFailed{
			Operation: "resume",
			TenantID:  t.ID,
			Err:       err,
		}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		output := &ResumeTenantResponse{
			TenantID:   t.ID,
			TenantName: tenantName,
			State:      "active",
			Success:    true,
		}
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant %s resumed successfully", tenantName))
		printer.PrintInfo("Network traffic has been restored")
		printer.PrintInfo("Resource operations are now enabled")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// ResumeTenantResponse represents the resume response
type ResumeTenantResponse struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	State      string `json:"state" yaml:"state"`
	Success    bool   `json:"success" yaml:"success"`
}
