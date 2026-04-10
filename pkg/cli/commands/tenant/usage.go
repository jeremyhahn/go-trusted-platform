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

// NewUsageCommand creates the tenant usage subcommand
func NewUsageCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "usage <tenant-name>",
		Short: "Show tenant resource usage",
		Long: `Display current resource usage for a tenant.

Shows quota limits for:
  - Compute: VMs, containers, vCPUs, memory
  - Network: bridges, ports
  - Storage: volumes, snapshots

Note: Actual usage tracking requires querying tenant usage metrics separately.

Examples:
  # Show usage for a tenant
  platformctl tenant usage my-tenant

  # Output as JSON
  platformctl tenant usage my-tenant -o json

  # Output as YAML
  platformctl tenant usage my-tenant -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantUsage(flags, args[0])
		},
	}

	return cmd
}

func runTenantUsage(flags *cli.CommonFlags, tenantName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create tenant service client from the platform client
	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	ctx := context.Background()

	// Get the tenant by name using domain-typed method
	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(toUsageSummary(t.ID, t))

	case cli.OutputFormatTable:
		fmt.Printf("Resource quotas for tenant: %s\n\n", tenantName)
		if t.ComputeQuota != nil {
			printComputeQuotaTable(printer, t.ComputeQuota)
		}
		fmt.Println()
		if t.NetworkQuota != nil {
			printNetworkQuotaTable(printer, t.NetworkQuota)
		}
		fmt.Println()
		if t.StorageQuota != nil {
			printStorageQuotaTable(printer, t.StorageQuota)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printComputeQuotaTable prints compute quota as a table from domain types.
func printComputeQuotaTable(printer *cli.Printer, quota *sdktenant.ComputeQuota) {
	fmt.Println("Compute Quotas:")

	table := cli.NewTableData("RESOURCE", "MAX")
	table.AddRow("VMs", formatQuotaLimit(quota.MaxVMs))
	table.AddRow("Containers", formatQuotaLimit(quota.MaxContainers))
	table.AddRow("vCPUs", formatQuotaLimit(quota.MaxVCPUs))
	table.AddRow("Memory (MB)", formatQuotaLimit(quota.MaxMemoryMB))

	printer.Print(*table)
}

// printNetworkQuotaTable prints network quota as a table from domain types.
func printNetworkQuotaTable(printer *cli.Printer, quota *sdktenant.NetworkQuota) {
	fmt.Println("Network Quotas:")

	table := cli.NewTableData("RESOURCE", "MAX")
	table.AddRow("Bridges", formatQuotaLimit(quota.MaxBridges))
	table.AddRow("Ports", formatQuotaLimit(quota.MaxPorts))

	printer.Print(*table)
}

// printStorageQuotaTable prints storage quota as a table from domain types.
func printStorageQuotaTable(printer *cli.Printer, quota *sdktenant.StorageQuota) {
	fmt.Println("Storage Quotas:")

	table := cli.NewTableData("RESOURCE", "MAX")
	table.AddRow("Volumes (GB)", formatQuotaLimit(quota.MaxVolumesGB))
	table.AddRow("Snapshots", formatQuotaLimit(quota.MaxSnapshots))

	printer.Print(*table)
}

// formatQuotaLimit formats a quota limit value
func formatQuotaLimit(limit int64) string {
	if limit <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", limit)
}
