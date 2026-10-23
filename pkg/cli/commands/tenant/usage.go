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
		Long: `Display current resource usage for a tenant beside its quotas.

Shows what is used and the limit for:
  - Compute: VMs, containers, vCPUs, memory
  - Network: bridges, ports, bandwidth
  - Storage: volume space, snapshots

A limit of 0 is shown as unlimited.

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

	usage, err := tenantClient.GetUsage(ctx, t.ID)
	if err != nil {
		return ErrUsageRetrievalFailed{TenantID: t.ID, Err: err}
	}

	summary := toUsageSummary(t, usage)
	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(summary)

	case cli.OutputFormatTable:
		fmt.Printf("Resource usage for tenant: %s\n\n", tenantName)
		return printUsageTable(printer, summary)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printUsageTable prints one row per resource: what is used beside its quota.
func printUsageTable(printer *cli.Printer, s *UsageSummary) error {
	rows := []struct {
		label string
		item  UsageItem
	}{
		{"VMs", s.Compute.VMs},
		{"Containers", s.Compute.Containers},
		{"vCPUs", s.Compute.VCPUs},
		{"Memory (MB)", s.Compute.MemoryMB},
		{"Bridges", s.Network.Bridges},
		{"Ports", s.Network.Ports},
		{"Bandwidth (Mbps)", s.Network.BandwidthMbps},
		{"Volumes (GB)", s.Storage.VolumesGB},
		{"Snapshots", s.Storage.Snapshots},
	}

	table := cli.NewTableData("RESOURCE", "USED", "MAX")
	for _, row := range rows {
		table.AddRow(row.label, fmt.Sprintf("%d", row.item.Used), formatQuotaLimit(row.item.Max))
	}
	return printer.Print(*table)
}

// formatQuotaLimit formats a quota limit value
func formatQuotaLimit(limit int64) string {
	if limit <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d", limit)
}
