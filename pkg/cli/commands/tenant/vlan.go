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

// NewVLANCommand creates the tenant vlan subcommand
func NewVLANCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vlan <tenant-name>",
		Short: "Show tenant VLAN allocation",
		Long: `Display VLAN allocation information for a tenant.

Each tenant is allocated a range of VLAN IDs for network isolation.
The VLAN range is used by the OVS bridge to tag and isolate tenant traffic.

Examples:
  # Show VLAN info for a tenant
  platformctl tenant vlan my-tenant

  # Output as JSON
  platformctl tenant vlan my-tenant -o json

  # Output as YAML
  platformctl tenant vlan my-tenant -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantVLAN(flags, args[0])
		},
	}

	return cmd
}

func runTenantVLAN(flags *cli.CommonFlags, tenantName string) error {
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
		return printer.Print(toVLANInfo(t))

	case cli.OutputFormatTable:
		fmt.Printf("VLAN allocation for tenant: %s\n\n", tenantName)
		printer.PrintKeyValue("Tenant ID", t.ID)
		printer.PrintKeyValue("Tenant Name", t.Name)
		fmt.Println()

		if t.VLANStart > 0 || t.VLANEnd > 0 {
			printer.PrintKeyValue("VLAN Start", fmt.Sprintf("%d", t.VLANStart))
			printer.PrintKeyValue("VLAN End", fmt.Sprintf("%d", t.VLANEnd))
			printer.PrintKeyValue("VLAN Count", fmt.Sprintf("%d", t.VLANEnd-t.VLANStart+1))
			fmt.Println()
			printer.PrintKeyValue("Range String", formatVLANRange(t.VLANStart, t.VLANEnd))
			printer.PrintInfo(fmt.Sprintf("VLANs %d through %d are allocated to this tenant",
				t.VLANStart, t.VLANEnd))
		} else {
			printer.PrintKeyValue("VLAN Start", "N/A")
			printer.PrintKeyValue("VLAN End", "N/A")
			printer.PrintKeyValue("VLAN Count", "0")
			fmt.Println()
			printer.PrintWarning("No VLAN range allocated")
		}

		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
