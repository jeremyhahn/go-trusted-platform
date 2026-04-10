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

// NewBridgeCommand creates the tenant bridge subcommand
func NewBridgeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bridge <tenant-name>",
		Short: "Show tenant bridge status",
		Long: `Display OVS bridge status for a tenant.

Each tenant has a dedicated OVS bridge for network isolation:
  - Bridge name follows the pattern: br-tenant-{tenant-name}
  - The bridge enforces VLAN isolation
  - Traffic is controlled via OpenFlow rules

Examples:
  # Show bridge status for a tenant
  platformctl tenant bridge my-tenant

  # Output as JSON
  platformctl tenant bridge my-tenant -o json

  # Output as YAML
  platformctl tenant bridge my-tenant -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantBridge(flags, args[0])
		},
	}

	return cmd
}

// bridgeStateMessages maps tenant states to user-facing bridge status messages.
var bridgeStateMessages = map[sdktenant.TenantState]struct {
	message string
	info    bool // true for PrintInfo, false for PrintWarning
}{
	sdktenant.StateActive:    {message: "Bridge is active and forwarding traffic", info: true},
	sdktenant.StateSuspended: {message: "Bridge is suspended - traffic is blocked", info: false},
	sdktenant.StatePending:   {message: "Bridge is pending activation", info: true},
	sdktenant.StateDeleting:  {message: "Bridge is being deleted", info: false},
}

func runTenantBridge(flags *cli.CommonFlags, tenantName string) error {
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

	// Set default bridge name if not set
	bridgeName := t.OVSBridge
	if bridgeName == "" {
		bridgeName = "br-tenant-" + t.Name
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(toBridgeInfo(t))

	case cli.OutputFormatTable:
		fmt.Printf("Bridge status for tenant: %s\n\n", tenantName)
		printer.PrintKeyValue("Tenant ID", t.ID)
		printer.PrintKeyValue("Tenant Name", t.Name)
		fmt.Println()
		printer.PrintKeyValue("Bridge Name", bridgeName)
		printer.PrintKeyValue("State", formatState(t.State))

		if t.VLANStart > 0 && t.VLANEnd > 0 {
			fmt.Println()
			fmt.Println("VLAN Configuration:")
			printer.PrintKeyValue("  VLAN Range", formatVLANRange(t.VLANStart, t.VLANEnd))
			printer.PrintKeyValue("  VLAN Count", fmt.Sprintf("%d", t.VLANEnd-t.VLANStart+1))
		}

		fmt.Println()
		if msg, ok := bridgeStateMessages[t.State]; ok {
			if msg.info {
				printer.PrintInfo(msg.message)
			} else {
				printer.PrintWarning(msg.message)
			}
		} else {
			printer.PrintKeyValue("Bridge State", string(t.State))
		}

		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
