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

// Package tenant provides CLI commands for tenant management operations
// including quotas, VLANs, bridges, and lifecycle operations.
package tenant

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the tenant root command for tenant management operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Tenant management operations",
		Long: `Manage tenants, quotas, VLANs, and network bridges.

The tenant subsystem provides comprehensive tenant management including:
  - Tenant lifecycle (create, suspend, resume, delete)
  - Quota management (compute, network, storage)
  - Usage monitoring
  - VLAN allocation information
  - OVS bridge status

Tenants provide isolated environments with:
  - Dedicated VLAN ranges for network isolation
  - Per-tenant OVS bridges for SDN
  - Resource quotas for compute, network, and storage
  - TPM-backed data encryption keys (DEK)

Examples:
  # List all tenants
  platformctl tenant list

  # Show tenant details
  platformctl tenant show my-tenant

  # Create a new tenant with quotas
  platformctl tenant create --name my-tenant --max-vms 100 --max-vcpus 400

  # Get tenant quotas
  platformctl tenant quotas get my-tenant

  # Update compute quota
  platformctl tenant quotas set my-tenant --max-vms 200 --max-vcpus 800

  # Get tenant usage
  platformctl tenant usage my-tenant

  # Get tenant VLAN info
  platformctl tenant vlan my-tenant

  # Get tenant bridge status
  platformctl tenant bridge my-tenant

  # Suspend a tenant
  platformctl tenant suspend my-tenant

  # Resume a suspended tenant
  platformctl tenant resume my-tenant`,
	}

	// Add subcommands
	cmd.AddCommand(NewListCommand(getFlags))
	cmd.AddCommand(NewShowCommand(getFlags))
	cmd.AddCommand(NewCreateCommand(getFlags))
	cmd.AddCommand(NewDeleteCommand(getFlags))
	cmd.AddCommand(NewSuspendCommand(getFlags))
	cmd.AddCommand(NewResumeCommand(getFlags))
	cmd.AddCommand(NewQuotasCommand(getFlags))
	cmd.AddCommand(NewUsageCommand(getFlags))
	cmd.AddCommand(NewVLANCommand(getFlags))
	cmd.AddCommand(NewBridgeCommand(getFlags))
	cmd.AddCommand(NewBarrierCommand(getFlags))

	return cmd
}
