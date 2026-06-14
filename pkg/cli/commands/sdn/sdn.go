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

// Package sdn provides CLI commands for SDN networking operations.
package sdn

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// defaultCLITimeout is the context deadline for all SDN CLI operations.
const defaultCLITimeout = 30 * time.Second

// newCLIContext returns a context with the default CLI timeout and its
// cancel function. Callers must defer cancel().
func newCLIContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultCLITimeout)
}

// NewCommand creates the root sdn command
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sdn",
		Short: "SDN networking operations",
		Long: `Software-defined networking operations including bridge, port, flow, VLAN,
overlay, gateway, IPAM, and policy management.

The SDN subsystem provides:
  - Bridge management for OVS, Linux, and VXLAN bridges
  - Port operations including state and statistics monitoring
  - OpenFlow flow rule management
  - VLAN creation and lifecycle management
  - Overlay networking with VXLAN tunnels for east-west VM/container traffic
  - Gateway nodes supporting overlay, edge, and transit modes
  - BGP integration for EVPN and IP block announcements
  - IPAM for IP address management across pools
  - Network policy enforcement (ACL, QoS, NAT, firewall, routing)

Examples:
  # Bridge operations
  platformctl sdn bridge create --id br0 --name my-bridge --type ovs
  platformctl sdn bridge list

  # Port operations
  platformctl sdn port add --bridge br0 --id port1 --name eth0 --type internal
  platformctl sdn port stats --bridge br0 port1

  # Flow operations
  platformctl sdn flow add --bridge br0 --id flow1 --table 0 --priority 100 --action output
  platformctl sdn flow list --bridge br0

  # VLAN operations
  platformctl sdn vlan create --id 100 --name prod-vlan
  platformctl sdn vlan list

  # Overlay operations
  platformctl sdn overlay status
  platformctl sdn overlay vtep list

  # Gateway operations
  platformctl sdn gateway status

  # IPAM operations
  platformctl sdn ipam pool list

  # Policy operations
  platformctl sdn policy apply --id pol1 --name block-external --type acl --priority 100
  platformctl sdn policy list`,
	}

	// Add subcommands
	cmd.AddCommand(NewBridgeCommand(getFlags))
	cmd.AddCommand(NewPortCommand(getFlags))
	cmd.AddCommand(NewFlowCommand(getFlags))
	cmd.AddCommand(NewVLANCommand(getFlags))
	cmd.AddCommand(NewOverlayCommand(getFlags))
	cmd.AddCommand(NewGatewayCommand(getFlags))
	cmd.AddCommand(NewIPAMCommand(getFlags))
	cmd.AddCommand(NewZoneCommand(getFlags))
	cmd.AddCommand(NewPolicyCommand(getFlags))

	return cmd
}
