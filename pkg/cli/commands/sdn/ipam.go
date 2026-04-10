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

package sdn

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// NewIPAMCommand creates the ipam subcommand
func NewIPAMCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ipam",
		Short: "IPAM operations",
		Long: `IP Address Management for network pools.

IPAM provides:
  - Pool management for IPv4 and IPv6 address ranges
  - Automatic allocation with lease tracking
  - Integration with DHCP for dynamic assignment
  - Multiple backends (memory, QuicBaaS, DHT)

Examples:
  # List all pools
  platformctl sdn ipam pool list

  # Allocate an IP
  platformctl sdn ipam allocate --pool-id pool1 --device-id vm-123

  # Release an IP
  platformctl sdn ipam release --ip 10.0.0.5`,
	}

	cmd.AddCommand(newIPAMPoolCommand(getFlags))
	cmd.AddCommand(newIPAMAllocateCommand(getFlags))
	cmd.AddCommand(newIPAMReleaseCommand(getFlags))
	cmd.AddCommand(newIPAMAllocationsCommand(getFlags))

	return cmd
}

func newIPAMPoolCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pool",
		Short: "Pool operations",
		Long:  "Manage IPAM pools",
	}

	// pool list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List pools",
		Long: `List all IPAM pools.

Shows:
  - Pool ID and CIDR
  - Gateway address
  - Total, allocated, and available addresses

Examples:
  platformctl sdn ipam pool list
  platformctl sdn ipam pool list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIPAMPoolList(getFlags())
		},
	}

	cmd.AddCommand(listCmd)
	return cmd
}

func newIPAMAllocateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var poolID, deviceID, hostname string

	cmd := &cobra.Command{
		Use:   "allocate",
		Short: "Allocate an IP",
		Long: `Allocate an IP address from a pool.

The allocation is associated with a device ID for tracking.
Optionally specify a hostname for DNS integration.

Examples:
  platformctl sdn ipam allocate --pool-id pool1 --device-id vm-123
  platformctl sdn ipam allocate --pool-id pool1 --device-id vm-123 --hostname webserver`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIPAMAllocate(getFlags(), poolID, deviceID, hostname)
		},
	}

	cmd.Flags().StringVar(&poolID, "pool-id", "", "Pool ID to allocate from (required)")
	cmd.Flags().StringVar(&deviceID, "device-id", "", "Device ID for the allocation (required)")
	cmd.Flags().StringVar(&hostname, "hostname", "", "Optional hostname")
	cmd.MarkFlagRequired("pool-id")
	cmd.MarkFlagRequired("device-id")

	return cmd
}

func newIPAMReleaseCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var ip string

	cmd := &cobra.Command{
		Use:   "release",
		Short: "Release an IP",
		Long: `Release an allocated IP address back to its pool.

Examples:
  platformctl sdn ipam release --ip 10.0.0.5
  platformctl sdn ipam release --ip 2602:F5BB::1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIPAMRelease(getFlags(), ip)
		},
	}

	cmd.Flags().StringVar(&ip, "ip", "", "IP address to release (required)")
	cmd.MarkFlagRequired("ip")

	return cmd
}

func newIPAMAllocationsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var poolID string

	cmd := &cobra.Command{
		Use:   "allocations",
		Short: "List allocations",
		Long: `List IP allocations.

Without --pool-id, lists allocations from all pools.

Examples:
  platformctl sdn ipam allocations
  platformctl sdn ipam allocations --pool-id pool1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIPAMAllocations(getFlags(), poolID)
		},
	}

	cmd.Flags().StringVar(&poolID, "pool-id", "", "Filter by pool ID")

	return cmd
}

// Implementation functions
func runIPAMPoolList(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.ListIPAMPools(ctx)
	if err != nil {
		return fmt.Errorf("failed to list IPAM pools: %w", err)
	}

	return base.Output(resp)
}

func runIPAMAllocate(flags *cli.CommonFlags, poolID, deviceID, hostname string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.AllocateIP(ctx, poolID, deviceID, hostname)
	if err != nil {
		return fmt.Errorf("failed to allocate IP: %w", err)
	}

	return base.Output(resp)
}

func runIPAMRelease(flags *cli.CommonFlags, ip string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := gatewayClient.ReleaseIP(ctx, ip); err != nil {
		return fmt.Errorf("failed to release IP: %w", err)
	}

	fmt.Printf("IP %s released successfully\n", ip)
	return nil
}

func runIPAMAllocations(flags *cli.CommonFlags, poolID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.ListAllocations(ctx, poolID)
	if err != nil {
		return fmt.Errorf("failed to list allocations: %w", err)
	}

	return base.Output(resp)
}
