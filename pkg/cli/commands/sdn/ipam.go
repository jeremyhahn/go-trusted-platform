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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

  # Create a pool
  platformctl sdn ipam pool create --name lab-net --cidr 10.4.9.0/24

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

	cmd.AddCommand(newIPAMPoolListCommand(getFlags))
	cmd.AddCommand(newIPAMPoolGetCommand(getFlags))
	cmd.AddCommand(newIPAMPoolCreateCommand(getFlags))
	cmd.AddCommand(newIPAMPoolUpdateCommand(getFlags))
	cmd.AddCommand(newIPAMPoolDeleteCommand(getFlags))

	return cmd
}

func newIPAMPoolListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var zone string

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List pools",
		Long: `List IPAM pools with optional zone filter.

Shows:
  - Pool ID, name, and CIDR
  - Gateway address
  - Zone
  - Total, allocated, and available addresses

Examples:
  platformctl sdn ipam pool list
  platformctl sdn ipam pool list --zone control-plane
  platformctl sdn ipam pool list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIPAMPoolList(getFlags(), zone)
		},
	}

	listCmd.Flags().StringVar(&zone, "zone", "", "Filter by zone (empty returns all pools)")

	return listCmd
}

func newIPAMPoolGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var poolID string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a pool",
		Long: `Get details of a specific IPAM pool by ID.

Examples:
  platformctl sdn ipam pool get --id pool-1
  platformctl sdn ipam pool get --id pool-1 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIPAMPoolGet(getFlags(), poolID)
		},
	}

	cmd.Flags().StringVar(&poolID, "id", "", "Pool ID (required)")
	cmd.MarkFlagRequired("id")

	return cmd
}

func newIPAMPoolCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		id          string
		name        string
		cidr        string
		gatewayAddr string
		zone        string
		description string
		leaseSecs   int64
		window      ipamWindowFlags
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a pool",
		Long: `Create a new IPAM pool.

The CIDR is immutable after creation. All other fields can be updated later.

Examples:
  platformctl sdn ipam pool create --name lab-net --cidr 10.4.9.0/24
  platformctl sdn ipam pool create --name lab-net --cidr 10.4.9.0/24 --gateway 10.4.9.1 \
      --reserved 10.4.9.1/32 --range-start 10.4.9.50 --range-end 10.4.9.254
  platformctl sdn ipam pool create --name public --cidr 203.0.113.0/24 --lease-seconds 86400`,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.CreateIPAMPoolRequest{
				Id:                        id,
				Name:                      name,
				Cidr:                      cidr,
				Gateway:                   gatewayAddr,
				Zone:                      zone,
				Description:               description,
				DefaultLeaseDurationNanos: leaseSecs * int64(1e9),
				Reserved:                  window.reserved,
				RangeStart:                window.rangeStart,
				RangeEnd:                  window.rangeEnd,
			}
			return runIPAMPoolCreate(getFlags(), req)
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "Optional pool ID (generated if omitted)")
	cmd.Flags().StringVar(&name, "name", "", "Display name for the pool (required)")
	cmd.Flags().StringVar(&cidr, "cidr", "", "CIDR range for the pool, e.g. 10.0.0.0/24 (required, immutable)")
	cmd.Flags().StringVar(&gatewayAddr, "gateway", "", "Gateway IP address within the CIDR")
	cmd.Flags().StringVar(&zone, "zone", "", "Underlay zone the pool serves, e.g. 'control-plane'")
	cmd.Flags().StringVar(&description, "description", "", "Description of the pool's purpose")
	cmd.Flags().Int64Var(&leaseSecs, "lease-seconds", 0, "Default lease duration in seconds (0 = never expire)")
	window.register(cmd)
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("cidr")

	return cmd
}

func newIPAMPoolUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		poolID      string
		name        string
		gatewayAddr string
		zone        string
		description string
		leaseSecs   int64
		window      ipamWindowFlags
	)

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update a pool",
		Long: `Update mutable fields of an existing IPAM pool.

The CIDR cannot be changed after pool creation.

Examples:
  platformctl sdn ipam pool update --id pool-1 --name new-name
  platformctl sdn ipam pool update --id pool-1 --zone control-plane --gateway 10.4.6.1
  platformctl sdn ipam pool update --id pool-1 --lease-seconds 3600
  platformctl sdn ipam pool update --id pool-1 --reserved 10.4.6.1/32 --range-start 10.4.6.50 --range-end 10.4.6.254

Passing any of --reserved, --range-start or --range-end replaces the pool's
allocation window with exactly the values given (omitted ones are cleared).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			req := &platformv1.UpdateIPAMPoolRequest{
				Id:                        poolID,
				Name:                      name,
				Gateway:                   gatewayAddr,
				Zone:                      zone,
				Description:               description,
				DefaultLeaseDurationNanos: leaseSecs * int64(1e9),
				UpdateWindow:              window.changed(cmd),
				Reserved:                  window.reserved,
				RangeStart:                window.rangeStart,
				RangeEnd:                  window.rangeEnd,
			}
			return runIPAMPoolUpdate(getFlags(), req)
		},
	}

	cmd.Flags().StringVar(&poolID, "id", "", "Pool ID to update (required)")
	cmd.Flags().StringVar(&name, "name", "", "Updated display name")
	cmd.Flags().StringVar(&gatewayAddr, "gateway", "", "Updated gateway IP address")
	cmd.Flags().StringVar(&zone, "zone", "", "Updated zone")
	cmd.Flags().StringVar(&description, "description", "", "Updated description")
	cmd.Flags().Int64Var(&leaseSecs, "lease-seconds", 0, "Updated default lease duration in seconds (0 = no change)")
	window.register(cmd)
	cmd.MarkFlagRequired("id")

	return cmd
}

func newIPAMPoolDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var poolID string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a pool",
		Long: `Delete an IPAM pool.

The pool must have no active IP allocations before it can be deleted.

Examples:
  platformctl sdn ipam pool delete --id pool-1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIPAMPoolDelete(getFlags(), poolID)
		},
	}

	cmd.Flags().StringVar(&poolID, "id", "", "Pool ID to delete (required)")
	cmd.MarkFlagRequired("id")

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
  platformctl sdn ipam release --ip 2001:DB8::1`,
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

func runIPAMPoolList(flags *cli.CommonFlags, zone string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.ListIPAMPools(ctx, zone)
	if err != nil {
		return &WrappedError{Msg: "failed to list IPAM pools", Err: err}
	}

	return base.Output(resp)
}

func runIPAMPoolGet(flags *cli.CommonFlags, poolID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	pool, err := gatewayClient.GetIPAMPool(ctx, poolID)
	if err != nil {
		return &WrappedError{Msg: "failed to get IPAM pool", Err: err}
	}

	return base.Output(pool)
}

func runIPAMPoolCreate(flags *cli.CommonFlags, req *platformv1.CreateIPAMPoolRequest) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	pool, err := gatewayClient.CreateIPAMPool(ctx, req)
	if err != nil {
		return &WrappedError{Msg: "failed to create IPAM pool", Err: err}
	}

	return base.Output(pool)
}

func runIPAMPoolUpdate(flags *cli.CommonFlags, req *platformv1.UpdateIPAMPoolRequest) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	pool, err := gatewayClient.UpdateIPAMPool(ctx, req)
	if err != nil {
		return &WrappedError{Msg: "failed to update IPAM pool", Err: err}
	}

	return base.Output(pool)
}

// ipamWindowFlags holds a pool's allocation-window flags: never-allocatable
// prefixes and the dynamic range.
type ipamWindowFlags struct {
	reserved   []string
	rangeStart string
	rangeEnd   string
}

// register adds the window flags to cmd.
func (w *ipamWindowFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&w.reserved, "reserved", nil, "Prefixes (CIDR) that are never allocatable; repeat or comma-separate")
	cmd.Flags().StringVar(&w.rangeStart, "range-start", "", "First address of the dynamic allocation window")
	cmd.Flags().StringVar(&w.rangeEnd, "range-end", "", "Last address of the dynamic allocation window")
}

// changed reports whether any window flag was set on cmd.
func (w *ipamWindowFlags) changed(cmd *cobra.Command) bool {
	f := cmd.Flags()
	return f.Changed("reserved") || f.Changed("range-start") || f.Changed("range-end")
}

func runIPAMPoolDelete(flags *cli.CommonFlags, poolID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := gatewayClient.DeleteIPAMPool(ctx, poolID); err != nil {
		return &WrappedError{Msg: "failed to delete IPAM pool", Err: err}
	}

	fmt.Printf("IPAM pool %s deleted successfully\n", poolID)
	return nil
}

func runIPAMAllocate(flags *cli.CommonFlags, poolID, deviceID, hostname string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.AllocateIP(ctx, poolID, deviceID, hostname)
	if err != nil {
		return &WrappedError{Msg: "failed to allocate IP", Err: err}
	}

	return base.Output(resp)
}

func runIPAMRelease(flags *cli.CommonFlags, ip string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := gatewayClient.ReleaseIP(ctx, ip); err != nil {
		return &WrappedError{Msg: "failed to release IP", Err: err}
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

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.ListAllocations(ctx, poolID)
	if err != nil {
		return &WrappedError{Msg: "failed to list allocations", Err: err}
	}

	return base.Output(resp)
}
