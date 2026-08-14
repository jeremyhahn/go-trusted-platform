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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// newGatewayPerfCommand creates the performance verification subcommand
// tree. Every value reported by these commands is a REAL measurement:
// flow programming is timed against a live OVS bridge, and datapath /
// conntrack numbers are read from ovs-vswitchd counters.
func newGatewayPerfCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "perf",
		Short: "Datapath performance verification",
		Long: `Verify gateway datapath performance with real measurements.

"perf flows" installs ephemeral flows into a dedicated OpenFlow table
(250), times the install with a monotonic clock, then removes them with
a cookie-scoped delete. "perf datapath" and "perf conntrack" report live
ovs-vswitchd counters (flow-cache hits/misses, hardware-offloaded flow
count, conntrack entries per zone).

Examples:
  # Measure batched flow programming (1000 flows, one barrier)
  platformctl sdn gateway perf flows --count 1000 --batch

  # Read the live datapath and offload counters
  platformctl sdn gateway perf datapath

  # Summarize conntrack entries in zone 12
  platformctl sdn gateway perf conntrack --zone 12`,
	}

	cmd.AddCommand(newGatewayPerfFlowsCommand(getFlags))
	cmd.AddCommand(newGatewayPerfDatapathCommand(getFlags))
	cmd.AddCommand(newGatewayPerfConntrackCommand(getFlags))

	return cmd
}

// newGatewayPerfFlowsCommand creates the "perf flows" command.
func newGatewayPerfFlowsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var count uint32
	var batch bool
	var bridge string

	cmd := &cobra.Command{
		Use:   "flows",
		Short: "Measure flow-programming throughput",
		Long: `Measure real OpenFlow programming throughput.

Installs --count ephemeral drop flows into the dedicated perf table
(250, cookie 0xf1be00ff00000000), measures the install duration, then
deletes them again with a cookie-scoped delete. --batch installs all
flows behind a single barrier; without it flows are installed one at a
time. This command MUTATES the bridge flow tables (sdn:write).

Examples:
  platformctl sdn gateway perf flows --count 1000 --batch
  platformctl sdn gateway perf flows --count 500 --bridge br-int -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPerfFlows(getFlags(), count, batch, bridge)
		},
	}
	cmd.Flags().Uint32Var(&count, "count", 1000, "Number of ephemeral flows to install (1-100000)")
	cmd.Flags().BoolVar(&batch, "batch", false, "Install all flows behind a single batched barrier")
	cmd.Flags().StringVar(&bridge, "bridge", "", "Target OVS bridge (default: daemon's default bridge)")

	return cmd
}

// newGatewayPerfDatapathCommand creates the "perf datapath" command.
func newGatewayPerfDatapathCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bridge string

	cmd := &cobra.Command{
		Use:   "datapath",
		Short: "Read live datapath counters",
		Long: `Read live datapath counters from ovs-vswitchd.

Reports the flow-cache hit / miss / lost lookup counters, the number of
datapath flows currently offloaded to hardware, the hw-offload
configuration state, and the bridge datapath type.

Examples:
  platformctl sdn gateway perf datapath
  platformctl sdn gateway perf datapath --bridge br-int -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPerfDatapath(getFlags(), bridge)
		},
	}
	cmd.Flags().StringVar(&bridge, "bridge", "", "Bridge whose datapath type to inspect (default: daemon's default bridge)")

	return cmd
}

// newGatewayPerfConntrackCommand creates the "perf conntrack" command.
func newGatewayPerfConntrackCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var zone int32

	cmd := &cobra.Command{
		Use:   "conntrack",
		Short: "Summarize the connection tracking table",
		Long: `Summarize the connection tracking table.

Reports the total conntrack entry count and per-zone counts. --zone
restricts the summary to one conntrack zone.

Examples:
  platformctl sdn gateway perf conntrack
  platformctl sdn gateway perf conntrack --zone 12 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var zoneFilter *uint32
			if cmd.Flags().Changed("zone") {
				if zone < 0 || zone > 65535 {
					return &ErrInvalidConntrackZone{Zone: zone}
				}
				value := uint32(zone)
				zoneFilter = &value
			}
			return runPerfConntrack(getFlags(), zoneFilter)
		},
	}
	cmd.Flags().Int32Var(&zone, "zone", 0, "Conntrack zone filter (0-65535; omit for every zone)")

	return cmd
}

// runPerfFlows executes the flow-programming measurement.
func runPerfFlows(flags *cli.CommonFlags, count uint32, batch bool, bridge string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetPerfFlows(ctx, count, batch, bridge)
	if err != nil {
		return &WrappedError{Msg: "failed to measure flow programming", Err: err}
	}

	return base.Output(resp)
}

// runPerfDatapath fetches and prints the live datapath counters.
func runPerfDatapath(flags *cli.CommonFlags, bridge string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetPerfDatapath(ctx, bridge)
	if err != nil {
		return &WrappedError{Msg: "failed to read datapath counters", Err: err}
	}

	return base.Output(resp)
}

// runPerfConntrack fetches and prints the conntrack summary.
func runPerfConntrack(flags *cli.CommonFlags, zone *uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetPerfConntrack(ctx, zone)
	if err != nil {
		return &WrappedError{Msg: "failed to read conntrack summary", Err: err}
	}

	return base.Output(resp)
}
