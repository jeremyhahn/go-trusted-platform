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
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// NewGatewayCommand creates the gateway subcommand
func NewGatewayCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Gateway node operations",
		Long: `Manage gateway nodes supporting overlay, edge, and transit modes.

Gateway modes:
  - Overlay: VXLAN tunneling for east-west VM/container traffic
  - Edge: IoT device onboarding, DHT bootstrap, NAT traversal
  - Transit: Announce platform IPv4/IPv6 blocks to ISPs/fabric

Examples:
  # Get gateway status
  platformctl sdn gateway status

  # Show the telemetry snapshot: sessions, tunnels, uplinks, filters
  platformctl sdn gateway snapshot

  # Set gateway modes
  platformctl sdn gateway mode set --modes overlay,edge

  # Get BGP status
  platformctl sdn gateway bgp status`,
	}

	cmd.AddCommand(newGatewayStatusCommand(getFlags))
	cmd.AddCommand(newGatewaySnapshotCommand(getFlags))
	cmd.AddCommand(newGatewayModeCommand(getFlags))
	cmd.AddCommand(newGatewayBGPCommand(getFlags))
	cmd.AddCommand(newGatewayLBCommand(getFlags))
	cmd.AddCommand(newGatewayPerfCommand(getFlags))

	return cmd
}

func newGatewayStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Get gateway status",
		Long: `Display the current status of the gateway node.

Shows:
  - Gateway ID and node ID
  - Active modes (overlay, edge, transit)
  - Speaker tier (backbone, datacenter, coordinator)
  - Reputation, uptime, and health status

Examples:
  platformctl sdn gateway status
  platformctl sdn gateway status -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGatewayStatus(getFlags())
		},
	}
}

func newGatewayModeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mode",
		Short: "Gateway mode operations",
		Long:  "Manage gateway operational modes",
	}

	var modes string

	// mode set
	setCmd := &cobra.Command{
		Use:   "set",
		Short: "Set gateway modes",
		Long: `Set the active operational modes for this gateway.

Available modes:
  - overlay: VXLAN/EVPN overlay networking
  - edge: IoT device onboarding and P2P gateway
  - transit: BGP route announcement

Examples:
  platformctl sdn gateway mode set --modes overlay
  platformctl sdn gateway mode set --modes overlay,edge
  platformctl sdn gateway mode set --modes overlay,edge,transit`,
		RunE: func(cmd *cobra.Command, args []string) error {
			modeList := strings.Split(modes, ",")
			return runGatewayModeSet(getFlags(), modeList)
		},
	}
	setCmd.Flags().StringVar(&modes, "modes", "", "Comma-separated list of modes (required)")
	setCmd.MarkFlagRequired("modes")

	cmd.AddCommand(setCmd)
	return cmd
}

func newGatewayBGPCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bgp",
		Short: "BGP operations",
		Long:  "Manage BGP for EVPN and transit routing",
	}

	var prefix, nextHop string

	// bgp status
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Get BGP status",
		Long: `Display the BGP speaker status.

Shows:
  - Local ASN and router ID
  - Peer count and established peers
  - Number of announced prefixes
  - Running state

Examples:
  platformctl sdn gateway bgp status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBGPStatus(getFlags())
		},
	}

	// bgp peers
	peersCmd := &cobra.Command{
		Use:   "peers",
		Short: "List BGP peers",
		Long: `List all configured BGP peers.

Examples:
  platformctl sdn gateway bgp peers
  platformctl sdn gateway bgp peers -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBGPPeers(getFlags())
		},
	}

	// bgp announce
	announceCmd := &cobra.Command{
		Use:   "announce",
		Short: "Announce a prefix",
		Long: `Announce a prefix via BGP.

Examples:
  platformctl sdn gateway bgp announce --prefix 2602:F5BB::/36
  platformctl sdn gateway bgp announce --prefix 23.143.36.0/24 --next-hop 10.0.0.1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBGPAnnounce(getFlags(), prefix, nextHop)
		},
	}
	announceCmd.Flags().StringVar(&prefix, "prefix", "", "Prefix to announce (required)")
	announceCmd.Flags().StringVar(&nextHop, "next-hop", "", "Next hop address (optional)")
	announceCmd.MarkFlagRequired("prefix")

	// bgp withdraw
	withdrawCmd := &cobra.Command{
		Use:   "withdraw",
		Short: "Withdraw a prefix",
		Long: `Withdraw a previously announced prefix.

Examples:
  platformctl sdn gateway bgp withdraw --prefix 2602:F5BB::/36`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBGPWithdraw(getFlags(), prefix)
		},
	}
	withdrawCmd.Flags().StringVar(&prefix, "prefix", "", "Prefix to withdraw (required)")
	withdrawCmd.MarkFlagRequired("prefix")

	// bgp routes
	routesCmd := &cobra.Command{
		Use:   "routes",
		Short: "List announced prefixes",
		Long: `List all prefixes currently being announced.

Examples:
  platformctl sdn gateway bgp routes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBGPRoutes(getFlags())
		},
	}

	cmd.AddCommand(statusCmd, peersCmd, announceCmd, withdrawCmd, routesCmd)
	return cmd
}

// Implementation functions
func runGatewayStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetStatus(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get gateway status", Err: err}
	}

	return base.Output(resp)
}

func runGatewayModeSet(flags *cli.CommonFlags, modes []string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.SetModeFromStrings(ctx, modes)
	if err != nil {
		return &WrappedError{Msg: "failed to set gateway mode", Err: err}
	}

	return base.Output(resp)
}

func runBGPStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.GetBGPStatus(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to get BGP status", Err: err}
	}

	return base.Output(resp)
}

func runBGPPeers(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.ListBGPPeers(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to list BGP peers", Err: err}
	}

	return base.Output(resp)
}

func runBGPAnnounce(flags *cli.CommonFlags, prefix, nextHop string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := gatewayClient.AnnouncePrefix(ctx, prefix, nextHop); err != nil {
		return &WrappedError{Msg: "failed to announce prefix", Err: err}
	}

	fmt.Printf("Prefix %s announced successfully\n", prefix)
	return nil
}

func runBGPWithdraw(flags *cli.CommonFlags, prefix string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := gatewayClient.WithdrawPrefix(ctx, prefix); err != nil {
		return &WrappedError{Msg: "failed to withdraw prefix", Err: err}
	}

	fmt.Printf("Prefix %s withdrawn successfully\n", prefix)
	return nil
}

func runBGPRoutes(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create gateway service client from the platform client
	gatewayClient := gateway.NewClientFromGRPC(base.Client().Gateway())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := gatewayClient.ListAnnouncedPrefixes(ctx)
	if err != nil {
		return &WrappedError{Msg: "failed to list announced prefixes", Err: err}
	}

	return base.Output(resp)
}
