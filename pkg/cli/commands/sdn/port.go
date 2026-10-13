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
	sdnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// ErrInvalidPortType indicates an unrecognized port type string.
type ErrInvalidPortType struct {
	Type string
}

func (e ErrInvalidPortType) Error() string {
	return fmt.Sprintf("invalid port type: %s (valid: internal, physical, tap, veth, vxlan, gre)", e.Type)
}

// NewPortCommand creates the port subcommand
func NewPortCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "port",
		Short: "Port operations",
		Long: `Manage ports on SDN bridges.

The port subsystem provides:
  - Add and delete ports on bridges
  - Get port state and statistics
  - Set port administrative state and rate limits

Examples:
  # Add a port to a bridge
  platformctl sdn port add --bridge br0 --id port1 --name eth0 --type internal

  # Get port state
  platformctl sdn port state --bridge br0 port1

  # Get port statistics
  platformctl sdn port stats --bridge br0 port1

  # Delete a port
  platformctl sdn port delete --bridge br0 port1`,
	}

	cmd.AddCommand(newPortAddCommand(getFlags))
	cmd.AddCommand(newPortDeleteCommand(getFlags))
	cmd.AddCommand(newPortStateCommand(getFlags))
	cmd.AddCommand(newPortSetStateCommand(getFlags))
	cmd.AddCommand(newPortStatsCommand(getFlags))

	return cmd
}

func newPortAddCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bridgeID   string
		portID     string
		name       string
		portType   string
		tag        int
		iface      string
		mac        string
		mtu        int
		adminState string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a port to a bridge",
		Long: `Add a new port to an existing bridge.

Supported port types: internal, physical, tap, veth, vxlan, gre

Examples:
  platformctl sdn port add --bridge br0 --id port1 --name eth0 --type internal
  platformctl sdn port add --bridge br0 --id port2 --name vx100 --type vxlan --tag 100 --mtu 1450`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPortAdd(getFlags(), bridgeID, portID, name, portType,
				tag, iface, mac, mtu, adminState)
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")
	cmd.Flags().StringVar(&portID, "id", "", "Port ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "Port name (required)")
	cmd.Flags().StringVar(&portType, "type", "", "Port type: internal, physical, tap, veth, vxlan, gre (required)")
	cmd.Flags().IntVar(&tag, "tag", 0, "VLAN tag for access ports")
	cmd.Flags().StringVar(&iface, "interface", "", "Interface name to attach")
	cmd.Flags().StringVar(&mac, "mac", "", "MAC address")
	cmd.Flags().IntVar(&mtu, "mtu", 0, "MTU size")
	cmd.Flags().StringVar(&adminState, "admin-state", "", "Administrative state: up, down")
	cmd.MarkFlagRequired("bridge")
	cmd.MarkFlagRequired("id")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("type")

	return cmd
}

func newPortDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bridgeID string

	cmd := &cobra.Command{
		Use:   "delete <port-id>",
		Short: "Delete a port from a bridge",
		Long: `Remove a port from its bridge.

Examples:
  platformctl sdn port delete --bridge br0 port1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPortDelete(getFlags(), bridgeID, args[0])
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")
	cmd.MarkFlagRequired("bridge")

	return cmd
}

func newPortStateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bridgeID string

	cmd := &cobra.Command{
		Use:   "state <port-id>",
		Short: "Get port state",
		Long: `Get the current state of a port.

Shows admin state, operational state, link state, speed, and rate limits.

Examples:
  platformctl sdn port state --bridge br0 port1
  platformctl sdn port state --bridge br0 port1 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPortGetState(getFlags(), bridgeID, args[0])
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")
	cmd.MarkFlagRequired("bridge")

	return cmd
}

func newPortSetStateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	// The flags fill the request; the port ID is the argument.
	req := &platformv1.SetPortStateRequest{}

	cmd := &cobra.Command{
		Use:   "set-state <port-id>",
		Short: "Set port state",
		Long: `Set the administrative state and rate limits for a port.

Examples:
  platformctl sdn port set-state --bridge br0 port1 --admin-state up
  platformctl sdn port set-state --bridge br0 port1 --admin-state up --ingress-rate 10000000 --ingress-burst 1000000
  platformctl sdn port set-state --bridge br0 port1 --admin-state up --egress-rate 20000000 --egress-burst 2000000`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			req.PortId = args[0]
			return runPortSetState(getFlags(), req)
		},
	}

	cmd.Flags().StringVar(&req.BridgeId, "bridge", "", "Bridge ID (required)")
	cmd.Flags().StringVar(&req.AdminState, "admin-state", "", "Administrative state: up, down (required)")
	cmd.Flags().Uint64Var(&req.IngressRate, "ingress-rate", 0, "Ingress policing rate in bps, a whole multiple of 1000 (0 leaves policing unchanged)")
	cmd.Flags().Uint64Var(&req.IngressBurst, "ingress-burst", 0, "Ingress policing burst in bits, a whole multiple of 1000 (needs --ingress-rate)")
	cmd.Flags().Uint64Var(&req.EgressRate, "egress-rate", 0, "Egress shaping rate in bps (0 leaves shaping unchanged)")
	cmd.Flags().Uint64Var(&req.EgressBurst, "egress-burst", 0, "Egress shaping burst in bits (needs --egress-rate)")
	cmd.MarkFlagRequired("bridge")
	cmd.MarkFlagRequired("admin-state")

	return cmd
}

func newPortStatsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bridgeID string

	cmd := &cobra.Command{
		Use:   "stats <port-id>",
		Short: "Get port statistics",
		Long: `Get traffic statistics for a port.

Shows packet counts, byte counts, errors, and drops.

Examples:
  platformctl sdn port stats --bridge br0 port1
  platformctl sdn port stats --bridge br0 port1 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPortGetStats(getFlags(), bridgeID, args[0])
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")
	cmd.MarkFlagRequired("bridge")

	return cmd
}

// Implementation functions

func runPortAdd(flags *cli.CommonFlags, bridgeID, portID, name, portType string,
	tag int, iface, mac string, mtu int, adminState string) error {

	pt, ok := sdnsvc.ParsePortType(portType)
	if !ok {
		return ErrInvalidPortType{Type: portType}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	options := make(map[string]string)
	if iface != "" {
		options["interface"] = iface
	}
	if adminState != "" {
		options["admin_state"] = adminState
	}

	config := &sdnsvc.PortConfig{
		Name:       name,
		Type:       pt,
		VLAN:       uint32(tag),
		MACAddress: mac,
		MTU:        uint32(mtu),
		Options:    options,
		Labels: map[string]string{
			"port_id": portID,
		},
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdkClient.AddPortDomain(ctx, bridgeID, config)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "port add", Err: err}
	}

	return base.Output(resp)
}

func runPortDelete(flags *cli.CommonFlags, bridgeID, portID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := sdkClient.DeletePort(ctx, bridgeID, portID); err != nil {
		return &cli.ErrOperationFailed{Operation: "port delete", Err: err}
	}

	result := map[string]interface{}{
		"bridge_id": bridgeID,
		"port_id":   portID,
		"deleted":   true,
	}

	return base.Output(result)
}

func runPortGetState(flags *cli.CommonFlags, bridgeID, portID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdkClient.GetPort(ctx, bridgeID, portID)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "port state", Err: err}
	}

	return base.Output(resp)
}

func runPortSetState(flags *cli.CommonFlags, req *platformv1.SetPortStateRequest) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	port, err := sdkClient.SetPortState(ctx, req)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "port set-state", Err: err}
	}

	return base.Output(port)
}

func runPortGetStats(flags *cli.CommonFlags, bridgeID, portID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdkClient.GetPortStats(ctx, bridgeID, portID)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "port stats", Err: err}
	}

	return base.Output(resp)
}
