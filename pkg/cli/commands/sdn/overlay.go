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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/overlay"
)

// NewOverlayCommand creates the overlay subcommand
func NewOverlayCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "overlay",
		Short: "Overlay network operations",
		Long: `Manage VXLAN overlay networking for multi-host communication.

The overlay subsystem provides:
  - VTEP (VXLAN Tunnel Endpoint) management
  - VNI (VXLAN Network Identifier) configuration
  - Tunnel state monitoring
  - Remote MAC address learning

Examples:
  # Get overlay status
  platformctl sdn overlay status

  # List all VTEPs
  platformctl sdn overlay vtep list

  # Create a VNI
  platformctl sdn overlay vni create --vni 1000100 --vlan 100`,
	}

	cmd.AddCommand(newOverlayStatusCommand(getFlags))
	cmd.AddCommand(newOverlayVTEPCommand(getFlags))
	cmd.AddCommand(newOverlayVNICommand(getFlags))
	cmd.AddCommand(newOverlayTunnelCommand(getFlags))
	cmd.AddCommand(newOverlayMACCommand(getFlags))

	return cmd
}

func newOverlayStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Get overlay network status",
		Long: `Display the current status of the overlay network.

Shows:
  - Node ID and VTEP IP
  - Number of VTEPs, VNIs, tunnels, and remote MACs
  - Overall health status

Examples:
  platformctl sdn overlay status
  platformctl sdn overlay status -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOverlayStatus(getFlags())
		},
	}
}

func newOverlayVTEPCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vtep",
		Short: "VTEP operations",
		Long:  "Manage VXLAN Tunnel Endpoints",
	}

	// vtep list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all VTEPs",
		Long: `List all known VXLAN Tunnel Endpoints in the overlay network.

Examples:
  platformctl sdn overlay vtep list
  platformctl sdn overlay vtep list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVTEPList(getFlags())
		},
	}

	// vtep get
	getCmd := &cobra.Command{
		Use:   "get <node-id>",
		Short: "Get VTEP details",
		Long: `Get details for a specific VTEP by node ID.

Examples:
  platformctl sdn overlay vtep get node-123`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVTEPGet(getFlags(), args[0])
		},
	}

	cmd.AddCommand(listCmd, getCmd)
	return cmd
}

func newOverlayVNICommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vni",
		Short: "VNI operations",
		Long:  "Manage VXLAN Network Identifiers",
	}

	var vni uint32
	var vlan uint16
	var name string

	// vni list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all VNIs",
		Long: `List all configured VNIs in the overlay network.

Examples:
  platformctl sdn overlay vni list
  platformctl sdn overlay vni list -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVNIList(getFlags())
		},
	}

	// vni create
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create a VNI",
		Long: `Create a new VXLAN Network Identifier.

Examples:
  platformctl sdn overlay vni create --vni 1000100 --vlan 100
  platformctl sdn overlay vni create --vni 1000200 --vlan 200 --name prod-network`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVNICreate(getFlags(), vni, vlan, name)
		},
	}
	createCmd.Flags().Uint32Var(&vni, "vni", 0, "VNI number (required)")
	createCmd.Flags().Uint16Var(&vlan, "vlan", 0, "VLAN to map (required)")
	createCmd.Flags().StringVar(&name, "name", "", "Optional name for the VNI")
	createCmd.MarkFlagRequired("vni")
	createCmd.MarkFlagRequired("vlan")

	// vni delete
	deleteCmd := &cobra.Command{
		Use:   "delete <vni>",
		Short: "Delete a VNI",
		Long: `Delete a VXLAN Network Identifier.

Examples:
  platformctl sdn overlay vni delete 1000100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var vniArg uint32
			if _, err := fmt.Sscanf(args[0], "%d", &vniArg); err != nil {
				return fmt.Errorf("invalid VNI: %s", args[0])
			}
			return runVNIDelete(getFlags(), vniArg)
		},
	}

	cmd.AddCommand(listCmd, createCmd, deleteCmd)
	return cmd
}

func newOverlayTunnelCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Tunnel operations",
		Long:  "Monitor VXLAN tunnels",
	}

	var vni uint32

	// tunnel list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List tunnels",
		Long: `List VXLAN tunnels.

Examples:
  platformctl sdn overlay tunnel list
  platformctl sdn overlay tunnel list --vni 1000100`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTunnelList(getFlags(), vni)
		},
	}
	listCmd.Flags().Uint32Var(&vni, "vni", 0, "Filter by VNI (0 for all)")

	cmd.AddCommand(listCmd)
	return cmd
}

func newOverlayMACCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mac",
		Short: "MAC address operations",
		Long:  "Manage remote MAC addresses learned via EVPN",
	}

	var vni uint32

	// mac list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List remote MACs",
		Long: `List MAC addresses learned from remote VTEPs.

Examples:
  platformctl sdn overlay mac list
  platformctl sdn overlay mac list --vni 1000100`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMACList(getFlags(), vni)
		},
	}
	listCmd.Flags().Uint32Var(&vni, "vni", 0, "Filter by VNI (0 for all)")

	// mac forget
	forgetCmd := &cobra.Command{
		Use:   "forget <mac>",
		Short: "Forget a MAC address",
		Long: `Remove a learned MAC address from the FDB.

Examples:
  platformctl sdn overlay mac forget 00:11:22:33:44:55 --vni 1000100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMACForget(getFlags(), args[0], vni)
		},
	}
	forgetCmd.Flags().Uint32Var(&vni, "vni", 0, "VNI for the MAC (required)")
	forgetCmd.MarkFlagRequired("vni")

	cmd.AddCommand(listCmd, forgetCmd)
	return cmd
}

// Implementation functions - these connect to the API
func runOverlayStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := overlayClient.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get overlay status: %w", err)
	}

	return base.Output(resp)
}

func runVTEPList(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := overlayClient.ListVTEPs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list VTEPs: %w", err)
	}

	return base.Output(resp)
}

func runVTEPGet(flags *cli.CommonFlags, nodeID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := overlayClient.GetVTEP(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("failed to get VTEP: %w", err)
	}

	return base.Output(resp)
}

func runVNIList(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := overlayClient.ListVNIs(ctx)
	if err != nil {
		return fmt.Errorf("failed to list VNIs: %w", err)
	}

	return base.Output(resp)
}

func runVNICreate(flags *cli.CommonFlags, vni uint32, vlan uint16, name string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	config := &platformv1.VNIConfig{
		Vni:  vni,
		Vlan: uint32(vlan),
		Name: name,
	}
	resp, err := overlayClient.CreateVNI(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to create VNI: %w", err)
	}

	return base.Output(resp)
}

func runVNIDelete(flags *cli.CommonFlags, vni uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := overlayClient.DeleteVNI(ctx, vni); err != nil {
		return fmt.Errorf("failed to delete VNI: %w", err)
	}

	fmt.Printf("VNI %d deleted successfully\n", vni)
	return nil
}

func runTunnelList(flags *cli.CommonFlags, vni uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := overlayClient.ListTunnels(ctx, vni)
	if err != nil {
		return fmt.Errorf("failed to list tunnels: %w", err)
	}

	return base.Output(resp)
}

func runMACList(flags *cli.CommonFlags, vni uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := overlayClient.ListRemoteMACs(ctx, vni)
	if err != nil {
		return fmt.Errorf("failed to list remote MACs: %w", err)
	}

	return base.Output(resp)
}

func runMACForget(flags *cli.CommonFlags, mac string, vni uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create overlay service client from the platform client
	overlayClient := overlay.NewClientFromGRPC(base.Client().Overlay())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := overlayClient.ForgetMAC(ctx, mac, vni); err != nil {
		return fmt.Errorf("failed to forget MAC: %w", err)
	}

	fmt.Printf("MAC %s forgotten from VNI %d\n", mac, vni)
	return nil
}
