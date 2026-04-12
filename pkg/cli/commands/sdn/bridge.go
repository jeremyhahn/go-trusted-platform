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
	sdnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// ErrInvalidBridgeType indicates an unrecognized bridge type string.
type ErrInvalidBridgeType struct {
	Type string
}

func (e ErrInvalidBridgeType) Error() string {
	return fmt.Sprintf("invalid bridge type: %s (valid: ovs, linux, vxlan)", e.Type)
}

// NewBridgeCommand creates the bridge subcommand
func NewBridgeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bridge",
		Short: "Bridge operations",
		Long: `Manage OVS and Linux bridges for SDN networking.

The bridge subsystem provides:
  - Create, get, list, and delete bridges
  - OVS, Linux, and VXLAN bridge types
  - STP/RSTP, fail-mode, and MTU configuration

Examples:
  # Create an OVS bridge
  platformctl sdn bridge create --id br0 --name my-bridge --type ovs

  # Get bridge details
  platformctl sdn bridge get br0

  # List all bridges
  platformctl sdn bridge list

  # Delete a bridge
  platformctl sdn bridge delete br0`,
	}

	cmd.AddCommand(newBridgeCreateCommand(getFlags))
	cmd.AddCommand(newBridgeGetCommand(getFlags))
	cmd.AddCommand(newBridgeListCommand(getFlags))
	cmd.AddCommand(newBridgeDeleteCommand(getFlags))

	return cmd
}

func newBridgeCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bridgeID    string
		name        string
		bridgeType  string
		description string
		datapathID  string
		failMode    string
		stp         bool
		rstp        bool
		mtu         int
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new bridge",
		Long: `Create a new SDN bridge.

Supported bridge types: ovs, linux, vxlan

Examples:
  platformctl sdn bridge create --id br0 --name my-bridge --type ovs
  platformctl sdn bridge create --id br1 --name prod-bridge --type ovs --fail-mode secure --stp --mtu 9000`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBridgeCreate(getFlags(), bridgeID, name, bridgeType,
				description, datapathID, failMode, stp, rstp, mtu)
		},
	}

	cmd.Flags().StringVar(&bridgeID, "id", "", "Bridge ID (required)")
	cmd.Flags().StringVar(&name, "name", "", "Bridge name (required)")
	cmd.Flags().StringVar(&bridgeType, "type", "", "Bridge type: ovs, linux, vxlan (required)")
	cmd.Flags().StringVar(&description, "description", "", "Bridge description")
	cmd.Flags().StringVar(&datapathID, "datapath-id", "", "Datapath ID")
	cmd.Flags().StringVar(&failMode, "fail-mode", "", "Fail mode: secure, standalone")
	cmd.Flags().BoolVar(&stp, "stp", false, "Enable STP")
	cmd.Flags().BoolVar(&rstp, "rstp", false, "Enable RSTP")
	cmd.Flags().IntVar(&mtu, "mtu", 0, "MTU size")
	cmd.MarkFlagRequired("id")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("type")

	return cmd
}

func newBridgeGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <bridge-id>",
		Short: "Get bridge details",
		Long: `Get detailed information about a bridge.

Examples:
  platformctl sdn bridge get br0
  platformctl sdn bridge get br0 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBridgeGet(getFlags(), args[0])
		},
	}
}

func newBridgeListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bridgeType string
		status     string
		limit      int
		cursor     string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List bridges",
		Long: `List all bridges with optional filtering.

Examples:
  platformctl sdn bridge list
  platformctl sdn bridge list --type ovs
  platformctl sdn bridge list --status up --limit 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBridgeList(getFlags(), bridgeType, status, limit, cursor)
		},
	}

	cmd.Flags().StringVar(&bridgeType, "type", "", "Filter by bridge type: ovs, linux, vxlan")
	cmd.Flags().StringVar(&status, "status", "", "Filter by status: up, down, error")
	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum number of results")
	cmd.Flags().StringVar(&cursor, "cursor", "", "Pagination cursor")

	return cmd
}

func newBridgeDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		force       bool
		deletePorts bool
		deleteFlows bool
	)

	cmd := &cobra.Command{
		Use:   "delete <bridge-id>",
		Short: "Delete a bridge",
		Long: `Delete a bridge by ID.

Examples:
  platformctl sdn bridge delete br0
  platformctl sdn bridge delete br0 --force --delete-ports --delete-flows`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBridgeDelete(getFlags(), args[0], force, deletePorts, deleteFlows)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "Force deletion even if bridge has ports")
	cmd.Flags().BoolVar(&deletePorts, "delete-ports", false, "Delete all ports on the bridge")
	cmd.Flags().BoolVar(&deleteFlows, "delete-flows", false, "Delete all flows on the bridge")

	return cmd
}

// Implementation functions

func runBridgeCreate(flags *cli.CommonFlags, bridgeID, name, bridgeType,
	description, datapathID, failMode string, stp, rstp bool, mtu int) error {

	bt, ok := sdnsvc.ParseBridgeType(bridgeType)
	if !ok {
		return ErrInvalidBridgeType{Type: bridgeType}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	options := make(map[string]string)
	if failMode != "" {
		options["fail_mode"] = failMode
	}
	if rstp {
		options["rstp_enable"] = "true"
	}
	if description != "" {
		options["description"] = description
	}

	config := &sdnsvc.BridgeConfig{
		Name:       name,
		Type:       bt,
		DatapathID: datapathID,
		STPEnabled: stp,
		MTU:        uint32(mtu),
		Options:    options,
		Labels: map[string]string{
			"bridge_id": bridgeID,
		},
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdkClient.CreateBridgeDomain(ctx, config)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "bridge create", Err: err}
	}

	return base.Output(resp)
}

func runBridgeGet(flags *cli.CommonFlags, bridgeID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdkClient.GetBridge(ctx, bridgeID)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "bridge get", Err: err}
	}

	return base.Output(resp)
}

func runBridgeList(flags *cli.CommonFlags, bridgeType, status string, limit int, cursor string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	var selector *sdnsvc.LabelSelector
	labels := make(map[string]string)
	if bridgeType != "" {
		labels["type"] = bridgeType
	}
	if status != "" {
		labels["status"] = status
	}
	if len(labels) > 0 {
		selector = &sdnsvc.LabelSelector{
			MatchLabels: labels,
		}
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, _, err := sdkClient.ListBridgesDomain(ctx, selector, uint32(limit))
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "bridge list", Err: err}
	}

	return base.Output(resp)
}

func runBridgeDelete(flags *cli.CommonFlags, bridgeID string, force, deletePorts, deleteFlows bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()

	if err := sdkClient.DeleteBridgeDomain(ctx, bridgeID, force, deleteFlows); err != nil {
		return &cli.ErrOperationFailed{Operation: "bridge delete", Err: err}
	}

	// Output deletion result as a structured response
	result := map[string]interface{}{
		"bridge_id": bridgeID,
		"deleted":   true,
	}

	return base.Output(result)
}
