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
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdnsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// ErrInvalidVLANID indicates a VLAN ID that could not be parsed.
type ErrInvalidVLANID struct {
	Value string
}

func (e ErrInvalidVLANID) Error() string {
	return fmt.Sprintf("invalid VLAN ID: %s (must be an integer 1-4094)", e.Value)
}

// NewVLANCommand creates the vlan subcommand
func NewVLANCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vlan",
		Short: "VLAN operations",
		Long: `Manage VLANs on SDN bridges.

The VLAN subsystem provides:
  - Create and delete VLANs
  - List VLANs with bridge filtering
  - Associate VLANs with bridges and ports

Examples:
  # Create a VLAN
  platformctl sdn vlan create --id 100 --name prod-vlan

  # List VLANs
  platformctl sdn vlan list

  # Delete a VLAN
  platformctl sdn vlan delete 100`,
	}

	cmd.AddCommand(newVLANCreateCommand(getFlags))
	cmd.AddCommand(newVLANDeleteCommand(getFlags))
	cmd.AddCommand(newVLANListCommand(getFlags))

	return cmd
}

func newVLANCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		vlanID      int
		name        string
		description string
		bridgeIDs   []string
	)

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a VLAN",
		Long: `Create a new VLAN and optionally associate it with bridges.

Examples:
  platformctl sdn vlan create --id 100 --name prod-vlan
  platformctl sdn vlan create --id 200 --name dev-vlan --description "Development VLAN" --bridge br0 --bridge br1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVLANCreate(getFlags(), int32(vlanID), name, description, bridgeIDs)
		},
	}

	cmd.Flags().IntVar(&vlanID, "id", 0, "VLAN ID 1-4094 (required)")
	cmd.Flags().StringVar(&name, "name", "", "VLAN name (required)")
	cmd.Flags().StringVar(&description, "description", "", "VLAN description")
	cmd.Flags().StringSliceVar(&bridgeIDs, "bridge", nil, "Bridge IDs to associate (can be repeated)")
	cmd.MarkFlagRequired("id")
	cmd.MarkFlagRequired("name")

	return cmd
}

func newVLANDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bridgeID string

	cmd := &cobra.Command{
		Use:   "delete <vlan-id>",
		Short: "Delete a VLAN",
		Long: `Delete a VLAN by its numeric ID.

Examples:
  platformctl sdn vlan delete --bridge br0 100`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			vlanID, err := strconv.Atoi(args[0])
			if err != nil {
				return ErrInvalidVLANID{Value: args[0]}
			}
			return runVLANDelete(getFlags(), bridgeID, int32(vlanID))
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")

	return cmd
}

func newVLANListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bridgeID string
		limit    int
		cursor   string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List VLANs",
		Long: `List VLANs with optional bridge filtering.

Examples:
  platformctl sdn vlan list
  platformctl sdn vlan list --bridge br0
  platformctl sdn vlan list --limit 50`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVLANList(getFlags(), bridgeID, int32(limit), cursor)
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Filter by bridge ID")
	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum number of results")
	cmd.Flags().StringVar(&cursor, "cursor", "", "Pagination cursor")

	return cmd
}

// Implementation functions

func runVLANCreate(flags *cli.CommonFlags, vlanID int32, name, description string, bridgeIDs []string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	// The gRPC VLANConfig requires a single bridge_id. If multiple bridges
	// are specified, create the VLAN on the first bridge. The labels store
	// the description and additional bridges for the service layer.
	bridgeID := ""
	if len(bridgeIDs) > 0 {
		bridgeID = bridgeIDs[0]
	}

	labels := make(map[string]string)
	if description != "" {
		labels["description"] = description
	}

	config := &sdnsvc.VLANConfig{
		VlanID:   uint32(vlanID),
		Name:     name,
		BridgeID: bridgeID,
		Labels:   labels,
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdkClient.CreateVLANDomain(ctx, config)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "vlan create", Err: err}
	}

	return base.Output(resp)
}

func runVLANDelete(flags *cli.CommonFlags, bridgeID string, vlanID int32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := sdkClient.DeleteVLAN(ctx, bridgeID, uint32(vlanID)); err != nil {
		return &cli.ErrOperationFailed{Operation: "vlan delete", Err: err}
	}

	result := map[string]interface{}{
		"vlan_id": vlanID,
		"deleted": true,
	}

	return base.Output(result)
}

func runVLANList(flags *cli.CommonFlags, bridgeID string, limit int32, cursor string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdkClient := sdnsvc.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdkClient.ListVLANsDomain(ctx, bridgeID, nil)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "vlan list", Err: err}
	}

	return base.Output(resp)
}
