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
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdnclient "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
)

// ErrInvalidFlowActionType indicates an unrecognized flow action type string.
type ErrInvalidFlowActionType struct {
	Type string
}

func (e ErrInvalidFlowActionType) Error() string {
	return fmt.Sprintf("invalid flow action type: %s (valid: output, normal, flood, drop, set_vlan, strip_vlan, set_field, goto_table, controller)", e.Type)
}

// flowActionTypeMap provides O(1) lookup from CLI string to protobuf enum.
var flowActionTypeMap = map[string]platformv1.FlowActionType{
	"output":     platformv1.FlowActionType_FLOW_ACTION_OUTPUT,
	"drop":       platformv1.FlowActionType_FLOW_ACTION_DROP,
	"set_vlan":   platformv1.FlowActionType_FLOW_ACTION_SET_VLAN,
	"strip_vlan": platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN,
	"set_field":  platformv1.FlowActionType_FLOW_ACTION_SET_FIELD,
	"goto_table": platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE,
	"controller": platformv1.FlowActionType_FLOW_ACTION_CONTROLLER,
	"normal":     platformv1.FlowActionType_FLOW_ACTION_OUTPUT,
	"flood":      platformv1.FlowActionType_FLOW_ACTION_OUTPUT,
}

// parseFlowActionType converts a CLI action type string to the protobuf enum.
func parseFlowActionType(s string) (platformv1.FlowActionType, error) {
	at, ok := flowActionTypeMap[strings.ToLower(s)]
	if !ok {
		return platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED, ErrInvalidFlowActionType{Type: s}
	}
	return at, nil
}

// flowTableMap provides O(1) lookup from table number to protobuf enum.
var flowTableMap = map[int]platformv1.FlowTable{
	0:   platformv1.FlowTable_FLOW_TABLE_0,
	1:   platformv1.FlowTable_FLOW_TABLE_1,
	2:   platformv1.FlowTable_FLOW_TABLE_2,
	3:   platformv1.FlowTable_FLOW_TABLE_3,
	255: platformv1.FlowTable_FLOW_TABLE_DROP,
}

// parseFlowTable converts a table number to the protobuf enum.
func parseFlowTable(table int) platformv1.FlowTable {
	ft, ok := flowTableMap[table]
	if !ok {
		return platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED
	}
	return ft
}

// NewFlowCommand creates the flow subcommand
func NewFlowCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flow",
		Short: "Flow operations",
		Long: `Manage OpenFlow flow rules on SDN bridges.

The flow subsystem provides:
  - Add and delete flow rules
  - List flows with table and priority filtering
  - Match criteria and action configuration

Examples:
  # Add a flow rule
  platformctl sdn flow add --bridge br0 --id flow1 --table 0 --priority 100 --action output --action-port 1

  # List flows on a bridge
  platformctl sdn flow list --bridge br0

  # Delete a flow
  platformctl sdn flow delete --bridge br0 flow1`,
	}

	cmd.AddCommand(newFlowAddCommand(getFlags))
	cmd.AddCommand(newFlowDeleteCommand(getFlags))
	cmd.AddCommand(newFlowListCommand(getFlags))

	return cmd
}

func newFlowAddCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bridgeID   string
		flowID     string
		table      int
		priority   int
		inPort     int
		dlSrc      string
		dlDst      string
		dlType     int
		nwSrc      string
		nwDst      string
		actions    []string
		actionPort int
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a flow rule",
		Long: `Add a new OpenFlow rule to a bridge.

Supported actions: output, drop, set_vlan, strip_vlan, set_field, goto_table, controller

Examples:
  platformctl sdn flow add --bridge br0 --id flow1 --table 0 --priority 100 --action output --action-port 1
  platformctl sdn flow add --bridge br0 --id flow2 --table 0 --priority 200 --dl-src 00:11:22:33:44:55 --action drop
  platformctl sdn flow add --bridge br0 --id flow3 --table 0 --priority 150 --nw-src 10.0.0.0/24 --action output --action-port 2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFlowAdd(getFlags(), bridgeID, flowID, table, priority,
				inPort, dlSrc, dlDst, dlType, nwSrc, nwDst, actions, actionPort)
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")
	cmd.Flags().StringVar(&flowID, "id", "", "Flow ID (required)")
	cmd.Flags().IntVar(&table, "table", 0, "Flow table number (required)")
	cmd.Flags().IntVar(&priority, "priority", 0, "Flow priority (required)")
	cmd.Flags().IntVar(&inPort, "in-port", 0, "Match on input port")
	cmd.Flags().StringVar(&dlSrc, "dl-src", "", "Match on source MAC")
	cmd.Flags().StringVar(&dlDst, "dl-dst", "", "Match on destination MAC")
	cmd.Flags().IntVar(&dlType, "dl-type", 0, "Match on ethertype")
	cmd.Flags().StringVar(&nwSrc, "nw-src", "", "Match on source IP")
	cmd.Flags().StringVar(&nwDst, "nw-dst", "", "Match on destination IP")
	cmd.Flags().StringSliceVar(&actions, "action", nil, "Action type (can be repeated)")
	cmd.Flags().IntVar(&actionPort, "action-port", 0, "Output port for action")
	cmd.MarkFlagRequired("bridge")
	cmd.MarkFlagRequired("id")
	cmd.MarkFlagRequired("table")
	cmd.MarkFlagRequired("priority")

	return cmd
}

func newFlowDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var bridgeID string

	cmd := &cobra.Command{
		Use:   "delete <flow-id>",
		Short: "Delete a flow rule",
		Long: `Delete an OpenFlow rule from a bridge.

Examples:
  platformctl sdn flow delete --bridge br0 flow1`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFlowDelete(getFlags(), bridgeID, args[0])
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")
	cmd.MarkFlagRequired("bridge")

	return cmd
}

func newFlowListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bridgeID string
		table    int
		limit    int
		cursor   string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List flow rules",
		Long: `List OpenFlow rules on a bridge.

Examples:
  platformctl sdn flow list --bridge br0
  platformctl sdn flow list --bridge br0 --table 0
  platformctl sdn flow list --bridge br0 --limit 50`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFlowList(getFlags(), bridgeID, table, limit, cursor)
		},
	}

	cmd.Flags().StringVar(&bridgeID, "bridge", "", "Bridge ID (required)")
	cmd.Flags().IntVar(&table, "table", -1, "Filter by table number")
	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum number of results")
	cmd.Flags().StringVar(&cursor, "cursor", "", "Pagination cursor")
	cmd.MarkFlagRequired("bridge")

	return cmd
}

// Implementation functions

func runFlowAdd(flags *cli.CommonFlags, bridgeID, flowID string, table, priority,
	inPort int, dlSrc, dlDst string, dlType int, nwSrc, nwDst string,
	actions []string, actionPort int) error {

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnclient.NewClientFromGRPC(base.Client().SDN())

	// Build flow match
	match := &platformv1.FlowMatch{}
	if inPort > 0 {
		match.InPort = strconv.Itoa(inPort)
	}
	if dlSrc != "" {
		match.EthSrc = dlSrc
	}
	if dlDst != "" {
		match.EthDst = dlDst
	}
	if dlType > 0 {
		match.EthType = uint32(dlType)
	}
	if nwSrc != "" {
		match.IpSrc = nwSrc
	}
	if nwDst != "" {
		match.IpDst = nwDst
	}

	// Build flow actions
	var flowActions []*platformv1.FlowAction
	for _, actionStr := range actions {
		actionType, parseErr := parseFlowActionType(actionStr)
		if parseErr != nil {
			return parseErr
		}
		action := &platformv1.FlowAction{
			Type: actionType,
		}
		if actionPort > 0 {
			action.Port = strconv.Itoa(actionPort)
		}
		flowActions = append(flowActions, action)
	}

	config := &platformv1.FlowConfig{
		BridgeId: bridgeID,
		Table:    parseFlowTable(table),
		Priority: uint32(priority),
		Match:    match,
		Actions:  flowActions,
		Metadata: map[string]string{
			"flow_id": flowID,
		},
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, err := sdnClient.AddFlow(ctx, config)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "flow add", Err: err}
	}

	return base.Output(resp)
}

func runFlowDelete(flags *cli.CommonFlags, bridgeID, flowID string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnclient.NewClientFromGRPC(base.Client().SDN())

	ctx, cancel := newCLIContext()
	defer cancel()
	if err := sdnClient.DeleteFlow(ctx, bridgeID, flowID); err != nil {
		return &cli.ErrOperationFailed{Operation: "flow delete", Err: err}
	}

	result := map[string]interface{}{
		"bridge_id": bridgeID,
		"flow_id":   flowID,
		"deleted":   true,
	}

	return base.Output(result)
}

func runFlowList(flags *cli.CommonFlags, bridgeID string, table, limit int, cursor string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	sdnClient := sdnclient.NewClientFromGRPC(base.Client().SDN())

	flowTable := platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED
	if table >= 0 {
		flowTable = parseFlowTable(table)
	}

	var pagination *platformv1.PaginationRequest
	if limit > 0 || cursor != "" {
		pagination = &platformv1.PaginationRequest{
			PageSize: uint32(limit),
		}
	}

	ctx, cancel := newCLIContext()
	defer cancel()
	resp, _, err := sdnClient.ListFlows(ctx, bridgeID, flowTable, pagination)
	if err != nil {
		return &cli.ErrOperationFailed{Operation: "flow list", Err: err}
	}

	return base.Output(resp)
}
