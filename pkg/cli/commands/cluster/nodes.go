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

package cluster

import (
	"fmt"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewNodesCommand creates the cluster nodes subcommand
func NewNodesCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "List cluster nodes",
		Long: `List all nodes in the cluster with their status information.

This command displays all cluster members with their current state:
  - Node identifier
  - Network address
  - Health state (alive/suspect/dead/left)
  - Raft state (leader/follower/candidate)
  - Uptime since joining

The node list is retrieved from the local node's membership view.

Examples:
  # List all cluster nodes
  platformctl cluster nodes

  # Output as table
  platformctl cluster nodes -o table

  # Output as JSON
  platformctl cluster nodes -o json

  # Output as YAML
  platformctl cluster nodes -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runNodes(flags)
		},
	}

	return cmd
}

func runNodes(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().Cluster()
	if client == nil {
		return ErrClusterClientNotInitialized{}
	}

	req := &platformv1.ListClusterNodesRequest{}

	ctx := base.Context()
	resp, err := client.ListNodes(ctx, req)
	if err != nil {
		return ErrClusterNodesFailed{Err: err}
	}

	// Convert response nodes to local NodeInfo type
	nodes := make([]*NodeInfo, 0, len(resp.GetNodes()))
	leaderID := ""
	voterCount := 0

	for _, node := range resp.GetNodes() {
		isLeader := node.GetRole() == platformv1.NodeRole_NODE_ROLE_LEADER
		if isLeader {
			leaderID = node.GetId()
		}

		// Count voters (non-observer nodes)
		if node.GetRole() != platformv1.NodeRole_NODE_ROLE_OBSERVER {
			voterCount++
		}

		nodeInfo := &NodeInfo{
			NodeID:    node.GetId(),
			Address:   fmt.Sprintf("%s:%d", node.GetAddress(), node.GetPort()),
			State:     nodeStateToString(node.GetState()),
			RaftState: nodeRoleToRaftState(node.GetRole()),
			IsVoter:   node.GetRole() != platformv1.NodeRole_NODE_ROLE_OBSERVER,
			IsLeader:  isLeader,
			LastSeen:  "N/A",
			Uptime:    "N/A",
		}

		if node.GetLastHeartbeat() != nil {
			nodeInfo.LastSeen = formatTimestamp(node.GetLastHeartbeat().AsTime())
		}

		if node.GetJoinedAt() != nil {
			nodeInfo.Uptime = formatUptime(node.GetJoinedAt().AsTime())
		}

		nodes = append(nodes, nodeInfo)
	}

	response := &NodeListResponse{
		Nodes:      nodes,
		TotalCount: int(resp.GetTotal()),
		VoterCount: voterCount,
		LeaderID:   leaderID,
	}

	// Use total from response if available, otherwise use slice length
	if response.TotalCount == 0 {
		response.TotalCount = len(nodes)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(response)

	case cli.OutputFormatTable:
		return printNodesTable(printer, response)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// nodeStateToString converts a protobuf NodeState to a local NodeState string
func nodeStateToString(state platformv1.NodeState) string {
	switch state {
	case platformv1.NodeState_NODE_STATE_ACTIVE:
		return string(NodeStateAlive)
	case platformv1.NodeState_NODE_STATE_JOINING:
		return string(NodeStateSuspect)
	case platformv1.NodeState_NODE_STATE_LEAVING:
		return string(NodeStateSuspect)
	case platformv1.NodeState_NODE_STATE_LEFT:
		return string(NodeStateLeft)
	case platformv1.NodeState_NODE_STATE_FAILED:
		return string(NodeStateDead)
	case platformv1.NodeState_NODE_STATE_UNREACHABLE:
		return string(NodeStateDead)
	default:
		return string(NodeStateUnknown)
	}
}

// printNodesTable prints nodes in table format
func printNodesTable(printer *cli.Printer, response *NodeListResponse) error {
	if len(response.Nodes) == 0 {
		printer.PrintInfo("No nodes found in cluster")
		return nil
	}

	table := cli.NewTableData("NODE_ID", "ADDRESS", "STATE", "RAFT_STATE", "UPTIME")
	for _, node := range response.Nodes {
		raftState := formatRaftState(RaftState(node.RaftState))
		if node.IsLeader {
			raftState = raftState + " *"
		}
		table.AddRow(
			truncateID(node.NodeID),
			node.Address,
			formatNodeState(NodeState(node.State)),
			raftState,
			node.Uptime,
		)
	}

	if err := printer.Print(*table); err != nil {
		return err
	}

	fmt.Println()
	printer.PrintKeyValue("Total Nodes", fmt.Sprintf("%d", response.TotalCount))
	printer.PrintKeyValue("Voter Count", fmt.Sprintf("%d", response.VoterCount))
	printer.PrintKeyValue("Leader", response.LeaderID)

	return nil
}
