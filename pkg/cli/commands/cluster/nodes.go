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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	clustersvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/cluster"
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

	grpcClient := base.Client().Cluster()
	if grpcClient == nil {
		return ErrClusterClientNotInitialized{}
	}

	sdkClient := clustersvc.NewClientFromGRPC(grpcClient)
	ctx := base.Context()

	resp, err := sdkClient.ListNodesDomain(ctx)
	if err != nil {
		return ErrClusterNodesFailed{Err: err}
	}

	// Convert response nodes to local NodeInfo type
	nodes := make([]*NodeInfo, 0, len(resp.Nodes))
	leaderID := ""
	voterCount := 0

	for _, node := range resp.Nodes {
		isLeader := node.Role == clustersvc.NodeRoleLeader
		if isLeader {
			leaderID = node.ID
		}

		// Count voters (non-observer nodes)
		if node.Role != clustersvc.NodeRoleObserver {
			voterCount++
		}

		nodeInfo := &NodeInfo{
			NodeID:    node.ID,
			Address:   fmt.Sprintf("%s:%d", node.Address, node.Port),
			State:     nodeStateToString(node.State),
			RaftState: nodeRoleToRaftState(node.Role),
			IsVoter:   node.Role != clustersvc.NodeRoleObserver,
			IsLeader:  isLeader,
			LastSeen:  "N/A",
			Uptime:    "N/A",
		}

		if node.LastHeartbeat != nil {
			nodeInfo.LastSeen = formatTimestamp(*node.LastHeartbeat)
		}

		if node.JoinedAt != nil {
			nodeInfo.Uptime = formatUptime(*node.JoinedAt)
		}

		nodes = append(nodes, nodeInfo)
	}

	response := &NodeListResponse{
		Nodes:      nodes,
		TotalCount: int(resp.Total),
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

// nodeStateToString converts an SDK NodeState to a local NodeState string
func nodeStateToString(state clustersvc.NodeState) string {
	switch state {
	case clustersvc.NodeStateActive:
		return string(NodeStateAlive)
	case clustersvc.NodeStateJoining:
		return string(NodeStateSuspect)
	case clustersvc.NodeStateLeaving:
		return string(NodeStateSuspect)
	case clustersvc.NodeStateLeft:
		return string(NodeStateLeft)
	case clustersvc.NodeStateFailed:
		return string(NodeStateDead)
	case clustersvc.NodeStateUnreachable:
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
			raftState += " *"
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
