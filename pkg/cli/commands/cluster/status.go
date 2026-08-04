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

// NewStatusCommand creates the cluster status subcommand
func NewStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var includeNodes bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show cluster status",
		Long: `Display the current cluster status and health information.

This command shows comprehensive information about the cluster state:
  - Cluster and node identifiers
  - Current Raft state (leader/follower/candidate)
  - Leader information and reachability
  - Raft term and commit index
  - Node count and voter count
  - Overall cluster health

The information is retrieved from the local node's view of the cluster.

Examples:
  # Show cluster status
  platformctl cluster status

  # Show cluster status with node list
  platformctl cluster status --include-nodes

  # Output as JSON
  platformctl cluster status -o json

  # Output as YAML
  platformctl cluster status -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStatus(flags, includeNodes)
		},
	}

	cmd.Flags().BoolVar(&includeNodes, "include-nodes", false, "include list of nodes in response")

	return cmd
}

func runStatus(flags *cli.CommonFlags, includeNodes bool) error {
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

	resp, err := sdkClient.GetStatusDomain(ctx, includeNodes)
	if err != nil {
		return ErrClusterStatusFailed{Err: err}
	}

	// Build status summary from response
	status := &ClusterStatusSummary{
		ClusterID:    resp.ClusterID,
		NodeID:       resp.LocalNodeID,
		RaftState:    nodeRoleToRaftState(resp.LocalRole),
		LeaderID:     resp.LeaderID,
		LeaderAddr:   resp.LeaderAddr,
		Term:         resp.Term,
		CommitIndex:  0,
		AppliedIndex: 0,
		LastContact:  "N/A",
		NodeCount:    int(resp.TotalNodes),
		VoterCount:   int(resp.HealthyNodes),
		Healthy:      resp.State == clustersvc.ClusterStateHealthy,
		Timestamp:    formatTimestamp(resp.Timestamp),
	}

	if resp.LastHeartbeat != nil {
		status.LastContact = formatTimestamp(*resp.LastHeartbeat)
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		return printClusterStatus(printer, status)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// nodeRoleToRaftState converts an SDK NodeRole to a local RaftState string
func nodeRoleToRaftState(role clustersvc.NodeRole) string {
	switch role {
	case clustersvc.NodeRoleLeader:
		return string(RaftStateLeader)
	case clustersvc.NodeRoleFollower:
		return string(RaftStateFollower)
	case clustersvc.NodeRoleCandidate:
		return string(RaftStateCandidate)
	default:
		return string(RaftStateUnknown)
	}
}

// printClusterStatus prints cluster status in table format
func printClusterStatus(printer *cli.Printer, status *ClusterStatusSummary) error {
	// Print health status header
	if status.Healthy {
		printer.PrintSuccess("Cluster is healthy")
	} else {
		printer.PrintWarning("Cluster health degraded")
	}

	fmt.Println()
	printer.PrintInfo("Cluster Information:")
	printer.PrintKeyValue("  Cluster ID", status.ClusterID)
	printer.PrintKeyValue("  Node ID", status.NodeID)
	printer.PrintKeyValue("  Node Count", fmt.Sprintf("%d", status.NodeCount))
	printer.PrintKeyValue("  Voter Count", fmt.Sprintf("%d", status.VoterCount))

	fmt.Println()
	printer.PrintInfo("Raft State:")
	printer.PrintKeyValue("  State", formatRaftState(RaftState(status.RaftState)))
	printer.PrintKeyValue("  Term", formatTerm(status.Term))
	printer.PrintKeyValue("  Commit Index", formatCommitIndex(status.CommitIndex))
	printer.PrintKeyValue("  Applied Index", formatCommitIndex(status.AppliedIndex))

	fmt.Println()
	printer.PrintInfo("Leader Information:")
	printer.PrintKeyValue("  Leader ID", status.LeaderID)
	printer.PrintKeyValue("  Leader Address", status.LeaderAddr)
	printer.PrintKeyValue("  Last Contact", status.LastContact)

	fmt.Println()
	printer.PrintKeyValue("Timestamp", status.Timestamp)

	return nil
}
