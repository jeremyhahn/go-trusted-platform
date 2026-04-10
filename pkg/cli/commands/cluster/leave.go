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

// NewLeaveCommand creates the cluster leave subcommand
func NewLeaveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool
	var nodeID string
	var timeoutSeconds uint32

	cmd := &cobra.Command{
		Use:   "leave",
		Short: "Leave the cluster",
		Long: `Remove this node from the cluster.

This command initiates a graceful departure from the cluster. The node
notifies the cluster leader of its intention to leave, allowing the
cluster to remove it from the configuration and rebalance if necessary.

Graceful leave (default):
  1. Notifies the cluster leader
  2. Waits for in-flight operations to complete
  3. Transfers leadership if this node is the leader
  4. Removes itself from the configuration
  5. Shuts down cluster communication

Force leave (--force):
  Use when the node is unable to communicate with the cluster or when
  a graceful leave has failed. This immediately stops cluster participation
  without coordinating with other nodes.

  WARNING: Force leave should be used with caution as it may cause the
  cluster to see this node as failed until it times out.

Examples:
  # Graceful leave
  platformctl cluster leave

  # Force leave (when cluster is unreachable)
  platformctl cluster leave --force

  # Leave a specific node
  platformctl cluster leave --node-id node2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runLeave(flags, nodeID, force, timeoutSeconds)
		},
	}

	cmd.Flags().BoolVar(&force, "force", false, "force leave without graceful shutdown")
	cmd.Flags().StringVar(&nodeID, "node-id", "", "node ID to remove (defaults to local node)")
	cmd.Flags().Uint32Var(&timeoutSeconds, "timeout", 30, "timeout in seconds for graceful leave")

	return cmd
}

func runLeave(flags *cli.CommonFlags, nodeID string, force bool, timeoutSeconds uint32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().Cluster()
	if client == nil {
		return ErrClusterClientNotInitialized{}
	}

	req := &platformv1.LeaveClusterRequest{
		NodeId:         nodeID,
		Force:          force,
		TimeoutSeconds: timeoutSeconds,
	}

	ctx := base.Context()
	resp, err := client.Leave(ctx, req)
	if err != nil {
		return ErrClusterLeaveFailed{Err: err}
	}

	// Build result from response
	result := &LeaveResult{
		NodeID:  nodeID,
		Force:   force,
		Success: true,
		Message: "Successfully left cluster",
	}

	if force {
		result.Message = "Force left cluster (immediate)"
	}

	if resp.GetStatus() != nil && resp.GetStatus().GetMessage() != "" {
		result.Message = resp.GetStatus().GetMessage()
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printLeaveResult(printer, result)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printLeaveResult prints leave result in table format
func printLeaveResult(printer *cli.Printer, result *LeaveResult) error {
	if result.Success {
		printer.PrintSuccess("Successfully left cluster")
	} else {
		printer.PrintError("Failed to leave cluster")
	}

	fmt.Println()
	printer.PrintKeyValue("Node ID", result.NodeID)
	printer.PrintKeyValue("Force Leave", formatBool(result.Force))
	fmt.Println()
	printer.PrintInfo(result.Message)

	return nil
}
