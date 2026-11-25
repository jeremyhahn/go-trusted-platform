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

// Package cluster provides CLI commands for cluster management operations
// including bootstrap, join, leave, status, and node listing.
package cluster

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the cluster root command for cluster management operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cluster",
		Short: "Cluster management operations",
		Long: `Manage cluster membership, status, and node operations.

The cluster subsystem provides Raft-based consensus for high availability:
  - Bootstrap a new cluster as the initial leader
  - Join existing clusters as a follower node
  - Graceful or forced leave from the cluster
  - Monitor cluster health and status
  - View cluster node membership

The cluster uses Raft consensus to ensure:
  - Strong consistency for state machine replication
  - Automatic leader election on failure
  - Durable log-based replication
  - Membership changes without downtime

Examples:
  # Bootstrap a new single-node cluster
  platformctl cluster bootstrap --node-id node1 --listen-addr 10.0.0.1:7946

  # Bootstrap with custom data directory
  platformctl cluster bootstrap --node-id node1 --listen-addr 10.0.0.1:7946 --data-dir /var/lib/platform/raft

  # Join an existing cluster
  platformctl cluster join --node-id node2 --listen-addr 10.0.0.2:7946 --join 10.0.0.1:7946

  # Join with multiple seed nodes
  platformctl cluster join --node-id node3 --listen-addr 10.0.0.3:7946 --join 10.0.0.1:7946,10.0.0.2:7946

  # Leave the cluster gracefully
  platformctl cluster leave

  # Force leave (for unresponsive nodes)
  platformctl cluster leave --force

  # Show cluster status
  platformctl cluster status

  # Show cluster status as JSON
  platformctl cluster status -o json

  # List all cluster nodes
  platformctl cluster nodes

  # List nodes as table
  platformctl cluster nodes -o table`,
	}

	// Add subcommands
	cmd.AddCommand(NewBootstrapCommand(getFlags))
	cmd.AddCommand(NewJoinCommand(getFlags))
	cmd.AddCommand(NewLeaveCommand(getFlags))
	cmd.AddCommand(NewStatusCommand(getFlags))
	cmd.AddCommand(NewNodesCommand(getFlags))

	return cmd
}
