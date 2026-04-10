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
	"net"
	"strconv"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewJoinCommand creates the cluster join subcommand
func NewJoinCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var nodeID string
	var listenAddr string
	var advertiseAddr string
	var joinAddrs string

	cmd := &cobra.Command{
		Use:   "join",
		Short: "Join an existing cluster",
		Long: `Join this node to an existing cluster as a follower.

This command connects to one or more existing cluster members and requests
to join the cluster. The cluster leader will add this node to the
configuration and begin replicating state to it.

The join operation:
  1. Connects to the specified seed nodes
  2. Discovers the current cluster leader
  3. Sends a join request to the leader
  4. Receives and applies the cluster state
  5. Begins participating in consensus

Multiple seed nodes can be specified for redundancy. The join will succeed
as long as at least one seed node is reachable and the cluster has quorum.

Examples:
  # Join using a single seed node
  platformctl cluster join --node-id node2 --listen-addr 10.0.0.2:7946 --join 10.0.0.1:7946

  # Join with multiple seed nodes for redundancy
  platformctl cluster join --node-id node3 --listen-addr 10.0.0.3:7946 --join 10.0.0.1:7946,10.0.0.2:7946

  # Join with advertise address (for NAT/container environments)
  platformctl cluster join --node-id node2 --listen-addr 0.0.0.0:7946 --advertise-addr 10.0.0.2:7946 --join 10.0.0.1:7946`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runJoin(flags, nodeID, listenAddr, advertiseAddr, joinAddrs)
		},
	}

	cmd.Flags().StringVar(&nodeID, "node-id", "", "unique identifier for this node (required)")
	cmd.Flags().StringVar(&listenAddr, "listen-addr", "", "address to listen on for cluster communication (host:port, required)")
	cmd.Flags().StringVar(&advertiseAddr, "advertise-addr", "", "address to advertise to other nodes (defaults to listen-addr)")
	cmd.Flags().StringVar(&joinAddrs, "join", "", "comma-separated list of existing cluster node addresses to join (required)")

	if err := cmd.MarkFlagRequired("node-id"); err != nil {
		panic(fmt.Sprintf("failed to mark node-id flag required: %v", err))
	}
	if err := cmd.MarkFlagRequired("listen-addr"); err != nil {
		panic(fmt.Sprintf("failed to mark listen-addr flag required: %v", err))
	}
	if err := cmd.MarkFlagRequired("join"); err != nil {
		panic(fmt.Sprintf("failed to mark join flag required: %v", err))
	}

	return cmd
}

func runJoin(flags *cli.CommonFlags, nodeID, listenAddr, advertiseAddr, joinAddrs string) error {
	// Validate inputs
	if nodeID == "" {
		return ErrMissingNodeID{}
	}
	if listenAddr == "" {
		return ErrMissingListenAddr{}
	}
	if joinAddrs == "" {
		return ErrMissingJoinAddrs{}
	}
	if err := validateAddress(listenAddr); err != nil {
		return ErrInvalidListenAddr{Addr: listenAddr, Reason: err.Error()}
	}
	if advertiseAddr != "" {
		if err := validateAddress(advertiseAddr); err != nil {
			return ErrInvalidListenAddr{Addr: advertiseAddr, Reason: err.Error()}
		}
	}

	// Parse and validate join addresses
	addrs := parseAddressList(joinAddrs)
	if len(addrs) == 0 {
		return ErrMissingJoinAddrs{}
	}
	if err := validateAddressList(addrs); err != nil {
		return err
	}

	// Use listen address as advertise address if not specified
	if advertiseAddr == "" {
		advertiseAddr = listenAddr
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().Cluster()
	if client == nil {
		return ErrClusterClientNotInitialized{}
	}

	// Parse listen address into host and port
	bindHost, bindPortStr, splitErr := net.SplitHostPort(listenAddr)
	if splitErr != nil {
		return ErrInvalidListenAddr{Addr: listenAddr, Reason: splitErr.Error()}
	}
	bindPort, parseErr := strconv.ParseUint(bindPortStr, 10, 32)
	if parseErr != nil {
		return ErrInvalidListenAddr{Addr: listenAddr, Reason: "invalid port number"}
	}

	// Parse advertise address into host and port
	advHost, advPortStr, advSplitErr := net.SplitHostPort(advertiseAddr)
	if advSplitErr != nil {
		return ErrInvalidListenAddr{Addr: advertiseAddr, Reason: advSplitErr.Error()}
	}
	advPort, advParseErr := strconv.ParseUint(advPortStr, 10, 32)
	if advParseErr != nil {
		return ErrInvalidListenAddr{Addr: advertiseAddr, Reason: "invalid port number"}
	}

	req := &platformv1.JoinClusterRequest{
		NodeName:         nodeID,
		BindAddress:      bindHost,
		BindPort:         uint32(bindPort),
		AdvertiseAddress: advHost,
		AdvertisePort:    uint32(advPort),
		SeedAddresses:    addrs,
	}

	ctx := base.Context()
	resp, err := client.Join(ctx, req)
	if err != nil {
		return ErrClusterJoinFailed{Err: err}
	}

	// Build result from response
	result := &JoinResult{
		NodeID:     nodeID,
		ClusterID:  "",
		LeaderID:   "",
		LeaderAddr: "",
		JoinedFrom: addrs,
		Success:    true,
		Message:    "Successfully joined cluster",
	}

	if resp.GetCluster() != nil {
		result.ClusterID = resp.GetCluster().GetId()
		result.LeaderID = resp.GetCluster().GetLeaderId()
		result.LeaderAddr = resp.GetCluster().GetLeaderAddress()
	}
	if resp.GetNode() != nil {
		result.NodeID = resp.GetNode().GetId()
	}
	if resp.GetStatus() != nil && resp.GetStatus().GetMessage() != "" {
		result.Message = resp.GetStatus().GetMessage()
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printJoinResult(printer, result)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printJoinResult prints join result in table format
func printJoinResult(printer *cli.Printer, result *JoinResult) error {
	if result.Success {
		printer.PrintSuccess("Successfully joined cluster")
	} else {
		printer.PrintError("Failed to join cluster")
	}

	fmt.Println()
	printer.PrintKeyValue("Node ID", result.NodeID)
	printer.PrintKeyValue("Cluster ID", result.ClusterID)
	printer.PrintKeyValue("Leader ID", result.LeaderID)
	printer.PrintKeyValue("Leader Address", result.LeaderAddr)

	if len(result.JoinedFrom) > 0 {
		for i, addr := range result.JoinedFrom {
			if i == 0 {
				printer.PrintKeyValue("Seed Nodes", addr)
			} else {
				printer.PrintKeyValue("           ", addr)
			}
		}
	}

	fmt.Println()
	printer.PrintInfo(result.Message)

	return nil
}
