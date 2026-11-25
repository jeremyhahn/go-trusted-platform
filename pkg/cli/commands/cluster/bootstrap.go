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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	clustersvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/cluster"
)

// NewBootstrapCommand creates the cluster bootstrap subcommand
func NewBootstrapCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var nodeID string
	var listenAddr string
	var advertiseAddr string
	var dataDir string

	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap a new cluster",
		Long: `Bootstrap a new cluster with this node as the initial leader.

This command initializes a new Raft cluster with the current node as the
founding member and initial leader. Use this only for the first node in
a new cluster; subsequent nodes should use the 'join' command.

The bootstrap operation:
  1. Initializes the Raft state machine
  2. Creates the cluster configuration
  3. Establishes this node as leader
  4. Begins accepting join requests from other nodes

IMPORTANT: Only run bootstrap once per cluster. Running bootstrap on
multiple nodes will create separate clusters that cannot be merged.

Examples:
  # Bootstrap with required flags
  platformctl cluster bootstrap --node-id node1 --listen-addr 10.0.0.1:7946

  # Bootstrap with advertise address (for NAT/container environments)
  platformctl cluster bootstrap --node-id node1 --listen-addr 0.0.0.0:7946 --advertise-addr 10.0.0.1:7946

  # Bootstrap with custom data directory
  platformctl cluster bootstrap --node-id node1 --listen-addr 10.0.0.1:7946 --data-dir /var/lib/platform/raft`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runBootstrap(flags, nodeID, listenAddr, advertiseAddr, dataDir)
		},
	}

	cmd.Flags().StringVar(&nodeID, "node-id", "", "unique identifier for this node (required)")
	cmd.Flags().StringVar(&listenAddr, "listen-addr", "", "address to listen on for cluster communication (host:port, required)")
	cmd.Flags().StringVar(&advertiseAddr, "advertise-addr", "", "address to advertise to other nodes (defaults to listen-addr)")
	cmd.Flags().StringVar(&dataDir, "data-dir", "", "directory for storing Raft data (optional)")

	if err := cmd.MarkFlagRequired("node-id"); err != nil {
		panic(fmt.Sprintf("failed to mark node-id flag required: %v", err))
	}
	if err := cmd.MarkFlagRequired("listen-addr"); err != nil {
		panic(fmt.Sprintf("failed to mark listen-addr flag required: %v", err))
	}

	return cmd
}

func runBootstrap(flags *cli.CommonFlags, nodeID, listenAddr, advertiseAddr, dataDir string) error {
	// Validate inputs
	if nodeID == "" {
		return ErrMissingNodeID{}
	}
	if listenAddr == "" {
		return ErrMissingListenAddr{}
	}
	if err := validateAddress(listenAddr); err != nil {
		return ErrInvalidListenAddr{Addr: listenAddr, Reason: err.Error()}
	}
	if advertiseAddr != "" {
		if err := validateAddress(advertiseAddr); err != nil {
			return ErrInvalidListenAddr{Addr: advertiseAddr, Reason: err.Error()}
		}
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

	grpcClient := base.Client().Cluster()
	if grpcClient == nil {
		return ErrClusterClientNotInitialized{}
	}

	sdkClient := clustersvc.NewClientFromGRPC(grpcClient)

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

	ctx := base.Context()
	resp, err := sdkClient.BootstrapDomain(ctx, nodeID, nodeID,
		bindHost, uint32(bindPort), advHost, uint32(advPort))
	if err != nil {
		return ErrClusterBootstrapFailed{Err: err}
	}

	// Build result from response
	result := &BootstrapResult{
		ClusterID:  resp.ClusterID,
		NodeID:     resp.NodeID,
		ListenAddr: advertiseAddr,
		DataDir:    dataDir,
		Success:    true,
		Message:    resp.Message,
	}

	if result.NodeID == "" {
		result.NodeID = nodeID
	}
	if result.Message == "" {
		result.Message = "Cluster bootstrap initiated successfully"
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		return printBootstrapResult(printer, result)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printBootstrapResult prints bootstrap result in table format
func printBootstrapResult(printer *cli.Printer, result *BootstrapResult) error {
	if result.Success {
		printer.PrintSuccess("Cluster bootstrapped successfully")
	} else {
		printer.PrintError("Cluster bootstrap failed")
	}

	fmt.Println()
	printer.PrintKeyValue("Cluster ID", result.ClusterID)
	printer.PrintKeyValue("Node ID", result.NodeID)
	printer.PrintKeyValue("Listen Address", result.ListenAddr)
	if result.DataDir != "" {
		printer.PrintKeyValue("Data Directory", result.DataDir)
	}
	fmt.Println()
	printer.PrintInfo(result.Message)

	return nil
}
