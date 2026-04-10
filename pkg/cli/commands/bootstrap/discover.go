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

package bootstrap

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newDiscoverCommand creates the discover subcommand for running Phase 0 only.
func newDiscoverCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Discover node MAC addresses",
		Long: `Run Phase 0 of the PXE bootstrap: discover MAC addresses from BMCs.

For BMC-managed nodes, this command connects to each BMC and retrieves
the host NIC MAC address. For manual nodes, the configured MAC is used.

Examples:
  # Discover all node MACs
  platformctl bootstrap discover --config bootstrap.yaml`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			return runDiscover(configPath, commonFlags)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bootstrap YAML configuration (required)")

	return cmd
}

// runDiscover loads config, creates the orchestrator, runs discovery, and prints results.
func runDiscover(configPath string, commonFlags *cli.CommonFlags) error {
	config, err := loadAndValidateConfig(configPath)
	if err != nil {
		return err
	}

	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr).Slog()

	orch, err := createOrchestrator(config, configPath, logger)
	if err != nil {
		return err
	}

	ctx := context.Background()
	discovered, err := orch.Discover(ctx)
	if err != nil {
		return ErrPXEDiscoveryFailed{Cause: err}
	}

	printDiscoveredNodes(discovered)
	return nil
}

// printDiscoveredNodes prints a table of discovered node MAC addresses.
func printDiscoveredNodes(nodes []bootstrap.DiscoveredNode) {
	fmt.Fprintf(os.Stdout, "\nDiscovered Nodes (%d)\n", len(nodes))
	fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %s\n",
		"HOSTNAME", "ROLE", "MAC", "BMC", "SYSTEM INFO")
	fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %s\n",
		"--------", "----", "---", "---", "-----------")

	for i := range nodes {
		n := &nodes[i]
		bmcStr := "manual"
		if n.BMCManaged {
			bmcStr = "bmc"
		}
		sysInfo := ""
		if n.SystemInfo != nil {
			sysInfo = n.SystemInfo.Manufacturer + " " + n.SystemInfo.Product
		}
		fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %s\n",
			n.Hostname, n.Role, joinMACs(n.DiscoveredMACs), bmcStr, sysInfo)
	}
	fmt.Fprintln(os.Stdout)
}
