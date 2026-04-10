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
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// healthCheckTimeout is the per-node health check HTTP timeout.
	healthCheckTimeout = 10 * time.Second

	// healthEndpointPath is the REST health endpoint path.
	healthEndpointPath = "/api/v1/health"
)

// newStatusCommand creates the status subcommand for checking node health.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check bootstrap node status",
		Long: `Check the health status of all nodes in the bootstrap configuration.

For each node, an HTTPS health check is performed against the REST
health endpoint. Results are displayed as a table.

Examples:
  # Check status of all nodes
  platformctl bootstrap status --config bootstrap.yaml`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			return runStatus(configPath, commonFlags)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bootstrap YAML configuration (required)")

	return cmd
}

// runStatus loads config, discovers nodes, checks health of each, and prints results.
func runStatus(configPath string, commonFlags *cli.CommonFlags) error {
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

	// Discover to get full node list with MACs.
	discovered, err := orch.Discover(ctx)
	if err != nil {
		return ErrPXEDiscoveryFailed{Cause: err}
	}

	// During bootstrap the CA may not yet exist on target nodes, so TLS
	// verification must be skipped for health probes.
	httpClient := &http.Client{
		Timeout: healthCheckTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // Required during bootstrap before CA exists on nodes.
			},
		},
	}

	fmt.Fprintf(os.Stdout, "\nNode Status (%d nodes)\n", len(discovered))
	fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %s\n",
		"HOSTNAME", "ROLE", "MAC", "BMC", "HEALTH")
	fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %s\n",
		"--------", "----", "---", "---", "------")

	for i := range discovered {
		n := &discovered[i]
		bmcStr := "manual"
		if n.BMCManaged {
			bmcStr = "bmc"
		}

		health := checkNodeHealth(ctx, httpClient, n.Hostname)

		fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %s\n",
			n.Hostname, n.Role, joinMACs(n.DiscoveredMACs), bmcStr, health)
	}
	fmt.Fprintln(os.Stdout)

	return nil
}

// checkNodeHealth performs an HTTPS GET against the node's health endpoint.
func checkNodeHealth(ctx context.Context, client *http.Client, hostname string) string {
	url := "https://" + hostname + ":8443" + healthEndpointPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "unreachable"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unreachable"
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "unhealthy"
	}
	return "healthy"
}
