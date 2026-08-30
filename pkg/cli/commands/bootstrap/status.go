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
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// healthCheckTimeout is the per-node health check HTTP timeout.
	healthCheckTimeout = 10 * time.Second

	// healthEndpointPath is the REST health endpoint path.
	healthEndpointPath = "/api/v1/health"
)

// healthPort is the HTTPS port the status probe dials on every node. A
// variable so a test can point the probe at an ephemeral listener.
var healthPort = "8443"

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

	// Health probes verify each node's TLS certificate against the
	// control plane's CA pool (fetched capture-then-verify). When the
	// CP CA bundle is unavailable — e.g. the CP itself is not yet
	// provisioned — health is reported as unknown rather than probing
	// over an unverified connection. Control-plane nodes are dialed at
	// whichever of their addresses answers and verified for the control
	// plane's TLS name: their certificate names that DNS identity, not
	// the hostname or address dialed.
	prober := statusProber{cpAddresses: orch.ControlPlaneAddresses}
	caPool, caErr := orch.ControlPlaneCAPool(ctx)
	if caErr != nil {
		fmt.Fprintf(os.Stderr,
			"warning: control-plane CA bundle unavailable, node health cannot be verified: %v\n", caErr)
	} else {
		prober.nodeClient = newHealthClient(caPool, "")
		if cpTLSName, nameErr := orch.ControlPlaneTLSName(); nameErr != nil {
			fmt.Fprintf(os.Stderr,
				"warning: control-plane TLS name unknown, control-plane health cannot be verified: %v\n", nameErr)
		} else {
			prober.cpClient = newHealthClient(caPool, cpTLSName)
		}
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

		health := prober.health(ctx, n)

		fmt.Fprintf(os.Stdout, "  %-20s %-15s %-18s %-10s %s\n",
			n.Hostname, n.Role, joinMACs(n.DiscoveredMACs), bmcStr, health)
	}
	fmt.Fprintln(os.Stdout)

	return nil
}

// statusProber selects how each node is probed. Control-plane nodes are
// dialed at their candidate addresses and verified for the control
// plane's TLS name (cpClient); every other node is dialed by hostname
// and verified for that hostname (nodeClient), which holds only while
// nodes[].hostname is a DNS SAN of the certificate the node serves — a
// short hostname against an FQDN-only certificate is reported
// unreachable, the same way the control plane was before #107.
type statusProber struct {
	nodeClient  *http.Client
	cpClient    *http.Client
	cpAddresses func(*bootstrap.DiscoveredNode) []string
}

// health reports one node's health string.
func (p statusProber) health(ctx context.Context, n *bootstrap.DiscoveredNode) string {
	if n.Role == bootstrap.RoleControlPlane {
		return checkNodeHealthAny(ctx, p.cpClient, p.cpAddresses(n))
	}
	return checkNodeHealth(ctx, p.nodeClient, n.Hostname)
}

// newHealthClient builds the status probe client for the given trust
// anchor. serverName, when set, is the DNS name the probed certificate
// must be issued for regardless of the address dialed.
func newHealthClient(caPool *x509.CertPool, serverName string) *http.Client {
	return &http.Client{
		Timeout: healthCheckTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    caPool,
				ServerName: serverName,
			},
		},
	}
}

// checkNodeHealthAny probes each address in turn and reports the first
// answer that is not "unreachable", or "unreachable" when none answers.
func checkNodeHealthAny(ctx context.Context, client *http.Client, addresses []string) string {
	if client == nil {
		return "unknown"
	}
	if len(addresses) == 0 {
		return "unreachable"
	}
	health := "unreachable"
	for _, address := range addresses {
		if health = checkNodeHealth(ctx, client, address); health != "unreachable" {
			break
		}
	}
	return health
}

// checkNodeHealth performs an HTTPS GET against the node's health endpoint.
// A nil client means no verified trust anchor is available; health is
// reported as unknown instead of probing over an unverified connection.
func checkNodeHealth(ctx context.Context, client *http.Client, address string) string {
	if client == nil {
		return "unknown"
	}
	url := "https://" + net.JoinHostPort(address, healthPort) + healthEndpointPath
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
