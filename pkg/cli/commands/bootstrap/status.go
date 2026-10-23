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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// healthCheckTimeout is the per-node health check HTTP timeout.
	healthCheckTimeout = 10 * time.Second

	// healthEndpointPath is the liveness endpoint every platformd webservice
	// serves without a credential.
	//
	// It is deliberately NOT /api/v1/health, which this probe used to target:
	// the webservice does not serve that path at all (its only /health is
	// /api/v1/platform/health), and the daemon's own listener that does serve
	// it is a different server on a different lifecycle (#232). The probe
	// therefore never reached a handler — before #251 the SPA catch-all
	// answered 200 with index.html so every node read "healthy", and after it
	// the path 404s so every node reads "unhealthy". Neither was a
	// measurement.
	//
	// It is also NOT /api/v1/platform/health, which does carry a component
	// verdict but requires an authenticated admin since #165. This probe runs
	// during bootstrap and holds no credential.
	//
	// /api/v1/status is public by necessity — pkg/bootstrap/orchestrator.go's
	// httpHealthChecker probes it to decide a node has finished booting, from
	// a machine that has no credential and may not yet trust the node's CA —
	// and it is the same question this command asks. Two probes in this repo
	// now agree instead of one of them being wrong.
	healthEndpointPath = "/api/v1/status"

	// healthProbeMinBodyBytes is the smallest response this probe accepts as
	// a platform answer. A status code alone cannot tell platformd from a
	// proxy, a load balancer or a static file server that returns 200 for
	// everything, and an empty 200 is the cheapest way for one of those to
	// look healthy.
	healthProbeMinBodyBytes = 2
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

	// Health probes verify each node's TLS certificate against the
	// control plane's CA pool (fetched capture-then-verify). When the
	// CP CA bundle is unavailable — e.g. the CP itself is not yet
	// provisioned — health is reported as unknown rather than probing
	// over an unverified connection. Control-plane nodes are dialed at
	// whichever of their addresses answers and verified for the control
	// plane's TLS name: their certificate names that DNS identity, not
	// the hostname or address dialed.
	prober := statusProber{cpAddresses: orch.ControlPlaneAddresses, ports: config.HealthProbePorts()}
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
//
// ports are the HTTPS ports tried on each address, in order, because the
// port depends on the node's role and is not carried on the discovered
// node: the control plane serves platform.control_plane_port (default
// 8443), compute 9443 and gateway 443 (configs/platform/templates/**). They
// are the candidates pkg/bootstrap's httpHealthChecker uses, from
// BootstrapConfig.HealthProbePorts.
type statusProber struct {
	nodeClient  *http.Client
	cpClient    *http.Client
	cpAddresses func(*bootstrap.DiscoveredNode) []string
	ports       []int
}

// health reports one node's health string.
func (p statusProber) health(ctx context.Context, n *bootstrap.DiscoveredNode) string {
	if n.Role == bootstrap.RoleControlPlane {
		return checkNodeHealthAny(ctx, p.cpClient, p.cpAddresses(n), p.ports)
	}
	return checkNodeHealth(ctx, p.nodeClient, n.Hostname, p.ports)
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
func checkNodeHealthAny(ctx context.Context, client *http.Client, addresses []string, ports []int) string {
	if client == nil {
		return "unknown"
	}
	if len(addresses) == 0 {
		return "unreachable"
	}
	health := "unreachable"
	for _, address := range addresses {
		if health = checkNodeHealth(ctx, client, address, ports); health != "unreachable" {
			break
		}
	}
	return health
}

// checkNodeHealth performs an HTTPS GET against the node's health endpoint.
// A nil client means no verified trust anchor is available; health is
// reported as unknown instead of probing over an unverified connection.
func checkNodeHealth(ctx context.Context, client *http.Client, address string, ports []int) string {
	if client == nil {
		return "unknown"
	}

	// The node's webservice port depends on its role and is not carried on
	// the discovered node, so try each candidate. "unreachable" from one port
	// says nothing about the others; any other verdict is that node's answer
	// and ends the search.
	health := "unreachable"
	for _, port := range ports {
		if health = probeNodeHealth(ctx, client, net.JoinHostPort(address, strconv.Itoa(port))); health != "unreachable" {
			return health
		}
	}
	return health
}

// probeNodeHealth performs one HTTPS GET against one host:port.
//
// It grades on the status code AND on there being a response body, because a
// status code alone cannot distinguish platformd from anything else willing to
// answer 200 on that port. That is not hypothetical: until #251 the platform's
// own SPA fallback answered this probe with index.html and a 200, and the
// command reported every node healthy on the strength of it.
func probeNodeHealth(ctx context.Context, client *http.Client, hostPort string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+hostPort+healthEndpointPath, nil)
	if err != nil {
		return "unreachable"
	}
	resp, err := client.Do(req)
	if err != nil {
		return "unreachable"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "unhealthy"
	}

	// Read a bounded prefix: enough to tell an answer from an empty 200,
	// without pulling a whole page from something that is not platformd.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil || len(bytes.TrimSpace(body)) < healthProbeMinBodyBytes {
		return "unhealthy"
	}
	if !json.Valid(pruneToJSON(body)) {
		return "unhealthy"
	}
	return "healthy"
}

// pruneToJSON trims a bounded prefix to something json.Valid can judge. The
// probe reads at most 512 bytes, so a genuine platform response is usually
// truncated mid-object; this keeps the check to what a truncated prefix can
// actually prove — that the response opens as a JSON object or array rather
// than as HTML, which is the distinction that matters here.
func pruneToJSON(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return trimmed
	}
	switch trimmed[0] {
	case '{':
		return []byte("{}")
	case '[':
		return []byte("[]")
	default:
		// Not JSON at all — "<!DOCTYPE html>" lands here, which is the case
		// this check exists for.
		return trimmed
	}
}
