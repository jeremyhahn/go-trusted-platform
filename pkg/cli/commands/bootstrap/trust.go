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
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// defaultCertPath is the default system trust store path for Alpine Linux.
const defaultCertPath = "/usr/local/share/ca-certificates/platform-ca.crt"

// defaultPerMethodTimeout is the default timeout for each trust strategy.
const defaultPerMethodTimeout = 5 * time.Second

// strategyAuto is the CLI flag value that expands to the full ordered
// fetch chain (dane, noise, spki).
const strategyAuto = "auto"

// trustFlags holds the flags for the trust subcommand.
type trustFlags struct {
	serverURL        string
	strategy         string
	dnsServer        string
	hostname         string
	noiseKey         string
	noiseAddr        string
	spkiPin          string
	bundlePath       string
	installToSystem  bool
	certPath         string
	perMethodTimeout time.Duration
}

// NewTrustCommand creates the trust subcommand for bootstrapping platform trust.
func NewTrustCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags trustFlags

	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Bootstrap platform trust",
		Long: `Bootstrap trust with the platform by fetching the CA certificate bundle.

This command fetches the platform CA bundle using the configured strategy
(DANE, Noise, SPKI, embedded, or auto) and optionally installs it into
the system trust store. It is used during ISO boot to establish TLS trust
before the device can communicate securely with the provisioning server.

Strategies:
  auto     - Ordered chain: dane, noise, spki (default)
  dane     - Verify CA via DANE/TLSA DNS records
  noise    - Fetch CA via Noise_NK encrypted channel
  spki     - Fetch CA with SPKI-pinned TLS
  embedded - Use CA bundle already embedded in the ISO

Examples:
  # Auto-detect best method
  platformctl bootstrap trust \
    --server-url https://platform:8443 \
    --strategy auto \
    --install-to-system-trust

  # Use DANE with custom DNS server
  platformctl bootstrap trust \
    --server-url https://platform:8443 \
    --strategy dane \
    --dns-server 8.8.8.8 \
    --install-to-system-trust

  # Use SPKI pin
  platformctl bootstrap trust \
    --server-url https://platform:8443 \
    --strategy spki \
    --spki-pin <64-hex-sha256> \
    --install-to-system-trust

  # Use Noise protocol
  platformctl bootstrap trust \
    --server-url https://platform:8443 \
    --strategy noise \
    --noise-key <hex-key> \
    --noise-addr platform:9999 \
    --install-to-system-trust`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			commonFlags := getFlags()
			return runTrust(cmd.Context(), &flags, commonFlags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "platform server URL (required)")
	cmd.Flags().StringVar(&flags.strategy, "strategy", strategyAuto, "bootstrap strategy: auto, dane, noise, spki, embedded")
	cmd.Flags().StringVar(&flags.dnsServer, "dns-server", "",
		"DNS server for DANE lookups. Accepts \"host\" (port 53 assumed) "+
			"or \"host:port\" for non-standard ports. Trusted Platform CPs "+
			"intentionally do NOT bind privileged port 53 (platformd runs "+
			"as a non-root user); the canonical DANE resolver port for a "+
			"control plane is 8053. Example: --dns-server 198.18.1.140:8053")
	cmd.Flags().StringVar(&flags.hostname, "hostname", "", "server hostname for DANE TLSA lookups")
	cmd.Flags().StringVar(&flags.noiseKey, "noise-key", "", "Noise_NK server static key (hex)")
	cmd.Flags().StringVar(&flags.noiseAddr, "noise-addr", "", "Noise server address (host:port)")
	cmd.Flags().StringVar(&flags.spkiPin, "spki-pin", "", "SPKI pin (hex-encoded SHA-256 of the server SubjectPublicKeyInfo)")
	cmd.Flags().StringVar(&flags.bundlePath, "bundle-path", "", "CA bundle endpoint path override (empty selects the server default)")
	cmd.Flags().BoolVar(&flags.installToSystem, "install-to-system-trust", false, "install CA bundle to system trust store")
	cmd.Flags().StringVar(&flags.certPath, "cert-path", defaultCertPath, "system trust store certificate path")
	cmd.Flags().DurationVar(&flags.perMethodTimeout, "per-method-timeout", defaultPerMethodTimeout, "timeout per bootstrap method")

	return cmd
}

// buildTrustConfig creates a trust.Config from the trust command flags.
// The default class carries the strategy chain; "auto" expands to the
// full ordered fetch chain (dane, noise, spki).
func buildTrustConfig(flags *trustFlags) (*trust.Config, error) {
	if flags.serverURL == "" {
		return nil, ErrTrustServerURLRequired{}
	}

	scope := &trust.ScopeConfig{
		Strategies:       strategiesFromFlag(flags.strategy),
		ServerURL:        flags.serverURL,
		Hostname:         flags.hostname,
		BundlePath:       flags.bundlePath,
		PerMethodTimeout: flags.perMethodTimeout,
	}

	// Configure DANE if a DNS server is provided
	if dnsServer := normalizeDNSServer(flags.dnsServer); dnsServer != "" {
		scope.DANE = &trust.DANEConfig{DNSServer: dnsServer}
	}

	// Configure Noise if key is provided
	if flags.noiseKey != "" {
		scope.Noise = &trust.NoiseConfig{
			ServerAddr:      flags.noiseAddr,
			ServerStaticKey: flags.noiseKey,
		}
	}

	// Configure SPKI if pin is provided
	if flags.spkiPin != "" {
		scope.SPKI = &trust.SPKIConfig{
			Pin: flags.spkiPin,
		}
	}

	return &trust.Config{Default: scope}, nil
}

// strategiesFromFlag maps the --strategy flag value onto an ordered
// strategy chain. "auto" (or empty) expands to dane, noise, spki; any
// other value selects a single-strategy chain. Unknown values are
// rejected by trust.NewResolver's config validation.
func strategiesFromFlag(strategy string) []trust.Strategy {
	if strategy == "" || strategy == strategyAuto {
		return []trust.Strategy{trust.StrategyDANE, trust.StrategyNoise, trust.StrategySPKI}
	}
	return []trust.Strategy{trust.Strategy(strategy)}
}

// normalizeDNSServer accepts "host" or "host:port" and returns the
// host:port form the underlying DANE resolver expects. Empty input
// passes through unchanged so the caller's empty-server check still
// works. Bare host (no port) defaults to :53 — the standard DNS
// port — preserving backward compatibility with the original
// host-only flag form. Trusted Platform CPs bind DANE on :8053
// because platformd runs unprivileged; operators targeting a CP
// must pass `host:8053` explicitly (documented in --dns-server help).
func normalizeDNSServer(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(in); err == nil {
		// Already host:port (handles bracketed IPv6 too).
		return in
	}
	// IPv6 without port needs brackets before we can append.
	if strings.Count(in, ":") >= 2 {
		return net.JoinHostPort(in, "53")
	}
	return net.JoinHostPort(in, "53")
}

// logLevelFromVerbose returns slog.LevelDebug when verbose is true, slog.LevelInfo otherwise.
func logLevelFromVerbose(verbose bool) slog.Level {
	if verbose {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// runTrust executes the trust bootstrap command. It builds a trust
// resolver, fetches the CA bundle through the default-class strategy
// chain, and optionally installs it to the system trust store.
func runTrust(ctx context.Context, flags *trustFlags, commonFlags *cli.CommonFlags) error {
	config, err := buildTrustConfig(flags)
	if err != nil {
		return err
	}

	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr)

	resolver, err := trust.NewResolver(config, logger)
	if err != nil {
		return ErrTrustBootstrapFailed{Cause: err}
	}

	bundlePEM, err := resolver.CABundlePEM(ctx, trust.ClassDefault)
	if err != nil {
		return ErrTrustBootstrapFailed{Cause: err}
	}

	// For the embedded strategy, bundlePEM is nil (trust already present)
	if bundlePEM == nil {
		fmt.Fprintln(os.Stdout, "Using embedded CA bundle (no fetch needed)")
		return nil
	}

	fmt.Fprintf(os.Stdout, "CA bundle fetched successfully (%d bytes)\n", len(bundlePEM))

	if flags.installToSystem {
		if err := trust.InstallToSystemTrust(bundlePEM, flags.certPath); err != nil {
			return ErrTrustInstallFailed{Path: flags.certPath, Cause: err}
		}
		fmt.Fprintf(os.Stdout, "CA bundle installed to %s\n", flags.certPath)

		// Run update-ca-certificates (Alpine)
		if err := runUpdateCACertificates(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: update-ca-certificates failed: %v\n", err)
			// Non-fatal: the cert file is already in place
		} else {
			fmt.Fprintln(os.Stdout, "System trust store updated")
		}
	}

	return nil
}

// runUpdateCACertificates runs the Alpine update-ca-certificates command.
func runUpdateCACertificates() error {
	cmd := exec.Command("update-ca-certificates")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
