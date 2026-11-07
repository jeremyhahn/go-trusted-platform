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

package commands

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// shutdownTimeout bounds the graceful drain of in-flight work during
// shutdown.
const shutdownTimeout = 30 * time.Second

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the gateway daemon",
	Long: `Starts the gateway daemon with config-driven service loading.

Services are activated based on the gateway configuration file. If a service
section exists and is enabled, the corresponding service loads automatically.

Supported services:
  proxy         - Trusted authenticating reverse proxy (mTLS + zone-aware L7 authz)
  overlay       - VXLAN tunneling for east-west VM/container traffic (EVPN Type-2/3/5)
  edge          - IoT device onboarding, DHT bootstrap, NAT traversal
  bgp           - BGP speaker for route announcement
  firewall      - Stateful packet filtering (requires the sdn: OVS runtime section)
  dhcp          - DHCP server for provisioning
  nat           - Network address translation (requires the sdn: OVS runtime section)
  load-balancer - L4/L7 load balancing (requires the sdn: OVS runtime section)
  tunnels       - GRE/VXLAN tunnel management

The sdn: section supplies the OVS datapath runtime (OVSDB socket, bridge,
zones, networks) for the firewall, NAT, and load-balancer services. The
control-plane: section enables periodic telemetry reporting to platformd's
gateway control-plane REST routes over mTLS.

Examples:
  # Start with config file (services determined by config)
  gatewayd serve --config /etc/gatewayd/config.yaml

  # Start with custom data directory
  gatewayd serve --config config.yaml --data-dir /var/lib/gatewayd`,
	RunE: runServe,
}

// buildServeLogger constructs the daemon logger from the persistent flags.
func buildServeLogger() *slog.Logger {
	level := slog.LevelInfo
	if debugMode {
		level = slog.LevelDebug
	}
	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if logFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}

// childInheritance is the part of this invocation's command line a
// supervised child is started with: the configuration file this process
// loaded, the state directory it resolved (the proxy's TOFU pins live under
// it) and the log settings buildServeLogger read.
func childInheritance(cfg *ServeConfig, configFile string) process.Inherited {
	return process.Inherited{
		ConfigFile: configFile,
		DataDir:    cfg.DataDir,
		LogFormat:  logFormat,
		Debug:      debugMode,
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	// SIGINT and SIGTERM are taken before anything starts. Until a process
	// registers for them, Go's default action terminates it on the spot: a
	// stop sent while the gateway was still starting would skip gw.Stop and
	// the supervisor's shutdown, and gatewayd would die by the signal.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	return serve(viper.GetViper(), buildServeLogger(), signals, serveIPsecSweep)
}

// ipsecSweep removes the ESP state the tunnel manager installed that no
// ensured tunnel names; serve runs it on a start with no tunnel configured.
type ipsecSweep func(logger *slog.Logger, inventory string) error

// serveIPsecSweep is the sweep runServe hands serve: the kernel's, which a
// test of runServe replaces so it never reads the host's XFRM state.
var serveIPsecSweep ipsecSweep = netlinkIPsecSweep

// netlinkIPsecSweep sweeps the kernel's XFRM state with a manager that has
// ensured no tunnel, so every SA, policy and carrier the platform installed
// is stale (tunnel.Manager.SweepIPsec). The platform's state is what the
// inventory records; anything else in the kernel is left alone.
func netlinkIPsecSweep(logger *slog.Logger, inventory string) error {
	return tunnel.NewManager(logger, tunnel.WithIPsecInventory(inventory)).SweepIPsec()
}

// gatewayTunnelsRecord is the file under --data-dir recording that a start
// enabled the tunnels service, so the ESP state it installed may outlive it.
const gatewayTunnelsRecord = "tunnels-installed"

// sweepDroppedTunnels removes a killed predecessor's tunnel state when the
// configuration no longer enables the tunnels service. With tunnels
// configured, the process hosting that service sweeps once it has ensured
// them (the gateway's own child under supervision), so exactly one process
// sweeps per start; this start only records under --data-dir that tunnels
// ran. Without tunnels, the sweep, which needs CAP_NET_ADMIN, runs only
// when that record or the ESP inventory (ipsecInventoryPath) exists, and
// fails the start closed if it cannot sweep; the record goes once the sweep
// succeeds, which it does only after every object the inventory records is
// gone or confirmed absent. A gateway that never ran tunnels (BGP only, say)
// has neither and may run without CAP_NET_ADMIN. A configuration without a
// `gateway:` section (proxy only) configures zero tunnels, so a tunnel-enabled
// predecessor's state is swept as when the last tunnel is dropped. Without a
// data directory nothing can be recorded, so every tunnel-less start sweeps,
// and with no ESP inventory to prove a pair the platform's that sweep removes
// nothing.
func sweepDroppedTunnels(cfg *ServeConfig, sweep ipsecSweep, logger *slog.Logger) error {
	record := tunnelsRecordPath(cfg.DataDir)
	if cfg.Gateway != nil && slices.Contains(cfg.Gateway.EnabledServices(), gateway.ServiceTunnels) {
		return writeTunnelsRecord(cfg.DataDir, record)
	}
	inventory := ipsecInventoryPath(cfg.DataDir)
	if record != "" {
		left, err := tunnelStateLeft(record, inventory)
		if err != nil || !left {
			return err
		}
	}
	if err := sweep(logger, inventory); err != nil {
		return &ErrStaleTunnelSweep{Cause: err}
	}
	if record == "" {
		return nil
	}
	if err := os.Remove(record); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return &ErrTunnelsRecord{Path: record, Cause: err}
	}
	logger.Info("Stale tunnel state swept", slog.String("record", record))
	return nil
}

// tunnelStateLeft reports whether a predecessor may have left tunnel state:
// the tunnels record or the ESP inventory exists. The inventory alone
// suffices, so state a predecessor recorded is swept even when its record
// was removed before everything the inventory names was gone.
func tunnelStateLeft(paths ...string) (bool, error) {
	for _, path := range paths {
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return false, &ErrTunnelsRecord{Path: path, Cause: err}
		}
	}
	return false, nil
}

// tunnelsRecordPath is the record under dataDir that tunnels were enabled,
// or empty without a data directory.
func tunnelsRecordPath(dataDir string) string {
	if dataDir == "" {
		return ""
	}
	return filepath.Join(dataDir, gatewayTunnelsRecord)
}

// writeTunnelsRecord records, before the tunnels service installs anything,
// that a later start without tunnels has state to sweep. Without a data
// directory there is nowhere to keep it, and such a start always sweeps.
func writeTunnelsRecord(dataDir, record string) error {
	if record == "" {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return &ErrTunnelsRecord{Path: record, Cause: err}
	}
	if err := os.WriteFile(record, nil, 0o600); err != nil {
		return &ErrTunnelsRecord{Path: record, Cause: err}
	}
	return nil
}

// serve runs the gateway daemon on the configuration in v until signals
// delivers a stop, then shuts it down. A signal already waiting when the
// gateway finishes starting stops it as soon as it has started.
func serve(v *viper.Viper, logger *slog.Logger, signals <-chan os.Signal, sweep ipsecSweep) error {
	logger.Info("Starting gateway daemon",
		slog.String("data_dir", v.GetString("data-dir")),
		slog.String("config", v.ConfigFileUsed()),
	)

	cfg, err := LoadServeConfig(v)
	if err != nil {
		return err
	}

	// With the `process:` section enabled, the supervised services run in
	// child processes. The children outlive gw.Stop, which stops the
	// services they host, so they are shut down after it on every exit path.
	supervisor, err := BuildSupervisor(cfg, childInheritance(cfg, v.ConfigFileUsed()), logger)
	if err != nil {
		return err
	}
	if supervisor != nil {
		defer shutdownSupervisor(supervisor, logger)
	}

	startCtx, startCancel := context.WithCancel(context.Background())
	defer startCancel()

	// Assemble the gateway node with all config-driven service handlers,
	// including the proxysvc reverse-proxy handler and, when the sdn:
	// section is enabled, the OVS datapath runtime. When platformd is
	// unreachable, the proxy starts on its static configuration and the
	// background sync loop keeps retrying.
	gw, err := BuildGateway(startCtx, cfg, logger)
	if err != nil {
		return err
	}
	// The OVS runtime (when assembled) holds a live OVSDB connection;
	// release it on every exit path, after gw.Stop has removed flows.
	defer closeGatewayRuntime(gw, logger)

	// Assemble the control-plane telemetry reporter before starting
	// services so configuration errors surface before the datapath is
	// touched.
	reporter, err := BuildReporter(startCtx, cfg, gw, logger)
	if err != nil {
		return err
	}
	// The control plane keeps the record of the management VPN's leases,
	// so a restart reinstates the clients admitted before it; the journal
	// under --data-dir keeps a revocation it has not yet taken from being
	// reinstated too.
	if reporter != nil {
		gw.SetVPNLeaseControl(reporter, vpnRevocationJournal(cfg.DataDir))
	}

	// The metrics endpoint is prepared before the datapath starts so a
	// port the operator asked for and cannot have fails the boot rather
	// than leaving a gateway running unscraped.
	metricsServer, err := BuildMetricsServer(cfg.Metrics, gw, logger)
	if err != nil {
		return err
	}

	// A predecessor killed while it ran tunnels left their carriers, SAs
	// and policies up; when the last tunnel has since been dropped, no
	// tunnels service starts to sweep them, so the start does.
	if err := sweepDroppedTunnels(cfg, sweep, logger); err != nil {
		return err
	}

	if err := gw.Start(startCtx); err != nil {
		return err
	}

	var metricsDone chan error
	if metricsServer != nil {
		metricsDone = make(chan error, 1)
		go func() { metricsDone <- metricsServer.Serve() }()
		logger.Info("Gateway metrics endpoint started", slog.String("address", metricsServer.Addr()))
	}

	logger.Info("Gateway daemon started",
		slog.Any("services", gw.ActiveServices()))

	// Run the telemetry reporter and the desired-config reconciler until
	// shutdown cancels startCtx. The reconciler is the pull half of the
	// control loop (#555): it fetches the control plane's intent on its
	// own ticker and applies the difference through the gateway.
	var reporterDone, reconcilerDone chan error
	if reporter != nil {
		reporterDone = make(chan error, 1)
		go func() {
			reporterDone <- reporter.Start(startCtx)
		}()
		logger.Info("Control-plane telemetry reporter started",
			slog.String("base_url", cfg.ControlPlane.BaseURL))

		reconciler, err := BuildReconciler(cfg, reporter, gw, logger)
		if err != nil {
			startCancel()
			<-reporterDone
			return err
		}
		reconcilerDone = make(chan error, 1)
		go func() {
			reconcilerDone <- reconciler.Start(startCtx)
		}()
		logger.Info("Desired-config reconciler started",
			slog.Duration("interval", cfg.ControlPlane.EffectiveReconcileInterval()))
	}

	// Block until SIGINT/SIGTERM.
	sig := <-signals
	logger.Info("Received signal, shutting down", slog.String("signal", sig.String()))

	// Stop the reporter first so no telemetry posts race the teardown,
	// then drain its goroutine.
	startCancel()
	if reconcilerDone != nil {
		if err := <-reconcilerDone; err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("Desired-config reconciler exited with error", slog.Any("error", err))
		}
	}
	if reporterDone != nil {
		if err := <-reporterDone; err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("Telemetry reporter exited with error", slog.Any("error", err))
		}
	}

	if metricsDone != nil {
		if err := metricsServer.Shutdown(); err != nil {
			logger.Warn("Gateway metrics endpoint shutdown failed", slog.Any("error", err))
		}
		if err := <-metricsDone; err != nil {
			logger.Warn("Gateway metrics endpoint exited with error", slog.Any("error", err))
		}
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer stopCancel()
	if err := gw.Stop(stopCtx); err != nil {
		logger.Error("Gateway shutdown failed", slog.Any("error", err))
		return err
	}

	logger.Info("Gateway daemon stopped")
	return nil
}

// processShutdowner is the part of the process supervisor runServe stops.
type processShutdowner interface {
	Shutdown(ctx context.Context) error
}

// shutdownSupervisor stops every child within shutdownTimeout. A failure is
// logged rather than returned: it runs on exit paths that already carry
// their own result.
func shutdownSupervisor(supervisor processShutdowner, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := supervisor.Shutdown(ctx); err != nil {
		logger.Warn("Process supervisor shutdown failed", slog.Any("error", err))
	}
}
