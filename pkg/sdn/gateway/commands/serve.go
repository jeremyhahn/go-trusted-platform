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
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

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

func runServe(cmd *cobra.Command, args []string) error {
	logger := buildServeLogger()

	logger.Info("Starting gateway daemon",
		slog.String("data_dir", viper.GetString("data-dir")),
		slog.String("config", viper.ConfigFileUsed()),
	)

	cfg, err := LoadServeConfig(viper.GetViper())
	if err != nil {
		return err
	}

	// With the `process:` section enabled, the supervised services run in
	// child processes. The children outlive gw.Stop, which stops the
	// services they host, so they are shut down after it on every exit path.
	supervisor, err := BuildSupervisor(cfg, viper.ConfigFileUsed(), logger)
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

	// The metrics endpoint is prepared before the datapath starts so a
	// port the operator asked for and cannot have fails the boot rather
	// than leaving a gateway running unscraped.
	metricsServer, err := BuildMetricsServer(cfg.Metrics, gw, logger)
	if err != nil {
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
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
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
