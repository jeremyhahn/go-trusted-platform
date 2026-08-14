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

var (
	serveListenAddr  string
	serveBGPASN      uint32
	serveBGPRouterID string
	serveAPIPort     int
	serveGRPCPort    int
)

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
  firewall      - Stateful packet filtering (requires platformd-injected OVS runtime)
  dhcp          - DHCP server for provisioning
  nat           - Network address translation (requires platformd-injected OVS runtime)
  load-balancer - L4/L7 load balancing
  tunnels       - GRE/VXLAN tunnel management

Examples:
  # Start with config file (services determined by config)
  gatewayd serve --config /etc/gatewayd/config.yaml

  # Start with custom data directory
  gatewayd serve --config config.yaml --data-dir /var/lib/gatewayd`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringVar(&serveListenAddr, "listen", ":8080", "API listen address")
	serveCmd.Flags().Uint32Var(&serveBGPASN, "bgp-asn", 0, "BGP AS number")
	serveCmd.Flags().StringVar(&serveBGPRouterID, "bgp-router-id", "", "BGP router ID")
	serveCmd.Flags().IntVar(&serveAPIPort, "api-port", 8080, "REST API port")
	serveCmd.Flags().IntVar(&serveGRPCPort, "grpc-port", 10444, "gRPC port")

	viper.BindPFlag("listen", serveCmd.Flags().Lookup("listen"))
	viper.BindPFlag("bgp.asn", serveCmd.Flags().Lookup("bgp-asn"))
	viper.BindPFlag("bgp.router_id", serveCmd.Flags().Lookup("bgp-router-id"))
	viper.BindPFlag("api.port", serveCmd.Flags().Lookup("api-port"))
	viper.BindPFlag("grpc.port", serveCmd.Flags().Lookup("grpc-port"))
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

	// Assemble the gateway node with all config-driven service handlers,
	// including the proxysvc reverse-proxy handler. When platformd is
	// unreachable, the proxy starts on its static configuration and the
	// background sync loop keeps retrying.
	gw, err := BuildGateway(cfg, logger)
	if err != nil {
		return err
	}

	startCtx, startCancel := context.WithCancel(context.Background())
	defer startCancel()
	if err := gw.Start(startCtx); err != nil {
		return err
	}

	logger.Info("Gateway daemon started",
		slog.Any("services", gw.ActiveServices()))

	// Block until SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("Received signal, shutting down", slog.String("signal", sig.String()))

	stopCtx, stopCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer stopCancel()
	if err := gw.Stop(stopCtx); err != nil {
		logger.Error("Gateway shutdown failed", slog.Any("error", err))
		return err
	}

	logger.Info("Gateway daemon stopped")
	return nil
}
