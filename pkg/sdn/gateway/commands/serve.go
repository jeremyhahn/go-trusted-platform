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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
  overlay       - VXLAN tunneling for east-west VM/container traffic (EVPN Type-2/3/5)
  edge          - IoT device onboarding, DHT bootstrap, NAT traversal
  bgp           - BGP speaker for route announcement
  firewall      - Stateful packet filtering
  dhcp          - DHCP server for provisioning
  nat           - Network address translation
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

func runServe(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Configure logger
	logLevel := slog.LevelInfo
	if debugMode {
		logLevel = slog.LevelDebug
	}

	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{Level: logLevel}

	if logFormat == "text" {
		handler = slog.NewTextHandler(os.Stdout, handlerOpts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	logger.Info("Starting gateway daemon",
		slog.String("listen", viper.GetString("listen")),
		slog.String("data_dir", viper.GetString("data-dir")),
		slog.String("config", viper.ConfigFileUsed()),
	)

	// DEFERRED: Create gateway node integrating with:
	// - pkg/sdn/gateway for gateway node management
	// - pkg/sdn/bgp for BGP service
	// - pkg/sdn/vxlan for VXLAN tunneling
	// - pkg/ipam for IP address management
	// Blocked by: SDN gateway architecture design.
	// The gateway config file is the sole source of truth for which services to load.

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	logger.Info("Gateway daemon started, press Ctrl+C to stop")

	select {
	case sig := <-sigCh:
		logger.Info("Received signal, shutting down", slog.String("signal", sig.String()))
	case <-ctx.Done():
		logger.Info("Context cancelled, shutting down")
	}

	logger.Info("Gateway daemon stopped")

	return nil
}
