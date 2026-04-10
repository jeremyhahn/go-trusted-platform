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
	serveModes       []string
	serveListenAddr  string
	serveBGPASN      uint32
	serveBGPRouterID string
	serveVXLANVNI    uint32
	serveAPIPort     int
	serveGRPCPort    int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the gateway daemon",
	Long: `Starts the gateway daemon with the configured operational modes.

Modes:
  overlay  - VXLAN tunneling for east-west VM/container traffic (EVPN Type-2/3/5)
  edge     - IoT device onboarding, DHT bootstrap, NAT traversal
  transit  - Announce platform IPv4/IPv6 blocks to ISPs/fabric

Examples:
  # Start in overlay mode (default)
  gatewayd serve

  # Start with multiple modes
  gatewayd serve --modes overlay,edge

  # Start in transit mode with BGP configuration
  gatewayd serve --modes transit --bgp-asn 65001 --bgp-router-id 10.0.0.1`,
	RunE: runServe,
}

func init() {
	serveCmd.Flags().StringSliceVar(&serveModes, "modes", []string{"overlay"}, "Gateway modes to enable (overlay, edge, transit)")
	serveCmd.Flags().StringVar(&serveListenAddr, "listen", ":8080", "API listen address")
	serveCmd.Flags().Uint32Var(&serveBGPASN, "bgp-asn", 0, "BGP AS number")
	serveCmd.Flags().StringVar(&serveBGPRouterID, "bgp-router-id", "", "BGP router ID")
	serveCmd.Flags().Uint32Var(&serveVXLANVNI, "vxlan-vni", 100, "Default VXLAN VNI")
	serveCmd.Flags().IntVar(&serveAPIPort, "api-port", 8080, "REST API port")
	serveCmd.Flags().IntVar(&serveGRPCPort, "grpc-port", 10444, "gRPC port")

	viper.BindPFlag("modes", serveCmd.Flags().Lookup("modes"))
	viper.BindPFlag("listen", serveCmd.Flags().Lookup("listen"))
	viper.BindPFlag("bgp.asn", serveCmd.Flags().Lookup("bgp-asn"))
	viper.BindPFlag("bgp.router_id", serveCmd.Flags().Lookup("bgp-router-id"))
	viper.BindPFlag("vxlan.vni", serveCmd.Flags().Lookup("vxlan-vni"))
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

	modes := viper.GetStringSlice("modes")
	if len(modes) == 0 {
		modes = serveModes
	}

	logger.Info("Starting gateway daemon",
		slog.Any("modes", modes),
		slog.String("listen", viper.GetString("listen")),
		slog.String("data_dir", viper.GetString("data-dir")),
	)

	// Validate modes
	validModes := map[string]bool{
		"overlay": true,
		"edge":    true,
		"transit": true,
	}
	for _, mode := range modes {
		if !validModes[mode] {
			logger.Error("Invalid gateway mode", slog.String("mode", mode))
			return ErrInvalidGatewayMode
		}
	}

	// Log mode-specific configuration
	for _, mode := range modes {
		switch mode {
		case "overlay":
			logger.Info("Overlay mode enabled",
				slog.Uint64("vxlan_vni", uint64(viper.GetUint32("vxlan.vni"))))
		case "edge":
			logger.Info("Edge mode enabled")
		case "transit":
			asn := viper.GetUint32("bgp.asn")
			routerID := viper.GetString("bgp.router_id")
			if asn == 0 {
				logger.Warn("Transit mode requires BGP ASN configuration")
			}
			logger.Info("Transit mode enabled",
				slog.Uint64("bgp_asn", uint64(asn)),
				slog.String("bgp_router_id", routerID))
		}
	}

	// DEFERRED: Create gateway node integrating with:
	// - pkg/sdn/gateway for gateway node management
	// - pkg/sdn/bgp for BGP service
	// - pkg/sdn/vxlan for VXLAN tunneling
	// - pkg/ipam for IP address management
	// Blocked by: SDN gateway architecture design.

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
