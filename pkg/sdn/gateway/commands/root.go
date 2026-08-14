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

// Package commands provides CLI commands for the gateway daemon (gatewayd).
// This package contains serve and version commands for the standalone gateway.
package commands

import (
	"log"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile   string
	debugMode bool
	logFormat string
	logLevel  string
	dataDir   string
	configDir string
)

var rootCmd = &cobra.Command{
	Use:   "gatewayd",
	Short: "go-trusted-platform Gateway Daemon",
	Long: `A standalone gateway daemon that supports three operational modes:

  - Overlay: VXLAN tunneling for east-west VM/container traffic (EVPN Type-2/3/5)
  - Edge: IoT device onboarding, DHT bootstrap, NAT traversal
  - Transit: Announce platform IPv4/IPv6 blocks to ISPs/fabric

The gateway daemon provides SDN capabilities for the Trusted Computing Platform,
enabling secure network overlays, BGP peering, and distributed routing.

Build without P2P support: make build-gatewayd
Build with P2P support: make build-gatewayd WITH_P2P=1`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default to serve command if no subcommand specified.
		if len(args) == 0 && len(cmd.Flags().Args()) == 0 {
			return serveCmd.RunE(cmd, args)
		}
		return nil
	},
	TraverseChildren: true,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/gatewayd/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&debugMode, "debug", "d", false, "Enable debug mode")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "json", "Log format (json, text)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "/var/lib/gatewayd", "Data directory for gateway state")
	rootCmd.PersistentFlags().StringVar(&configDir, "config-dir", "/etc/gatewayd", "Configuration directory")

	viper.BindPFlags(rootCmd.PersistentFlags())

	if runtime.GOOS == "darwin" {
		signal.Ignore(syscall.Signal(0xd))
	}

	// Register daemon commands
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/gatewayd")
		viper.AddConfigPath("$HOME/.gatewayd")
		viper.AddConfigPath(".")
	}

	viper.SetEnvPrefix("GATEWAYD")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Warning: error reading config file: %v", err)
		}
	}
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		return err
	}
	return nil
}
