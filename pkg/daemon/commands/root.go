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

// Package commands provides daemon-only CLI commands for platformd.
// This package contains only the serve and version commands.
// All other commands are in pkg/cli/commands for platformctl.
package commands

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// App is the application instance shared by all commands.
	App *app.App

	// InitParams are the initialization parameters for the application.
	InitParams *app.AppInitParams

	bPin   bool
	bSOPin bool
	SOPin  string
	Pin    string
)

var rootCmd = &cobra.Command{
	Use:   "platformd",
	Short: "Trusted Platform Daemon",
	Long: `The Trusted Platform Daemon (platformd) provides multi-protocol API
services for the Trusted Computing Platform.

The daemon exposes services via:
  - Unix socket for local CLI communication (platformctl)
  - REST API for HTTP clients
  - gRPC for high-performance service-to-service communication
  - QUIC for low-latency connections
  - MCP for AI/LLM integration

Use 'platformctl' for all operational commands (tpm, ca, vtpm, iso, etc.)
Use 'platform-initrd' for boot-time operations in the initramfs.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Default to serve command if no subcommand specified
		if len(args) == 0 && len(cmd.Flags().Args()) == 0 {
			serveCmd.Run(cmd, args)
			return
		}
	},
	TraverseChildren: true,
}

func init() {
	cobra.OnInitialize(func() {
		// If --config flag is set, use that specific config file
		if InitParams.ConfigFile != "" {
			viper.SetConfigFile(InitParams.ConfigFile)
		}

		prompter := prompt.NewPrompter()
		if bSOPin {
			pin, err := prompter.SOPin()
			if err != nil {
				log.Fatal(err)
			}
			InitParams.SOPin = pin
		}
		if bPin {
			pin, err := prompter.Pin()
			if err != nil {
				log.Fatal(err)
			}
			InitParams.Pin = pin
		}
		if SOPin != "" {
			InitParams.SOPin = []byte(SOPin)
		}
		if Pin != "" {
			InitParams.Pin = []byte(Pin)
		}

		App = app.NewApp()
	})

	// Set provided initialization parameters for commands package
	InitParams = &app.AppInitParams{}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	platformDir := fmt.Sprintf("%s/%s", wd, "trusted-data")
	rootCmd.PersistentFlags().BoolVarP(&InitParams.Debug, "debug", "d", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVarP(&InitParams.DebugSecrets, "debug-secrets", "", false, "Enable secret debugging mode. Includes passwords and secrets in logs")
	rootCmd.PersistentFlags().StringVarP(&InitParams.Env, "env", "e", "dev", "Runtime environment (dev, staging, prod)")
	rootCmd.PersistentFlags().StringVarP(&InitParams.PlatformDir, "platform-dir", "", platformDir, "Trusted Platform home directory where data is stored")
	rootCmd.PersistentFlags().StringVarP(&InitParams.ConfigDir, "config-dir", "", fmt.Sprintf("/etc/%s", app.Name), "Platform configuration file directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.ConfigFile, "config", "c", "", "Path to specific config file (overrides config-dir)")
	rootCmd.PersistentFlags().StringVarP(&InitParams.LogDir, "log-dir", "", "trusted-data/log", "Platform logs directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.CADir, "ca-dir", "", "trusted-data/ca", "Certificate Authority data directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.RuntimeUser, "setuid", "", "root", "The operating system user to run as")
	rootCmd.PersistentFlags().IntVarP(&InitParams.PlatformCA, "intermediate", "", 1, "The target Certificate Authority index")
	rootCmd.PersistentFlags().BoolVar(&bSOPin, "so-pin", false, "Security Officer PIN / password")
	rootCmd.PersistentFlags().BoolVar(&bPin, "pin", false, "Platform Administrator or user PIN / password")
	rootCmd.PersistentFlags().BoolVar(&InitParams.Initialize, "init", false, "True to automatically initialize and provision the platform")

	// For devops automation, testing and development - bypass PIN prompts
	rootCmd.PersistentFlags().StringVar(&SOPin, "raw-so-pin", "", "Raw plain-text Security Officer PIN / password")
	rootCmd.PersistentFlags().StringVar(&Pin, "raw-pin", "", "Raw plain-text Platform Administrator or user PIN / password")

	// Global defaults applied before config file is read. These are the
	// last-resort values when neither the YAML config nor a CLI flag
	// provides a value. Keep this list small — per-subsystem defaults
	// belong in their own config packages.
	viper.SetDefault("tenant-id", "default")

	viper.BindPFlags(rootCmd.PersistentFlags())

	if runtime.GOOS == "darwin" {
		signal.Ignore(syscall.Signal(0xd))
	}

	// Register daemon-only commands
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
}

// Execute runs the root command.
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
	return nil
}
