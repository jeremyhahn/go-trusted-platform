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

// Package commands provides the CLI commands for platform-initrd.
// This binary is optimized for initramfs boot operations and contains
// only the minimal commands needed during early boot: boot and recovery.
//
// Note: firstboot runs AFTER switch_root via platformctl, not in initrd.
package commands

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
)

// Version information (set at build time via ldflags)
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "platform-initrd",
	Short: "Initramfs boot operations for Trusted Platform",
	Long: `platform-initrd provides boot-time operations for the Trusted Platform.

This binary is NOT user-facing. It is called by dracut hooks during
the early boot process to unlock encrypted volumes:

  boot       - Unlock encrypted root filesystem using TPM-sealed keys
  recovery   - Recovery mode for boot failures

After switch_root, firstboot provisioning runs via: platformctl firstboot

For all other operational commands, use platformctl.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("platform-initrd %s\n", Version)
		fmt.Printf("  Git Commit: %s\n", GitCommit)
		fmt.Printf("  Build Date: %s\n", BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(BootCmd)
	rootCmd.AddCommand(RecoveryCmd)
}

// Execute runs the root command
func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		log.Printf("Error: %v", err)
		return err
	}
	return nil
}
