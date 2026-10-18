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

package iso

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// buildFlags holds flags for the build command
type buildFlags struct {
	sourceDir   string
	output      string
	volumeID    string
	generateSum bool
	configFile  string
	workDir     string
	debug       bool
	verbose     bool
}

// newBuildCommand creates the build subcommand for building final bootable ISO
func newBuildCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &buildFlags{}

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build final bootable ISO image",
		Long: `Builds a bootable ISO image from customized ISO directory contents.

This command creates a hybrid BIOS/UEFI bootable ISO image using xorriso
with El Torito boot catalog and isohybrid MBR for USB booting support.

The resulting ISO can boot via:
- Legacy BIOS (using isolinux/syslinux)
- UEFI (using grub EFI bootloader)
- USB/HDD (via isohybrid MBR)

Examples:
  # Build ISO with default settings
  platformctl iso build --iso-dir work/iso --output platform.iso

  # Build with custom label
  platformctl iso build --iso-dir work/iso --output platform.iso --label MY_PLATFORM

  # Build without checksum
  platformctl iso build --iso-dir work/iso --output platform.iso --checksum=false`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBuild(getFlags(), flags)
		},
	}

	// Build flags
	cmd.Flags().StringVar(&flags.sourceDir, "iso-dir", "", "Source directory containing ISO contents (required)")
	cmd.Flags().StringVar(&flags.output, "output", "", "Output ISO file path (required)")
	cmd.Flags().StringVar(&flags.volumeID, "label", "TRUSTED_PLATFORM", "ISO volume label (max 32 chars)")
	cmd.Flags().BoolVar(&flags.generateSum, "checksum", true, "Generate SHA256 checksum file")

	// Common flags
	cmd.Flags().StringVar(&flags.configFile, "config", "", "Path to ISO build configuration file")
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Working directory for ISO operations")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")

	// Mark required flags
	cli.MarkFlagsRequired(cmd, "iso-dir")
	cli.MarkFlagsRequired(cmd, "output")

	return cmd
}

// runBuild executes the build command
func runBuild(commonFlags *cli.CommonFlags, flags *buildFlags) error {
	// ISO build requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso build"}
}
