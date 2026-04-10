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

// customizeFlags holds flags for the customize command
type customizeFlags struct {
	isoDir          string
	overlay         string
	keysDir         string
	platformdPath   string
	autoinstall     bool
	modifyInitramfs bool
	configFile      string
	workDir         string
	debug           bool
	verbose         bool
}

// newCustomizeCommand creates the customize subcommand for customizing ISO contents
func newCustomizeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &customizeFlags{}

	cmd := &cobra.Command{
		Use:   "customize",
		Short: "Customize ISO with overlays and initramfs",
		Long: `Customize an extracted ISO with platform-specific components.

This command:
- Integrates platformd into the initramfs
- Applies overlay files and configurations
- Configures Secure Boot keys
- Generates autoinstall configurations

Example:
  platformctl iso customize --iso-dir work/iso --platformd-binary ./platformd-static \
    --keys-dir secure-boot-keys --autoinstall`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCustomize(getFlags(), flags)
		},
	}

	// Customize flags
	cmd.Flags().StringVar(&flags.isoDir, "iso-dir", "", "Directory containing extracted ISO contents (required)")
	cmd.Flags().StringVar(&flags.overlay, "overlay", "", "Overlay directory to merge into ISO")
	cmd.Flags().StringVar(&flags.keysDir, "keys-dir", "", "Secure Boot keys directory")
	cmd.Flags().StringVar(&flags.platformdPath, "platformd-binary", "", "Path to platformd binary")
	cmd.Flags().BoolVar(&flags.autoinstall, "autoinstall", false, "Generate autoinstall configuration")
	cmd.Flags().BoolVar(&flags.modifyInitramfs, "modify-initramfs", false, "Modify initramfs with platformd")

	// Common flags
	cmd.Flags().StringVar(&flags.configFile, "config", "", "Path to ISO build configuration file")
	cmd.Flags().StringVar(&flags.workDir, "work-dir", "work", "Working directory for ISO operations")
	cmd.Flags().BoolVar(&flags.debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&flags.verbose, "verbose", false, "Enable verbose output")

	// Mark required flags
	_ = cmd.MarkFlagRequired("iso-dir")

	return cmd
}

// runCustomize executes the customize command
func runCustomize(commonFlags *cli.CommonFlags, flags *customizeFlags) error {
	// ISO customize requires App initialization which needs daemon connection
	// Dual-mode will be added later to support local-only operations
	return ErrDaemonConnectionRequired{Command: "iso customize"}
}
