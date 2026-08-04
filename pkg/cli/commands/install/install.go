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

// Package install provides CLI commands for system installation operations
// including complete OS installation and Unified Kernel Image (UKI) building.
package install

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the install root command for system installation operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "System installation operations",
		Long: `Manage system installation and deployment operations.

The install subsystem provides tools for:
  - Complete operating system installation with encryption
  - Unified Kernel Image (UKI) building for Secure Boot

These commands are typically run during initial system installation from
live media or during system deployment and configuration.

Examples:
  # Install complete operating system using config file
  platformctl install system --config /etc/platformd/install.yaml

  # Install Alpine Linux with encryption using flags
  platformctl install system --os alpine --disk /dev/sda --password "secret" --automated

  # Build a Unified Kernel Image (UKI)
  platformctl install uki --kernel /boot/vmlinuz --initramfs /boot/initramfs --cmdline "root=/dev/mapper/cryptroot ro" --output /boot/efi/EFI/BOOT/BOOTX64.EFI`,
	}

	// Add subcommands
	cmd.AddCommand(newSystemCommand(getFlags))
	cmd.AddCommand(newUKICommand(getFlags))
	cmd.AddCommand(newUKIRebuildCommand(getFlags))

	return cmd
}
