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

// Package iso provides CLI commands for ISO image management operations
// including building, customizing, downloading, and extracting ISO images
// for Trusted Platform deployment.
package iso

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the iso root command for ISO image operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "iso",
		Short: "ISO image management operations",
		Long: `Manage ISO images for Trusted Platform deployment.

The ISO subsystem provides tools for creating custom bootable ISO images:
  - create: All-in-one ISO creation (download, extract, customize, build)
  - download: Download Alpine Linux base ISO
  - extract: Extract ISO contents for customization
  - customize: Apply platform components and overlays
  - build: Build final bootable ISO image
  - profile: Manage installation profiles
  - test: Test ISO images in QEMU with TPM support
  - module-signing-key: Generate the stable kernel module-signing key

These tools enable creating custom Trusted Platform deployment images
with Secure Boot, TPM auto-unseal, and LUKS encryption support.

Examples:
  # Create a complete custom ISO with defaults
  platformctl iso create

  # Create ISO with FIPS mode enabled
  platformctl iso create --fips

  # Download Alpine ISO only
  platformctl iso download --version 3.22.2

  # Extract and customize an existing ISO
  platformctl iso extract --iso alpine.iso
  platformctl iso customize --iso-dir work/iso

  # Build final ISO from customized directory
  platformctl iso build --iso-dir work/iso --output platform.iso

  # List available installation profiles
  platformctl iso profile list

  # Test ISO installation in QEMU
  platformctl iso test install --iso platform.iso

  # Test client-server deployment
  platformctl iso test client-server --iso platform.iso`,
	}

	// Add subcommands
	cmd.AddCommand(newCreateCommand(getFlags))
	cmd.AddCommand(newDownloadCommand(getFlags))
	cmd.AddCommand(newExtractCommand(getFlags))
	cmd.AddCommand(newCustomizeCommand(getFlags))
	cmd.AddCommand(newBuildCommand(getFlags))
	cmd.AddCommand(newProfileCommand(getFlags))
	cmd.AddCommand(newTestCommand(getFlags))
	cmd.AddCommand(newModuleSigningKeyCommand(getFlags))

	return cmd
}
