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

// Package authenticode provides CLI commands for Authenticode/PKCS#7 signing
// and verification of PE/COFF executables for UEFI Secure Boot compatibility.
package authenticode

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the authenticode root command for PE/COFF signing operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authenticode",
		Short: "Authenticode signing and verification",
		Long: `Sign and verify PE/COFF executables using Authenticode/PKCS#7.

The authenticode subsystem provides native Go implementations for:
  - Signing PE/COFF executables (EFI binaries, Windows executables)
  - Verifying Authenticode/PKCS#7 signatures
  - UEFI Secure Boot compatibility

This replaces external tools like sbsigntool with native Go implementation.

Examples:
  # Sign a PE/COFF file
  platformctl authenticode sign \
    --key /path/to/key.pem \
    --cert /path/to/cert.pem \
    --input unsigned.efi \
    --output signed.efi

  # Verify a signed file
  platformctl authenticode verify --input signed.efi

  # Verify with specific certificate
  platformctl authenticode verify \
    --cert /path/to/cert.pem \
    --input signed.efi`,
	}

	// Add subcommands
	cmd.AddCommand(newSignCommand(getFlags))
	cmd.AddCommand(newVerifyCommand(getFlags))

	return cmd
}
