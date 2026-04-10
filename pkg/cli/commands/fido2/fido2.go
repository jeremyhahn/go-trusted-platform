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

// Package fido2 provides CLI commands for FIDO2 security key operations
// including enrollment, listing, removal, and testing of FIDO2 tokens
// for LUKS disk encryption.
package fido2

import (
	"os"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the fido2 root command for FIDO2 security key operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fido2",
		Short: "FIDO2 security key operations",
		Long: `Manage FIDO2 security keys for LUKS disk encryption.

The FIDO2 subsystem provides security key management for disk unlock:
  - Enroll FIDO2 security keys for LUKS unlock
  - List enrolled FIDO2 tokens
  - Remove FIDO2 tokens and keyslots
  - Test FIDO2 unlock functionality
  - View detailed FIDO2 and LUKS information

These commands require root privileges and a LUKS-encrypted device.

Examples:
  # Enroll a FIDO2 security key
  platformctl fido2 enroll --passphrase "your-luks-password"

  # List enrolled FIDO2 tokens
  platformctl fido2 list

  # Test FIDO2 unlock
  platformctl fido2 test

  # Show detailed information
  platformctl fido2 info

  # Remove a FIDO2 token
  platformctl fido2 remove --slot 3`,
	}

	// Add subcommands
	cmd.AddCommand(newEnrollCommand(getFlags))
	cmd.AddCommand(newListCommand(getFlags))
	cmd.AddCommand(newInfoCommand(getFlags))
	cmd.AddCommand(newRemoveCommand(getFlags))
	cmd.AddCommand(newTestCommand(getFlags))

	return cmd
}

// checkRoot verifies the command is running as root
func checkRoot() error {
	if os.Geteuid() != 0 {
		return ErrRootRequired{}
	}
	return nil
}

// autoDetectLUKSDevice attempts to find a LUKS device
func autoDetectLUKSDevice() (string, error) {
	// Common partition locations
	devices := []string{
		"/dev/vda3", "/dev/vda2",
		"/dev/sda3", "/dev/sda2",
		"/dev/nvme0n1p3", "/dev/nvme0n1p2",
	}

	for _, dev := range devices {
		if _, err := os.Stat(dev); err != nil {
			continue
		}

		// Check if LUKS using native go-luks2
		isLuks, err := luks2.IsLUKS(dev)
		if err == nil && isLuks {
			return dev, nil
		}
	}

	return "", ErrDeviceAutoDetectFailed{}
}
