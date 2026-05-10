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

// Package fido2 provides CLI commands for FIDO2 device enumeration and
// WebAuthn operations. It mirrors the "xkmsctl fido2" subcommand surface.
//
// Historical note: the former "platformctl fido2 enroll|list|remove|test"
// subcommands were LUKS-specific and have moved to the "platformctl luks"
// command tree. This package no longer imports go-luks2.
package fido2

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the fido2 root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fido2",
		Short: "FIDO2 device and WebAuthn operations",
		Long: `Manage FIDO2 authenticators and WebAuthn credentials.

The fido2 subsystem provides:
  - Device enumeration (CTAP2 over HID)
  - Wait-for-device (useful in scripts before a register / authenticate step)
  - Device info (AAGUID, capabilities, firmware version)
  - WebAuthn credential registration
  - WebAuthn credential authentication test

Migration note: the LUKS-specific subcommands that used to live here
(enroll, list, remove, test) have moved to "platformctl luks":

  platformctl fido2 enroll  -> platformctl luks enroll-fido2
  platformctl fido2 list    -> platformctl luks list-slots
  platformctl fido2 remove  -> platformctl luks remove-key
  platformctl fido2 test    -> platformctl luks test-unlock

Examples:
  # Enumerate attached FIDO2 authenticators
  platformctl fido2 list-devices

  # Block until a FIDO2 device arrives (10 seconds)
  platformctl fido2 wait-device --timeout 10

  # Show authenticator info
  platformctl fido2 info --device <device-id>

  # Register a WebAuthn credential for an admin officer with user verification
  platformctl fido2 register --username alice --role admin --require-uv

  # Test authentication against a registered credential
  platformctl fido2 authenticate --credential-id <credID>`,
	}

	cmd.AddCommand(newListDevicesCommand(getFlags))
	cmd.AddCommand(newWaitDeviceCommand(getFlags))
	cmd.AddCommand(newInfoCommand(getFlags))
	cmd.AddCommand(newRegisterCommand(getFlags))
	cmd.AddCommand(newAuthenticateCommand(getFlags))

	return cmd
}
