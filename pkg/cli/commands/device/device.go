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

// Package device provides CLI commands for device management operations
// including listing, retrieving, finding, registering, and deleting devices.
package device

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the device root command for device management operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Device management operations",
		Long: `Manage devices registered with the platform.

The device subsystem provides device management capabilities:
  - List all registered devices with pagination
  - Get device details by ID
  - Find devices by serial number
  - Register new devices with the control plane
  - Update a device's model and key material
  - Delete devices
  - Manage device profiles and the templates they are built from
  - Disable a device (cut its switch port) and enable it again

Examples:
  # List all devices
  platformctl device list

  # List devices with pagination
  platformctl device list --page 2 --page-size 50

  # Get device by ID
  platformctl device get 123

  # Get device info as JSON
  platformctl device get 123 -o json

  # Find device by serial number
  platformctl device find-serial ABC123

  # Register a device with the control plane
  platformctl device register --serial SN-0001 --model r640

  # Change a device's model
  platformctl device update 123 --model r650

  # Delete a device
  platformctl device delete 123

  # Build a profile from a template
  platformctl device template create-profile 456 --name r650-01 --ek-serial 0A1B2C

  # Record a device's attestation certificate without re-enrolling it
  platformctl device attest-cert record 123

  # Disable a device, then re-admit it pending re-attestation
  platformctl device disable 123 --reason "RMA pending"
  platformctl device enable 123`,
	}

	// Add subcommands
	cmd.AddCommand(newListCommand(getFlags))
	cmd.AddCommand(newGetCommand(getFlags))
	cmd.AddCommand(newFindSerialCommand(getFlags))
	cmd.AddCommand(newRegisterCommand(getFlags))
	cmd.AddCommand(newUpdateCommand(getFlags))
	cmd.AddCommand(newDeleteCommand(getFlags))
	cmd.AddCommand(newProfileCommand(getFlags))
	cmd.AddCommand(newTemplateCommand(getFlags))
	cmd.AddCommand(newAttestCommand(getFlags))
	cmd.AddCommand(newAttestCertCommand(getFlags))
	cmd.AddCommand(newDisableCommand(getFlags))
	cmd.AddCommand(newEnableCommand(getFlags))
	cmd.AddCommand(newBootCommand(getFlags))

	return cmd
}
