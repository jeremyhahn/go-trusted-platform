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

// Package tpm provides CLI commands for TPM device identity operations
// including IDevID (Initial Device Identifier) and IAK (Initial Attestation Key)
// management per TCG specifications.
package tpm

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the tpm root command for TPM device identity operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tpm",
		Short: "TPM device identity operations",
		Long: `Manage TPM device identity keys and certificates.

The TPM subsystem provides device identity management per TCG specifications:
  - IDevID (Initial Device Identifier) key management
  - IAK (Initial Attestation Key) management
  - Certificate signing request (CSR) generation
  - Certificate installation and retrieval
  - TPM provisioning and management
  - EK and SRK key operations
  - Seal/Unseal operations
  - NVRAM management
  - PCR policy operations

These keys are used for device authentication and attestation in
trusted computing environments.

Examples:
  # Generate an IDevID key with ECDSA-P256 algorithm
  platformctl tpm idevid generate --algorithm ECDSA-P256

  # Get IDevID key information
  platformctl tpm idevid info

  # Get TPM device information
  platformctl tpm info

  # Provision the TPM
  platformctl tpm provision

  # Seal data to the TPM
  platformctl tpm seal --cn my-secret --data "secret data"

  # Unseal data from the TPM
  platformctl tpm unseal --cn my-secret`,
	}

	// Add subcommands - existing commands
	cmd.AddCommand(NewIDevIDCommand(getFlags))
	cmd.AddCommand(NewIAKCommand(getFlags))
	cmd.AddCommand(newFlushCommand(getFlags))
	cmd.AddCommand(newDeviceCommand(getFlags))

	// Add new subcommands - platform commands
	cmd.AddCommand(newInfoCommand(getFlags))
	cmd.AddCommand(newProvisionCommand(getFlags))
	cmd.AddCommand(newClearCommand(getFlags))
	cmd.AddCommand(newInstallCommand(getFlags))
	cmd.AddCommand(newDestroyCommand(getFlags))
	cmd.AddCommand(newPolicyCommand(getFlags))
	cmd.AddCommand(newExtendCommand(getFlags))
	cmd.AddCommand(newXKMSCommand(getFlags))

	// Add new subcommands - tpm commands
	cmd.AddCommand(newEKCommand(getFlags))
	cmd.AddCommand(newSRKCommand(getFlags))
	cmd.AddCommand(newSealCommand(getFlags))
	cmd.AddCommand(newUnsealCommand(getFlags))
	cmd.AddCommand(newEventlogCommand(getFlags))
	cmd.AddCommand(newNVRAMCommand(getFlags))
	cmd.AddCommand(newEnrollCommand(getFlags))

	return cmd
}

// newFlushCommand creates the flush subcommand for flushing transient TPM contexts
func newFlushCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "flush",
		Short: "Flush transient TPM contexts",
		Long: `Flush all transient TPM contexts to free up memory.

This command is useful when TPM_RC_OBJECT_MEMORY errors occur
due to too many temporary handles. It flushes all transient
contexts (handles 0x80000000 - 0x80FFFFFF).

Examples:
  # Flush transient contexts
  platformctl tpm flush

  # Flush and get result as JSON
  platformctl tpm flush -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runFlush(flags)
		},
	}

	return cmd
}

// runFlush executes the flush command
func runFlush(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runFlushWithClient(&baseCommandAdapter{base: base})
}

// newDeviceCommand creates the device subcommand group for TPM device information
func newDeviceCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "TPM device information",
		Long: `Get information about the TPM device.

The device command provides access to TPM device attributes and
information such as manufacturer, model, and firmware version.

Examples:
  # Get device attributes
  platformctl tpm device attributes

  # Get device attributes as JSON
  platformctl tpm device attributes -o json`,
	}

	// Add subcommands
	cmd.AddCommand(newDeviceAttributesCommand(getFlags))

	return cmd
}

// newDeviceAttributesCommand creates the attributes subcommand for device info
func newDeviceAttributesCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attributes",
		Short: "Get TPM device attributes",
		Long: `Get device attributes from the TPM.

Returns information about the TPM including:
  - Manufacturer name
  - Device model
  - Firmware version
  - TPM specification level

Examples:
  # Get device attributes
  platformctl tpm device attributes

  # Get as JSON output
  platformctl tpm device attributes -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runDeviceAttributes(flags)
		},
	}

	return cmd
}

// runDeviceAttributes executes the device attributes command
func runDeviceAttributes(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runDeviceAttributesWithClient(&baseCommandAdapter{base: base})
}
