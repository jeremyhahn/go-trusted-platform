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

// Package vtpm provides CLI commands for vTPM (virtual TPM) bundle management
// including creation, cloning, import/export, template operations, and runtime
// TPM operations such as starting/stopping the swtpm daemon, quoting, sealing,
// unsealing, and PCR management for VM provisioning workflows.
package vtpm

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the vtpm root command for vTPM bundle operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vtpm",
		Short: "vTPM bundle management operations",
		Long: `Manage virtual TPM (vTPM) bundles for VM provisioning.

The vTPM subsystem provides bundle management for virtual machine TPM provisioning:
  - Create pre-assigned bundles with CA-issued EK certificates
  - Manage templates for rapid cloning
  - Clone templates to create bundles with unique identities
  - Import/export bundles for distribution
  - List and inspect bundle information
  - Start/stop swtpm daemons for runtime TPM operations
  - Generate TPM quotes for attestation
  - Seal/unseal data using the TPM
  - Manage PCR (Platform Configuration Register) values

These bundles are used for secure VM provisioning with trusted computing
capabilities including Secure Boot and TPM-based attestation.

Examples:
  # Create a pre-assigned vTPM bundle
  platformctl vtpm create --hostname vm001.example.com

  # List all bundles
  platformctl vtpm list

  # Get bundle information
  platformctl vtpm info bundle-123

  # Create a template for cloning
  platformctl vtpm template create --id base-vtpm

  # Clone a template to create a new bundle
  platformctl vtpm clone --template base-vtpm --hostname vm002.example.com

  # Export a bundle for distribution
  platformctl vtpm export bundle-123 -o my-bundle.vtpm.tar.gz

  # Import a bundle from archive
  platformctl vtpm import bundle.vtpm.tar.gz

  # Start the vTPM daemon
  platformctl vtpm start --bundle-id bundle-123

  # Check if vTPM is running
  platformctl vtpm is-running --bundle-id bundle-123

  # Generate a TPM quote
  platformctl vtpm quote --bundle-id bundle-123 --nonce deadbeef --pcrs 0,1,7

  # Seal data to the TPM
  platformctl vtpm seal --bundle-id bundle-123 --data aGVsbG8= --pcrs 0,1,7

  # Read a PCR value
  platformctl vtpm pcr read --bundle-id bundle-123 --pcr-index 7`,
	}

	// Bundle management subcommands
	cmd.AddCommand(newCreateCommand(getFlags))
	cmd.AddCommand(newListCommand(getFlags))
	cmd.AddCommand(newInfoCommand(getFlags))
	cmd.AddCommand(newDeleteCommand(getFlags))
	cmd.AddCommand(newCloneCommand(getFlags))
	cmd.AddCommand(newExportCommand(getFlags))
	cmd.AddCommand(newImportCommand(getFlags))
	cmd.AddCommand(newTemplateCommand(getFlags))

	// Runtime TPM operation subcommands
	cmd.AddCommand(newStartCommand(getFlags))
	cmd.AddCommand(newStopCommand(getFlags))
	cmd.AddCommand(newIsRunningCommand(getFlags))
	cmd.AddCommand(newQuoteCommand(getFlags))
	cmd.AddCommand(newSealCommand(getFlags))
	cmd.AddCommand(newUnsealCommand(getFlags))
	cmd.AddCommand(newPCRCommand(getFlags))

	return cmd
}
