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

package compute

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the compute root command for virtual machine operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "compute",
		Short: "Virtual machine operations",
		Long: `Manage virtual machines with Trusted Computing attestation support.

The compute subsystem provides comprehensive VM lifecycle management including:
  - Create and configure VMs with security policies
  - Start, stop, and delete virtual machines
  - View VM details and resource usage
  - Enable vTPM and Secure Boot for hardware-rooted trust
  - Manage VM networking, storage, and firmware configuration

Examples:
  # List all VMs
  platformctl compute list

  # Create a new VM
  platformctl compute create --name myvm --cpus 4 --memory 4096

  # Start a VM
  platformctl compute start myvm

  # Get VM details
  platformctl compute get myvm

  # Stop a VM gracefully
  platformctl compute stop myvm

  # Delete a VM and its disks
  platformctl compute delete myvm --delete-disks`,
	}

	// Add subcommands
	cmd.AddCommand(newCreateCommand(getFlags))
	cmd.AddCommand(newStartCommand(getFlags))
	cmd.AddCommand(newStopCommand(getFlags))
	cmd.AddCommand(newDeleteCommand(getFlags))
	cmd.AddCommand(newGetCommand(getFlags))
	cmd.AddCommand(newListCommand(getFlags))
	cmd.AddCommand(newMigrateCommand(getFlags))

	return cmd
}
