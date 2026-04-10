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

// Package profile provides CLI commands for device profile management
// including listing, retrieving, deleting, and matching device profiles.
package profile

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the profile root command for device profile operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Device profile management",
		Long: `Manage device profiles for provisioning and network assignment.

The profile subsystem provides device profile management:
  - List all device profiles with pagination
  - Get profile details by ID
  - Delete profiles by ID
  - Match devices to profiles by MAC, serial, or model

Device profiles define provisioning and network configurations
for devices based on matching rules.

Examples:
  # List all profiles
  platformctl profile list

  # List profiles with pagination
  platformctl profile list --page 2 --page-size 50

  # Get a profile by ID
  platformctl profile get 123

  # Delete a profile
  platformctl profile delete 123

  # Find a matching profile for a device
  platformctl profile match --mac 00:11:22:33:44:55`,
	}

	// Add subcommands
	cmd.AddCommand(newListCommand(getFlags))
	cmd.AddCommand(newGetCommand(getFlags))
	cmd.AddCommand(newDeleteCommand(getFlags))
	cmd.AddCommand(newMatchCommand(getFlags))

	return cmd
}
