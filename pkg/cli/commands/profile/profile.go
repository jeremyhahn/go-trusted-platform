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

// Package profile is the top-level `platformctl profile` group.
package profile

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli/commands/device"
)

// NewCommand creates the profile root command. Its verbs are the
// `platformctl device profile` get, list, delete and match commands, so the
// two trees share one implementation; `device profile` is canonical.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Device profile management",
		Long: `Read, match and delete device profiles on the control plane.

These are the get, list, delete and match verbs of 'platformctl device
profile', which also creates, updates, assigns and unassigns profiles.

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

	cmd.AddCommand(device.NewProfileLookupCommands(getFlags)...)

	return cmd
}
