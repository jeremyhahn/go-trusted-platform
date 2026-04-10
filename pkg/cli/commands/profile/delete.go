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

package profile

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newDeleteCommand creates the delete subcommand for deleting a device profile
func newDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete device profile by ID",
		Long: `Delete a device profile by its ID.

This will permanently remove the profile from the system.
The profile must exist or an error will be returned.

Examples:
  # Delete a profile by ID
  platformctl profile delete 123

  # Delete a profile with JSON output
  platformctl profile delete 123 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()

			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return ErrInvalidID{ID: args[0]}
			}

			return runDelete(flags, id)
		},
	}

	return cmd
}

// runDelete executes the delete command
func runDelete(flags *cli.CommonFlags, id uint64) error {
	// Daemon connection required - dual-mode will be added later
	return ErrDaemonConnectionRequired{}
}
