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

// newGetCommand creates the get subcommand for retrieving a device profile
func newGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get device profile by ID",
		Long: `Retrieve a device profile by its ID.

Returns detailed information about the profile including:
  - Basic info (ID, name, model, role, tenant)
  - Match rules (MAC prefix, serial prefix, model)
  - Network configurations (provisioning, production, quarantine)

Examples:
  # Get a profile by ID
  platformctl profile get 123

  # Get a profile as JSON
  platformctl profile get 123 -o json

  # Get a profile as YAML
  platformctl profile get 123 -o yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()

			id, err := strconv.ParseUint(args[0], 10, 64)
			if err != nil {
				return ErrInvalidID{ID: args[0]}
			}

			return runGet(flags, id)
		},
	}

	return cmd
}

// runGet executes the get command
func runGet(flags *cli.CommonFlags, id uint64) error {
	// Daemon connection required - dual-mode will be added later
	return ErrDaemonConnectionRequired{}
}
