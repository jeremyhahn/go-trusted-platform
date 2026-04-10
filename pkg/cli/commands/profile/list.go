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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newListCommand creates the list subcommand for listing device profiles
func newListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		page     int
		pageSize int
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List device profiles",
		Long: `List all device profiles with pagination support.

Returns a paginated list of device profiles showing ID, name,
model, role, and tenant information.

Examples:
  # List profiles with default pagination
  platformctl profile list

  # List profiles with custom pagination
  platformctl profile list --page 2 --page-size 50

  # List profiles as JSON
  platformctl profile list -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runList(flags, page, pageSize)
		},
	}

	cmd.Flags().IntVar(&page, "page", 1, "Page number (1-indexed)")
	cmd.Flags().IntVar(&pageSize, "page-size", 20, "Number of items per page")

	return cmd
}

// runList executes the list command
func runList(flags *cli.CommonFlags, page, pageSize int) error {
	// Daemon connection required - dual-mode will be added later
	return ErrDaemonConnectionRequired{}
}

// truncate truncates a string to the specified max length with ellipsis
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
