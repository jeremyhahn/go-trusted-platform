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

package db

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the db root command for database operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database operations",
		Long: `Manage QuicBaaS datastore operations.

The db subsystem provides tools for database management including:
  - Listing partitions and entity counts
  - Exporting data to JSON/YAML files
  - Importing data from JSON/YAML files
  - Database inspection and debugging

Examples:
  # List all partitions with entity counts
  platformctl db list

  # Dump all database data to JSON files
  platformctl db dump --output ./backup --format json

  # Dump with pretty printing
  platformctl db dump --output ./backup --format json --pretty

  # Dump only DNS zones
  platformctl db dump --output ./backup --partition dns/zones

  # Dump to YAML format
  platformctl db dump --output ./backup --format yaml`,
	}

	// Add subcommands
	cmd.AddCommand(NewListCommand(getFlags))
	cmd.AddCommand(NewDumpCommand(getFlags))

	return cmd
}
