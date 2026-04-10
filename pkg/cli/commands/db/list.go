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
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// List command flags
type listFlags struct {
	configDir string
}

// NewListCommand creates the list subcommand
func NewListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &listFlags{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List QuicBaaS entity types and counts",
		Long: `List all entity types in the QuicBaaS database.

QuicBaaS stores entities grouped by type using key prefixes in PebbleDB.
This command connects to platformd via Unix socket and queries the
database to show all known entity types along with their entity counts.

Known entity types:
  - Organization     User organizations
  - User             User accounts
  - Registration     Registration requests
  - Role             User roles
  - WebAuthn         WebAuthn credentials
  - Device           Registered devices
  - DeviceProfile    Device profiles
  - Zone             DNS zones

Examples:
  # List all entity types
  platformctl db list
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(getFlags(), flags)
		},
	}

	cmd.Flags().StringVar(&flags.configDir, "config-dir", "", "platform configuration directory (unused, kept for compatibility)")

	return cmd
}

// runList executes the list command via gRPC
func runList(commonFlags *cli.CommonFlags, flags *listFlags) error {
	printer := cli.NewPrinter(commonFlags.OutputFormat, commonFlags.NoColor)

	// Create base command to get SDK client
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return fmt.Errorf("failed to connect to platformd: %w", err)
	}
	defer base.Close()

	// Create request context with timeout
	reqCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Call ListEntityTypes RPC
	resp, err := base.Client().Daemon().ListEntityTypes(reqCtx, &platformv1.ListEntityTypesRequest{})
	if err != nil {
		return fmt.Errorf("failed to list entity types: %w", err)
	}

	// Print header
	printer.PrintInfo(fmt.Sprintf("QuicBaaS Entity Types (%s)", resp.DatabasePath))
	fmt.Println(strings.Repeat("-", 60))

	// Create tabwriter for aligned output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENTITY TYPE\tCOUNT\tSTATUS")

	for _, entityType := range resp.EntityTypes {
		fmt.Fprintf(w, "%s\t%d\t%s\n", entityType.Name, entityType.EntityCount, entityType.Status)
	}

	w.Flush()

	// Print summary
	fmt.Println(strings.Repeat("-", 60))
	printer.PrintSuccess(fmt.Sprintf("Total: %d entities across %d active types",
		resp.TotalEntities, resp.ActiveTypes))

	return nil
}
