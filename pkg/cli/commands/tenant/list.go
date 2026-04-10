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

package tenant

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// NewListCommand creates the tenant list subcommand
func NewListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var limit int32
	var offset int32

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all tenants",
		Long: `Display a list of all tenants with pagination support.

The list shows tenant name, state, VLAN range, and bridge information.

Examples:
  # List all tenants
  platformctl tenant list

  # List with pagination
  platformctl tenant list --limit 50 --offset 0

  # Output as JSON
  platformctl tenant list -o json

  # Output as YAML
  platformctl tenant list -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runTenantList(flags, limit, offset)
		},
	}

	cmd.Flags().Int32VarP(&limit, "limit", "l", 50, "maximum number of tenants to return")
	cmd.Flags().Int32VarP(&offset, "offset", "O", 0, "number of tenants to skip")

	return cmd
}

func runTenantList(flags *cli.CommonFlags, limit, offset int32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// Create tenant service client from the platform client
	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	ctx := context.Background()
	tenants, total, err := tenantClient.ListDomain(ctx, limit, offset)
	if err != nil {
		return ErrOperationFailed{
			Operation: "list",
			TenantID:  "",
			Err:       err,
		}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		summaries := make([]*TenantListItem, 0, len(tenants))
		for _, t := range tenants {
			summaries = append(summaries, &TenantListItem{
				ID:        t.ID,
				Name:      t.Name,
				CreatedAt: formatTime(t.CreatedAt),
			})
		}

		output := &TenantListResponse{
			Tenants: summaries,
			Total:   total,
			Limit:   limit,
			Offset:  offset,
		}

		return printer.Print(output)

	case cli.OutputFormatTable:
		if len(tenants) == 0 {
			printer.PrintInfo("No tenants found")
			return nil
		}

		table := cli.NewTableData("NAME", "ID", "CREATED AT")
		for _, t := range tenants {
			table.AddRow(
				t.Name,
				truncateID(t.ID),
				formatTime(t.CreatedAt),
			)
		}

		if err := printer.Print(*table); err != nil {
			return err
		}

		fmt.Println()
		printer.PrintKeyValue("Total Count", fmt.Sprintf("%d", total))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// TenantListItem represents a tenant in list output
type TenantListItem struct {
	ID        string `json:"id" yaml:"id"`
	Name      string `json:"name" yaml:"name"`
	CreatedAt string `json:"created_at" yaml:"created_at"`
}

// TenantListResponse represents the list response
type TenantListResponse struct {
	Tenants []*TenantListItem `json:"tenants" yaml:"tenants"`
	Total   int32             `json:"total" yaml:"total"`
	Limit   int32             `json:"limit" yaml:"limit"`
	Offset  int32             `json:"offset" yaml:"offset"`
}

// truncateID truncates a UUID for display
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12] + "..."
	}
	return id
}
