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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// SyncTenantsResponse is the JSON/YAML output of tenant sync.
type SyncTenantsResponse struct {
	Success bool `json:"success" yaml:"success"`
}

// NewSyncCommand creates the tenant sync command.
func NewSyncCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Resynchronize tenant usage and quota reservations",
		Long: `Resynchronize the tenant manager: recount every tenant's resource usage
and release quota reservations that have expired.

It is safe to run at any time and to run again.

Examples:
  platformctl tenant sync
  platformctl tenant sync -o json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTenantSync(getFlags())
		},
	}
}

func runTenantSync(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	if err := tenantClient.Sync(context.Background()); err != nil {
		return ErrOperationFailed{Operation: "sync", TenantID: "all tenants", Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(&SyncTenantsResponse{Success: true})

	case cli.OutputFormatTable:
		printer.PrintSuccess("Tenant state synchronized")
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
