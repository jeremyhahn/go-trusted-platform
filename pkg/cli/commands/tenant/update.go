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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// updateTenantOptions holds the values given to tenant update. Labels and
// annotations replace the tenant's whole map when given; an empty display
// name leaves the current one in place.
type updateTenantOptions struct {
	DisplayName string
	Labels      map[string]string
	Annotations map[string]string
}

// empty reports whether the options would change nothing.
func (o *updateTenantOptions) empty() bool {
	return o.DisplayName == "" && len(o.Labels) == 0 && len(o.Annotations) == 0
}

// NewUpdateCommand creates the tenant update command.
func NewUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &updateTenantOptions{}

	cmd := &cobra.Command{
		Use:   "update <tenant-name>",
		Short: "Update a tenant's display name, labels or annotations",
		Long: `Update a tenant's display name, labels or annotations.

--labels and --annotations replace the tenant's whole map. A value that is
not given is left as it is. Quotas are changed with "tenant quotas set".

Examples:
  # Change the display name
  platformctl tenant update my-tenant --display-name "My Tenant"

  # Replace the labels
  platformctl tenant update my-tenant --labels env=prod,tier=gold

  # Output the updated tenant as JSON
  platformctl tenant update my-tenant --annotations owner=ops -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTenantUpdate(getFlags(), args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.DisplayName, "display-name", "", "new display name")
	cmd.Flags().StringToStringVar(&opts.Labels, "labels", nil, "labels as key=value pairs (replaces all labels)")
	cmd.Flags().StringToStringVar(&opts.Annotations, "annotations", nil, "annotations as key=value pairs (replaces all annotations)")

	return cmd
}

func runTenantUpdate(flags *cli.CommonFlags, tenantName string, opts *updateTenantOptions) error {
	if opts.empty() {
		return ErrInvalidArguments{Reason: "nothing to update: give --display-name, --labels or --annotations"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())

	ctx := context.Background()

	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	tenantID := t.ID
	if _, err := tenantClient.Update(ctx, &platformv1.UpdateTenantRequest{
		TenantId:    tenantID,
		DisplayName: opts.DisplayName,
		Labels:      opts.Labels,
		Annotations: opts.Annotations,
	}); err != nil {
		return ErrOperationFailed{Operation: "update", TenantID: tenantID, Err: err}
	}

	t, err = tenantClient.GetDomain(ctx, tenantID)
	if err != nil {
		return ErrOperationFailed{Operation: "get", TenantID: tenantID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(toTenantDetail(t))

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant updated: %s", tenantName))
		printTenantDetails(printer, t)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
