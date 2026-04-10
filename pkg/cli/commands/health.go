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

package commands

import (
	"fmt"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewHealthCommand creates the health command
func NewHealthCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var detailed bool

	cmd := &cobra.Command{
		Use:   "health",
		Short: "Show platform health status",
		Long:  "Display the health status of the Trusted Platform and its components",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runHealth(flags, detailed)
		},
	}

	cmd.Flags().BoolVarP(&detailed, "detailed", "d", false, "show detailed component health")

	return cmd
}

func runHealth(flags *cli.CommonFlags, detailed bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	ctx := base.Context()
	resp, err := base.Client().Daemon().GetHealth(ctx, &platformv1.GetHealthRequest{
		Detailed: detailed,
	})
	if err != nil {
		return fmt.Errorf("failed to get health: %w", err)
	}

	printer := base.Printer()

	// Format output based on output format
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printHealthTable(printer, resp, detailed)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printHealthTable(printer *cli.Printer, resp *platformv1.GetHealthResponse, detailed bool) error {
	// Print overall status
	statusMsg := fmt.Sprintf("Overall Health: %s", formatHealthStatus(resp.Status))
	switch resp.Status {
	case platformv1.HealthStatus_HEALTH_STATUS_HEALTHY:
		printer.PrintSuccess(statusMsg)
	case platformv1.HealthStatus_HEALTH_STATUS_DEGRADED:
		printer.PrintWarning(statusMsg)
	case platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY:
		printer.PrintError(statusMsg)
	default:
		printer.PrintInfo(statusMsg)
	}
	fmt.Println()

	// Print component health if detailed
	if detailed && len(resp.Components) > 0 {
		printer.PrintInfo("Component Health:")
		fmt.Println()

		table := cli.NewTableData("Component", "Status", "Message")
		for _, component := range resp.Components {
			table.AddRow(
				component.Name,
				formatHealthStatus(component.Status),
				component.Message,
			)
		}
		return printer.Print(*table)
	}

	return nil
}
