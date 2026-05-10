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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	daemonsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
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

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	health, err := daemonClient.GetHealthDomain(ctx, detailed)
	if err != nil {
		return err
	}

	printer := base.Printer()

	// Format output based on output format
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(health)

	case cli.OutputFormatTable:
		return printHealthTable(printer, health, detailed)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printHealthTable(printer *cli.Printer, health *daemonsvc.HealthInfo, detailed bool) error {
	// Print overall status
	statusMsg := fmt.Sprintf("Overall Health: %s", string(health.Status))
	switch health.Status {
	case daemonsvc.HealthStatusHealthy:
		printer.PrintSuccess(statusMsg)
	case daemonsvc.HealthStatusDegraded:
		printer.PrintWarning(statusMsg)
	case daemonsvc.HealthStatusUnhealthy:
		printer.PrintError(statusMsg)
	default:
		printer.PrintInfo(statusMsg)
	}
	fmt.Println()

	// Print component health if detailed
	if detailed && len(health.Components) > 0 {
		printer.PrintInfo("Component Health:")
		fmt.Println()

		table := cli.NewTableData("Component", "Status", "Message")
		for _, component := range health.Components {
			table.AddRow(
				component.Name,
				string(component.Status),
				component.Message,
			)
		}
		return printer.Print(*table)
	}

	return nil
}
