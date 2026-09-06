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

	printUnhealthyComponents(printer, health)
	return nil
}

// printUnhealthyComponents names every component that is not healthy, in the
// DEFAULT view.
//
// "Overall Health: degraded" on its own tells an operator that something is
// wrong and nothing about what, so the condition that caused it needs a
// second command to find. That is how a fleet ran time-unsynced from
// enrolment without anyone noticing (#509): the `ntp` component was reporting
// `time-unsynced` the whole time, one flag away from being read.
//
// It prints nothing when every component is healthy, and nothing under
// --detailed, where the full table above already carries the same rows.
func printUnhealthyComponents(printer *cli.Printer, health *daemonsvc.HealthInfo) {
	var affected []*daemonsvc.ComponentHealth
	for _, component := range health.Components {
		if component == nil || component.Status == daemonsvc.HealthStatusHealthy {
			continue
		}
		affected = append(affected, component)
	}
	if len(affected) == 0 {
		return
	}

	for _, component := range affected {
		line := fmt.Sprintf("%s: %s", component.Name, string(component.Status))
		if component.Message != "" {
			line += " — " + component.Message
		}
		if component.Status == daemonsvc.HealthStatusUnhealthy {
			printer.PrintError(line)
			continue
		}
		printer.PrintWarning(line)
	}
	fmt.Println()
	printer.PrintInfo("Run with --detailed for every component.")
}
