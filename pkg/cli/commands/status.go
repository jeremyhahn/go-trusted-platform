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

// NewStatusCommand creates the status command
func NewStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show platform status",
		Long:  "Display the current status of the Trusted Platform and its services",
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStatus(flags)
		},
	}

	return cmd
}

func runStatus(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	daemonClient := daemonsvc.NewClientFromGRPC(base.Client().Daemon())

	ctx := base.Context()
	status, err := daemonClient.GetStatusDomain(ctx)
	if err != nil {
		return err
	}

	printer := base.Printer()

	// Format output based on output format
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		return printStatusTable(printer, status)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printStatusTable(printer *cli.Printer, status *daemonsvc.StatusInfo) error {
	// Print system status
	printer.PrintInfo(fmt.Sprintf("System Status: %s", string(status.Status)))
	fmt.Println()

	// Print platform info
	if status.Info != nil {
		printer.PrintKeyValue("Hostname", status.Info.Hostname)
		printer.PrintKeyValue("Platform ID", status.Info.PlatformID)
		printer.PrintKeyValue("Version", status.Info.Version)
		printer.PrintKeyValue("Build Time", status.Info.BuildTime)
		printer.PrintKeyValue("Git Commit", status.Info.GitCommit)
		printer.PrintKeyValue("FIPS Mode", fmt.Sprintf("%v", status.Info.FIPSMode))
		fmt.Println()

		// Print system info
		if status.Info.SystemInfo != nil {
			si := status.Info.SystemInfo
			printer.PrintInfo("System Information:")
			fmt.Println()
			printer.PrintKeyValue("  OS", si.OS)
			printer.PrintKeyValue("  Architecture", si.Arch)
			printer.PrintKeyValue("  Kernel", si.KernelVersion)
			printer.PrintKeyValue("  CPUs", fmt.Sprintf("%d", si.NumCPUs))
			printer.PrintKeyValue("  Memory", fmt.Sprintf("%d MB total, %d MB available",
				si.TotalMemoryMB, si.AvailableMemoryMB))
			printer.PrintKeyValue("  Uptime", fmt.Sprintf("%d seconds", si.UptimeSeconds))
			fmt.Println()
		}

		// Print TPM info
		if status.Info.TPMInfo != nil {
			ti := status.Info.TPMInfo
			printer.PrintInfo("TPM Information:")
			fmt.Println()
			printer.PrintKeyValue("  Version", string(ti.Version))
			printer.PrintKeyValue("  Manufacturer", ti.Manufacturer)
			printer.PrintKeyValue("  Firmware", ti.FirmwareVersion)
			printer.PrintKeyValue("  Simulator", fmt.Sprintf("%v", ti.IsSimulator))
			printer.PrintKeyValue("  FIPS Mode", fmt.Sprintf("%v", ti.FIPSMode))
			fmt.Println()
		}
	}

	// Print services
	if len(status.Services) > 0 {
		printer.PrintInfo("Services:")
		fmt.Println()

		table := cli.NewTableData("Name", "Type", "Status", "Health", "Uptime")
		for _, svc := range status.Services {
			table.AddRow(
				svc.Name,
				string(svc.Type),
				string(svc.Status),
				string(svc.Health),
				fmt.Sprintf("%ds", svc.UptimeSeconds),
			)
		}
		return printer.Print(*table)
	}

	return nil
}
