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

	ctx := base.Context()
	resp, err := base.Client().Daemon().GetStatus(ctx, &platformv1.GetStatusRequest{})
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	printer := base.Printer()

	// Format output based on output format
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		return printStatusTable(printer, resp)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

func printStatusTable(printer *cli.Printer, resp *platformv1.GetStatusResponse) error {
	// Print system status
	printer.PrintInfo(fmt.Sprintf("System Status: %s", formatSystemStatus(resp.Status)))
	fmt.Println()

	// Print platform info
	if resp.Info != nil {
		printer.PrintKeyValue("Hostname", resp.Info.Hostname)
		printer.PrintKeyValue("Platform ID", resp.Info.PlatformId)
		printer.PrintKeyValue("Version", resp.Info.Version)
		printer.PrintKeyValue("Build Time", resp.Info.BuildTime)
		printer.PrintKeyValue("Git Commit", resp.Info.GitCommit)
		printer.PrintKeyValue("FIPS Mode", fmt.Sprintf("%v", resp.Info.FipsMode))
		fmt.Println()

		// Print system info
		if resp.Info.SystemInfo != nil {
			printer.PrintInfo("System Information:")
			fmt.Println()
			printer.PrintKeyValue("  OS", resp.Info.SystemInfo.Os)
			printer.PrintKeyValue("  Architecture", resp.Info.SystemInfo.Arch)
			printer.PrintKeyValue("  Kernel", resp.Info.SystemInfo.KernelVersion)
			printer.PrintKeyValue("  CPUs", fmt.Sprintf("%d", resp.Info.SystemInfo.NumCpus))
			printer.PrintKeyValue("  Memory", fmt.Sprintf("%d MB total, %d MB available",
				resp.Info.SystemInfo.TotalMemoryMb, resp.Info.SystemInfo.AvailableMemoryMb))
			printer.PrintKeyValue("  Uptime", fmt.Sprintf("%d seconds", resp.Info.SystemInfo.UptimeSeconds))
			fmt.Println()
		}

		// Print TPM info
		if resp.Info.TpmInfo != nil {
			printer.PrintInfo("TPM Information:")
			fmt.Println()
			printer.PrintKeyValue("  Version", formatTPMVersion(resp.Info.TpmInfo.Version))
			printer.PrintKeyValue("  Manufacturer", resp.Info.TpmInfo.Manufacturer)
			printer.PrintKeyValue("  Firmware", resp.Info.TpmInfo.FirmwareVersion)
			printer.PrintKeyValue("  Simulator", fmt.Sprintf("%v", resp.Info.TpmInfo.IsSimulator))
			printer.PrintKeyValue("  FIPS Mode", fmt.Sprintf("%v", resp.Info.TpmInfo.FipsMode))
			fmt.Println()
		}
	}

	// Print services
	if len(resp.Services) > 0 {
		printer.PrintInfo("Services:")
		fmt.Println()

		table := cli.NewTableData("Name", "Type", "Status", "Health", "Uptime")
		for _, svc := range resp.Services {
			table.AddRow(
				svc.Name,
				formatServiceType(svc.Type),
				formatServiceStatus(svc.Status),
				formatHealthStatus(svc.Health),
				fmt.Sprintf("%ds", svc.UptimeSeconds),
			)
		}
		return printer.Print(*table)
	}

	return nil
}

func formatSystemStatus(status platformv1.SystemStatus) string {
	switch status {
	case platformv1.SystemStatus_SYSTEM_STATUS_READY:
		return "READY"
	case platformv1.SystemStatus_SYSTEM_STATUS_INITIALIZING:
		return "INITIALIZING"
	case platformv1.SystemStatus_SYSTEM_STATUS_DEGRADED:
		return "DEGRADED"
	case platformv1.SystemStatus_SYSTEM_STATUS_UNAVAILABLE:
		return "UNAVAILABLE"
	case platformv1.SystemStatus_SYSTEM_STATUS_SHUTTING_DOWN:
		return "SHUTTING_DOWN"
	default:
		return "UNKNOWN"
	}
}

func formatServiceType(t platformv1.ServiceType) string {
	switch t {
	case platformv1.ServiceType_SERVICE_TYPE_TPM:
		return "TPM"
	case platformv1.ServiceType_SERVICE_TYPE_SDN:
		return "SDN"
	case platformv1.ServiceType_SERVICE_TYPE_COMPUTE:
		return "Compute"
	case platformv1.ServiceType_SERVICE_TYPE_DNS:
		return "DNS"
	case platformv1.ServiceType_SERVICE_TYPE_ACME:
		return "ACME"
	case platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE:
		return "WebService"
	case platformv1.ServiceType_SERVICE_TYPE_ATTESTATION:
		return "Attestation"
	default:
		return "Unknown"
	}
}

func formatServiceStatus(status platformv1.ServiceStatus) string {
	switch status {
	case platformv1.ServiceStatus_SERVICE_STATUS_RUNNING:
		return "RUNNING"
	case platformv1.ServiceStatus_SERVICE_STATUS_STOPPED:
		return "STOPPED"
	case platformv1.ServiceStatus_SERVICE_STATUS_STARTING:
		return "STARTING"
	case platformv1.ServiceStatus_SERVICE_STATUS_STOPPING:
		return "STOPPING"
	case platformv1.ServiceStatus_SERVICE_STATUS_ERROR:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func formatHealthStatus(status platformv1.HealthStatus) string {
	switch status {
	case platformv1.HealthStatus_HEALTH_STATUS_HEALTHY:
		return "HEALTHY"
	case platformv1.HealthStatus_HEALTH_STATUS_DEGRADED:
		return "DEGRADED"
	case platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY:
		return "UNHEALTHY"
	default:
		return "UNKNOWN"
	}
}

func formatTPMVersion(version platformv1.TPMVersion) string {
	switch version {
	case platformv1.TPMVersion_TPM_VERSION_2_0:
		return "2.0"
	case platformv1.TPMVersion_TPM_VERSION_1_2:
		return "1.2"
	default:
		return "Unknown"
	}
}
