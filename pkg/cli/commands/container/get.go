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

package container

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newGetCommand creates the container get subcommand
func newGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get <container-id>",
		Aliases: []string{"inspect", "describe"},
		Short:   "Get container details",
		Long: `Get detailed information about a container.

Displays comprehensive information about the specified container
including configuration, state, resource usage, and networking.

Examples:
  # Get container details
  platformctl container get myapp

  # Get container details with JSON output
  platformctl container get myapp --output json

  # Get container details with YAML output
  platformctl container get myapp --output yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGet(flags, args[0])
		},
	}

	return cmd
}

// runGet executes the container get command
func runGet(flags *cli.CommonFlags, containerID string) error {
	if containerID == "" {
		return ErrInvalidContainerConfig{Field: "id", Reason: "container ID is required"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client := base.Client().Compute()
	if client == nil {
		return ErrContainerClientNotInitialized{}
	}

	req := &platformv1.GetContainerRequest{
		Id: containerID,
	}

	ctx := base.Context()
	resp, err := client.GetContainer(ctx, req)
	if err != nil {
		return ErrContainerNotFound{ID: containerID}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp.Container)

	case cli.OutputFormatTable:
		return printFullContainerDetails(printer, resp.Container)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printFullContainerDetails prints comprehensive container details
func printFullContainerDetails(printer *cli.Printer, container *platformv1.Container) error {
	if container == nil {
		return nil
	}

	// Basic information
	printer.PrintInfo("Container Information")
	printer.PrintKeyValue("ID", container.Id)

	if container.Config != nil {
		printer.PrintKeyValue("Name", container.Config.Name)
		printer.PrintKeyValue("Image", container.Config.Image)
		if container.Config.ImageHash != "" {
			printer.PrintKeyValue("Image Hash", container.Config.ImageHash)
		}
	}

	printer.PrintKeyValue("State", formatContainerState(container.State))
	printer.PrintKeyValue("Created At", formatTimestamp(container.CreatedAt))

	if container.StartedAt != nil {
		printer.PrintKeyValue("Started At", formatTimestamp(container.StartedAt))
	}
	if container.FinishedAt != nil {
		printer.PrintKeyValue("Finished At", formatTimestamp(container.FinishedAt))
	}
	if container.ExitCode != 0 || container.State == platformv1.ContainerState_CONTAINER_STATE_EXITED {
		printer.PrintKeyValue("Exit Code", fmt.Sprintf("%d", container.ExitCode))
	}

	if container.HostId != "" {
		printer.PrintKeyValue("Host ID", container.HostId)
	}

	// Configuration details
	if container.Config != nil {
		fmt.Println()
		printer.PrintInfo("Configuration")

		if container.Config.WorkingDir != "" {
			printer.PrintKeyValue("Working Directory", container.Config.WorkingDir)
		}

		if len(container.Config.Command) > 0 {
			printer.PrintKeyValue("Command", strings.Join(container.Config.Command, " "))
		}

		if len(container.Config.Args) > 0 {
			printer.PrintKeyValue("Args", strings.Join(container.Config.Args, " "))
		}

		printer.PrintKeyValue("Privileged", formatBool(container.Config.Privileged))
		printer.PrintKeyValue("TPM Access", formatBool(container.Config.TpmAccess))

		if container.Config.Network != "" {
			printer.PrintKeyValue("Network", container.Config.Network)
		}

		if container.Config.RestartPolicy != platformv1.RestartPolicy_RESTART_POLICY_UNSPECIFIED {
			printer.PrintKeyValue("Restart Policy", formatRestartPolicy(container.Config.RestartPolicy))
		}

		// Environment variables
		if len(container.Config.Env) > 0 {
			fmt.Println()
			printer.PrintInfo("Environment Variables")
			for _, env := range container.Config.Env {
				printer.PrintKeyValue(fmt.Sprintf("  %s", env.Name), env.Value)
			}
		}

		// Port mappings
		if len(container.Config.Ports) > 0 {
			fmt.Println()
			printer.PrintInfo("Port Mappings")
			for _, port := range container.Config.Ports {
				mapping := fmt.Sprintf("%d -> %d/%s", port.HostPort, port.ContainerPort, port.Protocol)
				if port.HostIp != "" {
					mapping = fmt.Sprintf("%s:%s", port.HostIp, mapping)
				}
				printer.PrintKeyValue("  Port", mapping)
			}
		}

		// Volume mounts
		if len(container.Config.Volumes) > 0 {
			fmt.Println()
			printer.PrintInfo("Volume Mounts")
			for _, vol := range container.Config.Volumes {
				mount := fmt.Sprintf("%s -> %s", vol.Source, vol.Destination)
				if vol.Readonly {
					mount += " (readonly)"
				}
				printer.PrintKeyValue("  Volume", mount)
			}
		}

		// Capabilities
		if len(container.Config.Capabilities) > 0 {
			fmt.Println()
			printer.PrintInfo("Capabilities")
			printer.PrintKeyValue("  Added", strings.Join(container.Config.Capabilities, ", "))
		}

		// Resource limits
		if container.Config.Resources != nil {
			fmt.Println()
			printer.PrintInfo("Resource Limits")
			if container.Config.Resources.MaxMemoryMb > 0 {
				printer.PrintKeyValue("  Max Memory", fmt.Sprintf("%d MB", container.Config.Resources.MaxMemoryMb))
			}
			if container.Config.Resources.MaxCpus > 0 {
				printer.PrintKeyValue("  Max CPUs", fmt.Sprintf("%d", container.Config.Resources.MaxCpus))
			}
		}

		// Labels
		if len(container.Config.Labels) > 0 {
			fmt.Println()
			printer.PrintInfo("Labels")
			for key, value := range container.Config.Labels {
				printer.PrintKeyValue(fmt.Sprintf("  %s", key), value)
			}
		}

		// Metadata
		if len(container.Config.Metadata) > 0 {
			fmt.Println()
			printer.PrintInfo("Metadata")
			for key, value := range container.Config.Metadata {
				printer.PrintKeyValue(fmt.Sprintf("  %s", key), value)
			}
		}
	}

	// Metrics
	if container.Metrics != nil {
		fmt.Println()
		printer.PrintInfo("Metrics")
		printer.PrintKeyValue("  CPU Usage", fmt.Sprintf("%.2f%%", container.Metrics.CpuUsagePercent))
		printer.PrintKeyValue("  Memory Used", fmt.Sprintf("%d MB", container.Metrics.MemoryUsedMb))
		if container.Metrics.MemoryLimitMb > 0 {
			printer.PrintKeyValue("  Memory Limit", fmt.Sprintf("%d MB", container.Metrics.MemoryLimitMb))
		}
		printer.PrintKeyValue("  Disk Read", formatBytes(container.Metrics.DiskReadBytes))
		printer.PrintKeyValue("  Disk Write", formatBytes(container.Metrics.DiskWriteBytes))
		printer.PrintKeyValue("  Network RX", formatBytes(container.Metrics.NetworkRxBytes))
		printer.PrintKeyValue("  Network TX", formatBytes(container.Metrics.NetworkTxBytes))
		if container.Metrics.UptimeSeconds > 0 {
			printer.PrintKeyValue("  Uptime", formatDuration(container.Metrics.UptimeSeconds))
		}
	}

	return nil
}

// formatRestartPolicy formats a restart policy for display
func formatRestartPolicy(policy platformv1.RestartPolicy) string {
	switch policy {
	case platformv1.RestartPolicy_RESTART_POLICY_NO:
		return "No"
	case platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE:
		return "On Failure"
	case platformv1.RestartPolicy_RESTART_POLICY_ALWAYS:
		return "Always"
	case platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED:
		return "Unless Stopped"
	default:
		return "Unknown"
	}
}
