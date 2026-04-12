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

package compute

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// newGetCommand creates the compute get subcommand
func newGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get <vm-id>",
		Aliases: []string{"inspect", "describe"},
		Short:   "Get virtual machine details",
		Long: `Get detailed information about a virtual machine.

Displays comprehensive information about the specified VM
including configuration, state, resource usage, and networking.

Examples:
  # Get VM details
  platformctl compute get myvm

  # Get VM details with JSON output
  platformctl compute get myvm --output json

  # Get VM details with YAML output
  platformctl compute get myvm --output yaml`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runGet(flags, args[0])
		},
	}

	return cmd
}

// runGet executes the compute get command
func runGet(flags *cli.CommonFlags, vmID string) error {
	if vmID == "" {
		return ErrInvalidVMConfig{Field: "id", Reason: "VM ID is required"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().Compute()
	if grpcClient == nil {
		return ErrComputeClientNotInitialized{}
	}

	sdkClient := computesvc.NewClientFromGRPC(grpcClient)

	ctx := base.Context()
	vm, err := sdkClient.GetVMDomain(ctx, vmID)
	if err != nil {
		return ErrVMNotFound{ID: vmID}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(vm)

	case cli.OutputFormatTable:
		return printFullVMDetails(printer, vm)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printFullVMDetails prints comprehensive VM details
func printFullVMDetails(printer *cli.Printer, vm *computesvc.VM) error {
	if vm == nil {
		return nil
	}

	// VM Information
	printer.PrintInfo("VM Information")
	printer.PrintKeyValue("ID", vm.ID)

	if vm.Config != nil {
		printer.PrintKeyValue("Name", vm.Config.Name)
		if vm.Config.Description != "" {
			printer.PrintKeyValue("Description", vm.Config.Description)
		}
	}

	printer.PrintKeyValue("State", formatVMState(vm.State))

	if vm.HostID != "" {
		printer.PrintKeyValue("Host ID", vm.HostID)
	}

	if !vm.CreatedAt.IsZero() {
		printer.PrintKeyValue("Created", formatTimestamp(vm.CreatedAt))
	}
	if !vm.UpdatedAt.IsZero() {
		printer.PrintKeyValue("Updated", formatTimestamp(vm.UpdatedAt))
	}

	if vm.Config != nil {
		// Configuration
		fmt.Println()
		printer.PrintInfo("Configuration")
		printer.PrintKeyValue("Firmware", formatFirmwareType(vm.Config.Firmware))
		printer.PrintKeyValue("Secure Boot", formatBool(vm.Config.SecureBoot))
		if vm.Config.TPM != nil {
			printer.PrintKeyValue("vTPM", formatBool(vm.Config.TPM.Enabled))
			if vm.Config.TPM.Emulated {
				printer.PrintKeyValue("vTPM Type", "Emulated")
			}
		}

		// CPU
		if vm.Config.CPU != nil {
			fmt.Println()
			printer.PrintInfo("CPU")
			printer.PrintKeyValue("Cores", fmt.Sprintf("%d", vm.Config.CPU.Cores))
			if vm.Config.CPU.Sockets > 0 {
				printer.PrintKeyValue("Sockets", fmt.Sprintf("%d", vm.Config.CPU.Sockets))
			}
			if vm.Config.CPU.Threads > 0 {
				printer.PrintKeyValue("Threads", fmt.Sprintf("%d", vm.Config.CPU.Threads))
			}
			if vm.Config.CPU.Model != "" {
				printer.PrintKeyValue("Model", vm.Config.CPU.Model)
			}
			if len(vm.Config.CPU.Features) > 0 {
				printer.PrintKeyValue("Features", strings.Join(vm.Config.CPU.Features, ", "))
			}
		}

		// Memory
		if vm.Config.Memory != nil {
			fmt.Println()
			printer.PrintInfo("Memory")
			printer.PrintKeyValue("Size", fmt.Sprintf("%d MB", vm.Config.Memory.SizeMB))
			printer.PrintKeyValue("Hugepages", formatBool(vm.Config.Memory.Hugepages))
			printer.PrintKeyValue("Shared", formatBool(vm.Config.Memory.Shared))
		}

		// Disks
		if len(vm.Config.Disks) > 0 {
			fmt.Println()
			printer.PrintInfo("Disks")
			for i, disk := range vm.Config.Disks {
				prefix := fmt.Sprintf("  Disk %d", i)
				if disk.ID != "" {
					printer.PrintKeyValue(prefix+" ID", disk.ID)
				}
				printer.PrintKeyValue(prefix+" Size", fmt.Sprintf("%d GB", disk.SizeGB))
				printer.PrintKeyValue(prefix+" Type", string(disk.Type))
				printer.PrintKeyValue(prefix+" Bus", string(disk.Bus))
				printer.PrintKeyValue(prefix+" Bootable", formatBool(disk.Bootable))
				if disk.Path != "" {
					printer.PrintKeyValue(prefix+" Path", disk.Path)
				}
			}
		}

		// Networks
		if len(vm.Config.Networks) > 0 {
			fmt.Println()
			printer.PrintInfo("Networks")
			for i, net := range vm.Config.Networks {
				prefix := fmt.Sprintf("  NIC %d", i)
				if net.ID != "" {
					printer.PrintKeyValue(prefix+" ID", net.ID)
				}
				if net.Bridge != "" {
					printer.PrintKeyValue(prefix+" Bridge", net.Bridge)
				}
				if net.MACAddress != "" {
					printer.PrintKeyValue(prefix+" MAC", net.MACAddress)
				}
				if net.VLAN > 0 {
					printer.PrintKeyValue(prefix+" VLAN", fmt.Sprintf("%d", net.VLAN))
				}
				printer.PrintKeyValue(prefix+" Model", string(net.Model))
				if net.BandwidthLimitMbps > 0 {
					printer.PrintKeyValue(prefix+" Bandwidth Limit", fmt.Sprintf("%d Mbps", net.BandwidthLimitMbps))
				}
			}
		}

		// Labels
		if len(vm.Config.Labels) > 0 {
			fmt.Println()
			printer.PrintInfo("Labels")
			for key, value := range vm.Config.Labels {
				printer.PrintKeyValue(fmt.Sprintf("  %s", key), value)
			}
		}

		// Metadata
		if len(vm.Config.Metadata) > 0 {
			fmt.Println()
			printer.PrintInfo("Metadata")
			for key, value := range vm.Config.Metadata {
				printer.PrintKeyValue(fmt.Sprintf("  %s", key), value)
			}
		}
	}

	// Metrics
	if vm.Metrics != nil {
		fmt.Println()
		printer.PrintInfo("Metrics")
		printer.PrintKeyValue("  CPU Usage", fmt.Sprintf("%.2f%%", vm.Metrics.CPUUsagePercent))
		printer.PrintKeyValue("  Memory Used", fmt.Sprintf("%d MB", vm.Metrics.MemoryUsedMB))
		if vm.Metrics.MemoryAvailableMB > 0 {
			printer.PrintKeyValue("  Memory Available", fmt.Sprintf("%d MB", vm.Metrics.MemoryAvailableMB))
		}
		printer.PrintKeyValue("  Disk Read", formatBytes(vm.Metrics.DiskReadBytes))
		printer.PrintKeyValue("  Disk Write", formatBytes(vm.Metrics.DiskWriteBytes))
		printer.PrintKeyValue("  Network RX", formatBytes(vm.Metrics.NetworkRxBytes))
		printer.PrintKeyValue("  Network TX", formatBytes(vm.Metrics.NetworkTxBytes))
		if vm.Metrics.UptimeSeconds > 0 {
			printer.PrintKeyValue("  Uptime", formatDuration(vm.Metrics.UptimeSeconds))
		}
	}

	return nil
}
