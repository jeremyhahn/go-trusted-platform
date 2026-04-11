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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// diskBusToString maps DiskBus enum values to human-readable strings
var diskBusToString = map[platformv1.DiskBus]string{
	platformv1.DiskBus_DISK_BUS_IDE:    "IDE",
	platformv1.DiskBus_DISK_BUS_SATA:   "SATA",
	platformv1.DiskBus_DISK_BUS_SCSI:   "SCSI",
	platformv1.DiskBus_DISK_BUS_VIRTIO: "VirtIO",
	platformv1.DiskBus_DISK_BUS_NVME:   "NVMe",
}

// diskTypeToString maps DiskType enum values to human-readable strings
var diskTypeToString = map[platformv1.DiskType]string{
	platformv1.DiskType_DISK_TYPE_RAW:   "RAW",
	platformv1.DiskType_DISK_TYPE_QCOW2: "QCOW2",
	platformv1.DiskType_DISK_TYPE_VDI:   "VDI",
	platformv1.DiskType_DISK_TYPE_VMDK:  "VMDK",
}

// networkModelToString maps NetworkModel enum values to human-readable strings
var networkModelToString = map[platformv1.NetworkModel]string{
	platformv1.NetworkModel_NETWORK_MODEL_E1000:   "e1000",
	platformv1.NetworkModel_NETWORK_MODEL_VIRTIO:  "virtio",
	platformv1.NetworkModel_NETWORK_MODEL_RTL8139: "rtl8139",
}

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

	client := base.Client().Compute()
	if client == nil {
		return ErrComputeClientNotInitialized{}
	}

	req := &platformv1.GetVMRequest{
		Id: vmID,
	}

	ctx := base.Context()
	resp, err := client.GetVM(ctx, req)
	if err != nil {
		return ErrVMNotFound{ID: vmID}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp.Vm)

	case cli.OutputFormatTable:
		return printFullVMDetails(printer, resp.Vm)

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printFullVMDetails prints comprehensive VM details
func printFullVMDetails(printer *cli.Printer, vm *platformv1.VM) error {
	if vm == nil {
		return nil
	}

	// VM Information
	printer.PrintInfo("VM Information")
	printer.PrintKeyValue("ID", vm.Id)

	if vm.Config != nil {
		printer.PrintKeyValue("Name", vm.Config.Name)
		if vm.Config.Description != "" {
			printer.PrintKeyValue("Description", vm.Config.Description)
		}
	}

	printer.PrintKeyValue("State", formatVMState(computesvc.VMStateFromProto(vm.State)))

	if vm.HostId != "" {
		printer.PrintKeyValue("Host ID", vm.HostId)
	}

	if vm.CreatedAt != nil {
		printer.PrintKeyValue("Created", formatTimestamp(vm.CreatedAt.AsTime()))
	}
	if vm.UpdatedAt != nil {
		printer.PrintKeyValue("Updated", formatTimestamp(vm.UpdatedAt.AsTime()))
	}

	if vm.Config != nil {
		// Configuration
		fmt.Println()
		printer.PrintInfo("Configuration")
		printer.PrintKeyValue("Firmware", formatFirmwareType(computesvc.FirmwareTypeFromProto(vm.Config.Firmware)))
		printer.PrintKeyValue("Secure Boot", formatBool(vm.Config.SecureBoot))
		if vm.Config.Tpm != nil {
			printer.PrintKeyValue("vTPM", formatBool(vm.Config.Tpm.Enabled))
			if vm.Config.Tpm.Emulated {
				printer.PrintKeyValue("vTPM Type", "Emulated")
			}
		}

		// CPU
		if vm.Config.Cpu != nil {
			fmt.Println()
			printer.PrintInfo("CPU")
			printer.PrintKeyValue("Cores", fmt.Sprintf("%d", vm.Config.Cpu.Cores))
			if vm.Config.Cpu.Sockets > 0 {
				printer.PrintKeyValue("Sockets", fmt.Sprintf("%d", vm.Config.Cpu.Sockets))
			}
			if vm.Config.Cpu.Threads > 0 {
				printer.PrintKeyValue("Threads", fmt.Sprintf("%d", vm.Config.Cpu.Threads))
			}
			if vm.Config.Cpu.Model != "" {
				printer.PrintKeyValue("Model", vm.Config.Cpu.Model)
			}
			if len(vm.Config.Cpu.Features) > 0 {
				printer.PrintKeyValue("Features", strings.Join(vm.Config.Cpu.Features, ", "))
			}
		}

		// Memory
		if vm.Config.Memory != nil {
			fmt.Println()
			printer.PrintInfo("Memory")
			printer.PrintKeyValue("Size", fmt.Sprintf("%d MB", vm.Config.Memory.SizeMb))
			printer.PrintKeyValue("Hugepages", formatBool(vm.Config.Memory.Hugepages))
			printer.PrintKeyValue("Shared", formatBool(vm.Config.Memory.Shared))
		}

		// Disks
		if len(vm.Config.Disks) > 0 {
			fmt.Println()
			printer.PrintInfo("Disks")
			for i, disk := range vm.Config.Disks {
				prefix := fmt.Sprintf("  Disk %d", i)
				if disk.Id != "" {
					printer.PrintKeyValue(prefix+" ID", disk.Id)
				}
				printer.PrintKeyValue(prefix+" Size", fmt.Sprintf("%d GB", disk.SizeGb))
				if t, ok := diskTypeToString[disk.Type]; ok {
					printer.PrintKeyValue(prefix+" Type", t)
				}
				if b, ok := diskBusToString[disk.Bus]; ok {
					printer.PrintKeyValue(prefix+" Bus", b)
				}
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
				if net.Id != "" {
					printer.PrintKeyValue(prefix+" ID", net.Id)
				}
				if net.Bridge != "" {
					printer.PrintKeyValue(prefix+" Bridge", net.Bridge)
				}
				if net.MacAddress != "" {
					printer.PrintKeyValue(prefix+" MAC", net.MacAddress)
				}
				if net.Vlan > 0 {
					printer.PrintKeyValue(prefix+" VLAN", fmt.Sprintf("%d", net.Vlan))
				}
				if m, ok := networkModelToString[net.Model]; ok {
					printer.PrintKeyValue(prefix+" Model", m)
				}
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
		printer.PrintKeyValue("  CPU Usage", fmt.Sprintf("%.2f%%", vm.Metrics.CpuUsagePercent))
		printer.PrintKeyValue("  Memory Used", fmt.Sprintf("%d MB", vm.Metrics.MemoryUsedMb))
		if vm.Metrics.MemoryAvailableMb > 0 {
			printer.PrintKeyValue("  Memory Available", fmt.Sprintf("%d MB", vm.Metrics.MemoryAvailableMb))
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
