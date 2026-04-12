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

// createOptions holds the options for the create command
type createOptions struct {
	name          string
	cpus          uint32
	memory        uint64
	diskSize      uint64
	firmware      string
	secureBoot    bool
	tpm           bool
	bootDevice    string
	networkBridge string
	label         []string
	start         bool
}

// newCreateCommand creates the compute create subcommand
func newCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &createOptions{}

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new virtual machine",
		Long: `Create a new virtual machine with the specified configuration.

The VM is created but not started unless --start is specified.

Examples:
  # Create a basic VM
  platformctl compute create --name myvm --cpus 2 --memory 2048

  # Create a VM with UEFI Secure Boot and vTPM
  platformctl compute create --name myvm --cpus 4 --memory 4096 \
    --firmware uefi-secure-boot --secure-boot --tpm

  # Create a VM with custom disk size
  platformctl compute create --name myvm --disk-size 100

  # Create a VM with network bridge
  platformctl compute create --name myvm --network-bridge br0

  # Create a VM with labels and start immediately
  platformctl compute create --name myvm --label env=production \
    --label team=platform --start`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCreate(flags, opts)
		},
	}

	// Required flags
	cmd.Flags().StringVarP(&opts.name, "name", "n", "", "VM name (required)")

	// Optional flags
	cmd.Flags().Uint32Var(&opts.cpus, "cpus", 2, "number of CPU cores")
	cmd.Flags().Uint64Var(&opts.memory, "memory", 2048, "memory size in MB")
	cmd.Flags().Uint64Var(&opts.diskSize, "disk-size", 20, "disk size in GB")
	cmd.Flags().StringVar(&opts.firmware, "firmware", "uefi", "firmware type: bios, uefi, uefi-secure-boot")
	cmd.Flags().BoolVar(&opts.secureBoot, "secure-boot", false, "enable UEFI Secure Boot")
	cmd.Flags().BoolVar(&opts.tpm, "tpm", false, "enable virtual TPM (vTPM)")
	cmd.Flags().StringVar(&opts.bootDevice, "boot-device", "disk", "boot device: disk, cdrom, network")
	cmd.Flags().StringVar(&opts.networkBridge, "network-bridge", "", "network bridge name")
	cmd.Flags().StringArrayVarP(&opts.label, "label", "l", nil, "labels (key=value)")
	cmd.Flags().BoolVar(&opts.start, "start", false, "start VM immediately after creation")

	// Mark required flags
	if err := cmd.MarkFlagRequired("name"); err != nil {
		return nil
	}

	return cmd
}

// runCreate executes the compute create command
func runCreate(flags *cli.CommonFlags, opts *createOptions) error {
	if opts.name == "" {
		return ErrInvalidVMConfig{Field: "name", Reason: "name is required"}
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

	// Parse labels
	labels := make(map[string]string)
	for _, l := range opts.label {
		parts := strings.SplitN(l, "=", 2)
		if len(parts) != 2 {
			return ErrInvalidVMConfig{Field: "label", Reason: "expected key=value"}
		}
		labels[parts[0]] = parts[1]
	}

	// Map firmware string to domain type
	fw, ok := computesvc.StringToFirmwareType[strings.ToLower(opts.firmware)]
	if !ok {
		return ErrInvalidVMConfig{Field: "firmware", Reason: "must be bios, uefi, or uefi-secure-boot"}
	}

	// Map boot device string to domain type
	bd, ok := computesvc.StringToBootDevice[strings.ToLower(opts.bootDevice)]
	if !ok {
		return ErrInvalidVMConfig{Field: "boot-device", Reason: "must be disk, cdrom, or network"}
	}

	params := &computesvc.CreateVMParams{
		Name:          opts.name,
		Firmware:      fw,
		BootDevice:    bd,
		CPUs:          opts.cpus,
		MemoryMB:      opts.memory,
		DiskSizeGB:    opts.diskSize,
		SecureBoot:    opts.secureBoot,
		TPM:           opts.tpm,
		Start:         opts.start,
		NetworkBridge: opts.networkBridge,
		Labels:        labels,
	}

	ctx := base.Context()
	vm, err := sdkClient.CreateVMDomain(ctx, params)
	if err != nil {
		return ErrVMOperationFailed{Operation: "create", ID: opts.name, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(vm)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("VM created successfully: %s", vm.ID))
		fmt.Println()
		printVMDetails(printer, vm)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printVMDetails prints basic VM details in a formatted way
func printVMDetails(printer *cli.Printer, vm *computesvc.VM) {
	if vm == nil {
		return
	}

	printer.PrintKeyValue("ID", vm.ID)
	if vm.Config != nil {
		printer.PrintKeyValue("Name", vm.Config.Name)
		printer.PrintKeyValue("Firmware", formatFirmwareType(vm.Config.Firmware))
		if vm.Config.CPU != nil {
			printer.PrintKeyValue("CPUs", fmt.Sprintf("%d", vm.Config.CPU.Cores))
		}
		if vm.Config.Memory != nil {
			printer.PrintKeyValue("Memory", fmt.Sprintf("%d MB", vm.Config.Memory.SizeMB))
		}
		if len(vm.Config.Disks) > 0 {
			printer.PrintKeyValue("Disk", fmt.Sprintf("%d GB", vm.Config.Disks[0].SizeGB))
		}
		printer.PrintKeyValue("Secure Boot", formatBool(vm.Config.SecureBoot))
		if vm.Config.TPM != nil {
			printer.PrintKeyValue("vTPM", formatBool(vm.Config.TPM.Enabled))
		}
	}
	printer.PrintKeyValue("State", formatVMState(vm.State))
	printer.PrintKeyValue("Created", formatTimestamp(vm.CreatedAt))
}
