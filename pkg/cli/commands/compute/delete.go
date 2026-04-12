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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// deleteOptions holds the options for the delete command
type deleteOptions struct {
	force       bool
	deleteDisks bool
}

// newDeleteCommand creates the compute delete subcommand
func newDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &deleteOptions{}

	cmd := &cobra.Command{
		Use:     "delete <vm-id>",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a virtual machine",
		Long: `Delete a virtual machine from the system.

By default, only stopped VMs can be deleted. The VM's disk images
are preserved unless --delete-disks is specified.

Examples:
  # Delete a stopped VM
  platformctl compute delete myvm

  # Force delete a running VM
  platformctl compute delete myvm --force

  # Delete VM and its disk images
  platformctl compute delete myvm --delete-disks

  # Delete VM with JSON output
  platformctl compute delete myvm --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runDelete(flags, args[0], opts)
		},
	}

	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "force delete a running VM")
	cmd.Flags().BoolVar(&opts.deleteDisks, "delete-disks", false, "delete associated disk images")

	return cmd
}

// runDelete executes the compute delete command
func runDelete(flags *cli.CommonFlags, vmID string, opts *deleteOptions) error {
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

	params := &computesvc.DeleteVMParams{
		ID:          vmID,
		DeleteDisks: opts.deleteDisks,
	}

	ctx := base.Context()
	status, err := sdkClient.DeleteVMDomain(ctx, params)
	if err != nil {
		return ErrVMOperationFailed{Operation: "delete", ID: vmID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("VM deleted successfully: %s", vmID))
		} else if status != nil {
			printer.PrintError(fmt.Sprintf("Failed to delete VM: %s", status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
