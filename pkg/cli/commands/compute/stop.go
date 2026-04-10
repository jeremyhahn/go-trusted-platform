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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// stopOptions holds the options for the stop command
type stopOptions struct {
	force   bool
	timeout uint32
}

// newStopCommand creates the compute stop subcommand
func newStopCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &stopOptions{}

	cmd := &cobra.Command{
		Use:   "stop <vm-id>",
		Short: "Stop a running virtual machine",
		Long: `Stop a running virtual machine gracefully.

The VM receives a shutdown signal and is given time to shut down
gracefully. If the VM does not stop within the timeout period,
it will be forcefully terminated when --force is specified.

Examples:
  # Stop a VM with default timeout
  platformctl compute stop myvm

  # Stop a VM with custom timeout (60 seconds)
  platformctl compute stop myvm --timeout 60

  # Force stop a VM immediately
  platformctl compute stop myvm --force

  # Stop VM with JSON output
  platformctl compute stop myvm --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStop(flags, args[0], opts)
		},
	}

	cmd.Flags().BoolVar(&opts.force, "force", false, "force stop the VM immediately")
	cmd.Flags().Uint32VarP(&opts.timeout, "timeout", "t", 30, "seconds to wait before timeout")

	return cmd
}

// runStop executes the compute stop command
func runStop(flags *cli.CommonFlags, vmID string, opts *stopOptions) error {
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

	req := &platformv1.StopVMRequest{
		Id:             vmID,
		Force:          opts.force,
		TimeoutSeconds: opts.timeout,
	}

	ctx := base.Context()
	resp, err := client.StopVM(ctx, req)
	if err != nil {
		return ErrVMOperationFailed{Operation: "stop", ID: vmID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("VM stopped successfully: %s", vmID))
		} else if resp.Status != nil {
			printer.PrintError(fmt.Sprintf("Failed to stop VM: %s", resp.Status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
