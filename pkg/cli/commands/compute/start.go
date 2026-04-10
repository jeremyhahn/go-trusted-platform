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

// newStartCommand creates the compute start subcommand
func newStartCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start <vm-id>",
		Short: "Start a virtual machine",
		Long: `Start a stopped virtual machine.

The VM must exist and be in a stopped state.

Examples:
  # Start a VM by name
  platformctl compute start myvm

  # Start a VM by ID
  platformctl compute start abc123def456

  # Start VM with JSON output
  platformctl compute start myvm --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runStart(flags, args[0])
		},
	}

	return cmd
}

// runStart executes the compute start command
func runStart(flags *cli.CommonFlags, vmID string) error {
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

	req := &platformv1.StartVMRequest{
		Id: vmID,
	}

	ctx := base.Context()
	resp, err := client.StartVM(ctx, req)
	if err != nil {
		return ErrVMOperationFailed{Operation: "start", ID: vmID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("VM started successfully: %s", vmID))
		} else if resp.Status != nil {
			printer.PrintError(fmt.Sprintf("Failed to start VM: %s", resp.Status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
