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

	grpcClient := base.Client().Compute()
	if grpcClient == nil {
		return ErrComputeClientNotInitialized{}
	}

	sdkClient := computesvc.NewClientFromGRPC(grpcClient)

	ctx := base.Context()
	status, err := sdkClient.StartVMDomain(ctx, vmID)
	if err != nil {
		return ErrVMOperationFailed{Operation: "start", ID: vmID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("VM started successfully: %s", vmID))
		} else if status != nil {
			printer.PrintError(fmt.Sprintf("Failed to start VM: %s", status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
