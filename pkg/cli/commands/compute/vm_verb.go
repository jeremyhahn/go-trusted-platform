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
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// vmVerb is one VM lifecycle verb the CLI sends through the SDK compute
// client: start, stop, reboot, suspend or resume.
type vmVerb struct {
	// operation names the verb in errors, e.g. "reboot".
	operation string
	// done is the verb's past tense for the table output, e.g. "rebooted".
	done string
	call func(ctx context.Context, client *computesvc.Client, vmID string) (*computesvc.VMStatus, error)
}

// runVMVerb validates vmID, connects to the daemon and runs verb against it.
func runVMVerb(flags *cli.CommonFlags, vmID string, verb vmVerb) error {
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
	return verb.run(base.Context(), sdkClient, base.Printer(), flags.OutputFormat, vmID)
}

// run sends the verb for vmID and prints the returned status in format.
func (v vmVerb) run(ctx context.Context, client *computesvc.Client, printer *cli.Printer, format cli.OutputFormat, vmID string) error {
	status, err := v.call(ctx, client, vmID)
	if err != nil {
		return ErrVMOperationFailed{Operation: v.operation, ID: vmID, Err: err}
	}

	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(status)

	case cli.OutputFormatTable:
		if status != nil && status.Success {
			printer.PrintSuccess(fmt.Sprintf("VM %s successfully: %s", v.done, vmID))
		} else if status != nil {
			printer.PrintError(fmt.Sprintf("Failed to %s VM: %s", v.operation, status.Message))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}
