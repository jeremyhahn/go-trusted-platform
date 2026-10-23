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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
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

The VM receives an ACPI shutdown request and is given --timeout seconds
to power down; if it is still running then, it is terminated. A timeout
of 0 takes the daemon's default (30 seconds); the maximum is 3600.

--force kills the VM at once without asking the guest, so it cannot be
combined with --timeout.

Examples:
  # Stop a VM with the default timeout
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
	cmd.Flags().Uint32VarP(&opts.timeout, "timeout", "t", 0, "seconds the guest gets to shut down (0 = daemon default)")

	return cmd
}

// runStop executes the compute stop command
func runStop(flags *cli.CommonFlags, vmID string, opts *stopOptions) error {
	return runVMVerb(flags, vmID, vmVerb{
		operation: "stop",
		done:      "stopped",
		call: func(ctx context.Context, client *computesvc.Client, id string) (*computesvc.VMStatus, error) {
			return client.StopVMDomain(ctx, &computesvc.StopVMParams{
				ID:             id,
				Force:          opts.force,
				TimeoutSeconds: opts.timeout,
			})
		},
	})
}
