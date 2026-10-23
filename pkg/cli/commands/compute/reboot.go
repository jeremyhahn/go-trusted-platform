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

// rebootOptions holds flags for the reboot command
type rebootOptions struct {
	force bool
}

// newRebootCommand creates the compute reboot subcommand
func newRebootCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &rebootOptions{}

	cmd := &cobra.Command{
		Use:   "reboot <vm-id>",
		Short: "Reboot a virtual machine",
		Long: `Reboot a running virtual machine.

The VM is stopped and started again. With --force the VM is
terminated immediately instead of being shut down gracefully.

Examples:
  # Reboot a VM
  platformctl compute reboot myvm

  # Force reboot a VM
  platformctl compute reboot myvm --force

  # Reboot VM with JSON output
  platformctl compute reboot myvm --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runReboot(flags, args[0], opts)
		},
	}

	cmd.Flags().BoolVar(&opts.force, "force", false, "force the VM off instead of shutting it down gracefully")

	return cmd
}

// runReboot executes the reboot command
func runReboot(flags *cli.CommonFlags, vmID string, opts *rebootOptions) error {
	return runVMVerb(flags, vmID, rebootVerb(opts))
}

// rebootVerb sends RebootVM with the command's options.
func rebootVerb(opts *rebootOptions) vmVerb {
	return vmVerb{
		operation: "reboot",
		done:      "rebooted",
		call: func(ctx context.Context, client *computesvc.Client, id string) (*computesvc.VMStatus, error) {
			return client.RebootVMDomain(ctx, id, opts.force)
		},
	}
}
