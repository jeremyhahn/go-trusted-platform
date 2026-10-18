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

// suspendVerb sends SuspendVM.
var suspendVerb = vmVerb{
	operation: "suspend",
	done:      "suspended",
	call: func(ctx context.Context, client *computesvc.Client, id string) (*computesvc.VMStatus, error) {
		return client.SuspendVMDomain(ctx, id)
	},
}

// newSuspendCommand creates the compute suspend subcommand
func newSuspendCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "suspend <vm-id>",
		Short: "Suspend a running virtual machine",
		Long: `Pause a running virtual machine in memory.

The VM keeps its memory and devices but stops executing until it is
resumed. The VM must be running.

Examples:
  # Suspend a VM
  platformctl compute suspend myvm

  # Suspend VM with JSON output
  platformctl compute suspend myvm --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVMVerb(getFlags(), args[0], suspendVerb)
		},
	}
}
