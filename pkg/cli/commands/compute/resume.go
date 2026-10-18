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

// resumeVerb sends ResumeVM.
var resumeVerb = vmVerb{
	operation: "resume",
	done:      "resumed",
	call: func(ctx context.Context, client *computesvc.Client, id string) (*computesvc.VMStatus, error) {
		return client.ResumeVMDomain(ctx, id)
	},
}

// newResumeCommand creates the compute resume subcommand
func newResumeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "resume <vm-id>",
		Short: "Resume a suspended virtual machine",
		Long: `Continue a virtual machine that was suspended.

The VM must be suspended.

Examples:
  # Resume a VM
  platformctl compute resume myvm

  # Resume VM with JSON output
  platformctl compute resume myvm --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVMVerb(getFlags(), args[0], resumeVerb)
		},
	}
}
