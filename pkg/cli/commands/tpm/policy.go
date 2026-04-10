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

package tpm

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newPolicyCommand creates the policy subcommand for PCR policy operations
func newPolicyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Platform PCR policy operations",
		Long: `Perform platform PCR policy operations.

The policy command manages platform PCR policies that are used to
protect TPM keys and sealed data. PCR policies bind access to the
current platform state.

Available actions:
  - (no args): Display the current platform policy digest hash
  - create: Create a new platform policy
  - session: Start a policy session and display the policy digest

Examples:
  # Display current policy digest
  platformctl tpm policy

  # Create platform policy
  platformctl tpm policy create

  # Start policy session
  platformctl tpm policy session`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrDaemonConnectionRequired{Operation: "policy"}
		},
	}

	return cmd
}
