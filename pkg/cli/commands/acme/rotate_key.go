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

package acme

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newRotateKeyCommand creates the rotate-key subcommand for account key rotation
func newRotateKeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate the ACME account key",
		Long: `Perform an account key rollover with the ACME server.

This command generates a new account key and performs the ACME
key rollover operation to update the account with the new key.
The old key is replaced atomically on the server.

WARNING: This operation should be performed carefully. Ensure
you have proper backups before rotating keys.

Examples:
  # Rotate account key
  platformctl acme rotate-key

  # Rotate and output result as JSON
  platformctl acme rotate-key -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRotateKey(flags)
		},
	}

	return cmd
}

// runRotateKey executes the rotate-key command
func runRotateKey(flags *cli.CommonFlags) error {
	// Daemon connection required for ACME operations
	// Dual-mode support will be added later
	return ErrDaemonConnectionRequired{Command: "rotate-key"}
}
