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

// newRegisterCommand creates the register subcommand for ACME account registration
func newRegisterCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var email string

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new ACME account",
		Long: `Register a new account with the ACME server.

This command creates a new ACME account using the configured
account key. The account is required before requesting certificates.

Examples:
  # Register with email contact
  platformctl acme register --email admin@example.com

  # Register and output as JSON
  platformctl acme register --email admin@example.com -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRegister(flags, email)
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "account email address for contact")

	return cmd
}

// runRegister executes the register command
func runRegister(flags *cli.CommonFlags, email string) error {
	// Daemon connection required for ACME operations
	// Dual-mode support will be added later
	return ErrDaemonConnectionRequired{Command: "register"}
}
