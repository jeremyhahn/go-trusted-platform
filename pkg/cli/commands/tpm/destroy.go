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

// newDestroyCommand creates the destroy subcommand for platform destruction
func newDestroyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "destroy",
		Short: "Destroy the platform and clear TPM",
		Long: `This command deletes all platform data, including TPM keys,
Certificate Authority keys, certificates, secrets, and blob storage.

A TPM2_Clear command is sent to the TPM, restoring it to the TPM
manufacturer and OEM factory settings.

WARNING: This operation is destructive and cannot be undone!

Examples:
  # Destroy platform (requires confirmation)
  platformctl tpm destroy --confirm

  # Destroy with lockout password
  platformctl tpm destroy --lockout-password mypassword --confirm`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrDaemonConnectionRequired{Operation: "destroy"}
		},
	}

	return cmd
}
