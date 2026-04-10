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

// newInstallCommand creates the install subcommand for safe TPM provisioning
func newInstallCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Safely provision the platform",
		Long: `Perform a modified version of the TCG recommended provisioning
guidance procedure, intended for platforms with a pre-provisioned TPM, either
from the TPM Manufacturer or Owner.

Instead of clearing the hierarchies, setting hierarchy authorizations and
provisioning new keys and certificates from scratch, this operation will use
pre-existing EK, Shared SRK and IAK keys and certificates if they already exist.

The Security Officer PIN is required and used as Endorsement and Storage
hierarchy authorization values during installation. This operation is safe
and idempotent, and will not modify or destroy existing data.

Examples:
  # Safe install with default settings
  platformctl tpm install

  # Install with explicit SO PIN
  platformctl tpm install --so-pin mypin`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrDaemonConnectionRequired{Operation: "install"}
		},
	}

	return cmd
}
