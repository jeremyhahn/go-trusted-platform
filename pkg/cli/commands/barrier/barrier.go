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

// Package barrier provides CLI commands for barrier storage management.
// The barrier protects sensitive platform data at rest using encryption,
// supporting both single-key and Shamir secret sharing unseal strategies.
package barrier

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the barrier root command for barrier storage management
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "barrier",
		Short: "Barrier storage management",
		Long: `Manage the platform barrier storage that protects sensitive data at rest.

The barrier subsystem provides:
  - Initialization with single-key or Shamir secret sharing
  - Seal/unseal operations to protect and access encrypted data
  - Status monitoring of the barrier state
  - Rekeying to rotate unseal credentials

Examples:
  # Initialize barrier with single key
  platformctl barrier init --secret "my-secret-key"

  # Initialize barrier with Shamir secret sharing (3-of-5)
  platformctl barrier init --threshold 3 --shares 5

  # Check barrier status
  platformctl barrier status

  # Unseal with single key
  platformctl barrier unseal --secret "my-secret-key"

  # Unseal with Shamir share
  platformctl barrier unseal --share "shamir-share-1"

  # Seal the barrier
  platformctl barrier seal

  # Rekey with new Shamir parameters
  platformctl barrier rekey --threshold 3 --shares 5`,
	}

	cmd.AddCommand(newInitCommand(getFlags))
	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newUnsealCommand(getFlags))
	cmd.AddCommand(newSealCommand(getFlags))
	cmd.AddCommand(newRekeyCommand(getFlags))

	return cmd
}
