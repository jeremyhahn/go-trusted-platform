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

// Package ceremony provides CLI commands for the platform ceremony service.
// It mirrors the "qrdb ceremony" subcommand surface and covers barrier
// initialization, officer enrollment, share claims, and CSR signing.
package ceremony

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the ceremony root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ceremony",
		Short: "Ceremony operations for barrier initialization and officer enrollment",
		Long: `Manage the platform ceremony that initializes the barrier and enrolls officers.

The ceremony subsystem provides:
  - Initial barrier bootstrap (Shamir n-of-m)
  - Officer claim-cert challenge / response (PIV, FIDO2, software)
  - Shamir share distribution
  - Security Officer CSR signing

Examples:
  # Initialize a ceremony with a 3-of-5 Shamir quorum
  platformctl ceremony init --so-pin 123456 --threshold 3-of-5 --hostname cp-01

  # Check current ceremony status
  platformctl ceremony status

  # Begin officer PIV enrollment
  platformctl ceremony claim-cert begin --username alice \
      --authenticator-type piv --slot 9a

  # Begin officer FIDO2 enrollment
  platformctl ceremony claim-cert begin --username alice \
      --authenticator-type fido2 --credential-id <credID>

  # Complete claim-cert after signing the nonce
  platformctl ceremony claim-cert complete --username alice \
      --nonce <nonce> --signature <sig>

  # Claim the caller's Shamir share
  platformctl ceremony claim-share --username alice

  # Sign a CSR with the ceremony CA
  platformctl ceremony sign-csr --username alice --so-pin 123456 \
      --csr-file ./alice.csr --role admin`,
	}

	cmd.AddCommand(newInitCommand(getFlags))
	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newClaimCertCommand(getFlags))
	cmd.AddCommand(newClaimShareCommand(getFlags))
	cmd.AddCommand(newSignCSRCommand(getFlags))

	return cmd
}
