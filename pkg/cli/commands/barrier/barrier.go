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

// Package barrier provides CLI commands for the canonical 9-verb
// platformctl barrier surface.
//
// The verb tree is identical across qrdbctl, xkmsctl, quicbaas, and
// platformctl per docs/08-bootstrap-auth-architecture.md §6. Verbs are
// dispatched to quicbaasd through the platform SDK's
// Client.QuicBaaS().Security().Barrier() accessor; platformd still
// exposes a legacy BarrierServiceClient for non-CLI callers that have
// not migrated.
//
// Canonical verb tree:
//
//	barrier status
//	barrier init           --barrier-strategy <none|passphrase|shamir>
//	                       [--passphrase <pass>] [--so-pin <pin>] [--user-pin <pin>]
//	barrier init-shamir    --passphrase <pass> --threshold <N> --total <M>
//	                       [--so-pin <pin>] [--user-pin <pin>]
//	barrier unseal         --passphrase <pass>
//	barrier unseal-shares  --share <s> [--share <s> ...]  |  --shares-file <path|->
//	barrier seal           [-y]                             (no PIN: BarrierSeal carries no request)
//	barrier rekey          [--so-pin <pin>]
//	                       [--threshold <N> --total <M>]    (paired; no secret on the wire)
//	barrier recovery generate --threshold <N> --total <M> [--so-pin <pin>]
//	barrier recovery recover  --share <s> [--share <s> ...]
package barrier

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the barrier root command for the canonical 9-verb
// barrier surface.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "barrier",
		Short: "Barrier storage management",
		Long: `Manage the cryptographic barrier that protects sensitive platform data at rest.

The barrier subsystem provides the canonical 9-verb surface shared by
qrdbctl, xkmsctl, quicbaas, and platformctl:

  status                 Show barrier state
  init                   Initialize with strategy (none|passphrase|shamir)
  init-shamir            Initialize with Shamir secret sharing (M-of-N)
  unseal                 Unseal with a single passphrase
  unseal-shares          Unseal with one or more Shamir shares
  seal                   Seal the barrier
  rekey                  Generate a new master key
  recovery generate      Generate recovery shares
  recovery recover       Unseal with recovery shares

All verbs are dispatched to the QuicBaaS daemon (quicbaasd) via the
platform SDK Client.QuicBaaS().Security().Barrier() surface.`,
	}

	cmd.AddCommand(newStatusCommand(getFlags))
	cmd.AddCommand(newInitCommand(getFlags))
	cmd.AddCommand(newInitShamirCommand(getFlags))
	cmd.AddCommand(newUnsealCommand(getFlags))
	cmd.AddCommand(newUnsealSharesCommand(getFlags))
	cmd.AddCommand(newSealCommand(getFlags))
	cmd.AddCommand(newRekeyCommand(getFlags))
	cmd.AddCommand(newRecoveryCommand(getFlags))

	return cmd
}
