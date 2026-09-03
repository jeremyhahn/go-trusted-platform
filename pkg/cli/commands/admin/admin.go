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

// Package admin provides the operator-facing half of the platform-admin
// claim ceremony: proving possession of the firstboot admin credential so
// an authenticator can be enrolled against the system admin identity.
//
// System-level enrollment is certificate-only
// (docs/08-bootstrap-auth-contract.md, amended 2026-09-01). This command
// never issues, redeems or accepts an invitation token; the certificate
// bundle qrdb firstboot wrote on this node is the sole bootstrap anchor.
package admin

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the admin root command.
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Platform administrator identity operations",
		Long: `Claim and inspect the platform's system administrator identity.

Every node comes up with a passwordless, certificate-based ` + "`admin`" + ` user in
the system tenant, created by qrdb first-boot. The credential bundle is
written to <quicbaas data-dir>/admin/{admin.crt,admin.key} — by default
/var/lib/trusted-platform/quicbaas/admin.

"admin claim" proves possession of that bundle to the running daemon and
returns a single-use claim token. Take the token to the console to finish
the ceremony by registering your passkey; from then on you sign in to the
console as the system admin with that authenticator.

The certificate is the ONLY bootstrap anchor for this identity — there is
no invitation path for the system admin. Adding the passkey afterwards is
ordinary auth-factor enrollment on an identity that is already
bootstrapped.

Examples:
  # Claim the local node's admin identity (run on the node)
  platformctl admin claim

  # Claim a remote node, trusting its CA bundle explicitly
  platformctl admin claim --api https://cp.example.com:8443 \
      --bundle /var/lib/trusted-platform/quicbaas/admin \
      --ca /etc/trusted-platform/ca.crt

  # Is this node already claimed?
  platformctl admin claim-status`,
	}

	cmd.AddCommand(newClaimCommand(getFlags))
	cmd.AddCommand(newClaimStatusCommand(getFlags))

	return cmd
}
