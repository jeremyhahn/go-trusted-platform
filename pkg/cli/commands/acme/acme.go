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

// Package acme provides CLI commands for ACME certificate management operations
// including account registration, certificate renewal, and key rotation.
package acme

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the acme root command for ACME certificate operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acme",
		Short: "ACME certificate management",
		Long: `Performs x509 certificate management operations using the Automated
Certificate Management Environment (ACME) client.

The ACME subsystem provides certificate lifecycle management:
  - Account registration with ACME servers
  - Certificate renewal and issuance
  - Account key rotation
  - Certificate download from ACME servers

Examples:
  # Register an ACME account
  platformctl acme register --email admin@example.com

  # Request/renew a certificate
  platformctl acme renew --cn example.com --sans-dns www.example.com

  # Download a certificate by URL
  platformctl acme download https://acme-server/acme/cert/abc123

  # Rotate account key
  platformctl acme rotate-key`,
	}

	// Add subcommands
	cmd.AddCommand(newDownloadCommand(getFlags))
	cmd.AddCommand(newRegisterCommand(getFlags))
	cmd.AddCommand(newRenewCommand(getFlags))
	cmd.AddCommand(newRotateKeyCommand(getFlags))

	return cmd
}
