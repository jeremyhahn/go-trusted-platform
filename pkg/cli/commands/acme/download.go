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

// newDownloadCommand creates the download subcommand for fetching certificates
func newDownloadCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download <certificate-url>",
		Short: "Download a certificate from the ACME server",
		Long: `Fetch certificates from the ACME server using a certificate URL.

The certificate URL is typically obtained after completing the ACME
certificate issuance flow. This command retrieves the certificate
chain from the ACME server.

Examples:
  # Download certificate by URL
  platformctl acme download https://acme-server/acme/cert/abc123

  # Download and output as JSON
  platformctl acme download https://acme-server/acme/cert/abc123 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			certURL := args[0]
			return runDownload(flags, certURL)
		},
	}

	return cmd
}

// runDownload executes the download command
func runDownload(flags *cli.CommonFlags, certURL string) error {
	// Daemon connection required for ACME operations
	// Dual-mode support will be added later
	return ErrDaemonConnectionRequired{Command: "download"}
}
