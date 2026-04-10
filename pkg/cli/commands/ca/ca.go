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

// Package ca provides CLI commands for Certificate Authority operations
// including certificate issuance, revocation, renewal, and management.
package ca

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NewCommand creates the ca root command for Certificate Authority operations
func NewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Certificate Authority operations",
		Long: `Manage Certificate Authority and x509 certificates.

The CA subsystem provides certificate lifecycle management:
  - Initialize the Certificate Authority
  - Issue new certificates
  - Revoke existing certificates
  - Renew expiring certificates
  - List and verify certificates
  - Manage Certificate Revocation Lists (CRL)
  - Export CA bundles for distribution

Examples:
  # Initialize the Certificate Authority
  platformctl ca init

  # Display CA information
  platformctl ca info

  # Issue a new certificate
  platformctl ca issue example.com pkcs8 ECDSA-P256

  # List all certificates
  platformctl ca list

  # Verify a certificate
  platformctl ca verify /path/to/cert.pem

  # Revoke a certificate
  platformctl ca revoke example.com pkcs8 ECDSA-P256

  # Display CRL information
  platformctl ca crl

  # Export CA bundle
  platformctl ca export-bundle -o /path/to/ca-bundle.pem`,
	}

	// Add subcommands
	cmd.AddCommand(newInitCommand(getFlags))
	cmd.AddCommand(newInfoCommand(getFlags))
	cmd.AddCommand(newIssueCommand(getFlags))
	cmd.AddCommand(newCertificateCommand(getFlags))
	cmd.AddCommand(newListCommand(getFlags))
	cmd.AddCommand(newVerifyCommand(getFlags))
	cmd.AddCommand(newRevokeCommand(getFlags))
	cmd.AddCommand(newRenewCommand(getFlags))
	cmd.AddCommand(newCRLCommand(getFlags))
	cmd.AddCommand(newExportBundleCommand(getFlags))
	cmd.AddCommand(newInstallCommand(getFlags))
	cmd.AddCommand(newUninstallCommand(getFlags))

	return cmd
}
