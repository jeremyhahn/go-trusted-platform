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

package ca

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newVerifyCommand creates the verify subcommand for certificate verification
func newVerifyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		checkCRL    bool
		checkExpiry bool
	)

	cmd := &cobra.Command{
		Use:   "verify [cert-path]",
		Short: "Verify a certificate",
		Long: `Verify a certificate against the Certificate Authority trust chain.

Verification checks:
  - Certificate signature against CA chain
  - Expiration status (optional)
  - Revocation status via CRL (optional)

Examples:
  # Verify certificate by file path
  platformctl ca verify /path/to/certificate.pem

  # Verify with CRL check disabled
  platformctl ca verify /path/to/cert.pem --crl=false

  # Verify without expiration check
  platformctl ca verify /path/to/cert.pem --expiry=false

  # Output in JSON format
  platformctl ca verify /path/to/cert.pem -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runVerify(flags, args[0], checkCRL, checkExpiry)
		},
	}

	cmd.Flags().BoolVar(&checkCRL, "crl", true, "Check certificate against CRL")
	cmd.Flags().BoolVar(&checkExpiry, "expiry", true, "Check certificate expiration")

	return cmd
}

// runVerify executes the certificate verification command
func runVerify(flags *cli.CommonFlags, certPath string, checkCRL, checkExpiry bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	grpcClient := base.Client().CA()
	if grpcClient == nil {
		return ErrCANotInitialized{}
	}

	sdkClient := casvc.NewClientFromGRPC(grpcClient)

	// Read certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return ErrVerifyCertificateFailed{Reason: fmt.Sprintf("failed to read certificate: %v", err)}
	}

	params := &casvc.VerifyCertificateParams{
		CertificatePEM:   certPEM,
		VerifyRevocation: checkCRL,
		VerifyExpiration: checkExpiry,
	}

	ctx := base.Context()
	result, err := sdkClient.VerifyCertificateDomain(ctx, params)
	if err != nil {
		return ErrVerifyCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		printVerificationResult(printer, result)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printVerificationResult prints the verification result
func printVerificationResult(printer *cli.Printer, result *casvc.VerifyCertificateResult) {
	if result.Valid {
		printer.PrintSuccess("Certificate is valid")
	} else {
		printer.PrintError("Certificate is invalid")
	}

	fmt.Println()

	if len(result.Chain) > 0 {
		printer.PrintInfo("Certificate Chain:")
		for i, cert := range result.Chain {
			fmt.Printf("  [%d] %s\n", i, cert)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Println()
		printer.PrintInfo("Validation Errors:")
		for _, err := range result.Errors {
			fmt.Printf("  - %s\n", err)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println()
		printer.PrintInfo("Warnings:")
		for _, warning := range result.Warnings {
			fmt.Printf("  - %s\n", warning)
		}
	}
}
