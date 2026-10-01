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

package authenticode

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newVerifyCommand creates the verify subcommand for verifying Authenticode signatures
func newVerifyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var certPath, input string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an Authenticode signature on a PE/COFF file",
		Long: `Verify the Authenticode/PKCS#7 signature on a PE/COFF executable.
This includes cryptographic verification of the RSA/ECDSA signature.

This command replaces sbverify with native Go implementation.

Examples:
  # Verify a signed file (basic verification)
  platformctl authenticode verify --input signed.efi

  # Verify with specific certificate for trust verification
  platformctl authenticode verify \
    --cert /path/to/cert.pem \
    --input signed.efi

  # Verify and output as JSON
  platformctl authenticode verify --input signed.efi -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runVerify(cmd.Context(), flags, certPath, input)
		},
	}

	cmd.Flags().StringVar(&certPath, "cert", "", "path to signing certificate (PEM) for trust verification (optional)")
	cmd.Flags().StringVar(&input, "input", "", "path to signed PE/COFF file")

	_ = cmd.MarkFlagRequired("input")

	return cmd
}

// runVerify executes the verify command
func runVerify(ctx context.Context, flags *cli.CommonFlags, certPath, input string) error {
	logger := logging.DefaultLogger()
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	// Read certificate if provided (optional for basic verification)
	var cert *x509.Certificate
	if certPath != "" {
		var err error
		if cert, err = authenticode.LoadCertificate(certPath); err != nil {
			return mapCertFileError(certPath, err)
		}
	}

	// Verification needs no key: the signature is checked against the
	// certificate embedded in it, and --cert pins who that must be.
	verifier := authenticode.NewVerifier(ctx, logger)

	// Verify the file
	logger.Info("[AUTHENTICODE] Verifying file", "input", input)
	if err := verifier.VerifyFile(input); err != nil {
		return ErrVerifyFileFailed{Input: input, Reason: err.Error()}
	}
	if cert != nil {
		embedded, err := verifier.ExtractCertificateFile(input)
		if err != nil {
			return ErrVerifyFileFailed{Input: input, Reason: err.Error()}
		}
		if !embedded.Equal(cert) {
			return ErrVerifyFileFailed{Input: input, Reason: "signed by " + embedded.Subject.String() + ", not by " + cert.Subject.String()}
		}
	}

	// Output result
	result := map[string]interface{}{
		"input":    input,
		"verified": true,
		"message":  "signature verification OK",
	}

	if certPath != "" {
		result["certificate"] = certPath
	}

	if flags.OutputFormat == cli.OutputFormatTable {
		printer.PrintSuccess(fmt.Sprintf("Signature verification OK: %s", input))
		return nil
	}

	return printer.Print(result)
}
