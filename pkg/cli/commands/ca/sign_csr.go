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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

// signCSROptions are the certificate settings the CA applies to a CSR.
type signCSROptions struct {
	validDays int
	out       string
}

// newSignCSRCommand creates the sign-csr subcommand, which certifies a KMS key
// for code signing from a certificate signing request the KMS signed.
func newSignCSRCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts signCSROptions

	cmd := &cobra.Command{
		Use:   "sign-csr [csr-file]",
		Short: "Certify a KMS key for code signing from its CSR",
		Long: `Certify a KMS key for code signing from a PEM certificate signing request.

The CSR's subject must be only a common name, and that name must be the ID of
an existing KMS key whose public key is the CSR's key; subject alternative
names, O, OU and every other subject field are refused. The certificate's
extended key usage is codeSigning and nothing else, whatever the CSR asks
for. No key is generated and none leaves the KMS. Create the CSR with
'platformctl kms key csr'.

Signing a CSR needs the ca:sign-csr scope, which ca:write does not grant.

The certificate PEM is written to --out, or to stdout when --out is not set.

Examples:
  # Certify the fleet signing key held by the KMS
  platformctl kms key csr rpi/fleet --out fleet.csr
  platformctl ca sign-csr fleet.csr --out fleet.pem`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSignCSR(getFlags(), args[0], opts)
		},
	}

	cmd.Flags().IntVar(&opts.validDays, "valid-days", 365, "Certificate validity period in days")
	cmd.Flags().StringVar(&opts.out, "out", "", "Write the certificate PEM to this file instead of stdout")

	return cmd
}

// runSignCSR executes the sign-csr command.
func runSignCSR(flags *cli.CommonFlags, csrFile string, opts signCSROptions) error {
	csrPEM, err := os.ReadFile(csrFile)
	if err != nil {
		return ErrReadCSRFailed{Path: csrFile, Reason: err.Error()}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	grpcClient := base.Client().CA()
	if grpcClient == nil {
		return ErrCANotInitialized{}
	}

	result, err := signCSR(base.Context(), casvc.NewClientFromGRPC(grpcClient), csrPEM, opts)
	if err != nil {
		return err
	}
	return printSignedCSR(base.Printer(), flags.OutputFormat, result, opts.out)
}

// signCSR asks the CA to certify, for code signing, the KMS key in csrPEM.
func signCSR(ctx context.Context, client *casvc.Client, csrPEM []byte, opts signCSROptions) (*casvc.IssueCertificateResult, error) {
	result, err := client.SignCSRDomain(ctx, &casvc.SignCSRParams{
		CSRPEM:    string(csrPEM),
		ValidDays: int32(opts.validDays),
	})
	if err != nil {
		return nil, ErrIssueCertificateFailed{Reason: err.Error()}
	}
	if result.Certificate == nil || len(result.Certificate.Pem) == 0 {
		return nil, ErrNoCertificateIssued{}
	}
	return result, nil
}

// printSignedCSR writes the certificate PEM to out, or to the printer when
// out is empty, and reports the certificate in the requested format — JSON
// and YAML print the result the way 'ca issue' does.
func printSignedCSR(printer *cli.Printer, format cli.OutputFormat, result *casvc.IssueCertificateResult, out string) error {
	cert := result.Certificate
	if out != "" {
		if err := os.WriteFile(out, cert.Pem, 0o644); err != nil {
			return ErrWriteCertificateFailed{Path: out, Reason: err.Error()}
		}
	}

	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if out == "" {
			printer.Println(strings.TrimRight(string(cert.Pem), "\n"))
			return nil
		}
		printer.PrintSuccess(fmt.Sprintf("Certificate written to %s: %s", out, cert.Serial))
		printCertificateDetails(printer, cert)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}
