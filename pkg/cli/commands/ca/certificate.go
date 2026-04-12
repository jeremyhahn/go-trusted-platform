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

	"github.com/spf13/cobra"

	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newCertificateCommand creates the certificate subcommand for certificate operations
func newCertificateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		pem bool
		der bool
	)

	cmd := &cobra.Command{
		Use:   "certificate [serial]",
		Short: "Retrieve an x509 certificate by serial number",
		Long: `Retrieve an x509 certificate from the Certificate Authority by serial number.

Arguments:
  serial - Serial number of the certificate to retrieve

Examples:
  # Get certificate details
  platformctl ca certificate 1234567890ABCDEF

  # Get certificate in PEM format
  platformctl ca certificate 1234567890ABCDEF --pem

  # Get certificate as JSON
  platformctl ca certificate 1234567890ABCDEF -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCertificate(flags, args[0], pem, der)
		},
	}

	cmd.Flags().BoolVar(&pem, "pem", false, "Display the x509 certificate in PEM format")
	cmd.Flags().BoolVar(&der, "der", false, "Include DER-encoded certificate in output")

	return cmd
}

// runCertificate executes the certificate retrieval command
func runCertificate(flags *cli.CommonFlags, serial string, includePem, includeDer bool) error {
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
	ctx := base.Context()

	params := &casvc.GetCertificateParams{
		Serial:     serial,
		IncludePEM: includePem || flags.OutputFormat == cli.OutputFormatTable,
		IncludeDER: includeDer,
	}

	cert, err := sdkClient.GetCertificateDomain(ctx, params)
	if err != nil {
		return ErrGetCertificateFailed{Reason: err.Error()}
	}

	if cert == nil {
		return ErrCertificateNotFound{Serial: serial}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(cert)

	case cli.OutputFormatTable:
		if includePem && len(cert.Pem) > 0 {
			fmt.Println(string(cert.Pem))
			return nil
		}
		printCertificateDetails(printer, cert)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
