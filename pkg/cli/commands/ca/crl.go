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

// newCRLCommand creates the crl subcommand for CRL operations
func newCRLCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var includeEntries bool

	cmd := &cobra.Command{
		Use:   "crl",
		Short: "Certificate Revocation List operations",
		Long: `Display and manage the Certificate Revocation List (CRL).

The CRL contains a list of all certificates that have been revoked by the CA.
Clients can use the CRL to check if a certificate is still valid.

Examples:
  # Display current CRL information
  platformctl ca crl

  # Display CRL in JSON format
  platformctl ca crl -o json

  # Include individual revoked certificates
  platformctl ca crl --entries

  # Export CRL to file
  platformctl ca crl export --output /path/to/crl.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCRL(flags, includeEntries)
		},
	}

	cmd.Flags().BoolVar(&includeEntries, "entries", false, "Include individual revoked certificate entries")

	// Add subcommands
	cmd.AddCommand(newCRLExportCommand(getFlags))

	return cmd
}

// runCRL executes the CRL info command
func runCRL(flags *cli.CommonFlags, includeEntries bool) error {
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

	crl, err := sdkClient.GetCRLDomain(ctx, includeEntries)
	if err != nil {
		return ErrGetCRLFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(crl)

	case cli.OutputFormatTable:
		printCRLDetails(printer, crl)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printCRLDetails prints CRL information in table format
func printCRLDetails(printer *cli.Printer, crl *casvc.CRL) {
	if crl == nil {
		printer.PrintInfo("No CRL data available")
		return
	}

	printer.PrintKeyValue("Last Update", formatTime(crl.LastUpdate))
	printer.PrintKeyValue("Next Update", formatTime(crl.NextUpdate))
	printer.PrintKeyValue("Revoked Certificates", fmt.Sprintf("%d", crl.RevokedCount))

	if len(crl.RevokedCerts) > 0 {
		fmt.Println()
		printer.PrintInfo("Revoked Certificates:")
		for _, entry := range crl.RevokedCerts {
			fmt.Printf("  Serial: %s  Revoked: %s  Reason: %s\n",
				entry.Serial,
				formatTime(entry.RevocationTime),
				string(entry.Reason),
			)
		}
	}
}

// newCRLExportCommand creates the export subcommand for CRL export
func newCRLExportCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export CRL to file",
		Long: `Export the Certificate Revocation List to a file.

The CRL is exported in DER format, suitable for distribution to clients
for offline revocation checking.

Examples:
  # Export CRL to specific file
  platformctl ca crl export --output /path/to/crl.crl

  # Export CRL to current directory
  platformctl ca crl export --output ./ca.crl`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runCRLExport(flags, output)
		},
	}

	cmd.Flags().StringVar(&output, "output", "", "Output file path for CRL export (required)")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}

// runCRLExport executes the CRL export command
func runCRLExport(flags *cli.CommonFlags, output string) error {
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

	crl, err := sdkClient.GetCRLDomain(ctx, false)
	if err != nil {
		return ErrGetCRLFailed{Reason: err.Error()}
	}

	if crl == nil || len(crl.Data) == 0 {
		return ErrCRLEmpty{}
	}

	if err := os.WriteFile(output, crl.Data, 0644); err != nil {
		return ErrCRLExportFailed{Reason: err.Error()}
	}

	printer := base.Printer()
	printer.PrintSuccess(fmt.Sprintf("CRL exported to %s", output))

	return nil
}
