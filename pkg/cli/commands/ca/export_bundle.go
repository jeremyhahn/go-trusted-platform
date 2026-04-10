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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newExportBundleCommand creates the export-bundle subcommand
func newExportBundleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		output               string
		includeIntermediates bool
	)

	cmd := &cobra.Command{
		Use:   "export-bundle",
		Short: "Export CA certificate bundle",
		Long: `Export the Certificate Authority trust chain (root CA + intermediate CAs)
as a PEM bundle file. This bundle can be embedded in client ISOs to establish
trust with the server without requiring insecure network fetches.

The exported bundle contains all CA certificates needed to verify certificates
issued by this CA, in the correct order (leaf to root).

Bundle contents:
  - Root CA certificate
  - Intermediate CA certificate(s) (if --intermediates is set)
  - Trust chain in proper order

Examples:
  # Export to specified file
  platformctl ca export-bundle -o /path/to/ca-bundle.pem

  # Export including intermediate CAs
  platformctl ca export-bundle -o ./ca-bundle.pem --intermediates

  # Export and use with ISO builder
  platformctl ca export-bundle -o ./ca-bundle.pem
  platformctl iso create --ca-bundle-path ./ca-bundle.pem ...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runExportBundle(flags, output, includeIntermediates)
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (required)")
	cmd.Flags().BoolVar(&includeIntermediates, "intermediates", true, "Include intermediate CA certificates")
	_ = cmd.MarkFlagRequired("output")

	return cmd
}

// runExportBundle executes the CA bundle export command
func runExportBundle(flags *cli.CommonFlags, output string, includeIntermediates bool) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	client := base.Client().CA()
	if client == nil {
		return ErrCANotInitialized{}
	}

	req := &platformv1.GetCABundleRequest{
		IncludeIntermediates: includeIntermediates,
	}

	ctx := base.Context()
	resp, err := client.GetCABundle(ctx, req)
	if err != nil {
		return ErrExportBundleFailed{Reason: err.Error()}
	}

	if resp.Bundle == nil || len(resp.Bundle.Pem) == 0 {
		return ErrBundleEmpty{}
	}

	// Write bundle to file
	if err := os.WriteFile(output, resp.Bundle.Pem, 0644); err != nil {
		return ErrExportBundleFailed{Reason: fmt.Sprintf("failed to write bundle: %v", err)}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		result := map[string]interface{}{
			"success":    true,
			"output":     output,
			"cert_count": resp.Bundle.CertCount,
		}
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("CA bundle exported to %s", output))
		printer.PrintKeyValue("Certificates", fmt.Sprintf("%d", resp.Bundle.CertCount))

		if len(resp.Bundle.Certificates) > 0 {
			fmt.Println()
			printer.PrintInfo("Bundle Contents:")
			for i, cert := range resp.Bundle.Certificates {
				fmt.Printf("  [%d] %s (%s)\n", i+1, cert.CommonName, cert.Serial)
			}
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
