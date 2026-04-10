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
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newInfoCommand creates the info subcommand for CA information
func newInfoCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Display information about the Certificate Authority",
		Long: `Display key store, certificate store, and general information
about the Certificate Authority.

Information displayed includes:
  - CA initialization status
  - CA identity (Common Name)
  - Configured key algorithms and stores
  - Certificate count
  - CRL status

Examples:
  # Display CA information
  platformctl ca info

  # Display as JSON
  platformctl ca info -o json

  # Display as YAML
  platformctl ca info -o yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInfo(flags)
		},
	}

	return cmd
}

// runInfo executes the CA info command
func runInfo(flags *cli.CommonFlags) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	client := base.Client().CA()
	if client == nil {
		return ErrCANotInitialized{}
	}

	ctx := base.Context()
	resp, err := client.GetCAInfo(ctx, &platformv1.GetCAInfoRequest{})
	if err != nil {
		return ErrGetCAInfoFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printCAInfoTable(printer, resp)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// printCAInfoTable prints CA information in table format
func printCAInfoTable(printer *cli.Printer, resp *platformv1.GetCAInfoResponse) {
	if resp.CaInfo == nil {
		printer.PrintInfo("No CA information available")
		return
	}

	info := resp.CaInfo

	printer.PrintKeyValue("Initialized", formatBool(info.IsInitialized))
	printer.PrintKeyValue("Common Name", info.CommonName)
	printer.PrintKeyValue("Is Intermediate", formatBool(info.IsIntermediate))
	printer.PrintKeyValue("Default Algorithm", info.DefaultAlgorithm)
	printer.PrintKeyValue("Default Validity", fmt.Sprintf("%d days", info.DefaultValidityDays))

	if info.RootCert != nil {
		fmt.Println()
		printer.PrintInfo("Root Certificate:")
		printCertSummary(printer, info.RootCert, "  ")
	}

	if len(info.Intermediates) > 0 {
		fmt.Println()
		printer.PrintInfo("Intermediate Certificates:")
		for i, cert := range info.Intermediates {
			fmt.Printf("  [%d]\n", i+1)
			printCertSummary(printer, cert, "    ")
		}
	}

	if len(info.KeyStores) > 0 {
		fmt.Println()
		printer.PrintInfo("Configured Key Stores:")
		for _, store := range info.KeyStores {
			printKeyStoreInfo(printer, store)
		}
	}
}

// printCertSummary prints a certificate summary with given indent
func printCertSummary(printer *cli.Printer, cert *platformv1.CertificateSummary, indent string) {
	if cert == nil {
		return
	}
	fmt.Printf("%sCommon Name: %s\n", indent, cert.CommonName)
	fmt.Printf("%sSerial: %s\n", indent, cert.Serial)
	fmt.Printf("%sIssuer: %s\n", indent, cert.Issuer)
	fmt.Printf("%sNot Before: %s\n", indent, formatTimestamp(cert.NotBefore))
	fmt.Printf("%sNot After: %s\n", indent, formatTimestamp(cert.NotAfter))
	fmt.Printf("%sStatus: %s\n", indent, cert.Status.String())
	fmt.Printf("%sKey Algorithm: %s\n", indent, cert.KeyAlgorithm.String())
}

// printKeyStoreInfo prints key store information
func printKeyStoreInfo(printer *cli.Printer, store *platformv1.KeyStoreInfo) {
	if store == nil {
		return
	}
	available := "No"
	if store.Available {
		available = "Yes"
	}
	fmt.Printf("  - Type: %s (Available: %s)\n", store.Type, available)
	if len(store.Capabilities) > 0 {
		fmt.Printf("    Capabilities: %s\n", strings.Join(store.Capabilities, ", "))
	}
}

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatTimestamp formats a protobuf timestamp for display
func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return "N/A"
	}
	return ts.AsTime().Format("2006-01-02 15:04:05 MST")
}
