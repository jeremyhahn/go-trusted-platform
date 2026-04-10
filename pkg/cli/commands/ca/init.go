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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newInitCommand creates the init subcommand for CA initialization
func newInitCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the Certificate Authority",
		Long: `Initialize the Certificate Authority by creating a Root and
Intermediates as specified in the platform configuration file.

This command sets up the complete CA infrastructure including:
  - Root CA certificate and key
  - Intermediate CA certificates and keys
  - Certificate and key stores
  - Initial CRL generation

Examples:
  # Initialize the CA with default configuration
  platformctl ca init

  # Initialize with verbose output
  platformctl ca init --verbose

  # Force re-initialization (overwrites existing CA)
  platformctl ca init --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInit(flags, force)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Force re-initialization even if CA already exists")

	return cmd
}

// runInit executes the CA init command
func runInit(flags *cli.CommonFlags, force bool) error {
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
	resp, err := client.InitCA(ctx, &platformv1.InitCARequest{
		Force: force,
	})
	if err != nil {
		return ErrInitCAFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.CaInfo == nil {
			printer.PrintInfo("CA initialized successfully (no info available)")
			return nil
		}

		printer.PrintInfo("Certificate Authority initialized successfully")
		fmt.Println()
		printer.PrintKeyValue("Common Name", resp.CaInfo.CommonName)
		printer.PrintKeyValue("Initialized", formatBool(resp.CaInfo.IsInitialized))
		printer.PrintKeyValue("Is Intermediate", formatBool(resp.CaInfo.IsIntermediate))
		printer.PrintKeyValue("Default Algorithm", resp.CaInfo.DefaultAlgorithm)
		printer.PrintKeyValue("Default Validity", fmt.Sprintf("%d days", resp.CaInfo.DefaultValidityDays))

		if resp.CaInfo.RootCert != nil {
			fmt.Println()
			printer.PrintInfo("Root Certificate:")
			printCertSummary(printer, resp.CaInfo.RootCert, "  ")
		}

		if len(resp.CaInfo.Intermediates) > 0 {
			fmt.Println()
			printer.PrintInfo("Intermediate Certificates:")
			for i, cert := range resp.CaInfo.Intermediates {
				fmt.Printf("  [%d]\n", i+1)
				printCertSummary(printer, cert, "    ")
			}
		}

		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
