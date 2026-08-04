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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

// newUninstallCommand creates the uninstall-ca-certificates subcommand
func newUninstallCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var includeIntermediates bool

	cmd := &cobra.Command{
		Use:   "uninstall-ca-certificates",
		Short: "Uninstall Certificate Authority certificates",
		Long: `Remove the Root and Intermediate Certificate Authority certificates
from the operating system trusted certificate store.

This command removes the CA certificates from the system trust store.
After removal, applications will no longer automatically trust certificates
issued by this CA.

Platform-specific behavior:
  - Linux: Removes certificates from /usr/local/share/ca-certificates/ and
           runs update-ca-certificates
  - macOS: Removes certificates from the system trust store
  - Windows: Removes certificates from the Trusted Root Certification Authorities

NOTE: This operation typically requires root/administrator privileges.

Examples:
  # Uninstall CA certificates from system trust store
  sudo platformctl ca uninstall-ca-certificates

  # Uninstall root and intermediate certificates
  sudo platformctl ca uninstall-ca-certificates --include-intermediates`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runUninstall(flags, includeIntermediates)
		},
	}

	cmd.Flags().BoolVar(&includeIntermediates, "include-intermediates", true, "Include intermediate certificates")

	return cmd
}

// runUninstall executes the CA certificates uninstallation command
func runUninstall(flags *cli.CommonFlags, includeIntermediates bool) error {
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

	result, err := sdkClient.UninstallCACertificatesDomain(ctx, includeIntermediates)
	if err != nil {
		return ErrUninstallCertificatesFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintInfo("CA certificates uninstalled successfully")
		fmt.Println()
		printer.PrintKeyValue("Certificates Removed", fmt.Sprintf("%d", result.CertificatesRemoved))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
