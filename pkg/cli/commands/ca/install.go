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

// newInstallCommand creates the install-ca-certificates subcommand
func newInstallCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var includeIntermediates bool

	cmd := &cobra.Command{
		Use:   "install-ca-certificates",
		Short: "Install Certificate Authority certificates",
		Long: `Install the Root and Intermediate Certificate Authority certificates
to the operating system trusted certificate store.

This command installs the CA certificates into the system trust store,
allowing applications to automatically trust certificates issued by this CA.

Platform-specific behavior:
  - Linux: Copies certificates to /usr/local/share/ca-certificates/ and
           runs update-ca-certificates
  - macOS: Adds certificates to the system trust store
  - Windows: Adds certificates to the Trusted Root Certification Authorities

NOTE: This operation typically requires root/administrator privileges.

Examples:
  # Install CA certificates to system trust store
  sudo platformctl ca install-ca-certificates

  # Install root and intermediate certificates
  sudo platformctl ca install-ca-certificates --include-intermediates`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runInstall(flags, includeIntermediates)
		},
	}

	cmd.Flags().BoolVar(&includeIntermediates, "include-intermediates", true, "Include intermediate certificates")

	return cmd
}

// runInstall executes the CA certificates installation command
func runInstall(flags *cli.CommonFlags, includeIntermediates bool) error {
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

	result, err := sdkClient.InstallCACertificatesDomain(ctx, includeIntermediates)
	if err != nil {
		return ErrInstallCertificatesFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintInfo("CA certificates installed successfully")
		fmt.Println()
		printer.PrintKeyValue("Certificates Installed", fmt.Sprintf("%d", result.CertificatesInstalled))
		if result.InstallPath != "" {
			printer.PrintKeyValue("Install Path", result.InstallPath)
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
