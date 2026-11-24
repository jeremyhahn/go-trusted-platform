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
		Long: `Ask the daemon to install this CA's certificates into its system trust
path.

The daemon writes one certificate per file. The root certificate goes to its
trust path, by default
/usr/local/share/ca-certificates/trusted-platform-ca.crt. With
--include-intermediates (the default) the intermediate certificate goes to the
sibling file trusted-platform-ca-intermediate-1.crt in the same directory.
Each file that already holds the same bytes is left alone; when every file is
already in place the daemon answers "already installed" and writes nothing.
The daemon does not run update-ca-certificates: run it afterwards to refresh
the system trust store.

The caller needs the trust:write scope.

Examples:
  # Install the root and intermediate certificates (the default)
  platformctl ca install-ca-certificates

  # Install the root certificate only
  platformctl ca install-ca-certificates --include-intermediates=false

  # Then refresh the system trust store on the daemon's host
  sudo update-ca-certificates`,
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
		if result.Message != "" {
			printer.PrintInfo(result.Message)
		} else {
			printer.PrintInfo("CA certificates installed successfully")
		}
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
