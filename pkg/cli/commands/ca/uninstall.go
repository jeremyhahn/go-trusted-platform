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
		Long: `Ask the daemon to remove this CA's certificates from its system trust
path.

The daemon removes the PEM bundle at its trust path, by default
/usr/local/share/ca-certificates/trusted-platform-ca.crt, only when it is a
bundle this CA wrote (the root, or the root plus the intermediate). It
answers "nothing installed" when there is no bundle and refuses any other
file. The daemon does not run update-ca-certificates: run it afterwards to
refresh the system trust store.

The caller needs the trust:write scope.

Examples:
  # Remove the CA bundle from the daemon's trust path
  platformctl ca uninstall-ca-certificates

  # Then refresh the system trust store on the daemon's host
  sudo update-ca-certificates`,
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
		if result.Message != "" {
			printer.PrintInfo(result.Message)
		} else {
			printer.PrintInfo("CA certificates uninstalled successfully")
		}
		fmt.Println()
		printer.PrintKeyValue("Certificates Removed", fmt.Sprintf("%d", result.CertificatesRemoved))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
