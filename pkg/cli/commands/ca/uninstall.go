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

The daemon removes the trust files this CA wrote: the root certificate at its
trust path, by default
/usr/local/share/ca-certificates/trusted-platform-ca.crt, and, with
--include-intermediates (the default), the intermediate certificate at the
sibling file trusted-platform-ca-intermediate-1.crt. It also removes a legacy
combined root-plus-intermediate bundle at the trust path when
--include-intermediates is set.

With --include-intermediates=false only the root file is removed: the
intermediate file is left in place, and a legacy combined
root-plus-intermediate bundle at the trust path is refused, because removing
it would also remove the intermediate.

The daemon answers "nothing installed" when there is no file to remove and
refuses a trust-path file this CA did not write. It does not run
update-ca-certificates: run it afterwards to refresh the system trust store.

The caller needs the trust:write scope.

Examples:
  # Remove the root and intermediate trust files
  platformctl ca uninstall-ca-certificates

  # Remove the root trust file only, keeping the intermediate
  platformctl ca uninstall-ca-certificates --include-intermediates=false

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
