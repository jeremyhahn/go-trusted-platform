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

// newRenewCommand creates the renew subcommand for certificate renewal
func newRenewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		days  int
		force bool
	)

	cmd := &cobra.Command{
		Use:   "renew <serial>",
		Short: "Renew an existing certificate",
		Long: `Renew an existing certificate by issuing a new certificate with the same
subject and key attributes.

The original certificate remains valid until the new certificate is issued.
The old certificate is NOT automatically revoked.

By default, renewal is only allowed for certificates that are close to expiration.
Use --force to renew certificates that are not yet near expiration.

Renewal process:
  1. Validate the existing certificate
  2. Issue new certificate with same subject/SANs
  3. Return the new certificate

Examples:
  # Renew certificate by serial number
  platformctl ca renew 123456789

  # Renew with custom validity period (2 years)
  platformctl ca renew 123456789 --days 730

  # Force renewal even if not expiring soon
  platformctl ca renew 123456789 --force

  # Output in JSON format
  platformctl ca renew 123456789 -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRenew(flags, args[0], days, force)
		},
	}

	cmd.Flags().IntVar(&days, "days", 365, "Validity period for renewed certificate in days")
	cmd.Flags().BoolVar(&force, "force", false, "Force renewal even if certificate is not near expiration")

	return cmd
}

// runRenew executes the certificate renewal command
func runRenew(flags *cli.CommonFlags, serial string, days int, force bool) error {
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

	params := &casvc.RenewCertificateParams{
		Serial:       serial,
		ValidDays:    int32(days),
		PreserveSANs: !force, // force=true means renew even if not expiring, preserveSans defaults to true
	}

	ctx := base.Context()
	result, err := sdkClient.RenewCertificateDomain(ctx, params)
	if err != nil {
		return ErrRenewCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if result.NewCertificate != nil {
			printer.PrintSuccess("Certificate renewed successfully")
			fmt.Println()
			printer.PrintKeyValue("Old Serial", serial)
			printer.PrintKeyValue("New Serial", result.NewCertificate.Serial)
			printCertificateDetails(printer, result.NewCertificate)
		} else {
			printer.PrintError("Failed to renew certificate")
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
