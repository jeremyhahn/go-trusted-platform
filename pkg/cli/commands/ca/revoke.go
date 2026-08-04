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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

// newRevokeCommand creates the revoke subcommand for certificate revocation
func newRevokeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		deleteKeys bool
		reason     string
	)

	cmd := &cobra.Command{
		Use:   "revoke [serial]",
		Short: "Revoke an issued certificate",
		Long: `Revoke an issued certificate and add it to the Certificate Revocation List.

Arguments:
  serial - Serial number of the certificate to revoke

Revocation reasons:
  - unspecified     : No reason specified
  - key-compromise  : Private key was compromised
  - ca-compromise   : CA key was compromised
  - superseded      : Certificate has been replaced
  - cessation       : Certificate is no longer needed
  - hold            : Certificate temporarily suspended

This command:
  - Adds the certificate to the CRL
  - Optionally deletes the associated key pair
  - Removes the certificate from active stores

WARNING: Revocation is permanent (except for hold). The certificate serial
number will be added to the CRL and clients will reject it.

Examples:
  # Revoke certificate by serial number
  platformctl ca revoke 1234567890ABCDEF

  # Revoke certificate and delete keys
  platformctl ca revoke 1234567890ABCDEF --delete-keys

  # Revoke with a specific reason
  platformctl ca revoke 1234567890ABCDEF --reason superseded`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runRevoke(flags, args[0], reason, deleteKeys)
		},
	}

	cmd.Flags().BoolVar(&deleteKeys, "delete-keys", false, "Delete associated key pair")
	cmd.Flags().StringVar(&reason, "reason", "unspecified", "Revocation reason: unspecified, key-compromise, ca-compromise, superseded, cessation, hold")

	return cmd
}

// runRevoke executes the certificate revocation command
func runRevoke(flags *cli.CommonFlags, serial, reason string, deleteKeys bool) error {
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

	revocationReason, err := parseRevocationReason(reason)
	if err != nil {
		return err
	}

	params := &casvc.RevokeCertificateParams{
		Serial:     serial,
		Reason:     revocationReason,
		DeleteKeys: deleteKeys,
	}

	ctx := base.Context()
	result, err := sdkClient.RevokeCertificateDomain(ctx, params)
	if err != nil {
		return ErrRevokeCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		if result.Success {
			printer.PrintSuccess(fmt.Sprintf("Certificate %s revoked successfully", result.Serial))
			printer.PrintKeyValue("Reason", string(result.Reason))
			if !result.RevokedAt.IsZero() {
				printer.PrintKeyValue("Revoked At", formatTime(result.RevokedAt))
			}
			if deleteKeys {
				printer.PrintInfo("Associated keys have been deleted")
			}
		} else {
			msg := "unknown error"
			if result.Message != "" {
				msg = result.Message
			}
			printer.PrintError(fmt.Sprintf("Failed to revoke certificate: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseRevocationReason parses a revocation reason string to the SDK domain type
func parseRevocationReason(reason string) (casvc.RevocationReason, error) {
	switch strings.ToLower(reason) {
	case "unspecified", "":
		return casvc.RevocationReasonUnspecified, nil
	case "key-compromise", "keycompromise":
		return casvc.RevocationReasonKeyCompromise, nil
	case "ca-compromise", "cacompromise":
		return casvc.RevocationReasonCACompromise, nil
	case "affiliation-changed", "affiliationchanged":
		return casvc.RevocationReasonAffiliationChanged, nil
	case "superseded":
		return casvc.RevocationReasonSuperseded, nil
	case "cessation", "cessation-of-operation":
		return casvc.RevocationReasonCessationOfOperation, nil
	case "hold", "certificate-hold":
		return casvc.RevocationReasonCertificateHold, nil
	case "privilege-withdrawn", "privilegewithdrawn":
		return casvc.RevocationReasonPrivilegeWithdrawn, nil
	default:
		return casvc.RevocationReasonUnspecified,
			ErrInvalidRevocationReason{Reason: reason}
	}
}
