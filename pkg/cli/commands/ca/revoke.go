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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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

	client := base.Client().CA()
	if client == nil {
		return ErrCANotInitialized{}
	}

	revocationReason, err := parseRevocationReason(reason)
	if err != nil {
		return err
	}

	req := &platformv1.RevokeCertificateRequest{
		Serial:     serial,
		Reason:     revocationReason,
		DeleteKeys: deleteKeys,
	}

	ctx := base.Context()
	resp, err := client.RevokeCertificate(ctx, req)
	if err != nil {
		return ErrRevokeCertificateFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess(fmt.Sprintf("Certificate %s revoked successfully", resp.Serial))
			printer.PrintKeyValue("Reason", resp.Reason.String())
			if resp.RevokedAt != nil {
				printer.PrintKeyValue("Revoked At", formatTimestamp(resp.RevokedAt))
			}
			if deleteKeys {
				printer.PrintInfo("Associated keys have been deleted")
			}
		} else {
			msg := "unknown error"
			if resp.Status != nil && resp.Status.Message != "" {
				msg = resp.Status.Message
			}
			printer.PrintError(fmt.Sprintf("Failed to revoke certificate: %s", msg))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parseRevocationReason parses a revocation reason string to the protobuf enum
func parseRevocationReason(reason string) (platformv1.RevocationReason, error) {
	switch strings.ToLower(reason) {
	case "unspecified", "":
		return platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED, nil
	case "key-compromise", "keycompromise":
		return platformv1.RevocationReason_REVOCATION_REASON_KEY_COMPROMISE, nil
	case "ca-compromise", "cacompromise":
		return platformv1.RevocationReason_REVOCATION_REASON_CA_COMPROMISE, nil
	case "affiliation-changed", "affiliationchanged":
		return platformv1.RevocationReason_REVOCATION_REASON_AFFILIATION_CHANGED, nil
	case "superseded":
		return platformv1.RevocationReason_REVOCATION_REASON_SUPERSEDED, nil
	case "cessation", "cessation-of-operation":
		return platformv1.RevocationReason_REVOCATION_REASON_CESSATION_OF_OPERATION, nil
	case "hold", "certificate-hold":
		return platformv1.RevocationReason_REVOCATION_REASON_CERTIFICATE_HOLD, nil
	case "privilege-withdrawn", "privilegewithdrawn":
		return platformv1.RevocationReason_REVOCATION_REASON_PRIVILEGE_WITHDRAWN, nil
	default:
		return platformv1.RevocationReason_REVOCATION_REASON_UNSPECIFIED,
			ErrInvalidRevocationReason{Reason: reason}
	}
}
