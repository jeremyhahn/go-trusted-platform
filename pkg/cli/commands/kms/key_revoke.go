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

package kms

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrKeyRevokeFailed is returned when key revocation fails
type ErrKeyRevokeFailed struct {
	KeyID string
	Err   error
}

func (e ErrKeyRevokeFailed) Error() string {
	return fmt.Sprintf("failed to revoke key %s: %v", e.KeyID, e.Err)
}

func (e ErrKeyRevokeFailed) Unwrap() error {
	return e.Err
}

// ErrRevocationReasonRequired is returned when revocation reason is not provided
type ErrRevocationReasonRequired struct{}

func (e ErrRevocationReasonRequired) Error() string {
	return "revocation reason is required"
}

// newKeyRevokeCommand creates the key revoke subcommand
func newKeyRevokeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var reason string

	cmd := &cobra.Command{
		Use:   "revoke <key-id>",
		Short: "Revoke a key",
		Long: `Revoke a cryptographic key, marking it as compromised and unusable.

Once revoked, a key cannot be used for any cryptographic operations.
This operation is typically used when a key is known or suspected to
be compromised. A reason must be provided for audit purposes.

Examples:
  platformctl kms key revoke my-key --reason "Key material exposed in security incident"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyRevoke(getFlags(), args[0], reason)
		},
	}

	cmd.Flags().StringVarP(&reason, "reason", "r", "", "reason for revocation (required)")

	return cmd
}

// runKeyRevoke opens the SDK connection and delegates to executeKeyRevoke.
func runKeyRevoke(flags *cli.CommonFlags, keyID, reason string) error {
	if reason == "" {
		return ErrRevocationReasonRequired{}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	return executeKeyRevoke(base.Context(), client, base.Printer(), keyID, reason)
}

// executeKeyRevoke revokes the key via the quicbaas SDK KMS client.
func executeKeyRevoke(ctx context.Context, client quicbaassdk.KMSClient, printer *cli.Printer, keyID, reason string) error {
	if err := client.RevokeKey(ctx, keyID, reason); err != nil {
		return ErrKeyRevokeFailed{KeyID: keyID, Err: err}
	}

	printer.PrintSuccess(fmt.Sprintf("Key %s revoked (reason: %s)", keyID, reason))
	return nil
}
