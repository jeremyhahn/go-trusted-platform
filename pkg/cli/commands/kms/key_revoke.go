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
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrKeyRevokeNotImplemented is returned when key revoke is not yet implemented
type ErrKeyRevokeNotImplemented struct{}

func (e ErrKeyRevokeNotImplemented) Error() string {
	return "key revocation is not yet implemented in the platform KMS service"
}

// ErrKeyRevokeFailed is returned when key revocation fails
type ErrKeyRevokeFailed struct {
	KeyID string
	Err   error
}

func (e ErrKeyRevokeFailed) Error() string {
	return fmt.Sprintf("failed to revoke key %s: %v", e.KeyID, e.Err)
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
		Short: "Revoke a key (not yet implemented)",
		Long: `Revoke a cryptographic key, marking it as compromised and unusable.

NOTE: This command is not yet implemented in the platform KMS service.

Once revoked, a key cannot be used for any cryptographic operations.
This operation is typically used when a key is known or suspected to
be compromised. A reason must be provided for audit purposes.

Examples:
  platformctl kms key revoke my-key --reason "Key material exposed in security incident"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyRevokeNotImplemented{}
		},
	}

	cmd.Flags().StringVarP(&reason, "reason", "r", "", "reason for revocation (required)")

	return cmd
}
