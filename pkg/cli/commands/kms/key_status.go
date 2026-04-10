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

// ErrKeyStatusNotImplemented is returned when key status operations are not yet implemented
type ErrKeyStatusNotImplemented struct{}

func (e ErrKeyStatusNotImplemented) Error() string {
	return "key status operations are not yet implemented in the platform KMS service"
}

// ErrUpdateKeyStatusFailed is returned when updating key status fails
type ErrUpdateKeyStatusFailed struct {
	KeyID string
	Err   error
}

func (e ErrUpdateKeyStatusFailed) Error() string {
	return fmt.Sprintf("failed to update status for key %s: %v", e.KeyID, e.Err)
}

// ErrInvalidKeyStatus is returned when an invalid key status is specified
type ErrInvalidKeyStatus struct {
	Status string
}

func (e ErrInvalidKeyStatus) Error() string {
	return fmt.Sprintf("invalid key status: %s (valid values: enabled, disabled)", e.Status)
}

// newKeyStatusCommand creates the key status subcommand group
func newKeyStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Manage key status (not yet implemented)",
		Long: `Enable or disable a key or specific key version.

NOTE: This command is not yet implemented in the platform KMS service.

A disabled key cannot be used for cryptographic operations but can be
re-enabled later. Use this for temporary access control or key suspension.`,
	}

	cmd.AddCommand(newKeyEnableCommand(getFlags))
	cmd.AddCommand(newKeyDisableCommand(getFlags))

	return cmd
}

// newKeyEnableCommand creates the key enable subcommand
func newKeyEnableCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var version uint64

	cmd := &cobra.Command{
		Use:   "enable <key-id>",
		Short: "Enable a key or key version (not yet implemented)",
		Long: `Enable a previously disabled key or key version.

NOTE: This command is not yet implemented in the platform KMS service.

Examples:
  platformctl kms key status enable my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyStatusNotImplemented{}
		},
	}

	cmd.Flags().Uint64VarP(&version, "version", "v", 0, "specific key version (0 for all versions)")

	return cmd
}

// newKeyDisableCommand creates the key disable subcommand
func newKeyDisableCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var version uint64

	cmd := &cobra.Command{
		Use:   "disable <key-id>",
		Short: "Disable a key or key version (not yet implemented)",
		Long: `Disable a key or key version, preventing it from being used.

NOTE: This command is not yet implemented in the platform KMS service.

Examples:
  platformctl kms key status disable my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyStatusNotImplemented{}
		},
	}

	cmd.Flags().Uint64VarP(&version, "version", "v", 0, "specific key version (0 for all versions)")

	return cmd
}
