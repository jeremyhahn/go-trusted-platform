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

// ErrKeyUnwrapNotImplemented is returned when key unwrap is not yet implemented
type ErrKeyUnwrapNotImplemented struct{}

func (e ErrKeyUnwrapNotImplemented) Error() string {
	return "key unwrap is not yet implemented in the platform KMS service"
}

// ErrKeyUnwrapFailed is returned when key unwrap/import fails
type ErrKeyUnwrapFailed struct {
	Err error
}

func (e ErrKeyUnwrapFailed) Error() string {
	return fmt.Sprintf("failed to unwrap key: %v", e.Err)
}

// ErrWrappedMaterialRequired is returned when no wrapped material is provided
type ErrWrappedMaterialRequired struct{}

func (e ErrWrappedMaterialRequired) Error() string {
	return "wrapped key material is required (use --input-file or --material)"
}

// ErrReadWrappedMaterialFailed is returned when reading wrapped material from file fails
type ErrReadWrappedMaterialFailed struct {
	Path string
	Err  error
}

func (e ErrReadWrappedMaterialFailed) Error() string {
	return fmt.Sprintf("failed to read wrapped material from %s: %v", e.Path, e.Err)
}

// newKeyUnwrapCommand creates the key unwrap subcommand
func newKeyUnwrapCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var keyID string
	var wrappingKeyID string
	var wrappingAlgorithm string
	var algorithm string
	var name string
	var description string
	var inputFile string
	var base64Material string

	cmd := &cobra.Command{
		Use:   "unwrap",
		Short: "Import a wrapped key (not yet implemented)",
		Long: `Import a wrapped (encrypted) key into the KMS.

NOTE: This command is not yet implemented in the platform KMS service.

This command unwraps a key that was previously wrapped/encrypted with
a wrapping key and imports it into the KMS. This is typically used for
secure key transport between systems. The wrapped material can be provided
as a base64-encoded string or from a file.

Examples:
  platformctl kms key unwrap --key-id my-new-key --wrapping-key wrap-key-id --algorithm aes-256-gcm --input-file wrapped-key.enc`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyUnwrapNotImplemented{}
		},
	}

	cmd.Flags().StringVar(&keyID, "key-id", "", "ID for the unwrapped key (required)")
	cmd.Flags().StringVar(&wrappingKeyID, "wrapping-key", "", "ID of the key used to wrap the material (required)")
	cmd.Flags().StringVar(&wrappingAlgorithm, "wrapping-algorithm", "aes-kw", "wrapping algorithm used")
	cmd.Flags().StringVarP(&algorithm, "algorithm", "a", "", "algorithm of the wrapped key (required)")
	cmd.Flags().StringVarP(&name, "name", "n", "", "human-readable key name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "key description")
	cmd.Flags().StringVarP(&inputFile, "input-file", "f", "", "file containing wrapped key material")
	cmd.Flags().StringVarP(&base64Material, "material", "m", "", "base64-encoded wrapped key material")

	return cmd
}
