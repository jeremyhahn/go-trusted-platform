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

// ErrKeyMetadataNotImplemented is returned when key metadata operations are not yet implemented
type ErrKeyMetadataNotImplemented struct{}

func (e ErrKeyMetadataNotImplemented) Error() string {
	return "key metadata operations are not yet implemented in the platform KMS service"
}

// ErrGetKeyMetadataFailed is returned when getting key metadata fails
type ErrGetKeyMetadataFailed struct {
	KeyID string
	Err   error
}

func (e ErrGetKeyMetadataFailed) Error() string {
	return fmt.Sprintf("failed to get metadata for key %s: %v", e.KeyID, e.Err)
}

// ErrUpdateKeyMetadataFailed is returned when updating key metadata fails
type ErrUpdateKeyMetadataFailed struct {
	KeyID string
	Err   error
}

func (e ErrUpdateKeyMetadataFailed) Error() string {
	return fmt.Sprintf("failed to update metadata for key %s: %v", e.KeyID, e.Err)
}

// ErrInvalidTagFormat is returned when a tag has an invalid format
type ErrInvalidTagFormat struct {
	Tag string
}

func (e ErrInvalidTagFormat) Error() string {
	return fmt.Sprintf("invalid tag format: %s (expected key=value)", e.Tag)
}

// newKeyMetadataCommand creates the key metadata subcommand group
func newKeyMetadataCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metadata",
		Short: "Manage key metadata (not yet implemented)",
		Long: `Get or update metadata for a cryptographic key.

NOTE: This command is not yet implemented in the platform KMS service.

Key metadata includes name, description, tags, and other non-sensitive
information about the key. This does not expose key material.`,
	}

	cmd.AddCommand(newKeyMetadataGetCommand(getFlags))
	cmd.AddCommand(newKeyMetadataUpdateCommand(getFlags))

	return cmd
}

// newKeyMetadataGetCommand creates the metadata get subcommand
func newKeyMetadataGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <key-id>",
		Short: "Get key metadata (not yet implemented)",
		Long: `Retrieve metadata for a cryptographic key without exposing key material.

NOTE: This command is not yet implemented in the platform KMS service.

Examples:
  # Get metadata for a key
  platformctl kms key metadata get my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyMetadataNotImplemented{}
		},
	}

	return cmd
}

// newKeyMetadataUpdateCommand creates the metadata update subcommand
func newKeyMetadataUpdateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var name string
	var description string
	var tags []string
	var removeTags []string

	cmd := &cobra.Command{
		Use:   "update <key-id>",
		Short: "Update key metadata (not yet implemented)",
		Long: `Update mutable metadata fields for a cryptographic key.

NOTE: This command is not yet implemented in the platform KMS service.

Tags are specified as key=value pairs. You can add new tags, update
existing tags, or remove tags.

Examples:
  # Update name and description
  platformctl kms key metadata update my-key --name "Production API Key" --description "Key for API authentication"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyMetadataNotImplemented{}
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "new key name")
	cmd.Flags().StringVarP(&description, "description", "d", "", "new key description")
	cmd.Flags().StringArrayVarP(&tags, "tag", "t", nil, "add or update tag (format: key=value)")
	cmd.Flags().StringArrayVar(&removeTags, "remove-tag", nil, "remove tag by key")

	return cmd
}
