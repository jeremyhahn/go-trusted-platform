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

// ErrKeyVersionsNotImplemented is returned when key versions listing is not yet implemented
type ErrKeyVersionsNotImplemented struct{}

func (e ErrKeyVersionsNotImplemented) Error() string {
	return "key versions listing is not yet implemented in the platform KMS service"
}

// ErrListKeyVersionsFailed is returned when listing key versions fails
type ErrListKeyVersionsFailed struct {
	KeyID string
	Err   error
}

func (e ErrListKeyVersionsFailed) Error() string {
	return fmt.Sprintf("failed to list versions for key %s: %v", e.KeyID, e.Err)
}

// newKeyVersionsCommand creates the key versions subcommand
func newKeyVersionsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var limit int32
	var cursor string

	cmd := &cobra.Command{
		Use:   "versions <key-id>",
		Short: "List all versions of a key (not yet implemented)",
		Long: `List all versions of a cryptographic key with their status and metadata.

NOTE: This command is not yet implemented in the platform KMS service.

Each key can have multiple versions created through rotation. This command
displays all versions with their creation time, status, and algorithm.
Use the --limit flag to control pagination.

Examples:
  platformctl kms key versions my-key`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrKeyVersionsNotImplemented{}
		},
	}

	cmd.Flags().Int32VarP(&limit, "limit", "l", 50, "maximum number of versions to return")
	cmd.Flags().StringVarP(&cursor, "cursor", "c", "", "pagination cursor for next page")

	return cmd
}
