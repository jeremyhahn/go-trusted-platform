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
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// ErrAlgorithmsNotImplemented is returned when the algorithms command is not yet implemented
type ErrAlgorithmsNotImplemented struct{}

func (e ErrAlgorithmsNotImplemented) Error() string {
	return "key algorithms listing is not yet implemented in the platform KMS service"
}

// newKeyAlgorithmsCommand creates the key algorithms subcommand
func newKeyAlgorithmsCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "algorithms",
		Short: "List supported algorithms (not yet implemented)",
		Long: `Display the list of cryptographic algorithms supported by the current KMS backend.

NOTE: This command is not yet implemented in the platform KMS service.

Different backends may support different algorithms. Use this command to check
which algorithms are available before generating or importing keys.

Examples:
  # List supported algorithms
  platformctl kms key algorithms

  # Output as JSON
  platformctl kms key algorithms --output json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = getFlags()
			return ErrAlgorithmsNotImplemented{}
		},
	}

	return cmd
}
