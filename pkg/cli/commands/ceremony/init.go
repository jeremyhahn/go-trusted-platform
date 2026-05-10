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

package ceremony

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// CanonicalRedirectError is emitted when an operator runs a legacy
// renamed command path. Per docs/08-bootstrap-auth-architecture.md §6
// "platformctl ceremony init" is collapsed into the root "init"
// command.
type CanonicalRedirectError struct {
	Old string
	New string
}

// Error returns a human-readable description.
func (e *CanonicalRedirectError) Error() string {
	return "subcommand '" + e.Old +
		"' has been replaced by '" + e.New +
		"' (per docs/08-bootstrap-auth-architecture.md §6). Run: " + e.New
}

// newInitCommand returns a redirect stub. Per
// docs/08-bootstrap-auth-architecture.md §6 the legacy
// "platformctl ceremony init" subcommand is collapsed into the root
// "platformctl init" command.
func newInitCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:                "init",
		Short:              "REMOVED: use the root 'platformctl init' command instead",
		Long:               "The legacy \"platformctl ceremony init\" command has been collapsed into the root \"platformctl init\" command per docs/08-bootstrap-auth-architecture.md §6.",
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return &CanonicalRedirectError{
				Old: "platformctl ceremony init",
				New: "platformctl init --barrier-strategy <name> --so-pin ... --user-pin ... [...]",
			}
		},
	}
}
