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

package cli

import "github.com/spf13/cobra"

// MarkFlagsRequired marks flags the command has just defined as required.
// Cobra fails only for a flag the command does not define, which is a
// programming error, so it panics with ErrFlagSetup while the command tree is
// built rather than letting the command run without the check.
func MarkFlagsRequired(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(ErrFlagSetup{Command: cmd.Name(), Flag: name, Err: err})
		}
	}
}
