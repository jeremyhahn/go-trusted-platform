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

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestMarkFlagsRequired(t *testing.T) {
	cmd := &cobra.Command{Use: "sign", RunE: func(*cobra.Command, []string) error { return nil }}
	cmd.Flags().String("input", "", "")
	cmd.Flags().String("output", "", "")

	MarkFlagsRequired(cmd, "input", "output")

	cmd.SetArgs([]string{"--input", "in.efi"})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	require.ErrorContains(t, cmd.Execute(), `required flag(s) "output" not set`)
}

// Marking a flag the command does not define panics with ErrFlagSetup
// instead of being dropped, which left the flag silently optional.
func TestMarkFlagsRequiredUndefinedFlagPanics(t *testing.T) {
	cmd := &cobra.Command{Use: "sign"}

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		MarkFlagsRequired(cmd, "missing")
	}()

	err, ok := recovered.(error)
	require.True(t, ok, "panic value %v is not an error", recovered)
	var setupErr ErrFlagSetup
	require.True(t, errors.As(err, &setupErr))
	require.Equal(t, "sign", setupErr.Command)
	require.Equal(t, "missing", setupErr.Flag)
	require.Error(t, errors.Unwrap(err))
	require.Contains(t, err.Error(), `command "sign": failed to set up flag --missing`)
}
