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

package iso

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// =============================================================================
// Profile Run* Function Tests (all return ErrDaemonConnectionRequired)
// =============================================================================

func TestRunProfileList_ReturnsDaemonRequired(t *testing.T) {
	flags := &cli.CommonFlags{}
	pFlags := &profileFlags{}
	err := runProfileList(flags, pFlags)
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestRunProfileShow_ReturnsDaemonRequired(t *testing.T) {
	flags := &cli.CommonFlags{}
	pFlags := &profileFlags{}
	err := runProfileShow(flags, pFlags, "dev")
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestRunProfileValidate_ReturnsDaemonRequired(t *testing.T) {
	flags := &cli.CommonFlags{}
	pFlags := &profileFlags{}
	err := runProfileValidate(flags, pFlags, "/tmp/config.yaml")
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestRunProfileGenerate_ReturnsDaemonRequired(t *testing.T) {
	flags := &cli.CommonFlags{}
	pFlags := &profileFlags{}
	genFlags := &generateProfileFlags{profileName: "dev"}
	err := runProfileGenerate(flags, pFlags, genFlags)
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

// =============================================================================
// Profile Command Execution Tests (execute via cobra)
// =============================================================================

func TestProfileListCommand_Execute(t *testing.T) {
	cmd := newProfileListCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }, &profileFlags{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestProfileShowCommand_Execute(t *testing.T) {
	cmd := newProfileShowCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }, &profileFlags{})
	cmd.SetArgs([]string{"dev"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

func TestProfileValidateCommand_Execute(t *testing.T) {
	cmd := newProfileValidateCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }, &profileFlags{})
	cmd.SetArgs([]string{"/tmp/config.yaml"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}

// =============================================================================
// Profile Command Structure Tests
// =============================================================================

func TestProfileListCommand_Aliases(t *testing.T) {
	cmd := newProfileListCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }, &profileFlags{})
	assert.Contains(t, cmd.Aliases, "ls")
}

func TestProfileShowCommand_ExactArgs(t *testing.T) {
	cmd := newProfileShowCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }, &profileFlags{})
	// Try with no args - should fail validation
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
}

func TestProfileValidateCommand_ExactArgs(t *testing.T) {
	cmd := newProfileValidateCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }, &profileFlags{})
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
}
