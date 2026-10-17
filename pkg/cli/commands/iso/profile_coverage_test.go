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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// executeProfileCommand runs cmd through cobra with args and returns stdout.
func executeProfileCommand(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestProfileListCommand_Execute(t *testing.T) {
	out, err := executeProfileCommand(t, newProfileListCommand(getJSONTestFlags))
	require.NoError(t, err)

	var result profileListResult
	require.NoError(t, json.Unmarshal([]byte(out), &result), out)
	assert.Len(t, result.Profiles, 4)
}

func TestProfileShowCommand_Execute(t *testing.T) {
	out, err := executeProfileCommand(t, newProfileShowCommand(getJSONTestFlags), "fips")
	require.NoError(t, err)

	var result profileShowResult
	require.NoError(t, json.Unmarshal([]byte(out), &result), out)
	assert.Equal(t, "fips", result.Profile.Name)
	assert.True(t, result.Profile.FIPS)
}

func TestProfileShowCommand_TableOutput(t *testing.T) {
	out, err := executeProfileCommand(t, newProfileShowCommand(getTestFlags), "dev")
	require.NoError(t, err)
	assert.Contains(t, out, "dev")
}

func TestProfileValidateCommand_Execute_MissingFile(t *testing.T) {
	_, err := executeProfileCommand(t, newProfileValidateCommand(getJSONTestFlags), "/nonexistent/config.yaml")
	require.Error(t, err)
	assert.IsType(t, ErrConfigParseError{}, err)
}

func TestProfileGenerateCommand_Execute_RequiresProfile(t *testing.T) {
	_, err := executeProfileCommand(t, newProfileGenerateCommand(getJSONTestFlags))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "profile")
}

func TestProfileShowCommand_ExactArgs(t *testing.T) {
	_, err := executeProfileCommand(t, newProfileShowCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }))
	require.Error(t, err)
}

func TestProfileValidateCommand_ExactArgs(t *testing.T) {
	_, err := executeProfileCommand(t, newProfileValidateCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} }))
	require.Error(t, err)
}
