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

package ca

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestNewBundleCommand verifies the consolidated `ca bundle` command exposes
// the expected name, optional --output flag, and --intermediates flag (true
// by default). It replaces the old `ca export-bundle` command, which had a
// REQUIRED --output flag.
func TestNewBundleCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newBundleCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "bundle", cmd.Use)
	assert.NotEmpty(t, cmd.Short)
	assert.NotNil(t, cmd.RunE)

	// --output is OPTIONAL on the consolidated command (stdout-by-default).
	outputFlag := cmd.Flag("output")
	require.NotNil(t, outputFlag, "bundle command must expose --output")
	assert.Equal(t, "", outputFlag.DefValue, "--output should default to empty (stdout)")

	// --intermediates is true by default to match the prior export-bundle behavior.
	intFlag := cmd.Flag("intermediates")
	require.NotNil(t, intFlag, "bundle command must expose --intermediates")
	assert.Equal(t, "true", intFlag.DefValue, "--intermediates should default to true")
}

// TestRunBundleNoConnection verifies that runBundle bubbles up the
// daemon-connection error when no platformd is reachable. This exercises
// the same code path the CLI uses; the file write path is integration-tested
// in test/integration/ca.
func TestRunBundleNoConnection(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runBundle(flags, "", true)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr),
		"runBundle should fail with ErrDaemonConnectionRequired when context is unavailable")
}

// TestRunBundleNoConnectionWithOutput verifies the file-output path also
// returns ErrDaemonConnectionRequired when platformd is unreachable. The
// consolidated command must NOT panic when --output is set without a daemon.
func TestRunBundleNoConnectionWithOutput(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runBundle(flags, "/tmp/should-not-exist-bundle.pem", false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr),
		"runBundle should fail with ErrDaemonConnectionRequired even when --output is set")
}

// TestErrCABundleFailedNotShadowingExportName guards against a regression
// where the renamed error type accidentally retains the old "export"
// wording in its formatted message.
func TestErrCABundleFailedNotShadowingExportName(t *testing.T) {
	err := ErrCABundleFailed{Reason: "kms unavailable"}
	msg := err.Error()

	assert.NotContains(t, msg, "export", "renamed error should not mention export")
	assert.Contains(t, msg, "CA bundle")
	assert.Contains(t, msg, "kms unavailable")
}
