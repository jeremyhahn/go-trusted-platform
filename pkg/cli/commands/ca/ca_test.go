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
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// testGetFlags returns a test getFlags function for use in tests.
func testGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}
}

// findSubcommand resolves a command path under a fresh ca root command.
func findSubcommand(t *testing.T, path ...string) *cobra.Command {
	t.Helper()
	cmd, _, err := NewCommand(testGetFlags()).Find(path)
	require.NoError(t, err)
	require.Equal(t, path[len(path)-1], cmd.Name())
	return cmd
}

// TestNewCommand verifies the root command and every registered subcommand.
func TestNewCommand(t *testing.T) {
	cmd := NewCommand(testGetFlags())

	assert.Equal(t, "ca", cmd.Use)
	assert.Equal(t, "Certificate Authority operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage Certificate Authority")

	var names []string
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	for _, want := range []string{
		"init", "info", "issue", "sign-csr", "certificate", "list", "verify",
		"revoke", "renew", "crl", "bundle", "export-bundle",
		"install-ca-certificates", "uninstall-ca-certificates",
	} {
		assert.Contains(t, names, want)
	}
}

// TestCommands_NoDaemon executes every command through the ca root with its
// flags set: the flags parse, getFlags is consulted and the run function
// reports that no daemon connection is configured.
func TestCommands_NoDaemon(t *testing.T) {
	testCases := []struct {
		name string
		args []string
	}{
		{"init", []string{"init"}},
		{"info", []string{"info"}},
		{"issue", []string{"issue", "example.com", "pkcs8", "ECDSA-P256",
			"--key-size", "2048",
			"--sans-dns", "www.example.com,api.example.com",
			"--sans-ips", "192.168.1.1,10.0.0.1",
			"--sans-email", "admin@example.com"}},
		{"certificate", []string{"certificate", "1234567890ABCDEF", "--pem"}},
		{"list", []string{"list", "--status", "valid", "--issuer", "My CA",
			"--page", "2", "--page-size", "50"}},
		{"verify", []string{"verify", "/path/to/cert.pem", "--crl=false", "--expiry=true"}},
		{"revoke", []string{"revoke", "1234567890ABCDEF", "--reason", "unspecified", "--delete-keys"}},
		{"renew", []string{"renew", "123456789", "--days", "730", "--force"}},
		{"crl", []string{"crl"}},
		{"crl export", []string{"crl", "export", "--output", "/path/to/crl.pem"}},
		{"install", []string{"install-ca-certificates"}},
		{"uninstall", []string{"uninstall-ca-certificates"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			getFlags := func() *cli.CommonFlags {
				called = true
				return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
			}

			cmd := NewCommand(getFlags)
			cmd.SetArgs(tc.args)
			err := cmd.Execute()

			require.Error(t, err)
			var daemonErr ErrDaemonConnectionRequired
			assert.True(t, errors.As(err, &daemonErr), "got %T: %v", err, err)
			assert.True(t, called, "getFlags should be called")
		})
	}
}

// TestCommands_ArgsValidation verifies the positional-argument and
// required-flag rules reject bad invocations before any daemon call.
func TestCommands_ArgsValidation(t *testing.T) {
	testCases := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"issue no args", []string{"issue"}, "accepts 3 arg(s)"},
		{"issue one arg", []string{"issue", "example.com"}, "accepts 3 arg(s)"},
		{"issue two args", []string{"issue", "example.com", "pkcs8"}, "accepts 3 arg(s)"},
		{"certificate no args", []string{"certificate"}, "accepts 1 arg(s)"},
		{"verify extra arg", []string{"verify", "/path/to/cert.pem", "extra-arg"}, "accepts 1 arg(s)"},
		{"revoke no args", []string{"revoke"}, "accepts 1 arg(s)"},
		{"renew no args", []string{"renew"}, "accepts 1 arg(s)"},
		{"crl export without output", []string{"crl", "export"}, "required flag"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewCommand(testGetFlags())
			cmd.SetArgs(tc.args)
			err := cmd.Execute()

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// TestCommands_FlagDefaults verifies the documented flag defaults.
func TestCommands_FlagDefaults(t *testing.T) {
	testCases := []struct {
		path []string
		flag string
		want string
	}{
		{[]string{"issue"}, "sans-dns", ""},
		{[]string{"issue"}, "sans-ips", ""},
		{[]string{"issue"}, "sans-email", ""},
		{[]string{"certificate"}, "pem", "false"},
		{[]string{"list"}, "status", "all"},
		{[]string{"list"}, "issuer", ""},
		{[]string{"verify"}, "crl", "true"},
		{[]string{"verify"}, "expiry", "true"},
		{[]string{"revoke"}, "delete-keys", "false"},
		{[]string{"renew"}, "days", "365"},
		{[]string{"renew"}, "force", "false"},
		{[]string{"crl", "export"}, "output", ""},
	}

	for _, tc := range testCases {
		t.Run(strings.Join(tc.path, " ")+" --"+tc.flag, func(t *testing.T) {
			flag := findSubcommand(t, tc.path...).Flag(tc.flag)
			require.NotNil(t, flag)
			assert.Equal(t, tc.want, flag.DefValue)
		})
	}
}

// TestCommands_HelpText verifies every command carries a meaningful short
// description and examples in its long description.
func TestCommands_HelpText(t *testing.T) {
	for _, name := range []string{
		"init", "info", "issue", "certificate", "list", "verify", "revoke",
		"renew", "crl", "install-ca-certificates", "uninstall-ca-certificates",
	} {
		t.Run(name, func(t *testing.T) {
			cmd := findSubcommand(t, name)
			assert.Greater(t, len(cmd.Short), 5)
			assert.Contains(t, cmd.Long, "Example")
		})
	}
	assert.Greater(t, len(findSubcommand(t, "crl", "export").Short), 5)
}
