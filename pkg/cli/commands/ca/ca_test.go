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

// getCommandName extracts the command name from the Use field.
// The Use field may contain arguments like "issue [cn] [store] [algorithm]".
func getCommandName(use string) string {
	parts := strings.Split(use, " ")
	return parts[0]
}

// TestNewCommand verifies the CA root command is created correctly with all subcommands.
func TestNewCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := NewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "ca", cmd.Use)
	assert.Equal(t, "Certificate Authority operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage Certificate Authority")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.GreaterOrEqual(t, len(subcommands), 10) // at least 10 CA subcommands

	// Verify some expected subcommands exist
	expectedCommands := map[string]bool{
		"init":        false,
		"info":        false,
		"issue":       false,
		"certificate": false,
		"list":        false,
		"verify":      false,
		"revoke":      false,
		"renew":       false,
		"crl":         false,
	}

	for _, sub := range subcommands {
		cmdName := getCommandName(sub.Use)
		if _, ok := expectedCommands[cmdName]; ok {
			expectedCommands[cmdName] = true
		}
	}

	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

// TestNewInitCommand verifies the init command is created correctly.
func TestNewInitCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newInitCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "init", cmd.Use)
	assert.Equal(t, "Initialize the Certificate Authority", cmd.Short)
	assert.Contains(t, cmd.Long, "Initialize the Certificate Authority")
	assert.NotNil(t, cmd.RunE)
}

// TestRunInit verifies the init command returns ErrDaemonConnectionRequired.
func TestRunInit(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runInit(flags, false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunInitWithForce verifies the init command handles the force parameter.
func TestRunInitWithForce(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runInit(flags, true)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewInfoCommand verifies the info command is created correctly.
func TestNewInfoCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newInfoCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "info", cmd.Use)
	assert.Equal(t, "Display information about the Certificate Authority", cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

// TestRunInfo verifies the info command returns ErrDaemonConnectionRequired.
func TestRunInfo(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runInfo(flags)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewIssueCommand verifies the issue command is created correctly.
func TestNewIssueCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newIssueCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "issue [cn] [store] [algorithm]", cmd.Use)
	assert.Equal(t, "Issue a new x509 certificate", cmd.Short)
	assert.Contains(t, cmd.Long, "Issue a new x509 certificate")
	assert.NotNil(t, cmd.RunE)

	// Verify flags
	keySizeFlag := cmd.Flag("key-size")
	require.NotNil(t, keySizeFlag)

	sansDNSFlag := cmd.Flag("sans-dns")
	require.NotNil(t, sansDNSFlag)
	assert.Equal(t, "", sansDNSFlag.DefValue)

	sansIPsFlag := cmd.Flag("sans-ips")
	require.NotNil(t, sansIPsFlag)
	assert.Equal(t, "", sansIPsFlag.DefValue)

	sansEmailFlag := cmd.Flag("sans-email")
	require.NotNil(t, sansEmailFlag)
	assert.Equal(t, "", sansEmailFlag.DefValue)
}

// TestIssueCommandArgsValidation verifies the issue command requires exactly 3 arguments.
func TestIssueCommandArgsValidation(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newIssueCommand(getFlags)

	// Test with no arguments
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 3 arg(s)")

	// Test with 1 argument
	cmd.SetArgs([]string{"example.com"})
	err = cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 3 arg(s)")

	// Test with 2 arguments
	cmd.SetArgs([]string{"example.com", "pkcs8"})
	err = cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 3 arg(s)")
}

// TestRunIssue verifies the issue command returns ErrDaemonConnectionRequired.
func TestRunIssue(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runIssue(flags, cn, store, algorithm, keySize, validDays, sansDNS, sansIPs, sansEmail, keyUsage, extKeyUsage)
	err := runIssue(flags, "example.com", "pkcs8", "ECDSA-P256", 0, 365, "", "", "", "", "")

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewCertificateCommand verifies the certificate command is created correctly.
func TestNewCertificateCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newCertificateCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "certificate [serial]", cmd.Use)
	assert.Equal(t, "Retrieve an x509 certificate by serial number", cmd.Short)
	assert.Contains(t, cmd.Long, "Retrieve an x509 certificate")
	assert.NotNil(t, cmd.RunE)

	// Verify pem flag
	pemFlag := cmd.Flag("pem")
	require.NotNil(t, pemFlag)
	assert.Equal(t, "false", pemFlag.DefValue)
}

// TestCertificateCommandArgsValidation verifies the certificate command requires exactly 1 argument.
func TestCertificateCommandArgsValidation(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newCertificateCommand(getFlags)

	// Test with no arguments
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestRunCertificate verifies the certificate command returns ErrDaemonConnectionRequired.
func TestRunCertificate(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runCertificate(flags, serial, includePem, includeDer)
	err := runCertificate(flags, "1234567890ABCDEF", false, false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewListCommand verifies the list command is created correctly.
func TestNewListCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newListCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List issued certificates", cmd.Short)
	assert.Contains(t, cmd.Long, "List all certificates")
	assert.NotNil(t, cmd.RunE)

	// Verify flags
	statusFlag := cmd.Flag("status")
	require.NotNil(t, statusFlag)
	assert.Equal(t, "all", statusFlag.DefValue)

	issuerFlag := cmd.Flag("issuer")
	require.NotNil(t, issuerFlag)
	assert.Equal(t, "", issuerFlag.DefValue)

	pageFlag := cmd.Flag("page")
	require.NotNil(t, pageFlag)

	pageSizeFlag := cmd.Flag("page-size")
	require.NotNil(t, pageSizeFlag)
}

// TestRunList verifies the list command returns ErrDaemonConnectionRequired.
func TestRunList(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runList(flags, status, issuer, page, pageSize)
	err := runList(flags, "all", "", 1, 50)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewVerifyCommand verifies the verify command is created correctly.
func TestNewVerifyCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newVerifyCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "verify [cert-path]", cmd.Use)
	assert.Equal(t, "Verify a certificate", cmd.Short)
	assert.Contains(t, cmd.Long, "Verify a certificate")
	assert.NotNil(t, cmd.RunE)

	// Verify flags
	crlFlag := cmd.Flag("crl")
	require.NotNil(t, crlFlag)
	assert.Equal(t, "true", crlFlag.DefValue)

	expiryFlag := cmd.Flag("expiry")
	require.NotNil(t, expiryFlag)
	assert.Equal(t, "true", expiryFlag.DefValue)
}

// TestVerifyCommandMaxArgs verifies the verify command accepts exactly 1 argument.
func TestVerifyCommandMaxArgs(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newVerifyCommand(getFlags)

	// Test with too many arguments
	cmd.SetArgs([]string{"/path/to/cert.pem", "extra-arg"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestRunVerify verifies the verify command returns error (file not found or daemon error).
func TestRunVerify(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runVerify(flags, certPath, checkCRL, checkExpiry)
	err := runVerify(flags, "/path/to/cert.pem", true, true)

	// Will fail either due to file not found or daemon connection
	require.Error(t, err)
}

// TestNewRevokeCommand verifies the revoke command is created correctly.
func TestNewRevokeCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newRevokeCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "revoke [serial]", cmd.Use)
	assert.Equal(t, "Revoke an issued certificate", cmd.Short)
	assert.Contains(t, cmd.Long, "Revoke an issued certificate")
	assert.Contains(t, cmd.Long, "Certificate Revocation List")
	assert.NotNil(t, cmd.RunE)

	// Verify delete-keys flag
	deleteKeysFlag := cmd.Flag("delete-keys")
	require.NotNil(t, deleteKeysFlag)
	assert.Equal(t, "false", deleteKeysFlag.DefValue)

	// Verify reason flag
	reasonFlag := cmd.Flag("reason")
	require.NotNil(t, reasonFlag)
}

// TestRevokeCommandArgsValidation verifies the revoke command requires exactly 1 argument.
func TestRevokeCommandArgsValidation(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newRevokeCommand(getFlags)

	// Test with no arguments
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestRunRevoke verifies the revoke command returns ErrDaemonConnectionRequired.
func TestRunRevoke(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runRevoke(flags, serial, reason, deleteKeys)
	err := runRevoke(flags, "1234567890ABCDEF", "unspecified", true)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunRevokeWithoutDeleteKeys verifies revoke command handles delete-keys=false.
func TestRunRevokeWithoutDeleteKeys(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runRevoke(flags, serial, reason, deleteKeys)
	err := runRevoke(flags, "1234567890ABCDEF", "unspecified", false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewRenewCommand verifies the renew command is created correctly.
func TestNewRenewCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newRenewCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "renew <serial>", cmd.Use)
	assert.Equal(t, "Renew an existing certificate", cmd.Short)
	assert.Contains(t, cmd.Long, "Renew an existing certificate")
	assert.NotNil(t, cmd.RunE)

	// Verify flags
	daysFlag := cmd.Flag("days")
	require.NotNil(t, daysFlag)
	assert.Equal(t, "365", daysFlag.DefValue)

	forceFlag := cmd.Flag("force")
	require.NotNil(t, forceFlag)
	assert.Equal(t, "false", forceFlag.DefValue)
}

// TestRenewCommandArgsValidation verifies the renew command requires exactly 1 argument.
func TestRenewCommandArgsValidation(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newRenewCommand(getFlags)

	// Test with no arguments
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestRunRenew verifies the renew command returns ErrDaemonConnectionRequired.
func TestRunRenew(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runRenew(flags, "123456789", 365, false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunRenewWithForce verifies renew command handles force parameter.
func TestRunRenewWithForce(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runRenew(flags, "123456789", 730, true)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewCRLCommand verifies the crl command is created correctly.
func TestNewCRLCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newCRLCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "crl", cmd.Use)
	assert.Equal(t, "Certificate Revocation List operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Certificate Revocation List")
	assert.NotNil(t, cmd.RunE)

	// Verify subcommands are registered (at least export)
	subcommands := cmd.Commands()
	assert.GreaterOrEqual(t, len(subcommands), 1)

	var hasExport bool
	for _, sub := range subcommands {
		if sub.Use == "export" {
			hasExport = true
		}
	}

	assert.True(t, hasExport, "export subcommand should exist")
}

// TestRunCRL verifies the crl command returns ErrDaemonConnectionRequired.
func TestRunCRL(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runCRL(flags, includeEntries)
	err := runCRL(flags, false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewCRLExportCommand verifies the crl export command is created correctly.
func TestNewCRLExportCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newCRLExportCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "export", cmd.Use)
	assert.Equal(t, "Export CRL to file", cmd.Short)
	assert.Contains(t, cmd.Long, "Export the Certificate Revocation List")
	assert.NotNil(t, cmd.RunE)

	// Verify output flag
	outputFlag := cmd.Flag("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "", outputFlag.DefValue)
}

// TestCRLExportCommandRequiredFlag verifies the crl export command has required output flag.
func TestCRLExportCommandRequiredFlag(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newCRLExportCommand(getFlags)

	// Test without required flag
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "required flag")
}

// TestRunCRLExport verifies the crl export command returns ErrDaemonConnectionRequired.
func TestRunCRLExport(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runCRLExport(flags, "/path/to/crl.pem")

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewInstallCommand verifies the install-ca-certificates command is created correctly.
func TestNewInstallCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newInstallCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "install-ca-certificates", cmd.Use)
	assert.Equal(t, "Install Certificate Authority certificates", cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

// TestRunInstall verifies the install command returns ErrDaemonConnectionRequired.
func TestRunInstall(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runInstall(flags, true)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunInstallWithoutIntermediates verifies install command handles include-intermediates=false.
func TestRunInstallWithoutIntermediates(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runInstall(flags, false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestNewUninstallCommand verifies the uninstall-ca-certificates command is created correctly.
func TestNewUninstallCommand(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newUninstallCommand(getFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "uninstall-ca-certificates", cmd.Use)
	assert.Equal(t, "Uninstall Certificate Authority certificates", cmd.Short)
	assert.NotNil(t, cmd.RunE)
}

// TestRunUninstall verifies the uninstall command returns ErrDaemonConnectionRequired.
func TestRunUninstall(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runUninstall(flags, true)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunUninstallWithoutIntermediates verifies uninstall command handles include-intermediates=false.
func TestRunUninstallWithoutIntermediates(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runUninstall(flags, false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestCommandLongDescriptions verifies all commands have descriptive Long help text.
func TestCommandLongDescriptions(t *testing.T) {
	getFlags := testGetFlags()

	testCases := []struct {
		name      string
		cmd       func(func() *cli.CommonFlags) *cobra.Command
		minLength int
	}{
		{
			name:      "init",
			cmd:       newInitCommand,
			minLength: 50,
		},
		{
			name:      "info",
			cmd:       newInfoCommand,
			minLength: 50,
		},
		{
			name:      "issue",
			cmd:       newIssueCommand,
			minLength: 100,
		},
		{
			name:      "certificate",
			cmd:       newCertificateCommand,
			minLength: 50,
		},
		{
			name:      "list",
			cmd:       newListCommand,
			minLength: 100,
		},
		{
			name:      "verify",
			cmd:       newVerifyCommand,
			minLength: 100,
		},
		{
			name:      "revoke",
			cmd:       newRevokeCommand,
			minLength: 100,
		},
		{
			name:      "renew",
			cmd:       newRenewCommand,
			minLength: 100,
		},
		{
			name:      "crl",
			cmd:       newCRLCommand,
			minLength: 50,
		},
		{
			name:      "install",
			cmd:       newInstallCommand,
			minLength: 50,
		},
		{
			name:      "uninstall",
			cmd:       newUninstallCommand,
			minLength: 50,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.cmd(getFlags)
			assert.GreaterOrEqual(t, len(cmd.Long), tc.minLength,
				"%s command Long description should be at least %d chars", tc.name, tc.minLength)
		})
	}
}

// TestCommandExamples verifies commands have usage examples in their Long descriptions.
func TestCommandExamples(t *testing.T) {
	getFlags := testGetFlags()

	commands := []func(func() *cli.CommonFlags) *cobra.Command{
		newInitCommand,
		newInfoCommand,
		newIssueCommand,
		newCertificateCommand,
		newListCommand,
		newVerifyCommand,
		newRevokeCommand,
		newRenewCommand,
		newCRLCommand,
		newInstallCommand,
		newUninstallCommand,
	}

	for _, cmdFunc := range commands {
		cmd := cmdFunc(getFlags)
		t.Run(getCommandName(cmd.Use), func(t *testing.T) {
			assert.Contains(t, cmd.Long, "Example",
				"%s command should have examples in Long description", cmd.Use)
		})
	}
}

// TestIssueCommandWithSANsFlags verifies issue command accepts SAN flags.
func TestIssueCommandWithSANsFlags(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newIssueCommand(getFlags)
	cmd.SetArgs([]string{
		"example.com",
		"pkcs8",
		"ECDSA-P256",
		"--sans-dns", "www.example.com,api.example.com",
		"--sans-ips", "192.168.1.1,10.0.0.1",
		"--sans-email", "admin@example.com",
	})

	// Command should execute but return daemon error
	err := cmd.Execute()
	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestVerifyCommandWithOptions verifies verify command accepts all option combinations.
func TestVerifyCommandWithOptions(t *testing.T) {
	getFlags := testGetFlags()

	testCases := []struct {
		name string
		args []string
	}{
		{
			name: "with cert path only",
			args: []string{"/path/to/cert.pem"},
		},
		{
			name: "with crl disabled",
			args: []string{"/path/to/cert.pem", "--crl=false"},
		},
		{
			name: "with all options",
			args: []string{"/path/to/cert.pem", "--crl=true", "--expiry=true"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newVerifyCommand(getFlags)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			// Will fail either due to file not found or daemon connection
			require.Error(t, err)
		})
	}
}

// TestListCommandWithFilters verifies list command accepts filter flags.
func TestListCommandWithFilters(t *testing.T) {
	getFlags := testGetFlags()

	testCases := []struct {
		name string
		args []string
	}{
		{
			name: "status valid",
			args: []string{"--status", "valid"},
		},
		{
			name: "status revoked",
			args: []string{"--status", "revoked"},
		},
		{
			name: "status expired",
			args: []string{"--status", "expired"},
		},
		{
			name: "with issuer filter",
			args: []string{"--issuer", "My Intermediate CA"},
		},
		{
			name: "with pagination",
			args: []string{"--page", "1", "--page-size", "20"},
		},
		{
			name: "all filters combined",
			args: []string{"--status", "valid", "--issuer", "My CA", "--page", "1", "--page-size", "50"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newListCommand(getFlags)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			require.Error(t, err)
			var daemonErr ErrDaemonConnectionRequired
			assert.True(t, errors.As(err, &daemonErr))
		})
	}
}

// TestRenewCommandWithDays verifies renew command accepts custom validity period.
func TestRenewCommandWithDays(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newRenewCommand(getFlags)
	cmd.SetArgs([]string{"123456789", "--days", "730"})

	err := cmd.Execute()
	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestCRLSubcommandExport verifies CRL export subcommand via parent.
func TestCRLSubcommandExport(t *testing.T) {
	getFlags := testGetFlags()

	cmd := newCRLCommand(getFlags)
	cmd.SetArgs([]string{"export", "--output", "/path/to/crl.pem"})

	err := cmd.Execute()
	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestCACommandHierarchy verifies the full command hierarchy.
func TestCACommandHierarchy(t *testing.T) {
	getFlags := testGetFlags()

	rootCmd := NewCommand(getFlags)

	// Execute init through root
	rootCmd.SetArgs([]string{"init"})
	err := rootCmd.Execute()
	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))

	// Execute issue through root
	rootCmd.SetArgs([]string{"issue", "example.com", "pkcs8", "ECDSA-P256"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.True(t, errors.As(err, &daemonErr))

	// Execute list through root
	rootCmd.SetArgs([]string{"list"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.True(t, errors.As(err, &daemonErr))

	// Execute crl export through root
	rootCmd.SetArgs([]string{"crl", "export", "--output", "/path/to/crl.pem"})
	err = rootCmd.Execute()
	require.Error(t, err)
	assert.True(t, errors.As(err, &daemonErr))
}

// TestCommandRunEFunctions verifies all commands have RunE functions properly set.
func TestCommandRunEFunctions(t *testing.T) {
	getFlags := testGetFlags()

	commands := []struct {
		name   string
		cmdGen func(func() *cli.CommonFlags) *cobra.Command
	}{
		{"init", newInitCommand},
		{"info", newInfoCommand},
		{"issue", newIssueCommand},
		{"certificate", newCertificateCommand},
		{"list", newListCommand},
		{"verify", newVerifyCommand},
		{"revoke", newRevokeCommand},
		{"renew", newRenewCommand},
		{"crl", newCRLCommand},
		{"install", newInstallCommand},
		{"uninstall", newUninstallCommand},
		{"crl-export", newCRLExportCommand},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.cmdGen(getFlags)
			assert.NotNil(t, cmd.RunE, "%s command should have RunE function", tc.name)
		})
	}
}

// TestNilFlagsHandling verifies commands handle the getFlags function call correctly.
func TestNilFlagsHandling(t *testing.T) {
	// This test verifies that the getFlags function is called during execution
	var flagsCalled bool

	getFlags := func() *cli.CommonFlags {
		flagsCalled = true
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newInitCommand(getFlags)
	cmd.SetArgs([]string{})

	_ = cmd.Execute()

	assert.True(t, flagsCalled, "getFlags should be called during command execution")
}

// TestAllCommandsCallGetFlags verifies all commands call getFlags during execution.
func TestAllCommandsCallGetFlags(t *testing.T) {
	testCases := []struct {
		name   string
		cmdGen func(func() *cli.CommonFlags) *cobra.Command
		args   []string
	}{
		{"init", newInitCommand, []string{}},
		{"info", newInfoCommand, []string{}},
		{"issue", newIssueCommand, []string{"cn", "store", "alg"}},
		{"certificate", newCertificateCommand, []string{"serial"}},
		{"list", newListCommand, []string{}},
		{"verify", newVerifyCommand, []string{"/path/cert.pem"}},
		{"revoke", newRevokeCommand, []string{"serial"}},
		{"renew", newRenewCommand, []string{"serial"}},
		{"crl", newCRLCommand, []string{}},
		{"install", newInstallCommand, []string{}},
		{"uninstall", newUninstallCommand, []string{}},
		{"crl-export", newCRLExportCommand, []string{"--output", "/path"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var called bool
			getFlags := func() *cli.CommonFlags {
				called = true
				return &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
			}

			cmd := tc.cmdGen(getFlags)
			cmd.SetArgs(tc.args)
			_ = cmd.Execute()

			assert.True(t, called, "%s command should call getFlags", tc.name)
		})
	}
}

// TestRunCertificateWithPEM verifies certificate command handles PEM flag.
func TestRunCertificateWithPEM(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runCertificate(flags, serial, includePem, includeDer)
	err := runCertificate(flags, "1234567890ABCDEF", true, false)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunListWithStatus verifies list command handles different status filters.
func TestRunListWithStatus(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	statuses := []string{"valid", "revoked", "expired", "all"}

	for _, status := range statuses {
		t.Run(status, func(t *testing.T) {
			// Match actual function signature: runList(flags, status, issuer, page, pageSize)
			err := runList(flags, status, "", 1, 50)
			require.Error(t, err)
			var daemonErr ErrDaemonConnectionRequired
			assert.True(t, errors.As(err, &daemonErr))
		})
	}
}

// TestRunListWithIssuerAndPagination verifies list command handles issuer and pagination.
func TestRunListWithIssuerAndPagination(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runList(flags, status, issuer, page, pageSize)
	err := runList(flags, "all", "CN=My CA", 2, 100)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunIssueWithKeySize verifies issue command handles key-size flag.
func TestRunIssueWithKeySize(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runIssue(flags, cn, store, algorithm, keySize, validDays, sansDNS, sansIPs, sansEmail, keyUsage, extKeyUsage)
	err := runIssue(flags, "example.com", "pkcs8", "RSA-2048", 2048, 365, "", "", "", "", "")

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestRunIssueWithAllSANs verifies issue command handles all SAN flags.
func TestRunIssueWithAllSANs(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	// Match actual function signature: runIssue(flags, cn, store, algorithm, keySize, validDays, sansDNS, sansIPs, sansEmail, keyUsage, extKeyUsage)
	err := runIssue(
		flags,
		"example.com",
		"pkcs8",
		"ECDSA-P256",
		0,
		365,
		"www.example.com,api.example.com",
		"192.168.1.1,10.0.0.1",
		"admin@example.com",
		"digitalSignature",
		"serverAuth",
	)

	require.Error(t, err)
	var daemonErr ErrDaemonConnectionRequired
	assert.True(t, errors.As(err, &daemonErr))
}

// TestCommandShortDescriptions verifies all commands have short descriptions.
func TestCommandShortDescriptions(t *testing.T) {
	getFlags := testGetFlags()

	commands := []struct {
		name    string
		cmdFunc func(func() *cli.CommonFlags) *cobra.Command
	}{
		{"init", newInitCommand},
		{"info", newInfoCommand},
		{"issue", newIssueCommand},
		{"certificate", newCertificateCommand},
		{"list", newListCommand},
		{"verify", newVerifyCommand},
		{"revoke", newRevokeCommand},
		{"renew", newRenewCommand},
		{"crl", newCRLCommand},
		{"install", newInstallCommand},
		{"uninstall", newUninstallCommand},
		{"crl-export", newCRLExportCommand},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.cmdFunc(getFlags)
			assert.NotEmpty(t, cmd.Short, "%s command should have Short description", tc.name)
			assert.Greater(t, len(cmd.Short), 5, "%s command Short description should be meaningful", tc.name)
		})
	}
}
