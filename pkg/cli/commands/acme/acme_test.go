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

package acme

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// testGetFlags returns a CommonFlags for testing
func testGetFlags() *cli.CommonFlags {
	return &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}
}

// The SDK-gap refusal each verb returns once its input is valid.
var (
	registerGap  = ErrACMEDaemonCallMissing{Command: "register", Section: "§7.3 newAccount"}
	renewGap     = ErrACMEDaemonCallMissing{Command: "renew", Section: "§7.4 order and finalize"}
	downloadGap  = ErrACMEDaemonCallMissing{Command: "download", Section: "§7.4.2 certificate download"}
	rotateKeyGap = ErrACMEDaemonCallMissing{Command: "rotate-key", Section: "§7.3.5 key change"}
)

// TestNewCommand verifies the ACME root command is properly configured
func TestNewCommand(t *testing.T) {
	cmd := NewCommand(testGetFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "acme", cmd.Use)
	assert.Equal(t, "ACME certificate management", cmd.Short)
	assert.Contains(t, cmd.Long, "Automated")
	assert.Contains(t, cmd.Long, "Certificate Management Environment")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 4) // download, register, renew, rotate-key

	// Verify all expected subcommands exist
	expectedCommands := map[string]bool{
		"download <certificate-url>": false,
		"register":                   false,
		"renew":                      false,
		"rotate-key":                 false,
	}
	for _, sub := range subcommands {
		if _, ok := expectedCommands[sub.Use]; ok {
			expectedCommands[sub.Use] = true
		}
	}
	for cmd, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmd)
	}
}

// TestNewCommand_SubcommandNames verifies subcommand names match expected values
func TestNewCommand_SubcommandNames(t *testing.T) {
	cmd := NewCommand(testGetFlags)

	subcommands := cmd.Commands()
	names := make([]string, len(subcommands))
	for i, sub := range subcommands {
		names[i] = sub.Name()
	}

	assert.Contains(t, names, "download")
	assert.Contains(t, names, "register")
	assert.Contains(t, names, "renew")
	assert.Contains(t, names, "rotate-key")
}

// TestNewDownloadCommand verifies the download command is properly configured
func TestNewDownloadCommand(t *testing.T) {
	cmd := newDownloadCommand(testGetFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "download <certificate-url>", cmd.Use)
	assert.Equal(t, "Download a certificate from the ACME server", cmd.Short)
	assert.Contains(t, cmd.Long, "certificate URL")

	// Verify Args requires exactly 1 argument
	assert.NotNil(t, cmd.Args)

	// Test with wrong number of args
	err := cmd.Args(cmd, []string{})
	assert.Error(t, err)

	err = cmd.Args(cmd, []string{"url1", "url2"})
	assert.Error(t, err)

	err = cmd.Args(cmd, []string{"https://acme-server/cert/123"})
	assert.NoError(t, err)
}

// TestNewDownloadCommand_RunE verifies download command execution
func TestNewDownloadCommand_RunE(t *testing.T) {
	cmd := newDownloadCommand(testGetFlags)

	// A valid URL passes validation and reaches the SDK gap
	cmd.SetArgs([]string{"https://acme-server/acme/cert/abc123"})
	err := cmd.Execute()

	require.Error(t, err)
	assert.True(t, errors.Is(err, downloadGap))
}

// TestNewRegisterCommand verifies the register command is properly configured
func TestNewRegisterCommand(t *testing.T) {
	cmd := newRegisterCommand(testGetFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "register", cmd.Use)
	assert.Equal(t, "Register a new ACME account", cmd.Short)
	assert.Contains(t, cmd.Long, "Register a new account")

	// Verify email flag exists
	emailFlag := cmd.Flag("email")
	require.NotNil(t, emailFlag)
	assert.Equal(t, "", emailFlag.DefValue)
	assert.Equal(t, "account email address for contact", emailFlag.Usage)
}

// TestNewRegisterCommand_RunE verifies register command execution
func TestNewRegisterCommand_RunE(t *testing.T) {
	cmd := newRegisterCommand(testGetFlags)

	// Without --email, validation refuses before the SDK gap
	err := cmd.Execute()

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingEmail{}))
	assert.False(t, errors.Is(err, registerGap))
}

// TestNewRegisterCommand_WithEmail verifies register command with email flag
func TestNewRegisterCommand_WithEmail(t *testing.T) {
	cmd := newRegisterCommand(testGetFlags)

	cmd.SetArgs([]string{"--email", "admin@example.com"})
	err := cmd.Execute()

	// A valid email passes validation and reaches the SDK gap
	require.Error(t, err)
	assert.True(t, errors.Is(err, registerGap))
}

// TestNewRenewCommand verifies the renew command is properly configured
func TestNewRenewCommand(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "renew", cmd.Use)
	assert.Equal(t, "Request or renew a certificate", cmd.Short)
	assert.Contains(t, cmd.Long, "certificate issuance flow")

	// Verify authorization flags
	authzFlag := cmd.Flag("authz")
	require.NotNil(t, authzFlag)
	assert.Equal(t, "dns", authzFlag.DefValue)

	challengeFlag := cmd.Flag("challenge")
	require.NotNil(t, challengeFlag)
	assert.Equal(t, "http-01", challengeFlag.DefValue)

	directoryFlag := cmd.Flag("directory")
	require.NotNil(t, directoryFlag)
	assert.Equal(t, "https://localhost:8443/api/v1/acme/directory", directoryFlag.DefValue)

	caCertFlag := cmd.Flag("ca-cert")
	require.NotNil(t, caCertFlag)
	assert.Equal(t, "ca-bundle.pem", caCertFlag.DefValue)

	emailFlag := cmd.Flag("email")
	require.NotNil(t, emailFlag)
	assert.Equal(t, "", emailFlag.DefValue)
}

// TestNewRenewCommand_SubjectFlags verifies renew command subject flags
func TestNewRenewCommand_SubjectFlags(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	// Verify subject flags exist
	subjectFlags := []string{
		"cn",
		"organization",
		"organizational-unit",
		"country",
		"province",
		"locality",
		"street-address",
		"postal-code",
	}

	for _, flagName := range subjectFlags {
		flag := cmd.Flag(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
		assert.Equal(t, "", flag.DefValue, "flag %s should have empty default", flagName)
	}
}

// TestNewRenewCommand_SANFlags verifies renew command SAN flags
func TestNewRenewCommand_SANFlags(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	// Verify SAN flags exist
	sansDNSFlag := cmd.Flag("sans-dns")
	require.NotNil(t, sansDNSFlag)
	assert.Equal(t, "[]", sansDNSFlag.DefValue)

	sansEmailFlag := cmd.Flag("sans-email")
	require.NotNil(t, sansEmailFlag)
	assert.Equal(t, "[]", sansEmailFlag.DefValue)

	sansIPFlag := cmd.Flag("sans-ip")
	require.NotNil(t, sansIPFlag)
	assert.Equal(t, "[]", sansIPFlag.DefValue)
}

// TestNewRenewCommand_RunE verifies renew command execution
func TestNewRenewCommand_RunE(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	// The defaults name no identifier, so validation refuses before the gap
	err := cmd.Execute()

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissingAuthorizationValue{}))
	assert.False(t, errors.Is(err, renewGap))
}

// TestNewRenewCommand_WithAllFlags verifies renew command with all flags set
func TestNewRenewCommand_WithAllFlags(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	cmd.SetArgs([]string{
		"--cn", "example.com",
		"--organization", "Example Corp",
		"--country", "US",
		"--province", "California",
		"--locality", "San Francisco",
		"--authz", "dns",
		"--challenge", "dns-01",
		"--sans-dns", "www.example.com",
		"--sans-dns", "api.example.com",
		"--email", "admin@example.com",
	})
	err := cmd.Execute()

	// Valid input reaches the SDK gap
	require.Error(t, err)
	assert.True(t, errors.Is(err, renewGap))
}

// TestNewRotateKeyCommand verifies the rotate-key command is properly configured
func TestNewRotateKeyCommand(t *testing.T) {
	cmd := newRotateKeyCommand(testGetFlags)

	require.NotNil(t, cmd)
	assert.Equal(t, "rotate-key", cmd.Use)
	assert.Equal(t, "Rotate the ACME account key", cmd.Short)
	assert.Contains(t, cmd.Long, "key rollover")
	assert.Contains(t, cmd.Long, "WARNING")
}

// TestNewRotateKeyCommand_RunE verifies rotate-key command execution
func TestNewRotateKeyCommand_RunE(t *testing.T) {
	cmd := newRotateKeyCommand(testGetFlags)

	err := cmd.Execute()

	require.Error(t, err)
	assert.True(t, errors.Is(err, rotateKeyGap))
}

// TestRunDownload verifies the runDownload function
func TestRunDownload(t *testing.T) {
	flags := testGetFlags()

	err := runDownload(flags, "https://acme-server/cert/123")

	require.Error(t, err)
	assert.True(t, errors.Is(err, downloadGap))
}

// TestRunDownload_InvalidURL verifies download refuses a URL that is not an
// absolute https URL before it reaches the SDK gap
func TestRunDownload_InvalidURL(t *testing.T) {
	testCases := []struct {
		name    string
		certURL string
		want    error
	}{
		{name: "empty", certURL: "", want: ErrMissingCertificateURL{}},
		{name: "http scheme", certURL: "http://acme-server/cert/123", want: ErrInvalidCertificateURL{URL: "http://acme-server/cert/123"}},
		{name: "relative", certURL: "/acme/cert/123", want: ErrInvalidCertificateURL{URL: "/acme/cert/123"}},
		{name: "no host", certURL: "https:///cert/123", want: ErrInvalidCertificateURL{URL: "https:///cert/123"}},
		{name: "unparseable", certURL: "https://acme server/%zz", want: ErrInvalidCertificateURL{URL: "https://acme server/%zz"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := runDownload(testGetFlags(), tc.certURL)

			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "got %v", err)
			assert.False(t, errors.Is(err, downloadGap))
		})
	}
}

// TestRunRegister verifies the runRegister function
func TestRunRegister(t *testing.T) {
	flags := testGetFlags()

	err := runRegister(flags, "admin@example.com")

	require.Error(t, err)
	assert.True(t, errors.Is(err, registerGap))
}

// TestRunRegister_InvalidEmail verifies register refuses a missing or
// malformed email before it reaches the SDK gap
func TestRunRegister_InvalidEmail(t *testing.T) {
	testCases := []struct {
		name  string
		email string
		want  error
	}{
		{name: "empty", email: "", want: ErrMissingEmail{}},
		{name: "no at sign", email: "admin.example.com", want: ErrInvalidEmail{Email: "admin.example.com"}},
		{name: "display name", email: "Admin <admin@example.com>", want: ErrInvalidEmail{Email: "Admin <admin@example.com>"}},
		{name: "mailto URL", email: "mailto:admin@example.com", want: ErrInvalidEmail{Email: "mailto:admin@example.com"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := runRegister(testGetFlags(), tc.email)

			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "got %v", err)
			assert.False(t, errors.Is(err, registerGap))
		})
	}
}

// TestRunRenew verifies the runRenew function
func TestRunRenew(t *testing.T) {
	testCases := []struct {
		name string
		rf   *renewFlags
	}{
		{name: "dns with CN", rf: &renewFlags{cn: "example.com", authzType: "dns", challengeType: "http-01"}},
		{name: "dns with SAN only", rf: &renewFlags{sansDNS: []string{"www.example.com"}, authzType: "dns", challengeType: "dns-01"}},
		{name: "ip with IP SAN", rf: &renewFlags{sansIPs: []string{"192.0.2.10"}, authzType: "ip", challengeType: "http-01"}},
		{name: "device attestation", rf: &renewFlags{cn: "device-01", authzType: "permanent-identifier", challengeType: "device-attest-01"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := runRenew(testGetFlags(), tc.rf)

			require.Error(t, err)
			assert.True(t, errors.Is(err, renewGap), "got %v", err)
		})
	}
}

// TestRunRenew_InvalidInput verifies renew refuses an invalid order before it
// reaches the SDK gap
func TestRunRenew_InvalidInput(t *testing.T) {
	testCases := []struct {
		name string
		rf   *renewFlags
		want error
	}{
		{name: "unknown authz", rf: &renewFlags{cn: "example.com", authzType: "invalid-authz-type", challengeType: "http-01"}, want: ErrInvalidAuthorizationType{Type: "invalid-authz-type"}},
		{name: "empty authz", rf: &renewFlags{cn: "example.com", challengeType: "http-01"}, want: ErrInvalidAuthorizationType{Type: ""}},
		{name: "unknown challenge", rf: &renewFlags{cn: "example.com", authzType: "dns", challengeType: "invalid-challenge-type"}, want: ErrInvalidChallengeType{Type: "invalid-challenge-type"}},
		{name: "ip without IP SAN", rf: &renewFlags{cn: "example.com", authzType: "ip", challengeType: "http-01"}, want: ErrIPAuthorizationRequiresIP{}},
		{name: "no identifier", rf: &renewFlags{authzType: "dns", challengeType: "http-01"}, want: ErrMissingAuthorizationValue{}},
		{name: "email SAN is not an identifier", rf: &renewFlags{sansEmails: []string{"admin@example.com"}, authzType: "dns", challengeType: "http-01"}, want: ErrMissingAuthorizationValue{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := runRenew(testGetFlags(), tc.rf)

			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "got %v", err)
			assert.False(t, errors.Is(err, renewGap))
		})
	}
}

// TestRunRotateKey verifies the runRotateKey function
func TestRunRotateKey(t *testing.T) {
	flags := testGetFlags()

	err := runRotateKey(flags)

	require.Error(t, err)
	assert.True(t, errors.Is(err, rotateKeyGap))
	assert.False(t, errors.Is(err, renewGap), "the gap names its own verb")
}

// TestRenewFlags_Initialization verifies renewFlags struct initialization
func TestRenewFlags_Initialization(t *testing.T) {
	rf := &renewFlags{
		authzType:          "dns",
		challengeType:      "http-01",
		directoryURL:       "https://localhost:8443/api/v1/acme/directory",
		caCert:             "ca-bundle.pem",
		email:              "admin@example.com",
		cn:                 "example.com",
		organization:       "Example Corp",
		organizationalUnit: "IT",
		country:            "US",
		province:           "California",
		locality:           "San Francisco",
		streetAddress:      "123 Main St",
		postalCode:         "94102",
		sansDNS:            []string{"www.example.com", "api.example.com"},
		sansEmails:         []string{"admin@example.com"},
		sansIPs:            []string{"192.168.1.1"},
	}

	assert.Equal(t, "dns", rf.authzType)
	assert.Equal(t, "http-01", rf.challengeType)
	assert.Equal(t, "https://localhost:8443/api/v1/acme/directory", rf.directoryURL)
	assert.Equal(t, "ca-bundle.pem", rf.caCert)
	assert.Equal(t, "admin@example.com", rf.email)
	assert.Equal(t, "example.com", rf.cn)
	assert.Equal(t, "Example Corp", rf.organization)
	assert.Equal(t, "IT", rf.organizationalUnit)
	assert.Equal(t, "US", rf.country)
	assert.Equal(t, "California", rf.province)
	assert.Equal(t, "San Francisco", rf.locality)
	assert.Equal(t, "123 Main St", rf.streetAddress)
	assert.Equal(t, "94102", rf.postalCode)
	assert.Len(t, rf.sansDNS, 2)
	assert.Len(t, rf.sansEmails, 1)
	assert.Len(t, rf.sansIPs, 1)
}

// TestNewCommand_LongDescription verifies the long description content
func TestNewCommand_LongDescription(t *testing.T) {
	cmd := NewCommand(testGetFlags)

	// Verify long description mentions key features
	assert.Contains(t, cmd.Long, "Account registration")
	assert.Contains(t, cmd.Long, "Certificate renewal")
	assert.Contains(t, cmd.Long, "Account key rotation")
	assert.Contains(t, cmd.Long, "Certificate download")
}

// TestNewDownloadCommand_Examples verifies download command examples
func TestNewDownloadCommand_Examples(t *testing.T) {
	cmd := newDownloadCommand(testGetFlags)

	assert.Contains(t, cmd.Long, "platformctl acme download")
	assert.Contains(t, cmd.Long, "acme/cert/abc123")
}

// TestNewRegisterCommand_Examples verifies register command examples
func TestNewRegisterCommand_Examples(t *testing.T) {
	cmd := newRegisterCommand(testGetFlags)

	assert.Contains(t, cmd.Long, "platformctl acme register")
	assert.Contains(t, cmd.Long, "--email")
}

// TestNewRenewCommand_Examples verifies renew command examples
func TestNewRenewCommand_Examples(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	assert.Contains(t, cmd.Long, "platformctl acme renew")
	assert.Contains(t, cmd.Long, "--cn example.com")
	assert.Contains(t, cmd.Long, "--sans-dns")
}

// TestNewRotateKeyCommand_Examples verifies rotate-key command examples
func TestNewRotateKeyCommand_Examples(t *testing.T) {
	cmd := newRotateKeyCommand(testGetFlags)

	assert.Contains(t, cmd.Long, "platformctl acme rotate-key")
}

// TestCommand_Hierarchy verifies command parent-child relationships
func TestCommand_Hierarchy(t *testing.T) {
	parentCmd := NewCommand(testGetFlags)

	// Verify each subcommand can find its parent after being added
	for _, sub := range parentCmd.Commands() {
		assert.Equal(t, parentCmd, sub.Parent())
	}
}

// TestNewCommand_WithDifferentOutputFormats verifies command works with different formats
func TestNewCommand_WithDifferentOutputFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format cli.OutputFormat
	}{
		{"JSON format", cli.OutputFormatJSON},
		{"Table format", cli.OutputFormatTable},
		{"YAML format", cli.OutputFormatYAML},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{
					OutputFormat: tc.format,
				}
			}

			cmd := NewCommand(getFlags)
			require.NotNil(t, cmd)
			assert.Equal(t, "acme", cmd.Use)
		})
	}
}

// TestNewRenewCommand_AuthorizationTypes verifies authorization type documentation
func TestNewRenewCommand_AuthorizationTypes(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	// Verify authorization types are documented
	assert.Contains(t, cmd.Long, "dns")
	assert.Contains(t, cmd.Long, "ip")
	assert.Contains(t, cmd.Long, "permanent-identifier")
}

// TestNewRenewCommand_ChallengeTypes verifies challenge type documentation
func TestNewRenewCommand_ChallengeTypes(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	// Verify challenge types are documented
	assert.Contains(t, cmd.Long, "http-01")
	assert.Contains(t, cmd.Long, "dns-01")
	assert.Contains(t, cmd.Long, "endorse-01")
	assert.Contains(t, cmd.Long, "device-01")
	assert.Contains(t, cmd.Long, "device-attest-01")
}

// TestDownloadCommand_RequiresArgument verifies download requires URL argument
func TestDownloadCommand_RequiresArgument(t *testing.T) {
	cmd := newDownloadCommand(testGetFlags)

	// Create a parent command to capture output
	rootCmd := &cobra.Command{Use: "root"}
	rootCmd.AddCommand(cmd)

	// Execute without args
	rootCmd.SetArgs([]string{"download"})
	err := rootCmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg")
}

// TestRegisterCommand_FlagParsing verifies flag parsing works correctly
func TestRegisterCommand_FlagParsing(t *testing.T) {
	var capturedEmail string
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := &cobra.Command{
		Use: "register",
		RunE: func(cmd *cobra.Command, args []string) error {
			email, _ := cmd.Flags().GetString("email")
			capturedEmail = email
			return nil
		},
	}
	cmd.Flags().String("email", "", "account email")

	cmd.SetArgs([]string{"--email", "test@example.com"})
	err := cmd.Execute()

	require.NoError(t, err)
	assert.Equal(t, "test@example.com", capturedEmail)

	// Verify getFlags is not nil
	assert.NotNil(t, getFlags)
}

// TestRenewCommand_MultipleSANs verifies multiple SANs can be specified
func TestRenewCommand_MultipleSANs(t *testing.T) {
	cmd := newRenewCommand(testGetFlags)

	cmd.SetArgs([]string{
		"--sans-dns", "www.example.com",
		"--sans-dns", "api.example.com",
		"--sans-dns", "mail.example.com",
		"--sans-ip", "192.168.1.1",
		"--sans-ip", "10.0.0.1",
		"--sans-email", "admin@example.com",
	})

	// The SANs are a valid identifier set, so execution reaches the SDK gap
	err := cmd.Execute()
	require.Error(t, err)
	assert.True(t, errors.Is(err, renewGap))

	// Verify the flags were parsed (command was set up correctly)
	sansDNS, _ := cmd.Flags().GetStringArray("sans-dns")
	assert.Len(t, sansDNS, 3)

	sansIP, _ := cmd.Flags().GetStringArray("sans-ip")
	assert.Len(t, sansIP, 2)

	sansEmail, _ := cmd.Flags().GetStringArray("sans-email")
	assert.Len(t, sansEmail, 1)
}

// TestCommandRunE_ReturnsError verifies all commands return appropriate errors
func TestCommandRunE_ReturnsError(t *testing.T) {
	testCases := []struct {
		name string
		cmd  *cobra.Command
		args []string
		want error
	}{
		{
			name: "download returns the SDK gap",
			cmd:  newDownloadCommand(testGetFlags),
			args: []string{"https://example.com/cert"},
			want: downloadGap,
		},
		{
			name: "register returns the SDK gap",
			cmd:  newRegisterCommand(testGetFlags),
			args: []string{"--email", "admin@example.com"},
			want: registerGap,
		},
		{
			name: "renew returns the SDK gap",
			cmd:  newRenewCommand(testGetFlags),
			args: []string{"--cn", "example.com"},
			want: renewGap,
		},
		{
			name: "rotate-key returns the SDK gap",
			cmd:  newRotateKeyCommand(testGetFlags),
			args: []string{},
			want: rotateKeyGap,
		},
		{
			name: "download refuses an http URL",
			cmd:  newDownloadCommand(testGetFlags),
			args: []string{"http://example.com/cert"},
			want: ErrInvalidCertificateURL{URL: "http://example.com/cert"},
		},
		{
			name: "register refuses a malformed email",
			cmd:  newRegisterCommand(testGetFlags),
			args: []string{"--email", "not-an-email"},
			want: ErrInvalidEmail{Email: "not-an-email"},
		},
		{
			name: "renew refuses an unknown challenge",
			cmd:  newRenewCommand(testGetFlags),
			args: []string{"--cn", "example.com", "--challenge", "tls-alpn-01"},
			want: ErrInvalidChallengeType{Type: "tls-alpn-01"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cmd.SetArgs(tc.args)
			err := tc.cmd.Execute()

			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.want), "got %v", err)
		})
	}
}

// TestNewCommand_CommandNaming verifies consistent command naming
func TestNewCommand_CommandNaming(t *testing.T) {
	cmd := NewCommand(testGetFlags)

	// Verify main command naming
	assert.Equal(t, "acme", cmd.Name())
	assert.Equal(t, "acme", cmd.Use)

	// Verify subcommands have consistent naming
	for _, sub := range cmd.Commands() {
		// Name should not contain spaces
		assert.NotContains(t, sub.Name(), " ")

		// Use may contain argument placeholders
		if sub.Name() == "download" {
			assert.Contains(t, sub.Use, "<certificate-url>")
		}
	}
}

// TestCommands_HaveShortDescriptions verifies all commands have short descriptions
func TestCommands_HaveShortDescriptions(t *testing.T) {
	cmd := NewCommand(testGetFlags)

	assert.NotEmpty(t, cmd.Short)

	for _, sub := range cmd.Commands() {
		assert.NotEmpty(t, sub.Short, "subcommand %s should have short description", sub.Name())
	}
}

// TestCommands_HaveLongDescriptions verifies all commands have long descriptions
func TestCommands_HaveLongDescriptions(t *testing.T) {
	cmd := NewCommand(testGetFlags)

	assert.NotEmpty(t, cmd.Long)

	for _, sub := range cmd.Commands() {
		assert.NotEmpty(t, sub.Long, "subcommand %s should have long description", sub.Name())
	}
}
