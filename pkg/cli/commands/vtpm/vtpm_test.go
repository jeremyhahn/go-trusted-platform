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

package vtpm

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// testGetFlags returns a CommonFlags getter for testing
func testGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}
}

// TestNewCommand tests the vtpm root command creation
// assertRunErr compares a run function's error with the table's. A
// connection failure must carry the setup error that caused it, so it is
// matched by type and a non-nil cause, not by value.
func assertRunErr(t *testing.T, want, got error) {
	t.Helper()
	var wantConn ErrDaemonConnectionRequired
	if errors.As(want, &wantConn) {
		var gotConn ErrDaemonConnectionRequired
		require.ErrorAs(t, got, &gotConn)
		require.Error(t, gotConn.Err, "the connection error must carry the setup failure")
		return
	}
	assert.Equal(t, want, got)
}

func TestNewCommand(t *testing.T) {
	cmd := NewCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "vtpm", cmd.Use)
	assert.Equal(t, "vTPM bundle management operations", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage virtual TPM (vTPM) bundles")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 15) // create, list, info, delete, clone, export, import, template, start, stop, is-running, quote, seal, unseal, pcr

	// Verify key subcommands exist by extracting command name from Use field
	expectedCommands := map[string]bool{
		"create":     false,
		"list":       false,
		"info":       false,
		"delete":     false,
		"clone":      false,
		"export":     false,
		"import":     false,
		"template":   false,
		"start":      false,
		"stop":       false,
		"is-running": false,
		"quote":      false,
		"seal":       false,
		"unseal":     false,
		"pcr":        false,
	}
	for _, sub := range subcommands {
		// Extract just the command name (first word of Use)
		cmdName := strings.Split(sub.Use, " ")[0]
		if _, ok := expectedCommands[cmdName]; ok {
			expectedCommands[cmdName] = true
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

// TestNewCreateCommand tests the create command structure
func TestNewCreateCommand(t *testing.T) {
	cmd := newCreateCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "create", cmd.Use)
	assert.Equal(t, "Create a pre-assigned vTPM bundle", cmd.Short)
	assert.Contains(t, cmd.Long, "pre-assigned vTPM bundle")

	// Verify flags
	hostnameFlag := cmd.Flag("hostname")
	require.NotNil(t, hostnameFlag)
	assert.Equal(t, "", hostnameFlag.DefValue)

	secureBootFlag := cmd.Flag("secure-boot")
	require.NotNil(t, secureBootFlag)
	assert.Equal(t, "true", secureBootFlag.DefValue)

	ekAlgFlag := cmd.Flag("ek-algorithm")
	require.NotNil(t, ekAlgFlag)
	assert.Equal(t, "RSA", ekAlgFlag.DefValue)
}

// TestRunCreate tests the create command run function
func TestRunCreate(t *testing.T) {
	// Tests for argument validation (don't need GetContext)
	t.Run("invalid EK algorithm", func(t *testing.T) {
		flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
		err := runCreate(flags, "vm001.example.com", true, "INVALID", "", nil)
		require.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "invalid ek algorithm")
	})

	// Tests for connection failures - should return ErrDaemonConnectionRequired
	t.Run("valid RSA EK algorithm but no daemon", func(t *testing.T) {
		flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
		err := runCreate(flags, "vm001.example.com", true, "RSA", "", nil)
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("valid ECC EK algorithm but no daemon", func(t *testing.T) {
		flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}
		err := runCreate(flags, "vm002.example.com", false, "ECC", "", nil)
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestParseEKAlgorithm tests EK algorithm parsing
func TestParseEKAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm   string
		expectErr   bool
		errContains string
	}{
		{"RSA", false, ""},
		{"ECC", false, ""},
		{"rsa", false, ""}, // parseEKAlgorithm uses ToUpper
		{"ecc", false, ""}, // parseEKAlgorithm uses ToUpper
		{"AES", true, "invalid EK algorithm"},
		{"", true, "invalid EK algorithm"},
		{"INVALID", true, "invalid EK algorithm"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			_, err := parseEKAlgorithm(tt.algorithm)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errContains))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestNewCloneCommand tests the clone command structure
func TestNewCloneCommand(t *testing.T) {
	cmd := newCloneCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "clone", cmd.Use)
	assert.Equal(t, "Clone a bundle from a template", cmd.Short)
	assert.Contains(t, cmd.Long, "Clone a new vTPM bundle")

	// Verify flags
	templateFlag := cmd.Flag("template")
	require.NotNil(t, templateFlag)
	assert.Equal(t, "", templateFlag.DefValue)

	hostnameFlag := cmd.Flag("hostname")
	require.NotNil(t, hostnameFlag)
	assert.Equal(t, "", hostnameFlag.DefValue)
}

// TestRunClone tests the clone command run function
func TestRunClone(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name       string
		templateID string
		hostname   string
		labels     []string
		expectErr  error
	}{
		{
			name:       "missing template ID",
			templateID: "",
			hostname:   "vm001.example.com",
			labels:     nil,
			expectErr:  ErrMissingRequiredFlag{Flag: "template"},
		},
		{
			name:       "missing hostname",
			templateID: "base-vtpm",
			hostname:   "",
			labels:     nil,
			expectErr:  ErrMissingRequiredFlag{Flag: "hostname"},
		},
		{
			name:       "valid inputs",
			templateID: "base-vtpm",
			hostname:   "vm001.example.com",
			labels:     nil,
			expectErr:  ErrDaemonConnectionRequired{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Match actual function signature: runClone(flags, templateID, hostname, labels)
			err := runClone(flags, tt.templateID, tt.hostname, tt.labels)
			require.Error(t, err)
			assertRunErr(t, tt.expectErr, err)
		})
	}
}

// TestNewListCommand tests the list command structure
func TestNewListCommand(t *testing.T) {
	cmd := newListCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List vTPM bundles", cmd.Short)
	assert.Contains(t, cmd.Long, "List all vTPM bundles")

	// Verify flags
	modeFlag := cmd.Flag("mode")
	require.NotNil(t, modeFlag)
	assert.Equal(t, "", modeFlag.DefValue)
}

// TestRunList tests the list command run function
func TestRunList(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name      string
		mode      string
		expectErr error
	}{
		{
			name:      "no filter",
			mode:      "",
			expectErr: ErrDaemonConnectionRequired{},
		},
		{
			name:      "template mode",
			mode:      "template",
			expectErr: ErrDaemonConnectionRequired{},
		},
		{
			name:      "pre-assigned mode",
			mode:      "pre-assigned",
			expectErr: ErrDaemonConnectionRequired{},
		},
		{
			name:      "invalid mode",
			mode:      "invalid",
			expectErr: ErrInvalidBundleMode{Mode: "invalid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runList(flags, tt.mode, 0, 0)
			require.Error(t, err)
			assertRunErr(t, tt.expectErr, err)
		})
	}
}

// TestParseBundleMode tests bundle mode parsing
func TestParseBundleMode(t *testing.T) {
	tests := []struct {
		mode        string
		expectErr   bool
		errContains string
	}{
		{"template", false, ""},
		{"pre-assigned", false, ""},
		{"preassigned", false, ""},  // accepts both formats
		{"Template", false, ""},     // parseBundleMode uses ToLower
		{"Pre-Assigned", false, ""}, // parseBundleMode uses ToLower
		{"", true, "invalid bundle mode"},
		{"invalid", true, "invalid bundle mode"},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			_, err := parseBundleMode(tt.mode)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errContains))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestNewInfoCommand tests the info command structure
func TestNewInfoCommand(t *testing.T) {
	cmd := newInfoCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "info [bundle-id]", cmd.Use)
	assert.Equal(t, "Display bundle information", cmd.Short)
	assert.Contains(t, cmd.Long, "Display detailed information")

	// Verify args validation
	assert.NotNil(t, cmd.Args)
}

// TestRunInfo tests the info command run function
func TestRunInfo(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name      string
		bundleID  string
		expectErr error
	}{
		{
			name:      "missing bundle ID",
			bundleID:  "",
			expectErr: ErrMissingRequiredFlag{Flag: "bundle-id"},
		},
		{
			name:      "valid bundle ID",
			bundleID:  "bundle-123",
			expectErr: ErrDaemonConnectionRequired{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runInfo(flags, tt.bundleID)
			require.Error(t, err)
			assertRunErr(t, tt.expectErr, err)
		})
	}
}

// TestNewDeleteCommand tests the delete command structure
func TestNewDeleteCommand(t *testing.T) {
	cmd := newDeleteCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "delete [bundle-id]", cmd.Use)
	assert.Equal(t, "Delete a vTPM bundle", cmd.Short)
	assert.Contains(t, cmd.Long, "Delete a vTPM bundle")

	// Verify flags
	forceFlag := cmd.Flag("force")
	require.NotNil(t, forceFlag)
	assert.Equal(t, "false", forceFlag.DefValue)
	assert.Equal(t, "f", forceFlag.Shorthand)

	// Verify args validation
	assert.NotNil(t, cmd.Args)
}

// TestRunDelete tests the delete command run function
func TestRunDelete(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name      string
		bundleID  string
		force     bool
		expectErr error
	}{
		{
			name:      "missing bundle ID",
			bundleID:  "",
			force:     false,
			expectErr: ErrMissingRequiredFlag{Flag: "bundle-id"},
		},
		{
			name:      "valid bundle ID without force",
			bundleID:  "bundle-123",
			force:     false,
			expectErr: ErrDaemonConnectionRequired{},
		},
		{
			name:      "valid bundle ID with force",
			bundleID:  "bundle-123",
			force:     true,
			expectErr: ErrDaemonConnectionRequired{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runDelete(flags, tt.bundleID, tt.force)
			require.Error(t, err)
			assertRunErr(t, tt.expectErr, err)
		})
	}
}

// TestNewExportCommand tests the export command structure
func TestNewExportCommand(t *testing.T) {
	cmd := newExportCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "export [bundle-id]", cmd.Use)
	assert.Equal(t, "Export a vTPM bundle to archive", cmd.Short)
	assert.Contains(t, cmd.Long, "Export a vTPM bundle")

	// Verify flags
	outputFlag := cmd.Flag("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "", outputFlag.DefValue)
	assert.Equal(t, "o", outputFlag.Shorthand)

	// Verify args validation
	assert.NotNil(t, cmd.Args)
}

// TestRunExport tests the export command run function
func TestRunExport(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name      string
		bundleID  string
		output    string
		overwrite bool
		expectErr error
	}{
		{
			name:      "missing bundle ID",
			bundleID:  "",
			output:    "",
			overwrite: false,
			expectErr: ErrMissingRequiredFlag{Flag: "bundle-id"},
		},
		{
			name:      "valid bundle ID default output",
			bundleID:  "bundle-123",
			output:    "",
			overwrite: false,
			expectErr: ErrDaemonConnectionRequired{},
		},
		{
			name:      "valid bundle ID custom output",
			bundleID:  "bundle-123",
			output:    "my-bundle.vtpm.tar.gz",
			overwrite: false,
			expectErr: ErrDaemonConnectionRequired{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Match actual function signature: runExport(flags, bundleID, output, overwrite)
			err := runExport(flags, tt.bundleID, tt.output, tt.overwrite)
			require.Error(t, err)
			assertRunErr(t, tt.expectErr, err)
		})
	}
}

// TestNewImportCommand tests the import command structure
func TestNewImportCommand(t *testing.T) {
	cmd := newImportCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "import [archive-path]", cmd.Use)
	assert.Equal(t, "Import a vTPM bundle from archive", cmd.Short)
	assert.Contains(t, cmd.Long, "Import a vTPM bundle")

	// Verify args validation
	assert.NotNil(t, cmd.Args)
}

// TestRunImport tests the import command run function
func TestRunImport(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name        string
		archivePath string
		expectErr   error
	}{
		{
			name:        "missing archive path",
			archivePath: "",
			expectErr:   ErrMissingRequiredFlag{Flag: "archive-path"},
		},
		{
			name:        "nonexistent archive path",
			archivePath: "bundle.vtpm.tar.gz",
			expectErr:   ErrOpenArchiveFailed{Path: "bundle.vtpm.tar.gz", Reason: "stat bundle.vtpm.tar.gz: no such file or directory"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runImport(flags, tt.archivePath)
			require.Error(t, err)
			assertRunErr(t, tt.expectErr, err)
		})
	}
}

// TestNewTemplateCommand tests the template root command structure
func TestNewTemplateCommand(t *testing.T) {
	cmd := newTemplateCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "template", cmd.Use)
	assert.Equal(t, "Manage vTPM templates", cmd.Short)
	assert.Contains(t, cmd.Long, "Manage vTPM templates for cloning")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 3) // create, list, delete

	expectedCommands := map[string]bool{
		"create": false,
		"list":   false,
		"delete": false,
	}
	for _, sub := range subcommands {
		// Extract just the command name (first word of Use)
		cmdName := strings.Split(sub.Use, " ")[0]
		if _, ok := expectedCommands[cmdName]; ok {
			expectedCommands[cmdName] = true
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

// TestNewTemplateCreateCommand tests the template create command structure
func TestNewTemplateCreateCommand(t *testing.T) {
	cmd := newTemplateCreateCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "create", cmd.Use)
	assert.Equal(t, "Create a new template", cmd.Short)
	assert.Contains(t, cmd.Long, "Create a new vTPM template")

	// Verify flags
	idFlag := cmd.Flag("id")
	require.NotNil(t, idFlag)
	assert.Equal(t, "", idFlag.DefValue)

	secureBootFlag := cmd.Flag("secure-boot")
	require.NotNil(t, secureBootFlag)
	assert.Equal(t, "true", secureBootFlag.DefValue)

	ekAlgFlag := cmd.Flag("ek-algorithm")
	require.NotNil(t, ekAlgFlag)
	assert.Equal(t, "RSA", ekAlgFlag.DefValue)
}

// TestRunTemplateCreate tests the template create command run function
func TestRunTemplateCreate(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name        string
		id          string
		description string
		secureBoot  bool
		ekAlgorithm string
		expectErr   bool
		errContains string
	}{
		{
			name:        "missing ID",
			id:          "",
			description: "",
			secureBoot:  true,
			ekAlgorithm: "RSA",
			expectErr:   true,
			errContains: "missing required flag",
		},
		{
			name:        "invalid EK algorithm",
			id:          "base-vtpm",
			description: "",
			secureBoot:  true,
			ekAlgorithm: "INVALID",
			expectErr:   true,
			errContains: "invalid EK algorithm",
		},
		{
			name:        "valid RSA template",
			id:          "base-vtpm",
			description: "",
			secureBoot:  true,
			ekAlgorithm: "RSA",
			expectErr:   true,
			errContains: "daemon",
		},
		{
			name:        "valid ECC template",
			id:          "ecc-template",
			description: "ECC template",
			secureBoot:  false,
			ekAlgorithm: "ECC",
			expectErr:   true,
			errContains: "daemon",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Match actual function signature: runTemplateCreate(flags, id, description, secureBoot, ekAlgorithm)
			err := runTemplateCreate(flags, tt.id, tt.description, tt.secureBoot, tt.ekAlgorithm)
			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errContains))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestNewTemplateListCommand tests the template list command structure
func TestNewTemplateListCommand(t *testing.T) {
	cmd := newTemplateListCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List all templates", cmd.Short)
	assert.Contains(t, cmd.Long, "List all available vTPM templates")
}

// TestRunTemplateList tests the template list command run function
func TestRunTemplateList(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	err := runTemplateList(flags)
	require.Error(t, err)
	assertRunErr(t, ErrDaemonConnectionRequired{}, err)
}

// TestNewTemplateDeleteCommand tests the template delete command structure
func TestNewTemplateDeleteCommand(t *testing.T) {
	cmd := newTemplateDeleteCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "delete [template-id]", cmd.Use)
	assert.Equal(t, "Delete a template", cmd.Short)
	assert.Contains(t, cmd.Long, "Delete a vTPM template")

	// Verify flags
	forceFlag := cmd.Flag("force")
	require.NotNil(t, forceFlag)
	assert.Equal(t, "false", forceFlag.DefValue)
	assert.Equal(t, "f", forceFlag.Shorthand)

	// Verify args validation
	assert.NotNil(t, cmd.Args)
}

// TestRunTemplateDelete tests the template delete command run function
func TestRunTemplateDelete(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	tests := []struct {
		name       string
		templateID string
		force      bool
		expectErr  error
	}{
		{
			name:       "missing template ID",
			templateID: "",
			force:      false,
			expectErr:  ErrMissingRequiredFlag{Flag: "template-id"},
		},
		{
			name:       "valid template ID without force",
			templateID: "base-vtpm",
			force:      false,
			expectErr:  ErrDaemonConnectionRequired{},
		},
		{
			name:       "valid template ID with force",
			templateID: "base-vtpm",
			force:      true,
			expectErr:  ErrDaemonConnectionRequired{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runTemplateDelete(flags, tt.templateID, tt.force)
			require.Error(t, err)
			assertRunErr(t, tt.expectErr, err)
		})
	}
}

// ============================================================================
// Runtime TPM Command Tests
// ============================================================================

// TestNewStartCommand tests the start command structure
func TestNewStartCommand(t *testing.T) {
	cmd := newStartCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "start", cmd.Use)
	assert.Equal(t, "Start the swtpm daemon for a bundle", cmd.Short)
	assert.Contains(t, cmd.Long, "Examples:")

	bundleIDFlag := cmd.Flag("bundle-id")
	require.NotNil(t, bundleIDFlag)
	assert.Equal(t, "", bundleIDFlag.DefValue)
}

// TestRunStart tests the start command run function
func TestRunStart(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runStart(flags, "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("valid bundle ID no daemon", func(t *testing.T) {
		err := runStart(flags, "bundle-123")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestNewStopCommand tests the stop command structure
func TestNewStopCommand(t *testing.T) {
	cmd := newStopCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "stop", cmd.Use)
	assert.Equal(t, "Stop the swtpm daemon for a bundle", cmd.Short)
	assert.Contains(t, cmd.Long, "Examples:")

	bundleIDFlag := cmd.Flag("bundle-id")
	require.NotNil(t, bundleIDFlag)
	assert.Equal(t, "", bundleIDFlag.DefValue)
}

// TestRunStop tests the stop command run function
func TestRunStop(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runStop(flags, "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("valid bundle ID no daemon", func(t *testing.T) {
		err := runStop(flags, "bundle-123")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestNewIsRunningCommand tests the is-running command structure
func TestNewIsRunningCommand(t *testing.T) {
	cmd := newIsRunningCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "is-running", cmd.Use)
	assert.Contains(t, cmd.Short, "Check if the vTPM daemon is running")
	assert.Contains(t, cmd.Long, "Examples:")

	bundleIDFlag := cmd.Flag("bundle-id")
	require.NotNil(t, bundleIDFlag)
	assert.Equal(t, "", bundleIDFlag.DefValue)
}

// TestRunIsRunning tests the is-running command run function
func TestRunIsRunning(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runIsRunning(flags, "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("valid bundle ID no daemon", func(t *testing.T) {
		err := runIsRunning(flags, "bundle-123")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestNewQuoteCommand tests the quote command structure
func TestNewQuoteCommand(t *testing.T) {
	cmd := newQuoteCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "quote", cmd.Use)
	assert.Contains(t, cmd.Short, "Generate a TPM quote")
	assert.Contains(t, cmd.Long, "Examples:")

	bundleIDFlag := cmd.Flag("bundle-id")
	require.NotNil(t, bundleIDFlag)

	nonceFlag := cmd.Flag("nonce")
	require.NotNil(t, nonceFlag)

	pcrsFlag := cmd.Flag("pcrs")
	require.NotNil(t, pcrsFlag)
}

// TestRunQuote tests the quote command run function
func TestRunQuote(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runQuote(flags, "", "deadbeef", "0,1,7")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("missing nonce", func(t *testing.T) {
		err := runQuote(flags, "bundle-123", "", "0,1,7")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "nonce"}, err)
	})

	t.Run("missing pcrs", func(t *testing.T) {
		err := runQuote(flags, "bundle-123", "deadbeef", "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "pcrs"}, err)
	})

	t.Run("invalid nonce hex", func(t *testing.T) {
		err := runQuote(flags, "bundle-123", "zzzz", "0,1,7")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidNonce{}, err)
	})

	t.Run("invalid PCR index", func(t *testing.T) {
		err := runQuote(flags, "bundle-123", "deadbeef", "0,99")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidPCRIndex{}, err)
	})

	t.Run("valid inputs no daemon", func(t *testing.T) {
		err := runQuote(flags, "bundle-123", "deadbeef", "0,1,7")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestNewSealCommand tests the seal command structure
func TestNewSealCommand(t *testing.T) {
	cmd := newSealCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "seal", cmd.Use)
	assert.Contains(t, cmd.Short, "Seal data to the TPM")
	assert.Contains(t, cmd.Long, "Examples:")

	bundleIDFlag := cmd.Flag("bundle-id")
	require.NotNil(t, bundleIDFlag)

	dataFlag := cmd.Flag("data")
	require.NotNil(t, dataFlag)

	pcrsFlag := cmd.Flag("pcrs")
	require.NotNil(t, pcrsFlag)

	authFlag := cmd.Flag("auth-value")
	require.NotNil(t, authFlag)
}

// TestRunSeal tests the seal command run function
func TestRunSeal(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runSeal(flags, "", "aGVsbG8=", "", "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("missing data", func(t *testing.T) {
		err := runSeal(flags, "bundle-123", "", "", "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "data"}, err)
	})

	t.Run("invalid base64 data", func(t *testing.T) {
		err := runSeal(flags, "bundle-123", "not-valid-base64!!!", "", "")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidBase64Data{}, err)
	})

	t.Run("valid inputs no daemon", func(t *testing.T) {
		err := runSeal(flags, "bundle-123", "aGVsbG8=", "", "")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("valid inputs with PCRs no daemon", func(t *testing.T) {
		err := runSeal(flags, "bundle-123", "aGVsbG8=", "0,1,7", "")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestNewUnsealCommand tests the unseal command structure
func TestNewUnsealCommand(t *testing.T) {
	cmd := newUnsealCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "unseal", cmd.Use)
	assert.Contains(t, cmd.Short, "Unseal data from the TPM")
	assert.Contains(t, cmd.Long, "Examples:")

	bundleIDFlag := cmd.Flag("bundle-id")
	require.NotNil(t, bundleIDFlag)

	sealedDataFlag := cmd.Flag("sealed-data")
	require.NotNil(t, sealedDataFlag)

	authFlag := cmd.Flag("auth-value")
	require.NotNil(t, authFlag)
}

// TestRunUnseal tests the unseal command run function
func TestRunUnseal(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runUnseal(flags, "", "aGVsbG8=", "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("missing sealed data", func(t *testing.T) {
		err := runUnseal(flags, "bundle-123", "", "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "sealed-data"}, err)
	})

	t.Run("invalid base64 sealed data", func(t *testing.T) {
		err := runUnseal(flags, "bundle-123", "not-valid-base64!!!", "")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidBase64Data{}, err)
	})

	t.Run("valid inputs no daemon", func(t *testing.T) {
		err := runUnseal(flags, "bundle-123", "aGVsbG8=", "")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestNewPCRCommand tests the pcr command structure
func TestNewPCRCommand(t *testing.T) {
	cmd := newPCRCommand(testGetFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "pcr", cmd.Use)
	assert.Contains(t, cmd.Short, "PCR")
	assert.Contains(t, cmd.Long, "Examples:")

	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 2) // extend, read

	expectedCommands := map[string]bool{
		"extend": false,
		"read":   false,
	}
	for _, sub := range subcommands {
		cmdName := strings.Split(sub.Use, " ")[0]
		if _, ok := expectedCommands[cmdName]; ok {
			expectedCommands[cmdName] = true
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

// TestRunPCRExtend tests the pcr extend command run function
func TestRunPCRExtend(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runPCRExtend(flags, "", 7, "deadbeef")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("invalid PCR index negative", func(t *testing.T) {
		err := runPCRExtend(flags, "bundle-123", -1, "deadbeef")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidPCRIndex{}, err)
	})

	t.Run("invalid PCR index too high", func(t *testing.T) {
		err := runPCRExtend(flags, "bundle-123", 24, "deadbeef")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidPCRIndex{}, err)
	})

	t.Run("missing data", func(t *testing.T) {
		err := runPCRExtend(flags, "bundle-123", 7, "")
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "data"}, err)
	})

	t.Run("invalid hex data", func(t *testing.T) {
		err := runPCRExtend(flags, "bundle-123", 7, "zzzz")
		require.Error(t, err)
		assert.IsType(t, ErrInvalidHexData{}, err)
	})

	t.Run("valid inputs no daemon", func(t *testing.T) {
		err := runPCRExtend(flags, "bundle-123", 7, "deadbeef")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestRunPCRRead tests the pcr read command run function
func TestRunPCRRead(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("missing bundle ID", func(t *testing.T) {
		err := runPCRRead(flags, "", 7)
		require.Error(t, err)
		assert.Equal(t, ErrMissingRequiredFlag{Flag: "bundle-id"}, err)
	})

	t.Run("invalid PCR index negative", func(t *testing.T) {
		err := runPCRRead(flags, "bundle-123", -1)
		require.Error(t, err)
		assert.IsType(t, ErrInvalidPCRIndex{}, err)
	})

	t.Run("invalid PCR index too high", func(t *testing.T) {
		err := runPCRRead(flags, "bundle-123", 24)
		require.Error(t, err)
		assert.IsType(t, ErrInvalidPCRIndex{}, err)
	})

	t.Run("valid inputs no daemon", func(t *testing.T) {
		err := runPCRRead(flags, "bundle-123", 7)
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestParsePCRIndices tests PCR indices parsing
func TestParsePCRIndices(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectErr bool
		expected  []int32
	}{
		{"single index", "0", false, []int32{0}},
		{"multiple indices", "0,1,7", false, []int32{0, 1, 7}},
		{"with spaces", "0, 1, 7", false, []int32{0, 1, 7}},
		{"max valid", "23", false, []int32{23}},
		{"out of range", "24", true, nil},
		{"negative", "-1", true, nil},
		{"non-numeric", "abc", true, nil},
		{"empty string", "", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parsePCRIndices(tt.input)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestErrorTypes tests all error type implementations
func TestErrorTypes(t *testing.T) {
	t.Run("ErrDaemonConnectionRequired", func(t *testing.T) {
		err := ErrDaemonConnectionRequired{}
		assert.Equal(t, "daemon connection required: this command requires a running platformd daemon", err.Error())
		var target ErrDaemonConnectionRequired
		assert.ErrorAs(t, err, &target)
	})

	t.Run("ErrDaemonConnectionRequired carries its cause", func(t *testing.T) {
		cause := errors.New("dial unix /run/platformd.sock: connect: no such file or directory")
		err := ErrDaemonConnectionRequired{Err: cause}
		assert.Equal(t, "daemon connection required: this command requires a running platformd daemon: "+cause.Error(), err.Error())
		assert.ErrorIs(t, err, cause)
	})

	t.Run("ErrBundleNotFound", func(t *testing.T) {
		err := ErrBundleNotFound{ID: "bundle-123"}
		assert.Equal(t, "bundle not found: bundle-123", err.Error())
		assert.Equal(t, "bundle-123", err.ID)
	})

	t.Run("ErrTemplateNotFound", func(t *testing.T) {
		err := ErrTemplateNotFound{ID: "template-abc"}
		assert.Equal(t, "template not found: template-abc", err.Error())
		assert.Equal(t, "template-abc", err.ID)
	})

	t.Run("ErrInvalidEKAlgorithm", func(t *testing.T) {
		err := ErrInvalidEKAlgorithm{Algorithm: "INVALID"}
		assert.Equal(t, "invalid EK algorithm: INVALID (use RSA or ECC)", err.Error())
		assert.Equal(t, "INVALID", err.Algorithm)
	})

	t.Run("ErrInvalidBundleMode", func(t *testing.T) {
		err := ErrInvalidBundleMode{Mode: "invalid"}
		assert.Equal(t, "invalid bundle mode: invalid (use template or pre-assigned)", err.Error())
		assert.Equal(t, "invalid", err.Mode)
	})

	t.Run("ErrCreateBundleFailed", func(t *testing.T) {
		err := ErrCreateBundleFailed{Reason: "disk full"}
		assert.Equal(t, "failed to create bundle: disk full", err.Error())
		assert.Equal(t, "disk full", err.Reason)
	})

	t.Run("ErrDeleteBundleFailed", func(t *testing.T) {
		err := ErrDeleteBundleFailed{Reason: "permission denied"}
		assert.Equal(t, "failed to delete bundle: permission denied", err.Error())
		assert.Equal(t, "permission denied", err.Reason)
	})

	t.Run("ErrListBundlesFailed", func(t *testing.T) {
		err := ErrListBundlesFailed{Reason: "database error"}
		assert.Equal(t, "failed to list bundles: database error", err.Error())
		assert.Equal(t, "database error", err.Reason)
	})

	t.Run("ErrGetBundleInfoFailed", func(t *testing.T) {
		err := ErrGetBundleInfoFailed{Reason: "timeout"}
		assert.Equal(t, "failed to get bundle info: timeout", err.Error())
		assert.Equal(t, "timeout", err.Reason)
	})

	t.Run("ErrCloneBundleFailed", func(t *testing.T) {
		err := ErrCloneBundleFailed{Reason: "source not found"}
		assert.Equal(t, "failed to clone bundle: source not found", err.Error())
		assert.Equal(t, "source not found", err.Reason)
	})

	t.Run("ErrExportBundleFailed", func(t *testing.T) {
		err := ErrExportBundleFailed{Reason: "write error"}
		assert.Equal(t, "failed to export bundle: write error", err.Error())
		assert.Equal(t, "write error", err.Reason)
	})

	t.Run("ErrImportBundleFailed", func(t *testing.T) {
		err := ErrImportBundleFailed{Reason: "invalid archive"}
		assert.Equal(t, "failed to import bundle: invalid archive", err.Error())
		assert.Equal(t, "invalid archive", err.Reason)
	})

	t.Run("ErrCreateTemplateFailed", func(t *testing.T) {
		err := ErrCreateTemplateFailed{Reason: "initialization error"}
		assert.Equal(t, "failed to create template: initialization error", err.Error())
		assert.Equal(t, "initialization error", err.Reason)
	})

	t.Run("ErrDeleteTemplateFailed", func(t *testing.T) {
		err := ErrDeleteTemplateFailed{Reason: "in use"}
		assert.Equal(t, "failed to delete template: in use", err.Error())
		assert.Equal(t, "in use", err.Reason)
	})

	t.Run("ErrListTemplatesFailed", func(t *testing.T) {
		err := ErrListTemplatesFailed{Reason: "connection lost"}
		assert.Equal(t, "failed to list templates: connection lost", err.Error())
		assert.Equal(t, "connection lost", err.Reason)
	})

	t.Run("ErrOutputFileExists", func(t *testing.T) {
		err := ErrOutputFileExists{Path: "/tmp/output.tar.gz"}
		assert.Equal(t, "output file already exists: /tmp/output.tar.gz", err.Error())
		assert.Equal(t, "/tmp/output.tar.gz", err.Path)
	})

	t.Run("ErrCreateOutputFileFailed", func(t *testing.T) {
		err := ErrCreateOutputFileFailed{Path: "/tmp/output.tar.gz", Reason: "no space left"}
		assert.Equal(t, "failed to create output file /tmp/output.tar.gz: no space left", err.Error())
		assert.Equal(t, "/tmp/output.tar.gz", err.Path)
		assert.Equal(t, "no space left", err.Reason)
	})

	t.Run("ErrOpenArchiveFailed", func(t *testing.T) {
		err := ErrOpenArchiveFailed{Path: "/tmp/archive.tar.gz", Reason: "corrupted"}
		assert.Equal(t, "failed to open archive /tmp/archive.tar.gz: corrupted", err.Error())
		assert.Equal(t, "/tmp/archive.tar.gz", err.Path)
		assert.Equal(t, "corrupted", err.Reason)
	})

	t.Run("ErrMissingRequiredFlag", func(t *testing.T) {
		err := ErrMissingRequiredFlag{Flag: "hostname"}
		assert.Equal(t, "missing required flag: --hostname", err.Error())
		assert.Equal(t, "hostname", err.Flag)
	})

	// Runtime TPM error types
	t.Run("ErrStartVTPMFailed", func(t *testing.T) {
		err := ErrStartVTPMFailed{Reason: "swtpm not found"}
		assert.Equal(t, "failed to start vTPM: swtpm not found", err.Error())
		assert.Equal(t, "swtpm not found", err.Reason)
	})

	t.Run("ErrStopVTPMFailed", func(t *testing.T) {
		err := ErrStopVTPMFailed{Reason: "not running"}
		assert.Equal(t, "failed to stop vTPM: not running", err.Error())
		assert.Equal(t, "not running", err.Reason)
	})

	t.Run("ErrIsRunningFailed", func(t *testing.T) {
		err := ErrIsRunningFailed{Reason: "connection error"}
		assert.Equal(t, "failed to check vTPM running status: connection error", err.Error())
		assert.Equal(t, "connection error", err.Reason)
	})

	t.Run("ErrQuoteVTPMFailed", func(t *testing.T) {
		err := ErrQuoteVTPMFailed{Reason: "TPM error"}
		assert.Equal(t, "failed to generate TPM quote: TPM error", err.Error())
		assert.Equal(t, "TPM error", err.Reason)
	})

	t.Run("ErrSealVTPMFailed", func(t *testing.T) {
		err := ErrSealVTPMFailed{Reason: "key not available"}
		assert.Equal(t, "failed to seal data: key not available", err.Error())
		assert.Equal(t, "key not available", err.Reason)
	})

	t.Run("ErrUnsealVTPMFailed", func(t *testing.T) {
		err := ErrUnsealVTPMFailed{Reason: "PCR mismatch"}
		assert.Equal(t, "failed to unseal data: PCR mismatch", err.Error())
		assert.Equal(t, "PCR mismatch", err.Reason)
	})

	t.Run("ErrExtendPCRFailed", func(t *testing.T) {
		err := ErrExtendPCRFailed{Reason: "invalid index"}
		assert.Equal(t, "failed to extend PCR: invalid index", err.Error())
		assert.Equal(t, "invalid index", err.Reason)
	})

	t.Run("ErrReadPCRFailed", func(t *testing.T) {
		err := ErrReadPCRFailed{Reason: "TPM not available"}
		assert.Equal(t, "failed to read PCR: TPM not available", err.Error())
		assert.Equal(t, "TPM not available", err.Reason)
	})

	t.Run("ErrInvalidNonce", func(t *testing.T) {
		err := ErrInvalidNonce{Reason: "odd length"}
		assert.Equal(t, "invalid nonce: odd length (must be hex-encoded)", err.Error())
		assert.Equal(t, "odd length", err.Reason)
	})

	t.Run("ErrInvalidPCRIndex", func(t *testing.T) {
		err := ErrInvalidPCRIndex{Index: "99", Reason: "out of range"}
		assert.Equal(t, "invalid PCR index 99: out of range", err.Error())
		assert.Equal(t, "99", err.Index)
		assert.Equal(t, "out of range", err.Reason)
	})

	t.Run("ErrInvalidBase64Data", func(t *testing.T) {
		err := ErrInvalidBase64Data{Reason: "illegal padding"}
		assert.Equal(t, "invalid base64 data: illegal padding", err.Error())
		assert.Equal(t, "illegal padding", err.Reason)
	})

	t.Run("ErrInvalidHexData", func(t *testing.T) {
		err := ErrInvalidHexData{Reason: "odd length"}
		assert.Equal(t, "invalid hex data: odd length", err.Error())
		assert.Equal(t, "odd length", err.Reason)
	})
}

// TestCommandExecution tests command execution through RunE
func TestCommandExecution(t *testing.T) {
	t.Run("create command execution", func(t *testing.T) {
		cmd := newCreateCommand(testGetFlags())
		cmd.SetArgs([]string{"--hostname", "vm001.example.com"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("clone command execution", func(t *testing.T) {
		cmd := newCloneCommand(testGetFlags())
		cmd.SetArgs([]string{"--template", "base-vtpm", "--hostname", "vm001.example.com"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("list command execution", func(t *testing.T) {
		cmd := newListCommand(testGetFlags())
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("list command with invalid mode", func(t *testing.T) {
		cmd := newListCommand(testGetFlags())
		cmd.SetArgs([]string{"--mode", "invalid"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrInvalidBundleMode{}, err)
	})

	t.Run("info command execution", func(t *testing.T) {
		cmd := newInfoCommand(testGetFlags())
		cmd.SetArgs([]string{"bundle-123"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("delete command execution", func(t *testing.T) {
		cmd := newDeleteCommand(testGetFlags())
		cmd.SetArgs([]string{"bundle-123"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("delete command with force", func(t *testing.T) {
		cmd := newDeleteCommand(testGetFlags())
		cmd.SetArgs([]string{"bundle-123", "--force"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("export command execution", func(t *testing.T) {
		cmd := newExportCommand(testGetFlags())
		cmd.SetArgs([]string{"bundle-123"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("export command with output", func(t *testing.T) {
		cmd := newExportCommand(testGetFlags())
		cmd.SetArgs([]string{"bundle-123", "-o", "my-bundle.tar.gz"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("import command execution", func(t *testing.T) {
		cmd := newImportCommand(testGetFlags())
		cmd.SetArgs([]string{"bundle.vtpm.tar.gz"})
		err := cmd.Execute()
		require.Error(t, err)
		// Expect file not found error since archive doesn't exist
		assert.IsType(t, ErrOpenArchiveFailed{}, err)
	})

	t.Run("template create command execution", func(t *testing.T) {
		cmd := newTemplateCreateCommand(testGetFlags())
		cmd.SetArgs([]string{"--id", "base-vtpm"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("template create with invalid algorithm", func(t *testing.T) {
		cmd := newTemplateCreateCommand(testGetFlags())
		cmd.SetArgs([]string{"--id", "base-vtpm", "--ek-algorithm", "INVALID"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrInvalidEKAlgorithm{}, err)
	})

	t.Run("template list command execution", func(t *testing.T) {
		cmd := newTemplateListCommand(testGetFlags())
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("template delete command execution", func(t *testing.T) {
		cmd := newTemplateDeleteCommand(testGetFlags())
		cmd.SetArgs([]string{"base-vtpm"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("template delete with force", func(t *testing.T) {
		cmd := newTemplateDeleteCommand(testGetFlags())
		cmd.SetArgs([]string{"base-vtpm", "--force"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	// Runtime TPM command executions
	t.Run("start command execution", func(t *testing.T) {
		cmd := newStartCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("stop command execution", func(t *testing.T) {
		cmd := newStopCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("is-running command execution", func(t *testing.T) {
		cmd := newIsRunningCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("quote command execution", func(t *testing.T) {
		cmd := newQuoteCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123", "--nonce", "deadbeef", "--pcrs", "0,1,7"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("seal command execution", func(t *testing.T) {
		cmd := newSealCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123", "--data", "aGVsbG8="})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("unseal command execution", func(t *testing.T) {
		cmd := newUnsealCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123", "--sealed-data", "aGVsbG8="})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("pcr extend command execution", func(t *testing.T) {
		cmd := newPCRExtendCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123", "--pcr-index", "7", "--data", "deadbeef"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("pcr read command execution", func(t *testing.T) {
		cmd := newPCRReadCommand(testGetFlags())
		cmd.SetArgs([]string{"--bundle-id", "bundle-123", "--pcr-index", "7"})
		err := cmd.Execute()
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestCommandStructureCompleteness verifies all commands have proper structure
func TestCommandStructureCompleteness(t *testing.T) {
	getFlags := testGetFlags()

	t.Run("vtpm root command has Long description", func(t *testing.T) {
		cmd := NewCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("create command has Long description", func(t *testing.T) {
		cmd := newCreateCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("clone command has Long description", func(t *testing.T) {
		cmd := newCloneCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("list command has Long description", func(t *testing.T) {
		cmd := newListCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("info command has Long description", func(t *testing.T) {
		cmd := newInfoCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("delete command has Long description", func(t *testing.T) {
		cmd := newDeleteCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("export command has Long description", func(t *testing.T) {
		cmd := newExportCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("import command has Long description", func(t *testing.T) {
		cmd := newImportCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("template command has Long description", func(t *testing.T) {
		cmd := newTemplateCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("template create command has Long description", func(t *testing.T) {
		cmd := newTemplateCreateCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("template list command has Long description", func(t *testing.T) {
		cmd := newTemplateListCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("template delete command has Long description", func(t *testing.T) {
		cmd := newTemplateDeleteCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	// Runtime TPM commands
	t.Run("start command has Long description", func(t *testing.T) {
		cmd := newStartCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("stop command has Long description", func(t *testing.T) {
		cmd := newStopCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("is-running command has Long description", func(t *testing.T) {
		cmd := newIsRunningCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("quote command has Long description", func(t *testing.T) {
		cmd := newQuoteCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("seal command has Long description", func(t *testing.T) {
		cmd := newSealCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("unseal command has Long description", func(t *testing.T) {
		cmd := newUnsealCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("pcr command has Long description", func(t *testing.T) {
		cmd := newPCRCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("pcr extend command has Long description", func(t *testing.T) {
		cmd := newPCRExtendCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})

	t.Run("pcr read command has Long description", func(t *testing.T) {
		cmd := newPCRReadCommand(getFlags)
		assert.NotEmpty(t, cmd.Long)
		assert.Contains(t, cmd.Long, "Examples:")
	})
}

// TestFlagDefaults verifies all flag default values
func TestFlagDefaults(t *testing.T) {
	getFlags := testGetFlags()

	t.Run("create command flags", func(t *testing.T) {
		cmd := newCreateCommand(getFlags)

		flag := cmd.Flag("hostname")
		assert.Equal(t, "", flag.DefValue)

		flag = cmd.Flag("secure-boot")
		assert.Equal(t, "true", flag.DefValue)

		flag = cmd.Flag("ek-algorithm")
		assert.Equal(t, "RSA", flag.DefValue)
	})

	t.Run("clone command flags", func(t *testing.T) {
		cmd := newCloneCommand(getFlags)

		flag := cmd.Flag("template")
		assert.Equal(t, "", flag.DefValue)

		flag = cmd.Flag("hostname")
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("list command flags", func(t *testing.T) {
		cmd := newListCommand(getFlags)

		flag := cmd.Flag("mode")
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("delete command flags", func(t *testing.T) {
		cmd := newDeleteCommand(getFlags)

		flag := cmd.Flag("force")
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("export command flags", func(t *testing.T) {
		cmd := newExportCommand(getFlags)

		flag := cmd.Flag("output")
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("template create command flags", func(t *testing.T) {
		cmd := newTemplateCreateCommand(getFlags)

		flag := cmd.Flag("id")
		assert.Equal(t, "", flag.DefValue)

		flag = cmd.Flag("secure-boot")
		assert.Equal(t, "true", flag.DefValue)

		flag = cmd.Flag("ek-algorithm")
		assert.Equal(t, "RSA", flag.DefValue)
	})

	t.Run("template delete command flags", func(t *testing.T) {
		cmd := newTemplateDeleteCommand(getFlags)

		flag := cmd.Flag("force")
		assert.Equal(t, "false", flag.DefValue)
	})

	t.Run("start command flags", func(t *testing.T) {
		cmd := newStartCommand(getFlags)

		flag := cmd.Flag("bundle-id")
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("stop command flags", func(t *testing.T) {
		cmd := newStopCommand(getFlags)

		flag := cmd.Flag("bundle-id")
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("pcr extend command flags", func(t *testing.T) {
		cmd := newPCRExtendCommand(getFlags)

		flag := cmd.Flag("bundle-id")
		assert.Equal(t, "", flag.DefValue)

		flag = cmd.Flag("pcr-index")
		assert.Equal(t, "-1", flag.DefValue)

		flag = cmd.Flag("data")
		assert.Equal(t, "", flag.DefValue)
	})

	t.Run("pcr read command flags", func(t *testing.T) {
		cmd := newPCRReadCommand(getFlags)

		flag := cmd.Flag("bundle-id")
		assert.Equal(t, "", flag.DefValue)

		flag = cmd.Flag("pcr-index")
		assert.Equal(t, "-1", flag.DefValue)
	})
}

// TestOutputFormats verifies commands work with different output formats
func TestOutputFormats(t *testing.T) {
	outputFormats := []cli.OutputFormat{
		cli.OutputFormatJSON,
		cli.OutputFormatYAML,
		cli.OutputFormatTable,
	}

	for _, format := range outputFormats {
		t.Run(string(format), func(t *testing.T) {
			flags := &cli.CommonFlags{OutputFormat: format}

			// Test list command with each format
			err := runList(flags, "", 0, 0)
			require.Error(t, err)
			assert.IsType(t, ErrDaemonConnectionRequired{}, err)

			// Test template list command with each format
			err = runTemplateList(flags)
			require.Error(t, err)
			assert.IsType(t, ErrDaemonConnectionRequired{}, err)
		})
	}
}

// TestCommandRunEFunctions tests that RunE functions are properly assigned
func TestCommandRunEFunctions(t *testing.T) {
	getFlags := testGetFlags()

	t.Run("create command has RunE", func(t *testing.T) {
		cmd := newCreateCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("clone command has RunE", func(t *testing.T) {
		cmd := newCloneCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("list command has RunE", func(t *testing.T) {
		cmd := newListCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("info command has RunE", func(t *testing.T) {
		cmd := newInfoCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("delete command has RunE", func(t *testing.T) {
		cmd := newDeleteCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("export command has RunE", func(t *testing.T) {
		cmd := newExportCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("import command has RunE", func(t *testing.T) {
		cmd := newImportCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("template command has no RunE (group command)", func(t *testing.T) {
		cmd := newTemplateCommand(getFlags)
		assert.Nil(t, cmd.RunE)
	})

	t.Run("template create command has RunE", func(t *testing.T) {
		cmd := newTemplateCreateCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("template list command has RunE", func(t *testing.T) {
		cmd := newTemplateListCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("template delete command has RunE", func(t *testing.T) {
		cmd := newTemplateDeleteCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	// Runtime TPM commands
	t.Run("start command has RunE", func(t *testing.T) {
		cmd := newStartCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("stop command has RunE", func(t *testing.T) {
		cmd := newStopCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("is-running command has RunE", func(t *testing.T) {
		cmd := newIsRunningCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("quote command has RunE", func(t *testing.T) {
		cmd := newQuoteCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("seal command has RunE", func(t *testing.T) {
		cmd := newSealCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("unseal command has RunE", func(t *testing.T) {
		cmd := newUnsealCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("pcr command has no RunE (group command)", func(t *testing.T) {
		cmd := newPCRCommand(getFlags)
		assert.Nil(t, cmd.RunE)
	})

	t.Run("pcr extend command has RunE", func(t *testing.T) {
		cmd := newPCRExtendCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})

	t.Run("pcr read command has RunE", func(t *testing.T) {
		cmd := newPCRReadCommand(getFlags)
		assert.NotNil(t, cmd.RunE)
	})
}

// TestArgsValidation tests that commands requiring args have proper validation
func TestArgsValidation(t *testing.T) {
	getFlags := testGetFlags()

	t.Run("info command requires exactly 1 arg", func(t *testing.T) {
		cmd := newInfoCommand(getFlags)
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "accepts 1 arg(s)")
	})

	t.Run("delete command requires exactly 1 arg", func(t *testing.T) {
		cmd := newDeleteCommand(getFlags)
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "accepts 1 arg(s)")
	})

	t.Run("export command requires exactly 1 arg", func(t *testing.T) {
		cmd := newExportCommand(getFlags)
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "accepts 1 arg(s)")
	})

	t.Run("import command requires exactly 1 arg", func(t *testing.T) {
		cmd := newImportCommand(getFlags)
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "accepts 1 arg(s)")
	})

	t.Run("template delete command requires exactly 1 arg", func(t *testing.T) {
		cmd := newTemplateDeleteCommand(getFlags)
		cmd.SetArgs([]string{})
		err := cmd.Execute()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "accepts 1 arg(s)")
	})
}

// TestEdgeCases tests edge cases and boundary conditions
func TestEdgeCases(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	t.Run("empty string validation for EK algorithm", func(t *testing.T) {
		_, err := parseEKAlgorithm("")
		require.Error(t, err)
	})

	t.Run("empty string validation for bundle mode", func(t *testing.T) {
		_, err := parseBundleMode("")
		require.Error(t, err)
	})

	t.Run("case insensitivity for algorithms", func(t *testing.T) {
		// parseEKAlgorithm uses ToUpper, so lowercase should work
		_, err := parseEKAlgorithm("rsa")
		require.NoError(t, err)
		_, err = parseEKAlgorithm("ecc")
		require.NoError(t, err)
	})

	t.Run("case insensitivity for bundle modes", func(t *testing.T) {
		// parseBundleMode uses ToLower, so uppercase should work
		_, err := parseBundleMode("Template")
		require.NoError(t, err)
		_, err = parseBundleMode("Pre-Assigned")
		require.NoError(t, err)
	})

	t.Run("special characters in bundle ID", func(t *testing.T) {
		err := runInfo(flags, "bundle-123_abc.test")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("long bundle ID", func(t *testing.T) {
		longID := "bundle-" + string(make([]byte, 1000))
		err := runInfo(flags, longID)
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("special characters in hostname", func(t *testing.T) {
		err := runCreate(flags, "vm-001.subdomain.example.com", true, "RSA", "", nil)
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})

	t.Run("unicode in template ID", func(t *testing.T) {
		err := runTemplateCreate(flags, "template-\u4e2d\u6587", "", true, "RSA")
		require.Error(t, err)
		assert.IsType(t, ErrDaemonConnectionRequired{}, err)
	})
}

// TestErrorInterface verifies error types implement the error interface
func TestErrorInterface(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrDaemonConnectionRequired", ErrDaemonConnectionRequired{}},
		{"ErrBundleNotFound", ErrBundleNotFound{ID: "test"}},
		{"ErrTemplateNotFound", ErrTemplateNotFound{ID: "test"}},
		{"ErrInvalidEKAlgorithm", ErrInvalidEKAlgorithm{Algorithm: "test"}},
		{"ErrInvalidBundleMode", ErrInvalidBundleMode{Mode: "test"}},
		{"ErrCreateBundleFailed", ErrCreateBundleFailed{Reason: "test"}},
		{"ErrDeleteBundleFailed", ErrDeleteBundleFailed{Reason: "test"}},
		{"ErrListBundlesFailed", ErrListBundlesFailed{Reason: "test"}},
		{"ErrGetBundleInfoFailed", ErrGetBundleInfoFailed{Reason: "test"}},
		{"ErrCloneBundleFailed", ErrCloneBundleFailed{Reason: "test"}},
		{"ErrExportBundleFailed", ErrExportBundleFailed{Reason: "test"}},
		{"ErrImportBundleFailed", ErrImportBundleFailed{Reason: "test"}},
		{"ErrCreateTemplateFailed", ErrCreateTemplateFailed{Reason: "test"}},
		{"ErrDeleteTemplateFailed", ErrDeleteTemplateFailed{Reason: "test"}},
		{"ErrListTemplatesFailed", ErrListTemplatesFailed{Reason: "test"}},
		{"ErrOutputFileExists", ErrOutputFileExists{Path: "test"}},
		{"ErrCreateOutputFileFailed", ErrCreateOutputFileFailed{Path: "test", Reason: "test"}},
		{"ErrOpenArchiveFailed", ErrOpenArchiveFailed{Path: "test", Reason: "test"}},
		{"ErrMissingRequiredFlag", ErrMissingRequiredFlag{Flag: "test"}},
		// Runtime TPM errors
		{"ErrStartVTPMFailed", ErrStartVTPMFailed{Reason: "test"}},
		{"ErrStopVTPMFailed", ErrStopVTPMFailed{Reason: "test"}},
		{"ErrIsRunningFailed", ErrIsRunningFailed{Reason: "test"}},
		{"ErrQuoteVTPMFailed", ErrQuoteVTPMFailed{Reason: "test"}},
		{"ErrSealVTPMFailed", ErrSealVTPMFailed{Reason: "test"}},
		{"ErrUnsealVTPMFailed", ErrUnsealVTPMFailed{Reason: "test"}},
		{"ErrExtendPCRFailed", ErrExtendPCRFailed{Reason: "test"}},
		{"ErrReadPCRFailed", ErrReadPCRFailed{Reason: "test"}},
		{"ErrInvalidNonce", ErrInvalidNonce{Reason: "test"}},
		{"ErrInvalidPCRIndex", ErrInvalidPCRIndex{Index: "test", Reason: "test"}},
		{"ErrInvalidBase64Data", ErrInvalidBase64Data{Reason: "test"}},
		{"ErrInvalidHexData", ErrInvalidHexData{Reason: "test"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify error interface is implemented
			assert.NotEmpty(t, tt.err.Error())
			// Verify error can be used as error
			err := tt.err
			assert.NotNil(t, err)
		})
	}
}

// TestMultipleCommandCreation tests that commands can be created multiple times
func TestMultipleCommandCreation(t *testing.T) {
	getFlags := testGetFlags()

	// Create multiple instances of the same command
	cmd1 := NewCommand(getFlags)
	cmd2 := NewCommand(getFlags)

	// Verify they are independent
	assert.NotSame(t, cmd1, cmd2)
	assert.Equal(t, cmd1.Use, cmd2.Use)
	assert.Equal(t, cmd1.Short, cmd2.Short)
	assert.Equal(t, len(cmd1.Commands()), len(cmd2.Commands()))
}

// TestCommandFlags tests that flags are properly isolated between command instances
func TestCommandFlags(t *testing.T) {
	getFlags := testGetFlags()

	cmd1 := newCreateCommand(getFlags)
	cmd2 := newCreateCommand(getFlags)

	// Set different values on different instances
	err := cmd1.Flags().Set("hostname", "host1.example.com")
	require.NoError(t, err)
	err = cmd2.Flags().Set("hostname", "host2.example.com")
	require.NoError(t, err)

	// Verify flags are isolated
	val1, _ := cmd1.Flags().GetString("hostname")
	val2, _ := cmd2.Flags().GetString("hostname")

	assert.Equal(t, "host1.example.com", val1)
	assert.Equal(t, "host2.example.com", val2)
}

// TestListValidModes tests list command with all valid modes
func TestListValidModes(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	validModes := []string{"template", "pre-assigned"}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			err := runList(flags, mode, 0, 0)
			require.Error(t, err)
			// Should pass validation and reach daemon connection error
			assert.IsType(t, ErrDaemonConnectionRequired{}, err)
		})
	}
}

// TestCreateValidAlgorithms tests create command with all valid algorithms
func TestCreateValidAlgorithms(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	validAlgorithms := []string{"RSA", "ECC"}

	for _, alg := range validAlgorithms {
		t.Run(alg, func(t *testing.T) {
			err := runCreate(flags, "test.example.com", true, alg, "", nil)
			require.Error(t, err)
			// Should pass validation and reach daemon connection error
			assert.IsType(t, ErrDaemonConnectionRequired{}, err)
		})
	}
}

// TestTemplateCreateValidAlgorithms tests template create with all valid algorithms
func TestTemplateCreateValidAlgorithms(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	validAlgorithms := []string{"RSA", "ECC"}

	for _, alg := range validAlgorithms {
		t.Run(alg, func(t *testing.T) {
			err := runTemplateCreate(flags, "test-template", "", true, alg)
			require.Error(t, err)
			// Should pass validation and reach daemon connection error
			assert.IsType(t, ErrDaemonConnectionRequired{}, err)
		})
	}
}

// TestParseLabels tests label parsing
func TestParseLabels(t *testing.T) {
	tests := []struct {
		name      string
		labels    []string
		expectErr bool
	}{
		{
			name:      "empty labels",
			labels:    nil,
			expectErr: false,
		},
		{
			name:      "valid labels",
			labels:    []string{"env=prod", "tier=1"},
			expectErr: false,
		},
		{
			name:      "invalid label",
			labels:    []string{"invalid"},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseLabels(tt.labels)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestHelperFunctions tests helper functions
func TestHelperFunctions(t *testing.T) {
	t.Run("formatBool", func(t *testing.T) {
		assert.Equal(t, "Yes", formatBool(true))
		assert.Equal(t, "No", formatBool(false))
	})

	t.Run("truncateID", func(t *testing.T) {
		assert.Equal(t, "short", truncateID("short", 10))
		assert.Equal(t, "longstr...", truncateID("longstring123", 10))
	})

	t.Run("truncateString", func(t *testing.T) {
		assert.Equal(t, "short", truncateString("short", 10))
		assert.Equal(t, "longstr...", truncateString("longstring123", 10))
	})

	t.Run("formatBytes", func(t *testing.T) {
		assert.Equal(t, "500 B", formatBytes(500))
		assert.Equal(t, "1.0 KB", formatBytes(1024))
		assert.Equal(t, "1.0 MB", formatBytes(1024*1024))
	})

	t.Run("formatRunningStatus", func(t *testing.T) {
		assert.Equal(t, "running", formatRunningStatus(true))
		assert.Equal(t, "stopped", formatRunningStatus(false))
	})
}
