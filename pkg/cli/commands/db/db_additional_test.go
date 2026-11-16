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

package db

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// NOTE ON COVERAGE:
// The runDump and runList functions require a live platformd connection with
// gRPC streaming capabilities. These are tested via integration tests in
// test/integration/db/ which run against a real platformd in a devcontainer.
// Unit test coverage for this package is limited to ~25% because the bulk
// of the code (runDump: ~57 lines, runList: ~47 lines) cannot be tested
// without external dependencies. All unit-testable code (command creation,
// error types, flag configuration) has 100% coverage.

// Additional tests for db package to improve coverage

func TestNewCommand_SubcommandConfiguration(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewCommand(getFlags)

	// Verify command has subcommands
	subcommands := cmd.Commands()
	require.NotEmpty(t, subcommands, "db command should have subcommands")

	// Verify both list and dump subcommands exist
	foundList := false
	foundDump := false
	for _, subcmd := range subcommands {
		switch subcmd.Name() {
		case "list":
			foundList = true
			assert.NotEmpty(t, subcmd.Long, "list command should have Long description")
			assert.NotNil(t, subcmd.RunE, "list command should have RunE set")
		case "dump":
			foundDump = true
			assert.NotEmpty(t, subcmd.Long, "dump command should have Long description")
			assert.NotNil(t, subcmd.RunE, "dump command should have RunE set")
		}
	}

	assert.True(t, foundList, "list subcommand should exist")
	assert.True(t, foundDump, "dump subcommand should exist")
}

func TestNewCommand_DoesNotHaveRunE(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)

	// The db command is a grouping command, should not have RunE
	assert.Nil(t, cmd.RunE, "db root command should not have RunE (it's a grouping command)")
	assert.True(t, cmd.HasSubCommands(), "db command should have subcommands")
}

func TestNewCommand_VerifySubcommandCount(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewCommand(getFlags)
	subcommands := cmd.Commands()

	// We expect exactly 2 subcommands: list and dump
	assert.Equal(t, 2, len(subcommands), "db command should have exactly 2 subcommands")
}

func TestNewListCommand_ConfigDirFlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	configDirFlag := cmd.Flags().Lookup("config-dir")
	require.NotNil(t, configDirFlag, "config-dir flag should exist")
	assert.NotEmpty(t, configDirFlag.Usage, "config-dir flag should have usage description")
}

func TestNewListCommand_LongDescriptionContainsExamples(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewListCommand(getFlags)

	assert.Contains(t, cmd.Long, "Examples:")
	assert.Contains(t, cmd.Long, "platformctl db list")
}

func TestNewDumpCommand_AllFlagsHaveUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDumpCommand(getFlags)

	flagNames := []string{"output", "format", "entity-type", "pretty", "config-dir"}
	for _, name := range flagNames {
		flag := cmd.Flags().Lookup(name)
		require.NotNil(t, flag, "flag %s should exist", name)
		assert.NotEmpty(t, flag.Usage, "flag %s should have usage description", name)
	}
}

func TestNewDumpCommand_LongDescriptionContainsExamples(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDumpCommand(getFlags)

	assert.Contains(t, cmd.Long, "Examples:")
	assert.Contains(t, cmd.Long, "platformctl db dump")
	assert.Contains(t, cmd.Long, "entity type")
}

func TestNewDumpCommand_OutputFlagShorthand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDumpCommand(getFlags)

	outputFlag := cmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "o", outputFlag.Shorthand, "output flag should have shorthand 'o'")

	formatFlag := cmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag)
	assert.Equal(t, "f", formatFlag.Shorthand, "format flag should have shorthand 'f'")

	entityTypeFlag := cmd.Flags().Lookup("entity-type")
	require.NotNil(t, entityTypeFlag)
	assert.Equal(t, "t", entityTypeFlag.Shorthand, "entity-type flag should have shorthand 't'")
}

// Error interface implementation tests

func TestAllErrors_ImplementErrorInterface(t *testing.T) {
	// Compile-time verification
	var _ error = ErrInvalidFormat{}
	var _ error = ErrConfigLoadFailed{}
	var _ error = ErrDatabaseConnectionFailed{}
	var _ error = ErrDatabaseStartFailed{}
	var _ error = ErrInvalidFactoryType{}
	var _ error = ErrOutputDirectoryFailed{}
	var _ error = ErrSerializationFailed{}
	var _ error = ErrDeserializationFailed{}
	var _ error = ErrFileWriteFailed{}
	var _ error = ErrGRPCRequired{}

	// Runtime verification
	tests := []error{
		ErrInvalidFormat{Format: "xml"},
		ErrConfigLoadFailed{Err: errors.New("test")},
		ErrDatabaseConnectionFailed{Err: errors.New("test")},
		ErrDatabaseStartFailed{Err: errors.New("test")},
		ErrInvalidFactoryType{},
		ErrOutputDirectoryFailed{Path: "/test", Err: errors.New("test")},
		ErrSerializationFailed{EntityType: "User", ID: 1, Err: errors.New("test")},
		ErrDeserializationFailed{EntityType: "User", ID: 1, Err: errors.New("test")},
		ErrFileWriteFailed{Path: "/test", Err: errors.New("test")},
		ErrGRPCRequired{Operation: "test"},
	}

	for _, err := range tests {
		assert.NotEmpty(t, err.Error(), "Error() should return non-empty string")
	}
}

func TestErrInvalidFormat_VariousFormats(t *testing.T) {
	tests := []struct {
		format   string
		contains []string
	}{
		{"xml", []string{"xml", "invalid format", "json", "yaml"}},
		{"CSV", []string{"CSV", "invalid format"}},
		{"", []string{"invalid format", "json", "yaml"}},
		{"protobuf", []string{"protobuf", "invalid format"}},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			err := ErrInvalidFormat{Format: tt.format}
			errStr := err.Error()
			for _, substr := range tt.contains {
				assert.Contains(t, errStr, substr)
			}
		})
	}
}

func TestErrSerializationFailed_VariousInputs(t *testing.T) {
	tests := []struct {
		entityType string
		id         uint64
		innerErr   error
	}{
		{"User", 123, errors.New("json marshal error")},
		{"Organization", 0, errors.New("invalid data")},
		{"Zone", 18446744073709551615, nil}, // max uint64
		{"", 456, errors.New("empty type")},
	}

	for _, tt := range tests {
		t.Run(tt.entityType, func(t *testing.T) {
			err := ErrSerializationFailed{
				EntityType: tt.entityType,
				ID:         tt.id,
				Err:        tt.innerErr,
			}
			errStr := err.Error()
			assert.Contains(t, errStr, "serialize")
			assert.Contains(t, errStr, tt.entityType)
		})
	}
}

func TestErrDeserializationFailed_VariousInputs(t *testing.T) {
	tests := []struct {
		entityType string
		id         uint64
		innerErr   error
	}{
		{"User", 123, errors.New("json unmarshal error")},
		{"Device", 789, errors.New("invalid JSON")},
		{"Registration", 1, nil},
	}

	for _, tt := range tests {
		t.Run(tt.entityType, func(t *testing.T) {
			err := ErrDeserializationFailed{
				EntityType: tt.entityType,
				ID:         tt.id,
				Err:        tt.innerErr,
			}
			errStr := err.Error()
			assert.Contains(t, errStr, "deserialize")
			assert.Contains(t, errStr, tt.entityType)
		})
	}
}

func TestErrOutputDirectoryFailed_VariousPaths(t *testing.T) {
	tests := []struct {
		path     string
		innerErr error
	}{
		{"/var/backup", errors.New("permission denied")},
		{"/nonexistent/path/to/dir", errors.New("no such file or directory")},
		{"", errors.New("empty path")},
		{"/read-only-dir", errors.New("read-only file system")},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ErrOutputDirectoryFailed{
				Path: tt.path,
				Err:  tt.innerErr,
			}
			errStr := err.Error()
			assert.Contains(t, errStr, "output directory")
			if tt.path != "" {
				assert.Contains(t, errStr, tt.path)
			}
		})
	}
}

func TestErrFileWriteFailed_VariousPaths(t *testing.T) {
	tests := []struct {
		path     string
		innerErr error
	}{
		{"/backup/user.json", errors.New("disk full")},
		{"/etc/readonly.txt", errors.New("permission denied")},
		{"output.yaml", errors.New("I/O error")},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ErrFileWriteFailed{
				Path: tt.path,
				Err:  tt.innerErr,
			}
			errStr := err.Error()
			assert.Contains(t, errStr, "write file")
			assert.Contains(t, errStr, tt.path)
		})
	}
}

// ErrGRPCRequired tests

func TestErrGRPCRequired_VariousOperations(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		contains  []string
	}{
		{
			name:      "db dump",
			operation: "db dump",
			contains:  []string{"db dump", "gRPC connection", "Unix socket"},
		},
		{
			name:      "db list",
			operation: "db list",
			contains:  []string{"db list", "gRPC connection"},
		},
		{
			name:      "empty operation",
			operation: "",
			contains:  []string{"requires gRPC connection"},
		},
		{
			name:      "streaming operation",
			operation: "data export streaming",
			contains:  []string{"data export streaming", "gRPC"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrGRPCRequired{Operation: tt.operation}
			errStr := err.Error()
			for _, substr := range tt.contains {
				assert.Contains(t, errStr, substr)
			}
		})
	}
}

// ListFlags struct tests

func TestListFlags_DefaultValues(t *testing.T) {
	flags := &listFlags{}

	assert.Empty(t, flags.configDir, "configDir should default to empty")
}

// Command with different OutputFormat configurations

func TestCommands_WithDifferentOutputFormats(t *testing.T) {
	formats := []cli.OutputFormat{
		cli.OutputFormatTable,
		cli.OutputFormatJSON,
		cli.OutputFormatYAML,
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{
					OutputFormat: format,
				}
			}

			cmd := NewCommand(getFlags)
			require.NotNil(t, cmd)

			listCmd := NewListCommand(getFlags)
			require.NotNil(t, listCmd)

			dumpCmd := NewDumpCommand(getFlags)
			require.NotNil(t, dumpCmd)
		})
	}
}

func TestCommands_WithNilFlags(t *testing.T) {
	// getFlags that returns nil should still create commands
	// (errors will occur at runtime when RunE is called)
	getFlags := func() *cli.CommonFlags {
		return nil
	}

	cmd := NewCommand(getFlags)
	assert.NotNil(t, cmd)
	assert.Equal(t, "db", cmd.Use)
	assert.Equal(t, 2, len(cmd.Commands()))

	listCmd := NewListCommand(getFlags)
	assert.NotNil(t, listCmd)
	assert.Equal(t, "list", listCmd.Use)

	dumpCmd := NewDumpCommand(getFlags)
	assert.NotNil(t, dumpCmd)
	assert.Equal(t, "dump", dumpCmd.Use)
}

func TestCommands_WithVerboseFlag(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			Verbose:      true,
		}
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
}

func TestCommands_WithNoColorFlag(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
			NoColor:      true,
		}
	}

	cmd := NewCommand(getFlags)
	require.NotNil(t, cmd)
}

// Test flag callback behaviors

func TestGetFlagsCallback_NotCalledDuringCreation(t *testing.T) {
	callCount := 0
	getFlags := func() *cli.CommonFlags {
		callCount++
		return &cli.CommonFlags{}
	}

	// Creating commands should not call getFlags
	_ = NewCommand(getFlags)
	assert.Equal(t, 0, callCount, "getFlags should not be called during NewCommand")

	_ = NewListCommand(getFlags)
	assert.Equal(t, 0, callCount, "getFlags should not be called during NewListCommand")

	_ = NewDumpCommand(getFlags)
	assert.Equal(t, 0, callCount, "getFlags should not be called during NewDumpCommand")
}

// Test command Use strings match expected patterns

func TestCommandUse_Patterns(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	tests := []struct {
		cmdFunc  func(func() *cli.CommonFlags) interface{}
		expected string
	}{
		{func(f func() *cli.CommonFlags) interface{} { return NewListCommand(f) }, "list"},
		{func(f func() *cli.CommonFlags) interface{} { return NewDumpCommand(f) }, "dump"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			// Get the command (type assertion handled differently)
			switch tt.expected {
			case "list":
				cmd := NewListCommand(getFlags)
				assert.Equal(t, tt.expected, cmd.Use)
			case "dump":
				cmd := NewDumpCommand(getFlags)
				assert.Equal(t, tt.expected, cmd.Use)
			}
		})
	}
}

// Test command Short descriptions

func TestCommand_ShortDescriptions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	t.Run("db root command", func(t *testing.T) {
		cmd := NewCommand(getFlags)
		assert.Equal(t, "Database operations", cmd.Short)
	})

	t.Run("list command", func(t *testing.T) {
		cmd := NewListCommand(getFlags)
		assert.Equal(t, "List QuicBaaS entity types and counts", cmd.Short)
	})

	t.Run("dump command", func(t *testing.T) {
		cmd := NewDumpCommand(getFlags)
		assert.Equal(t, "Export QuicBaaS data to files", cmd.Short)
	})
}

// Test command Long descriptions contain required content

func TestCommand_LongDescriptionContent(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	t.Run("db root command contains QuicBaaS", func(t *testing.T) {
		cmd := NewCommand(getFlags)
		assert.Contains(t, cmd.Long, "QuicBaaS")
		assert.Contains(t, cmd.Long, "datastore")
	})

	t.Run("list command contains entity types", func(t *testing.T) {
		cmd := NewListCommand(getFlags)
		assert.Contains(t, cmd.Long, "entity types")
		assert.Contains(t, cmd.Long, "Organization")
		assert.Contains(t, cmd.Long, "User")
		assert.Contains(t, cmd.Long, "Zone")
	})

	t.Run("dump command contains export info", func(t *testing.T) {
		cmd := NewDumpCommand(getFlags)
		assert.Contains(t, cmd.Long, "Export")
		assert.Contains(t, cmd.Long, "JSON")
		assert.Contains(t, cmd.Long, "YAML")
	})
}
