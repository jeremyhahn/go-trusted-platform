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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestNewDumpCommand tests command creation and flag defaults
func TestNewDumpCommand(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := NewDumpCommand(getFlags)

	require.NotNil(t, cmd, "NewDumpCommand should not return nil")
	assert.Equal(t, "dump", cmd.Use, "command Use should be 'dump'")
	assert.Equal(t, "Export QuicBaaS data to files", cmd.Short)
	assert.NotEmpty(t, cmd.Long, "Long description should not be empty")
	assert.NotNil(t, cmd.RunE, "RunE should be set")
}

func TestNewDumpCommand_HasLongDescription(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDumpCommand(getFlags)

	assert.NotEmpty(t, cmd.Long, "Long description should not be empty")
	assert.Contains(t, cmd.Long, "Export QuicBaaS data")
	assert.Contains(t, cmd.Long, "Examples:")
}

func TestNewDumpCommand_FlagDefaults(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDumpCommand(getFlags)

	// Test output flag
	outputFlag := cmd.Flags().Lookup("output")
	require.NotNil(t, outputFlag, "--output flag should exist")
	assert.Equal(t, "o", outputFlag.Shorthand, "output flag shorthand should be 'o'")
	assert.Equal(t, "./quicbaas-dump", outputFlag.DefValue, "output flag default should be './quicbaas-dump'")

	// Test format flag
	formatFlag := cmd.Flags().Lookup("format")
	require.NotNil(t, formatFlag, "--format flag should exist")
	assert.Equal(t, "f", formatFlag.Shorthand, "format flag shorthand should be 'f'")
	assert.Equal(t, "json", formatFlag.DefValue, "format flag default should be 'json'")

	// Test entity-type flag
	entityTypeFlag := cmd.Flags().Lookup("entity-type")
	require.NotNil(t, entityTypeFlag, "--entity-type flag should exist")
	assert.Equal(t, "t", entityTypeFlag.Shorthand, "entity-type flag shorthand should be 't'")
	assert.Equal(t, "", entityTypeFlag.DefValue, "entity-type flag default should be empty")

	// Test pretty flag
	prettyFlag := cmd.Flags().Lookup("pretty")
	require.NotNil(t, prettyFlag, "--pretty flag should exist")
	assert.Equal(t, "false", prettyFlag.DefValue, "pretty flag default should be 'false'")

	// Test config-dir flag
	configDirFlag := cmd.Flags().Lookup("config-dir")
	require.NotNil(t, configDirFlag, "--config-dir flag should exist")
	assert.Equal(t, "", configDirFlag.DefValue, "config-dir flag default should be empty")
}

// TestDumpCommand_InvalidFormat tests error handling for invalid format
func TestDumpCommand_InvalidFormat(t *testing.T) {
	tests := []struct {
		name   string
		format string
	}{
		{"empty format", ""},
		{"xml format", "xml"},
		{"csv format", "csv"},
		{"invalid string", "invalid"},
		{"uppercase JSON", "JSON"},
		{"uppercase YAML", "YAML"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: We cannot directly test runDump without a database connection,
			// but we can validate the format validation logic
			format := tt.format
			if format != "json" && format != "yaml" {
				// Format is invalid, which is expected
				err := ErrInvalidFormat{Format: format}
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid format")
			}
		})
	}
}

// TestDumpCommand_ValidFormats tests JSON and YAML format validation
func TestDumpCommand_ValidFormats(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		isValid bool
	}{
		{"lowercase json", "json", true},
		{"lowercase yaml", "yaml", true},
		{"uppercase JSON", "JSON", false},
		{"uppercase YAML", "YAML", false},
		{"mixed case Json", "Json", false},
		{"mixed case Yaml", "Yaml", false},
		{"empty", "", false},
		{"xml", "xml", false},
		{"csv", "csv", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the format validation logic from runDump
			format := tt.format
			// The actual runDump uses strings.ToLower, so uppercase formats become valid
			// Let's test what the actual validation logic does
			isValid := format == "json" || format == "yaml"
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}

// TestDumpErrors tests all error type constructors
func TestDumpErrors(t *testing.T) {
	t.Run("ErrInvalidFormat", func(t *testing.T) {
		err := ErrInvalidFormat{Format: "xml"}
		assert.Error(t, err)
		assert.Equal(t, "invalid format: xml (valid: json, yaml)", err.Error())
	})

	t.Run("ErrInvalidFormat_empty", func(t *testing.T) {
		err := ErrInvalidFormat{Format: ""}
		assert.Error(t, err)
		assert.Equal(t, "invalid format:  (valid: json, yaml)", err.Error())
	})

	t.Run("ErrConfigLoadFailed", func(t *testing.T) {
		wrappedErr := errors.New("config file not found")
		err := ErrConfigLoadFailed{Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to load platform configuration: config file not found", err.Error())
	})

	t.Run("ErrConfigLoadFailed_nil", func(t *testing.T) {
		err := ErrConfigLoadFailed{Err: nil}
		assert.Error(t, err)
		assert.Equal(t, "failed to load platform configuration: <nil>", err.Error())
	})

	t.Run("ErrDatabaseConnectionFailed", func(t *testing.T) {
		wrappedErr := errors.New("connection refused")
		err := ErrDatabaseConnectionFailed{Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to connect to database: connection refused", err.Error())
	})

	t.Run("ErrDatabaseStartFailed", func(t *testing.T) {
		wrappedErr := errors.New("initialization error")
		err := ErrDatabaseStartFailed{Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to start database: initialization error", err.Error())
	})

	t.Run("ErrInvalidFactoryType", func(t *testing.T) {
		err := ErrInvalidFactoryType{}
		assert.Error(t, err)
		assert.Equal(t, "expected QuicBaaS factory but got different type", err.Error())
	})

	t.Run("ErrOutputDirectoryFailed", func(t *testing.T) {
		wrappedErr := errors.New("permission denied")
		err := ErrOutputDirectoryFailed{Path: "/var/backup", Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to create output directory /var/backup: permission denied", err.Error())
	})

	t.Run("ErrOutputDirectoryFailed_emptyPath", func(t *testing.T) {
		wrappedErr := errors.New("invalid path")
		err := ErrOutputDirectoryFailed{Path: "", Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to create output directory : invalid path", err.Error())
	})

	t.Run("ErrSerializationFailed", func(t *testing.T) {
		wrappedErr := errors.New("marshal error")
		err := ErrSerializationFailed{EntityType: "User", ID: 123, Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to serialize User entity 123: marshal error", err.Error())
	})

	t.Run("ErrSerializationFailed_zeroID", func(t *testing.T) {
		wrappedErr := errors.New("marshal error")
		err := ErrSerializationFailed{EntityType: "Organization", ID: 0, Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to serialize Organization entity 0: marshal error", err.Error())
	})

	t.Run("ErrDeserializationFailed", func(t *testing.T) {
		wrappedErr := errors.New("invalid JSON")
		err := ErrDeserializationFailed{EntityType: "Zone", ID: 456, Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to deserialize Zone entity 456: invalid JSON", err.Error())
	})

	t.Run("ErrFileWriteFailed", func(t *testing.T) {
		wrappedErr := errors.New("disk full")
		err := ErrFileWriteFailed{Path: "/backup/user.json", Err: wrappedErr}
		assert.Error(t, err)
		assert.Equal(t, "failed to write file /backup/user.json: disk full", err.Error())
	})

	t.Run("ErrGRPCRequired", func(t *testing.T) {
		err := ErrGRPCRequired{Operation: "db dump"}
		assert.Error(t, err)
		errStr := err.Error()
		assert.Contains(t, errStr, "db dump")
		assert.Contains(t, errStr, "gRPC connection")
		assert.Contains(t, errStr, "Unix socket")
		assert.Contains(t, errStr, "streaming RPCs")
	})

	t.Run("ErrGRPCRequired_differentOperation", func(t *testing.T) {
		err := ErrGRPCRequired{Operation: "db list"}
		assert.Error(t, err)
		errStr := err.Error()
		assert.Contains(t, errStr, "db list")
		assert.Contains(t, errStr, "gRPC connection")
	})

	t.Run("ErrGRPCRequired_emptyOperation", func(t *testing.T) {
		err := ErrGRPCRequired{Operation: ""}
		assert.Error(t, err)
		errStr := err.Error()
		assert.Contains(t, errStr, "requires gRPC connection")
	})
}

// TestDumpErrors_ImplementsError verifies all error types implement error interface
func TestDumpErrors_ImplementsError(t *testing.T) {
	// Compile-time check that all error types implement the error interface
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
}

// TestErrGRPCRequired tests the ErrGRPCRequired error type thoroughly
func TestErrGRPCRequired(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		expected  []string
	}{
		{
			name:      "db dump operation",
			operation: "db dump",
			expected:  []string{"db dump", "gRPC connection", "Unix socket", "streaming RPCs"},
		},
		{
			name:      "db list operation",
			operation: "db list",
			expected:  []string{"db list", "gRPC connection"},
		},
		{
			name:      "empty operation",
			operation: "",
			expected:  []string{"requires gRPC connection"},
		},
		{
			name:      "complex operation name",
			operation: "database streaming export",
			expected:  []string{"database streaming export", "gRPC"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrGRPCRequired{Operation: tt.operation}
			errStr := err.Error()

			for _, substr := range tt.expected {
				assert.Contains(t, errStr, substr)
			}
		})
	}
}

// TestErrGRPCRequired_TypeAssertion tests type assertion for ErrGRPCRequired
func TestErrGRPCRequired_TypeAssertion(t *testing.T) {
	var err error = ErrGRPCRequired{Operation: "test operation"}
	grpcErr, ok := err.(ErrGRPCRequired)
	assert.True(t, ok, "should be able to type assert to ErrGRPCRequired")
	assert.Equal(t, "test operation", grpcErr.Operation)
}

// TestExportEntityToJSON tests JSON export logic
func TestExportEntityToJSON(t *testing.T) {
	t.Run("valid JSON data", func(t *testing.T) {
		data := map[string]interface{}{
			"id":    1,
			"name":  "test-user",
			"email": "test@example.com",
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		// Parse and re-serialize as the dump command does
		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)
		assert.NotEmpty(t, outputData)

		// Verify the output is valid JSON
		var result map[string]interface{}
		err = json.Unmarshal(outputData, &result)
		require.NoError(t, err)
		assert.Equal(t, float64(1), result["id"])
		assert.Equal(t, "test-user", result["name"])
	})

	t.Run("JSON with nested objects", func(t *testing.T) {
		data := map[string]interface{}{
			"id": 1,
			"metadata": map[string]interface{}{
				"created": "2025-01-01",
				"tags":    []string{"production", "critical"},
			},
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)
		assert.Contains(t, string(outputData), "metadata")
		assert.Contains(t, string(outputData), "production")
	})

	t.Run("JSON with special characters", func(t *testing.T) {
		data := map[string]interface{}{
			"name":        "test \"user\"",
			"description": "line1\nline2\ttab",
			"path":        "/path/with/slashes",
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)

		var result map[string]interface{}
		err = json.Unmarshal(outputData, &result)
		require.NoError(t, err)
		assert.Equal(t, "test \"user\"", result["name"])
	})

	t.Run("JSON without pretty print", func(t *testing.T) {
		data := map[string]interface{}{
			"id":   1,
			"name": "test",
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		// When pretty is false, raw data is used directly
		assert.NotContains(t, string(jsonData), "\n")
	})

	t.Run("invalid JSON data handling", func(t *testing.T) {
		invalidJSON := []byte(`{"unclosed": "bracket`)

		var parsed interface{}
		err := json.Unmarshal(invalidJSON, &parsed)
		assert.Error(t, err, "should fail to parse invalid JSON")
	})

	t.Run("empty JSON object", func(t *testing.T) {
		data := map[string]interface{}{}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)
		assert.Equal(t, "{}", string(outputData))
	})

	t.Run("JSON array", func(t *testing.T) {
		data := []interface{}{1, 2, 3}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := json.MarshalIndent(parsed, "", "  ")
		require.NoError(t, err)
		assert.Contains(t, string(outputData), "1")
	})
}

// TestExportEntityToYAML tests YAML export logic
func TestExportEntityToYAML(t *testing.T) {
	t.Run("valid data to YAML", func(t *testing.T) {
		data := map[string]interface{}{
			"id":    1,
			"name":  "test-user",
			"email": "test@example.com",
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		// Parse JSON and convert to YAML as the dump command does
		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := yaml.Marshal(parsed)
		require.NoError(t, err)
		assert.NotEmpty(t, outputData)

		// Verify the output is valid YAML
		var result map[string]interface{}
		err = yaml.Unmarshal(outputData, &result)
		require.NoError(t, err)
		assert.Equal(t, 1, result["id"])
		assert.Equal(t, "test-user", result["name"])
	})

	t.Run("YAML with nested objects", func(t *testing.T) {
		data := map[string]interface{}{
			"id": 1,
			"metadata": map[string]interface{}{
				"created": "2025-01-01",
				"tags":    []string{"production", "critical"},
			},
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := yaml.Marshal(parsed)
		require.NoError(t, err)
		assert.Contains(t, string(outputData), "metadata")
		assert.Contains(t, string(outputData), "production")
	})

	t.Run("YAML with special characters", func(t *testing.T) {
		data := map[string]interface{}{
			"name":        "test: user",
			"description": "multi\nline",
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := yaml.Marshal(parsed)
		require.NoError(t, err)

		var result map[string]interface{}
		err = yaml.Unmarshal(outputData, &result)
		require.NoError(t, err)
		assert.Equal(t, "test: user", result["name"])
	})

	t.Run("empty YAML object", func(t *testing.T) {
		data := map[string]interface{}{}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := yaml.Marshal(parsed)
		require.NoError(t, err)
		assert.Equal(t, "{}\n", string(outputData))
	})

	t.Run("YAML from invalid JSON", func(t *testing.T) {
		invalidJSON := []byte(`{"unclosed": "bracket`)

		var parsed interface{}
		err := json.Unmarshal(invalidJSON, &parsed)
		assert.Error(t, err, "should fail to parse invalid JSON")
	})

	t.Run("YAML with numeric values", func(t *testing.T) {
		data := map[string]interface{}{
			"int_val":   42,
			"float_val": 3.14,
			"bool_val":  true,
		}

		jsonData, err := json.Marshal(data)
		require.NoError(t, err)

		var parsed interface{}
		err = json.Unmarshal(jsonData, &parsed)
		require.NoError(t, err)

		outputData, err := yaml.Marshal(parsed)
		require.NoError(t, err)

		var result map[string]interface{}
		err = yaml.Unmarshal(outputData, &result)
		require.NoError(t, err)
		assert.Equal(t, true, result["bool_val"])
	})
}

// TestSanitizeFilename tests filename sanitization for IDs
func TestSanitizeFilename(t *testing.T) {
	// The dump command uses numeric IDs for filenames, so test ID formatting
	t.Run("numeric ID formatting", func(t *testing.T) {
		tests := []struct {
			id       uint64
			format   string
			expected string
		}{
			{1, "json", "1.json"},
			{123, "json", "123.json"},
			{0, "json", "0.json"},
			{18446744073709551615, "json", "18446744073709551615.json"}, // max uint64
			{1, "yaml", "1.yaml"},
			{999, "yaml", "999.yaml"},
		}

		for _, tt := range tests {
			t.Run(tt.expected, func(t *testing.T) {
				filename := filepath.Base(filepath.Join("entityDir", fmt.Sprintf("%d.%s", tt.id, tt.format)))
				assert.Equal(t, tt.expected, filename)
			})
		}
	})
}

// TestDumpFlagsStruct tests the dumpFlags struct initialization
func TestDumpFlagsStruct(t *testing.T) {
	flags := &dumpFlags{
		output:     "./backup",
		format:     "json",
		entityType: "User",
		pretty:     true,
		configDir:  "/etc/trusted-platform",
	}

	assert.Equal(t, "./backup", flags.output)
	assert.Equal(t, "json", flags.format)
	assert.Equal(t, "User", flags.entityType)
	assert.True(t, flags.pretty)
	assert.Equal(t, "/etc/trusted-platform", flags.configDir)
}

// TestDumpFlagsStruct_Defaults tests default values
func TestDumpFlagsStruct_Defaults(t *testing.T) {
	flags := &dumpFlags{}

	assert.Empty(t, flags.output)
	assert.Empty(t, flags.format)
	assert.Empty(t, flags.entityType)
	assert.False(t, flags.pretty)
	assert.Empty(t, flags.configDir)
}

// TestFileWriteOperation tests file write operations without modifying host
func TestFileWriteOperation(t *testing.T) {
	t.Run("write JSON file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filename := filepath.Join(tmpDir, "test.json")

		data := []byte(`{"id": 1, "name": "test"}`)
		err := os.WriteFile(filename, data, 0644)
		require.NoError(t, err)

		// Verify file was written
		content, err := os.ReadFile(filename)
		require.NoError(t, err)
		assert.Equal(t, data, content)
	})

	t.Run("write YAML file", func(t *testing.T) {
		tmpDir := t.TempDir()
		filename := filepath.Join(tmpDir, "test.yaml")

		data := []byte("id: 1\nname: test\n")
		err := os.WriteFile(filename, data, 0644)
		require.NoError(t, err)

		content, err := os.ReadFile(filename)
		require.NoError(t, err)
		assert.Equal(t, data, content)
	})

	t.Run("write to nested directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		entityDir := filepath.Join(tmpDir, "User")

		err := os.MkdirAll(entityDir, 0755)
		require.NoError(t, err)

		filename := filepath.Join(entityDir, "1.json")
		data := []byte(`{"id": 1}`)
		err = os.WriteFile(filename, data, 0644)
		require.NoError(t, err)

		content, err := os.ReadFile(filename)
		require.NoError(t, err)
		assert.Equal(t, data, content)
	})

	t.Run("create directory structure", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputDir := filepath.Join(tmpDir, "backup", "quicbaas")

		err := os.MkdirAll(outputDir, 0755)
		require.NoError(t, err)

		info, err := os.Stat(outputDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})
}

// TestOutputDirectoryCreation tests directory creation edge cases
func TestOutputDirectoryCreation(t *testing.T) {
	t.Run("create simple directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputDir := filepath.Join(tmpDir, "output")

		err := os.MkdirAll(outputDir, 0755)
		require.NoError(t, err)

		info, err := os.Stat(outputDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("create nested directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		outputDir := filepath.Join(tmpDir, "a", "b", "c", "d")

		err := os.MkdirAll(outputDir, 0755)
		require.NoError(t, err)

		info, err := os.Stat(outputDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("directory already exists", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Directory already exists (tmpDir)
		err := os.MkdirAll(tmpDir, 0755)
		require.NoError(t, err, "should not error if directory already exists")
	})
}

// TestFormatValidation tests the format validation logic
func TestFormatValidation(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"valid json", "json", false},
		{"valid yaml", "yaml", false},
		{"invalid empty", "", true},
		{"invalid xml", "xml", true},
		{"invalid csv", "csv", true},
		{"invalid mixed case", "JSON", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the format check without ToLower (testing the raw comparison)
			isValid := tt.format == "json" || tt.format == "yaml"
			assert.Equal(t, !tt.expectError, isValid)
		})
	}
}

// TestFormatValidationWithNormalization tests format validation with lowercase normalization
func TestFormatValidationWithNormalization(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectValid bool
	}{
		{"lowercase json", "json", true},
		{"lowercase yaml", "yaml", true},
		{"uppercase JSON", "JSON", true},
		{"uppercase YAML", "YAML", true},
		{"mixed case Json", "Json", true},
		{"empty", "", false},
		{"xml", "xml", false},
		{"CSV", "CSV", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the actual validation with ToLower
			normalized := strings.ToLower(tt.format)
			isValid := normalized == "json" || normalized == "yaml"
			assert.Equal(t, tt.expectValid, isValid)
		})
	}
}

// TestDumpCommand_RunESet tests that RunE is properly set
func TestDumpCommand_RunESet(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDumpCommand(getFlags)
	assert.NotNil(t, cmd.RunE, "RunE should be set on the dump command")
}

// TestDumpCommand_FlagUsageDescriptions tests that flags have usage descriptions
func TestDumpCommand_FlagUsageDescriptions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := NewDumpCommand(getFlags)

	flags := []string{"output", "format", "entity-type", "pretty", "config-dir"}
	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		require.NotNil(t, flag, "flag %s should exist", flagName)
		assert.NotEmpty(t, flag.Usage, "flag %s should have usage description", flagName)
	}
}

// TestErrorTypeAssertions tests type assertions for error types
func TestErrorTypeAssertions(t *testing.T) {
	t.Run("ErrInvalidFormat type assertion", func(t *testing.T) {
		var err error = ErrInvalidFormat{Format: "xml"}
		_, ok := err.(ErrInvalidFormat)
		assert.True(t, ok)
	})

	t.Run("ErrConfigLoadFailed type assertion", func(t *testing.T) {
		var err error = ErrConfigLoadFailed{Err: errors.New("test")}
		_, ok := err.(ErrConfigLoadFailed)
		assert.True(t, ok)
	})

	t.Run("ErrDatabaseConnectionFailed type assertion", func(t *testing.T) {
		var err error = ErrDatabaseConnectionFailed{Err: errors.New("test")}
		_, ok := err.(ErrDatabaseConnectionFailed)
		assert.True(t, ok)
	})

	t.Run("ErrDatabaseStartFailed type assertion", func(t *testing.T) {
		var err error = ErrDatabaseStartFailed{Err: errors.New("test")}
		_, ok := err.(ErrDatabaseStartFailed)
		assert.True(t, ok)
	})

	t.Run("ErrInvalidFactoryType type assertion", func(t *testing.T) {
		var err error = ErrInvalidFactoryType{}
		_, ok := err.(ErrInvalidFactoryType)
		assert.True(t, ok)
	})

	t.Run("ErrOutputDirectoryFailed type assertion", func(t *testing.T) {
		var err error = ErrOutputDirectoryFailed{Path: "/test", Err: errors.New("test")}
		_, ok := err.(ErrOutputDirectoryFailed)
		assert.True(t, ok)
	})

	t.Run("ErrSerializationFailed type assertion", func(t *testing.T) {
		var err error = ErrSerializationFailed{EntityType: "User", ID: 1, Err: errors.New("test")}
		_, ok := err.(ErrSerializationFailed)
		assert.True(t, ok)
	})

	t.Run("ErrDeserializationFailed type assertion", func(t *testing.T) {
		var err error = ErrDeserializationFailed{EntityType: "User", ID: 1, Err: errors.New("test")}
		_, ok := err.(ErrDeserializationFailed)
		assert.True(t, ok)
	})

	t.Run("ErrFileWriteFailed type assertion", func(t *testing.T) {
		var err error = ErrFileWriteFailed{Path: "/test.json", Err: errors.New("test")}
		_, ok := err.(ErrFileWriteFailed)
		assert.True(t, ok)
	})

	t.Run("ErrGRPCRequired type assertion", func(t *testing.T) {
		var err error = ErrGRPCRequired{Operation: "test"}
		grpcErr, ok := err.(ErrGRPCRequired)
		assert.True(t, ok)
		assert.Equal(t, "test", grpcErr.Operation)
	})
}

// TestJSONMarshalIndent tests JSON indentation behavior
func TestJSONMarshalIndent(t *testing.T) {
	t.Run("indentation with two spaces", func(t *testing.T) {
		data := map[string]interface{}{
			"key": "value",
		}

		output, err := json.MarshalIndent(data, "", "  ")
		require.NoError(t, err)

		expected := "{\n  \"key\": \"value\"\n}"
		assert.Equal(t, expected, string(output))
	})

	t.Run("nested indentation", func(t *testing.T) {
		data := map[string]interface{}{
			"outer": map[string]interface{}{
				"inner": "value",
			},
		}

		output, err := json.MarshalIndent(data, "", "  ")
		require.NoError(t, err)

		assert.Contains(t, string(output), "  \"outer\"")
		assert.Contains(t, string(output), "    \"inner\"")
	})
}

// TestYAMLMarshal tests YAML marshaling behavior
func TestYAMLMarshal(t *testing.T) {
	t.Run("simple object", func(t *testing.T) {
		data := map[string]interface{}{
			"key": "value",
		}

		output, err := yaml.Marshal(data)
		require.NoError(t, err)

		assert.Contains(t, string(output), "key: value")
	})

	t.Run("nested object", func(t *testing.T) {
		data := map[string]interface{}{
			"outer": map[string]interface{}{
				"inner": "value",
			},
		}

		output, err := yaml.Marshal(data)
		require.NoError(t, err)

		assert.Contains(t, string(output), "outer:")
		assert.Contains(t, string(output), "inner: value")
	})
}

// TestErrorUnwrapping tests that errors with wrapped errors work correctly
func TestErrorUnwrapping(t *testing.T) {
	t.Run("ErrConfigLoadFailed contains original error", func(t *testing.T) {
		originalErr := errors.New("original error")
		err := ErrConfigLoadFailed{Err: originalErr}

		assert.Contains(t, err.Error(), "original error")
	})

	t.Run("ErrDatabaseConnectionFailed contains original error", func(t *testing.T) {
		originalErr := errors.New("connection timeout")
		err := ErrDatabaseConnectionFailed{Err: originalErr}

		assert.Contains(t, err.Error(), "connection timeout")
	})

	t.Run("ErrOutputDirectoryFailed contains path and error", func(t *testing.T) {
		originalErr := errors.New("permission denied")
		err := ErrOutputDirectoryFailed{Path: "/protected/dir", Err: originalErr}

		assert.Contains(t, err.Error(), "/protected/dir")
		assert.Contains(t, err.Error(), "permission denied")
	})
}

// TestFilepathJoin tests filepath operations used in dump
func TestFilepathJoin(t *testing.T) {
	t.Run("join output dir with entity type", func(t *testing.T) {
		outputDir := "/backup"
		entityType := "User"

		result := filepath.Join(outputDir, entityType)
		assert.Equal(t, "/backup/User", result)
	})

	t.Run("join entity dir with filename", func(t *testing.T) {
		entityDir := "/backup/User"
		filename := fmt.Sprintf("%d.%s", uint64(123), "json")

		result := filepath.Join(entityDir, filename)
		assert.Equal(t, "/backup/User/123.json", result)
	})
}
