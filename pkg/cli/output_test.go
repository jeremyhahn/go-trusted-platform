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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNewPrinter_WithColor(t *testing.T) {
	printer := NewPrinter(OutputFormatTable, false)

	require.NotNil(t, printer)
	assert.Equal(t, OutputFormatTable, printer.format)
	assert.False(t, printer.noColor)
	assert.NotNil(t, printer.writer)
}

func TestNewPrinter_WithoutColor(t *testing.T) {
	printer := NewPrinter(OutputFormatJSON, true)

	require.NotNil(t, printer)
	assert.Equal(t, OutputFormatJSON, printer.format)
	assert.True(t, printer.noColor)
}

func TestNewPrinterWithWriter_WithColor(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinterWithWriter(OutputFormatJSON, false, &buf)

	require.NotNil(t, printer)
	assert.Equal(t, OutputFormatJSON, printer.format)
	assert.False(t, printer.noColor)
	assert.Equal(t, &buf, printer.writer)
}

func TestNewPrinterWithWriter_WithoutColor(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinterWithWriter(OutputFormatYAML, true, &buf)

	require.NotNil(t, printer)
	assert.Equal(t, OutputFormatYAML, printer.format)
	assert.True(t, printer.noColor)
	assert.Equal(t, &buf, printer.writer)
}

func TestNewPrinterWithWriter_PrintsToCustomWriter(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinterWithWriter(OutputFormatJSON, true, &buf)

	data := map[string]string{"key": "value"}
	err := printer.Print(data)
	require.NoError(t, err)

	// Verify output went to our buffer
	output := buf.String()
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")

	// Verify it is valid JSON
	var result map[string]string
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestNewPrinterWithWriter_AllFormats(t *testing.T) {
	tests := []struct {
		name   string
		format OutputFormat
	}{
		{"JSON", OutputFormatJSON},
		{"YAML", OutputFormatYAML},
		{"Table", OutputFormatTable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			printer := NewPrinterWithWriter(tt.format, true, &buf)

			require.NotNil(t, printer)
			assert.Equal(t, tt.format, printer.format)
			assert.Equal(t, &buf, printer.writer)
		})
	}
}

func TestPrinter_PrintJSON_ValidData(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatJSON, true)
	printer.writer = &buf

	data := map[string]interface{}{
		"name":    "test",
		"version": "1.0.0",
		"active":  true,
	}

	err := printer.Print(data)
	require.NoError(t, err)

	// Verify JSON output
	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "test", result["name"])
	assert.Equal(t, "1.0.0", result["version"])
	assert.Equal(t, true, result["active"])
}

func TestPrinter_PrintJSON_EmptyData(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatJSON, true)
	printer.writer = &buf

	data := map[string]interface{}{}

	err := printer.Print(data)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestPrinter_PrintYAML_ValidData(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatYAML, true)
	printer.writer = &buf

	data := map[string]interface{}{
		"name":    "test",
		"version": "1.0.0",
		"active":  true,
	}

	err := printer.Print(data)
	require.NoError(t, err)

	// Verify YAML output
	var result map[string]interface{}
	err = yaml.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "test", result["name"])
	assert.Equal(t, "1.0.0", result["version"])
	assert.Equal(t, true, result["active"])
}

func TestPrinter_PrintYAML_EmptyData(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatYAML, true)
	printer.writer = &buf

	data := map[string]interface{}{}

	err := printer.Print(data)
	require.NoError(t, err)

	var result map[string]interface{}
	err = yaml.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestPrinter_PrintTable_ValidData(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	data := NewTableData("Name", "Version", "Status")
	data.AddRow("platformd", "1.0.0", "active")
	data.AddRow("tpm-service", "2.1.3", "inactive")

	err := printer.Print(*data)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "VERSION")
	assert.Contains(t, output, "STATUS")
	assert.Contains(t, output, "platformd")
	assert.Contains(t, output, "1.0.0")
	assert.Contains(t, output, "active")
	assert.Contains(t, output, "tpm-service")
	assert.Contains(t, output, "2.1.3")
	assert.Contains(t, output, "inactive")
}

func TestPrinter_PrintTable_EmptyData(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	data := NewTableData("Name", "Version", "Status")

	err := printer.Print(*data)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "VERSION")
	assert.Contains(t, output, "STATUS")
}

func TestPrinter_PrintTable_NoHeaders(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	data := &TableData{
		Headers: []string{},
		Rows: [][]string{
			{"row1-col1", "row1-col2"},
			{"row2-col1", "row2-col2"},
		},
	}

	err := printer.Print(*data)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "row1-col1")
	assert.Contains(t, output, "row2-col2")
}

func TestPrinter_Print_InvalidFormat(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormat("invalid"), true)
	printer.writer = &buf

	data := map[string]string{"test": "data"}

	err := printer.Print(data)
	require.Error(t, err)
	assert.IsType(t, ErrInvalidOutputFormat{}, err)
}

func TestPrinter_Print_NonTableDataFallback(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	// Non-TableData should fall back to YAML
	data := map[string]string{"key": "value"}

	err := printer.Print(data)
	require.NoError(t, err)

	var result map[string]string
	err = yaml.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])
}

func TestPrinter_PrintSuccess_WithColor(t *testing.T) {
	printer := NewPrinter(OutputFormatTable, false)

	// With color enabled, fatih/color writes to os.Stdout directly
	// We just verify it doesn't panic
	assert.NotPanics(t, func() {
		printer.PrintSuccess("Operation completed")
	})
}

func TestPrinter_PrintSuccess_NoColor(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	printer.PrintSuccess("Operation completed")

	output := buf.String()
	assert.Contains(t, output, "[SUCCESS]")
	assert.Contains(t, output, "Operation completed")
}

func TestPrinter_PrintError_WithColor(t *testing.T) {
	printer := NewPrinter(OutputFormatTable, false)

	assert.NotPanics(t, func() {
		printer.PrintError("Operation failed")
	})
}

func TestPrinter_PrintError_NoColor(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	printer.PrintError("Operation failed")

	output := buf.String()
	assert.Contains(t, output, "[ERROR]")
	assert.Contains(t, output, "Operation failed")
}

func TestPrinter_PrintWarning_WithColor(t *testing.T) {
	printer := NewPrinter(OutputFormatTable, false)

	assert.NotPanics(t, func() {
		printer.PrintWarning("Deprecated feature")
	})
}

func TestPrinter_PrintWarning_NoColor(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	printer.PrintWarning("Deprecated feature")

	output := buf.String()
	assert.Contains(t, output, "[WARNING]")
	assert.Contains(t, output, "Deprecated feature")
}

func TestPrinter_PrintInfo_WithColor(t *testing.T) {
	printer := NewPrinter(OutputFormatTable, false)

	assert.NotPanics(t, func() {
		printer.PrintInfo("Information message")
	})
}

func TestPrinter_PrintInfo_NoColor(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	printer.PrintInfo("Information message")

	output := buf.String()
	assert.Contains(t, output, "[INFO]")
	assert.Contains(t, output, "Information message")
}

func TestPrinter_PrintKeyValue(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	printer.PrintKeyValue("Version", "1.2.3")

	output := buf.String()
	assert.Contains(t, output, "Version")
	assert.Contains(t, output, "1.2.3")
	assert.Contains(t, output, ":")
}

func TestNewTableData_WithHeaders(t *testing.T) {
	data := NewTableData("Col1", "Col2", "Col3")

	require.NotNil(t, data)
	assert.Equal(t, []string{"Col1", "Col2", "Col3"}, data.Headers)
	assert.Empty(t, data.Rows)
}

func TestNewTableData_NoHeaders(t *testing.T) {
	data := NewTableData()

	require.NotNil(t, data)
	assert.Empty(t, data.Headers)
	assert.Empty(t, data.Rows)
}

func TestTableData_AddRow(t *testing.T) {
	data := NewTableData("Name", "Age")

	data.AddRow("Alice", "30")
	data.AddRow("Bob", "25")

	assert.Len(t, data.Rows, 2)
	assert.Equal(t, []string{"Alice", "30"}, data.Rows[0])
	assert.Equal(t, []string{"Bob", "25"}, data.Rows[1])
}

func TestTableData_AddRow_MultipleValues(t *testing.T) {
	data := NewTableData("A", "B", "C", "D")

	data.AddRow("1", "2", "3", "4")

	assert.Len(t, data.Rows, 1)
	assert.Len(t, data.Rows[0], 4)
}

func TestTableData_IsEmpty_True(t *testing.T) {
	data := NewTableData("Header1", "Header2")

	assert.True(t, data.IsEmpty())
}

func TestTableData_IsEmpty_False(t *testing.T) {
	data := NewTableData("Header1", "Header2")
	data.AddRow("value1", "value2")

	assert.False(t, data.IsEmpty())
}

func TestTableData_RowCount_Zero(t *testing.T) {
	data := NewTableData("Header1")

	assert.Equal(t, 0, data.RowCount())
}

func TestTableData_RowCount_Multiple(t *testing.T) {
	data := NewTableData("Header1")
	data.AddRow("row1")
	data.AddRow("row2")
	data.AddRow("row3")

	assert.Equal(t, 3, data.RowCount())
}

func TestTableData_ComplexScenario(t *testing.T) {
	data := NewTableData("Service", "Status", "Uptime")

	// Initially empty
	assert.True(t, data.IsEmpty())
	assert.Equal(t, 0, data.RowCount())

	// Add some rows
	data.AddRow("daemon", "running", "24h")
	data.AddRow("tpm", "stopped", "0h")
	data.AddRow("sdn", "running", "12h")

	// Should not be empty
	assert.False(t, data.IsEmpty())
	assert.Equal(t, 3, data.RowCount())

	// Verify content
	assert.Equal(t, "daemon", data.Rows[0][0])
	assert.Equal(t, "running", data.Rows[0][1])
	assert.Equal(t, "24h", data.Rows[0][2])
}

func TestPrinter_PrintTable_MismatchedColumns(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	data := NewTableData("Col1", "Col2", "Col3")
	data.AddRow("a", "b")           // Missing column
	data.AddRow("x", "y", "z", "w") // Extra column

	err := printer.Print(*data)
	require.NoError(t, err)

	output := buf.String()
	// Table should still render, even with mismatched columns
	assert.NotEmpty(t, output)
	assert.Contains(t, output, "COL1")
}

func TestPrinter_StructuredOutput_ComplexNested(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatJSON, true)
	printer.writer = &buf

	data := map[string]interface{}{
		"server": map[string]interface{}{
			"host": "example.com",
			"port": 8443,
			"tls": map[string]bool{
				"enabled": true,
			},
		},
		"clients": []string{"client1", "client2"},
	}

	err := printer.Print(data)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)

	server := result["server"].(map[string]interface{})
	assert.Equal(t, "example.com", server["host"])
	assert.Equal(t, float64(8443), server["port"])
}

func TestPrinter_AllMessageTypes(t *testing.T) {
	// Test that all message types render without panic
	printer := NewPrinter(OutputFormatTable, true)
	var buf bytes.Buffer
	printer.writer = &buf

	tests := []struct {
		name string
		fn   func(string)
		msg  string
	}{
		{"success", printer.PrintSuccess, "Success message"},
		{"error", printer.PrintError, "Error message"},
		{"warning", printer.PrintWarning, "Warning message"},
		{"info", printer.PrintInfo, "Info message"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			assert.NotPanics(t, func() {
				tt.fn(tt.msg)
			})
			output := buf.String()
			assert.NotEmpty(t, output)
			assert.Contains(t, output, tt.msg)
		})
	}
}

func TestPrinter_MultilineContent(t *testing.T) {
	var buf bytes.Buffer
	printer := NewPrinter(OutputFormatTable, true)
	printer.writer = &buf

	data := NewTableData("Name", "Description")
	data.AddRow("test", "Line 1\nLine 2\nLine 3")

	err := printer.Print(*data)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "test")
	// Newlines in cells will be preserved in output
	lines := strings.Split(output, "\n")
	assert.True(t, len(lines) > 2)
}
