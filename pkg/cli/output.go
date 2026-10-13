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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/fatih/color"
)

// Printer handles output formatting for CLI commands
type Printer struct {
	format  OutputFormat
	writer  io.Writer
	noColor bool
}

// NewPrinter creates a new output printer
func NewPrinter(format OutputFormat, noColor bool) *Printer {
	if noColor {
		color.NoColor = true
	}

	return &Printer{
		format:  format,
		writer:  os.Stdout,
		noColor: noColor,
	}
}

// NewPrinterWithWriter creates a new output printer with a custom writer.
// This is useful for testing where output needs to be captured.
func NewPrinterWithWriter(format OutputFormat, noColor bool, w io.Writer) *Printer {
	if noColor {
		color.NoColor = true
	}

	return &Printer{
		format:  format,
		writer:  w,
		noColor: noColor,
	}
}

// Print outputs data in the configured format
func (p *Printer) Print(data interface{}) error {
	switch p.format {
	case OutputFormatJSON:
		return p.printJSON(data)
	case OutputFormatYAML:
		return p.printYAML(data)
	case OutputFormatTable:
		return p.printTable(data)
	default:
		return ErrInvalidOutputFormat{Format: string(p.format)}
	}
}

// printJSON outputs data as JSON
func (p *Printer) printJSON(data interface{}) error {
	encoder := json.NewEncoder(p.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// printYAML outputs data as YAML
func (p *Printer) printYAML(data interface{}) error {
	encoder := yaml.NewEncoder(p.writer)
	encoder.SetIndent(2)
	defer encoder.Close()
	return encoder.Encode(data)
}

// printTable outputs data as a formatted table
func (p *Printer) printTable(data interface{}) error {
	// Use reflection to handle different types
	switch v := data.(type) {
	case TableData:
		return p.printTableData(v)
	case *TableData:
		// NewTableData returns a pointer; it is a table, not a YAML document.
		if v == nil {
			return nil
		}
		return p.printTableData(*v)
	default:
		// Fall back to YAML for unknown types
		return p.printYAML(data)
	}
}

// printTableData prints tabular data
func (p *Printer) printTableData(data TableData) error {
	w := tabwriter.NewWriter(p.writer, 0, 0, 3, ' ', 0)
	defer w.Flush()

	// Print header
	if len(data.Headers) > 0 {
		headerColor := color.New(color.Bold, color.FgCyan)
		headers := make([]string, len(data.Headers))
		for i, h := range data.Headers {
			headers[i] = headerColor.Sprint(strings.ToUpper(h))
		}
		fmt.Fprintln(w, strings.Join(headers, "\t"))
	}

	// Print rows
	for _, row := range data.Rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}

	return nil
}

// PrintSuccess prints a success message
func (p *Printer) PrintSuccess(message string) {
	if p.noColor {
		fmt.Fprintf(p.writer, "[SUCCESS] %s\n", message)
	} else {
		color.Green("// %s", message)
	}
}

// PrintError prints an error message
func (p *Printer) PrintError(message string) {
	if p.noColor {
		fmt.Fprintf(p.writer, "[ERROR] %s\n", message)
	} else {
		color.Red("x %s", message)
	}
}

// PrintWarning prints a warning message
func (p *Printer) PrintWarning(message string) {
	if p.noColor {
		fmt.Fprintf(p.writer, "[WARNING] %s\n", message)
	} else {
		color.Yellow("! %s", message)
	}
}

// PrintInfo prints an informational message
func (p *Printer) PrintInfo(message string) {
	if p.noColor {
		fmt.Fprintf(p.writer, "[INFO] %s\n", message)
	} else {
		color.Cyan("i %s", message)
	}
}

// PrintKeyValue prints a key-value pair
func (p *Printer) PrintKeyValue(key, value string) {
	keyColor := color.New(color.Bold)
	fmt.Fprintf(p.writer, "%s: %s\n", keyColor.Sprint(key), value)
}

// Println writes a raw line of text to the printer's writer followed by a
// newline. Use this when emitting a pre-formatted multi-line report (for
// example the comprehensive TPM info string produced by go-xkms) where
// the upstream library owns the presentation and the CLI should not
// re-interpret it.
func (p *Printer) Println(s string) {
	fmt.Fprintln(p.writer, s)
}

// TableData represents data to be displayed in table format
type TableData struct {
	Headers []string
	Rows    [][]string
}

// NewTableData creates a new TableData instance
func NewTableData(headers ...string) *TableData {
	return &TableData{
		Headers: headers,
		Rows:    make([][]string, 0),
	}
}

// AddRow adds a row to the table
func (t *TableData) AddRow(values ...string) {
	t.Rows = append(t.Rows, values)
}

// IsEmpty returns true if the table has no rows
func (t *TableData) IsEmpty() bool {
	return len(t.Rows) == 0
}

// RowCount returns the number of rows in the table
func (t *TableData) RowCount() int {
	return len(t.Rows)
}
