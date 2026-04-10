package uki

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewParser(t *testing.T) {
	logger := testLogger(t)
	p := NewParser(logger)
	require.NotNil(t, p)
}

func TestParser_Parse_InvalidPE(t *testing.T) {
	logger := testLogger(t)
	p := NewParser(logger)

	_, err := p.Parse(strings.NewReader("not a PE file"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PE file")
}

func TestParser_Parse_EmptyReader(t *testing.T) {
	logger := testLogger(t)
	p := NewParser(logger)

	_, err := p.Parse(bytes.NewReader(nil))
	require.Error(t, err)
}

func TestParser_ParseFile_NotFound(t *testing.T) {
	logger := testLogger(t)
	p := NewParser(logger)

	_, err := p.ParseFile(filepath.Join(t.TempDir(), "nonexistent.efi"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
}

func TestParser_ExtractSection_InvalidPE(t *testing.T) {
	logger := testLogger(t)
	p := NewParser(logger)

	_, err := p.ExtractSection(strings.NewReader("not a PE"), ".cmdline")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PE file")
}

func TestParser_ListSections_InvalidPE(t *testing.T) {
	logger := testLogger(t)
	p := NewParser(logger)

	_, err := p.ListSections(strings.NewReader("not a PE"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PE file")
}

func TestTrimNullBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "no nulls", input: ".text", expected: ".text"},
		{name: "trailing nulls", input: ".text\x00\x00\x00", expected: ".text"},
		{name: "empty", input: "", expected: ""},
		{name: "all nulls", input: "\x00\x00\x00", expected: ""},
		{name: "no trailing nulls", input: ".cmdline", expected: ".cmdline"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimNullBytes(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
