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

package prompt

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPasswordReader is a mock implementation of PasswordReader for testing.
type mockPasswordReader struct {
	password []byte
	err      error
}

func (m *mockPasswordReader) ReadPassword(fd int) ([]byte, error) {
	return m.password, m.err
}

// failingWriter is a writer that always fails.
type failingWriter struct {
	failAfter int
	count     int
}

func (w *failingWriter) Write(p []byte) (n int, err error) {
	w.count++
	if w.count > w.failAfter {
		return 0, errors.New("write failed")
	}
	return len(p), nil
}

func TestPrintBanner(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{
			name:    "standard version",
			version: "1.0.0",
		},
		{
			name:    "development version",
			version: "dev",
		},
		{
			name:    "empty version",
			version: "",
		},
		{
			name:    "version with build metadata",
			version: "1.2.3-beta+20230101",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// PrintBanner uses color library which caches os.Stdout
			// So we just test that it doesn't panic
			assert.NotPanics(t, func() {
				PrintBanner(tt.version)
			}, "PrintBanner should not panic")
		})
	}
}

func TestPrintBanner_ColorOutput(t *testing.T) {
	// Test that PrintBanner doesn't panic with various version formats
	assert.NotPanics(t, func() {
		PrintBanner("1.0.0-test")
	}, "PrintBanner should not panic for any version string")
}

func TestPrintBanner_MultipleVersionFormats(t *testing.T) {
	versions := []string{
		"0.0.1",
		"1.0.0",
		"2.1.3",
		"10.20.30",
		"1.0.0-alpha",
		"1.0.0-beta.1",
		"1.0.0-rc.1+build.123",
		"dev-123abc",
	}

	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			assert.NotPanics(t, func() {
				PrintBanner(version)
			}, "PrintBanner should not panic for version: "+version)
		})
	}
}

func TestPrintBanner_DoesNotPanic(t *testing.T) {
	// Test various version inputs to ensure no panics
	versions := []string{
		"1.0.0",
		"",
		"v2.0.0",
		"development",
		strings.Repeat("a", 100),
	}

	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			assert.NotPanics(t, func() {
				PrintBanner(version)
			}, "PrintBanner should not panic for any version string")
		})
	}
}

// Tests for legacy Prompt function using SetDefaultPrompter
func TestLegacyPrompt_WithMockPrompter(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	tests := []struct {
		name           string
		message        string
		input          string
		expectedOutput []byte
	}{
		{
			name:           "simple input",
			message:        "Enter your name",
			input:          "Alice\n",
			expectedOutput: []byte("Alice\n"),
		},
		{
			name:           "input with spaces",
			message:        "Enter full name",
			input:          "Alice Smith\n",
			expectedOutput: []byte("Alice Smith\n"),
		},
		{
			name:           "empty input",
			message:        "Press enter",
			input:          "\n",
			expectedOutput: []byte("\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			writer := &bytes.Buffer{}

			mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
			SetDefaultPrompter(mockPrompter)

			result := Prompt(tt.message)

			assert.Equal(t, tt.expectedOutput, result,
				"Prompt should return the expected input")
			assert.Contains(t, writer.String(), tt.message,
				"Output should contain the prompt message")
		})
	}
}

func TestLegacyNoOpPrompt_WithMockPrompter(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	tests := []struct {
		name           string
		input          string
		expectedOutput []byte
	}{
		{
			name:           "simple input",
			input:          "test\n",
			expectedOutput: []byte("test\n"),
		},
		{
			name:           "empty line",
			input:          "\n",
			expectedOutput: []byte("\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			writer := &bytes.Buffer{}

			mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
			SetDefaultPrompter(mockPrompter)

			result := NoOpPrompt()

			assert.Equal(t, tt.expectedOutput, result,
				"NoOpPrompt should return the expected input")
		})
	}
}

func TestLegacyPasswordPrompt_WithMockPrompter(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("secret123")}

	mockPrompter := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))
	SetDefaultPrompter(mockPrompter)

	result := PasswordPrompt("Enter password")

	assert.Equal(t, []byte("secret123"), result, "PasswordPrompt should return the password")
	assert.Contains(t, writer.String(), "Enter password", "Output should contain the message")
}

func TestLegacySOPin_WithMockPrompter(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("123456")}

	mockPrompter := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))
	SetDefaultPrompter(mockPrompter)

	result := SOPin()

	assert.Equal(t, []byte("123456"), result, "SOPin should return the PIN")
	assert.Contains(t, writer.String(), "Security Officer PIN", "Output should contain SO PIN message")
}

func TestLegacyPin_WithMockPrompter(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("7890")}

	mockPrompter := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))
	SetDefaultPrompter(mockPrompter)

	result := Pin()

	assert.Equal(t, []byte("7890"), result, "Pin should return the PIN")
	assert.Contains(t, writer.String(), "User PIN", "Output should contain User PIN message")
}

func TestLegacyKeyPassword_WithMockPrompter(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("keypass")}

	mockPrompter := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))
	SetDefaultPrompter(mockPrompter)

	result := KeyPassword()

	assert.Equal(t, []byte("keypass"), result, "KeyPassword should return the password")
	assert.Contains(t, writer.String(), "Key Password", "Output should contain Key Password message")
}

func TestSetDefaultPrompter(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	reader := strings.NewReader("test\n")
	writer := &bytes.Buffer{}
	newPrompter := NewPrompter(WithReader(reader), WithWriter(writer))

	SetDefaultPrompter(newPrompter)

	assert.Equal(t, newPrompter, defaultPrompter, "SetDefaultPrompter should update defaultPrompter")
}

// ===== Tests for Prompter (new testable interface) =====

func TestNewPrompter_Defaults(t *testing.T) {
	p := NewPrompter()

	assert.NotNil(t, p, "NewPrompter should return a non-nil Prompter")
	assert.NotNil(t, p.reader, "Default reader should be set")
	assert.NotNil(t, p.writer, "Default writer should be set")
	assert.NotNil(t, p.passwordReader, "Default passwordReader should be set")
}

func TestNewPrompter_WithOptions(t *testing.T) {
	reader := strings.NewReader("test\n")
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("secret")}

	p := NewPrompter(
		WithReader(reader),
		WithWriter(writer),
		WithPasswordReader(pwReader),
		WithStdinFd(99),
	)

	assert.Equal(t, reader, p.reader, "Reader should be set via option")
	assert.Equal(t, writer, p.writer, "Writer should be set via option")
	assert.Equal(t, pwReader, p.passwordReader, "PasswordReader should be set via option")
	assert.Equal(t, 99, p.stdinFd, "StdinFd should be set via option")
}

func TestPrompter_Prompt_Success(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		input    string
		expected []byte
	}{
		{
			name:     "simple input",
			message:  "Enter name",
			input:    "John\n",
			expected: []byte("John\n"),
		},
		{
			name:     "empty input",
			message:  "Press enter",
			input:    "\n",
			expected: []byte("\n"),
		},
		{
			name:     "input with spaces",
			message:  "Full name",
			input:    "John Doe\n",
			expected: []byte("John Doe\n"),
		},
		{
			name:     "special characters",
			message:  "Enter value",
			input:    "test@123!$%\n",
			expected: []byte("test@123!$%\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			writer := &bytes.Buffer{}

			p := NewPrompter(WithReader(reader), WithWriter(writer))

			result, err := p.Prompt(tt.message)

			require.NoError(t, err, "Prompt should not return an error")
			assert.Equal(t, tt.expected, result, "Prompt should return expected input")
			assert.Contains(t, writer.String(), tt.message, "Output should contain message")
			assert.Contains(t, writer.String(), userPrompt, "Output should contain user prompt")
		})
	}
}

func TestPrompter_Prompt_ReadError(t *testing.T) {
	// Create a reader that returns an error (empty reader without newline)
	reader := strings.NewReader("")
	writer := &bytes.Buffer{}

	p := NewPrompter(WithReader(reader), WithWriter(writer))

	result, err := p.Prompt("Enter")

	assert.Nil(t, result, "Result should be nil on error")
	require.Error(t, err, "Should return an error when read fails")

	var promptReadErr *PromptReadError
	assert.True(t, errors.As(err, &promptReadErr), "Error should be PromptReadError")
}

func TestPrompter_Prompt_WriteError(t *testing.T) {
	reader := strings.NewReader("test\n")
	writer := &failingWriter{failAfter: 0}

	p := NewPrompter(WithReader(reader), WithWriter(writer))

	result, err := p.Prompt("Enter")

	assert.Nil(t, result, "Result should be nil on write error")
	require.Error(t, err, "Should return an error when write fails")

	var promptWriteErr *PromptWriteError
	assert.True(t, errors.As(err, &promptWriteErr), "Error should be PromptWriteError")
}

func TestPrompter_Prompt_SecondWriteError(t *testing.T) {
	reader := strings.NewReader("test\n")
	writer := &failingWriter{failAfter: 1}

	p := NewPrompter(WithReader(reader), WithWriter(writer))

	result, err := p.Prompt("Enter")

	assert.Nil(t, result, "Result should be nil on write error")
	require.Error(t, err, "Should return an error when second write fails")

	var promptWriteErr *PromptWriteError
	assert.True(t, errors.As(err, &promptWriteErr), "Error should be PromptWriteError")
}

func TestPrompter_NoOpPrompt_Success(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "simple input",
			input:    "test\n",
			expected: []byte("test\n"),
		},
		{
			name:     "empty line",
			input:    "\n",
			expected: []byte("\n"),
		},
		{
			name:     "with spaces",
			input:    "hello world\n",
			expected: []byte("hello world\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)

			p := NewPrompter(WithReader(reader))

			result, err := p.NoOpPrompt()

			require.NoError(t, err, "NoOpPrompt should not return an error")
			assert.Equal(t, tt.expected, result, "NoOpPrompt should return expected input")
		})
	}
}

func TestPrompter_NoOpPrompt_ReadError(t *testing.T) {
	reader := strings.NewReader("")

	p := NewPrompter(WithReader(reader))

	result, err := p.NoOpPrompt()

	assert.Nil(t, result, "Result should be nil on error")
	require.Error(t, err, "Should return an error when read fails")

	var promptReadErr *PromptReadError
	assert.True(t, errors.As(err, &promptReadErr), "Error should be PromptReadError")
}

func TestPrompter_PasswordPrompt_Success(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		password []byte
	}{
		{
			name:     "simple password",
			message:  "Enter password",
			password: []byte("secret123"),
		},
		{
			name:     "empty password",
			message:  "Password",
			password: []byte(""),
		},
		{
			name:     "complex password",
			message:  "Secure PIN",
			password: []byte("P@ssw0rd!#$%"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writer := &bytes.Buffer{}
			pwReader := &mockPasswordReader{password: tt.password}

			p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

			result, err := p.PasswordPrompt(tt.message)

			require.NoError(t, err, "PasswordPrompt should not return an error")
			assert.Equal(t, tt.password, result, "PasswordPrompt should return expected password")
			assert.Contains(t, writer.String(), tt.message, "Output should contain message")
			assert.Contains(t, writer.String(), userPrompt, "Output should contain user prompt")
		})
	}
}

func TestPrompter_PasswordPrompt_ReadError(t *testing.T) {
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{err: errors.New("terminal error")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.PasswordPrompt("Password")

	assert.Nil(t, result, "Result should be nil on error")
	require.Error(t, err, "Should return an error when password read fails")

	var pwReadErr *PasswordReadError
	assert.True(t, errors.As(err, &pwReadErr), "Error should be PasswordReadError")
}

func TestPrompter_PasswordPrompt_WriteError(t *testing.T) {
	writer := &failingWriter{failAfter: 0}
	pwReader := &mockPasswordReader{password: []byte("secret")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.PasswordPrompt("Password")

	assert.Nil(t, result, "Result should be nil on write error")
	require.Error(t, err, "Should return an error when write fails")

	var promptWriteErr *PromptWriteError
	assert.True(t, errors.As(err, &promptWriteErr), "Error should be PromptWriteError")
}

func TestPrompter_PasswordPrompt_SecondWriteError(t *testing.T) {
	writer := &failingWriter{failAfter: 1}
	pwReader := &mockPasswordReader{password: []byte("secret")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.PasswordPrompt("Password")

	assert.Nil(t, result, "Result should be nil on write error")
	require.Error(t, err, "Should return an error when second write fails")

	var promptWriteErr *PromptWriteError
	assert.True(t, errors.As(err, &promptWriteErr), "Error should be PromptWriteError")
}

func TestPrompter_PasswordPrompt_FinalNewlineWriteError(t *testing.T) {
	writer := &failingWriter{failAfter: 2}
	pwReader := &mockPasswordReader{password: []byte("secret")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.PasswordPrompt("Password")

	assert.Nil(t, result, "Result should be nil on write error")
	require.Error(t, err, "Should return an error when final newline write fails")

	var promptWriteErr *PromptWriteError
	assert.True(t, errors.As(err, &promptWriteErr), "Error should be PromptWriteError")
}

func TestPrompter_SOPin_Success(t *testing.T) {
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("123456")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.SOPin()

	require.NoError(t, err, "SOPin should not return an error")
	assert.Equal(t, []byte("123456"), result, "SOPin should return expected PIN")
	assert.Contains(t, writer.String(), "Security Officer PIN", "Output should contain SO PIN message")
}

func TestPrompter_SOPin_Error(t *testing.T) {
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{err: errors.New("terminal error")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.SOPin()

	assert.Nil(t, result, "Result should be nil on error")
	require.Error(t, err, "Should return an error")
}

func TestPrompter_Pin_Success(t *testing.T) {
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("7890")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.Pin()

	require.NoError(t, err, "Pin should not return an error")
	assert.Equal(t, []byte("7890"), result, "Pin should return expected PIN")
	assert.Contains(t, writer.String(), "User PIN", "Output should contain User PIN message")
}

func TestPrompter_Pin_Error(t *testing.T) {
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{err: errors.New("terminal error")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.Pin()

	assert.Nil(t, result, "Result should be nil on error")
	require.Error(t, err, "Should return an error")
}

func TestPrompter_KeyPassword_Success(t *testing.T) {
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("keypass")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.KeyPassword()

	require.NoError(t, err, "KeyPassword should not return an error")
	assert.Equal(t, []byte("keypass"), result, "KeyPassword should return expected password")
	assert.Contains(t, writer.String(), "Key Password", "Output should contain Key Password message")
}

func TestPrompter_KeyPassword_Error(t *testing.T) {
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{err: errors.New("terminal error")}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.KeyPassword()

	assert.Nil(t, result, "Result should be nil on error")
	require.Error(t, err, "Should return an error")
}

func TestTermPasswordReader(t *testing.T) {
	// Test that TermPasswordReader implements the interface
	var _ PasswordReader = &TermPasswordReader{}

	tr := &TermPasswordReader{}
	assert.NotNil(t, tr, "TermPasswordReader should be creatable")
}

// ===== Tests for functional options =====

func TestWithReader(t *testing.T) {
	reader := strings.NewReader("test")
	opt := WithReader(reader)

	p := &Prompter{}
	opt(p)

	assert.Equal(t, reader, p.reader, "WithReader should set the reader")
}

func TestWithWriter(t *testing.T) {
	writer := &bytes.Buffer{}
	opt := WithWriter(writer)

	p := &Prompter{}
	opt(p)

	assert.Equal(t, writer, p.writer, "WithWriter should set the writer")
}

func TestWithPasswordReader(t *testing.T) {
	pwReader := &mockPasswordReader{}
	opt := WithPasswordReader(pwReader)

	p := &Prompter{}
	opt(p)

	assert.Equal(t, pwReader, p.passwordReader, "WithPasswordReader should set the passwordReader")
}

func TestWithStdinFd(t *testing.T) {
	opt := WithStdinFd(42)

	p := &Prompter{}
	opt(p)

	assert.Equal(t, 42, p.stdinFd, "WithStdinFd should set the stdinFd")
}

// ===== Tests for Prompter boundary conditions =====

func TestPrompter_Prompt_LongInput(t *testing.T) {
	longInput := strings.Repeat("a", 10000) + "\n"
	reader := strings.NewReader(longInput)
	writer := &bytes.Buffer{}

	p := NewPrompter(WithReader(reader), WithWriter(writer))

	result, err := p.Prompt("Enter long text")

	require.NoError(t, err, "Prompt should handle long input")
	assert.Equal(t, []byte(longInput), result, "Should return full long input")
}

func TestPrompter_Prompt_Unicode(t *testing.T) {
	unicodeInput := "Hello World test 123\n"
	reader := strings.NewReader(unicodeInput)
	writer := &bytes.Buffer{}

	p := NewPrompter(WithReader(reader), WithWriter(writer))

	result, err := p.Prompt("Enter unicode")

	require.NoError(t, err, "Prompt should handle unicode input")
	assert.Equal(t, []byte(unicodeInput), result, "Should return unicode input")
}

func TestPrompter_NoOpPrompt_LongInput(t *testing.T) {
	longInput := strings.Repeat("b", 10000) + "\n"
	reader := strings.NewReader(longInput)

	p := NewPrompter(WithReader(reader))

	result, err := p.NoOpPrompt()

	require.NoError(t, err, "NoOpPrompt should handle long input")
	assert.Equal(t, []byte(longInput), result, "Should return full long input")
}

func TestPrompter_PasswordPrompt_LongPassword(t *testing.T) {
	longPassword := []byte(strings.Repeat("x", 1000))
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: longPassword}

	p := NewPrompter(WithWriter(writer), WithPasswordReader(pwReader))

	result, err := p.PasswordPrompt("Long password")

	require.NoError(t, err, "PasswordPrompt should handle long password")
	assert.Equal(t, longPassword, result, "Should return full long password")
}

func TestPrompter_MultipleOperations_WithBufferedReader(t *testing.T) {
	// Test using a shared bufio.Reader for multiple operations
	// This demonstrates proper usage with a pre-buffered reader
	inputs := "first\nsecond\nthird\n"
	bufReader := bufio.NewReader(strings.NewReader(inputs))
	writer := &bytes.Buffer{}

	// Each call creates a new Prompter but shares the buffered reader
	// which maintains state between reads
	p1 := NewPrompter(WithReader(bufReader), WithWriter(writer))
	result1, err1 := p1.NoOpPrompt()
	require.NoError(t, err1)
	assert.Equal(t, []byte("first\n"), result1)

	p2 := NewPrompter(WithReader(bufReader), WithWriter(writer))
	result2, err2 := p2.NoOpPrompt()
	require.NoError(t, err2)
	assert.Equal(t, []byte("second\n"), result2)

	p3 := NewPrompter(WithReader(bufReader), WithWriter(writer))
	result3, err3 := p3.NoOpPrompt()
	require.NoError(t, err3)
	assert.Equal(t, []byte("third\n"), result3)
}

func TestPrompter_MixedOperations(t *testing.T) {
	// Test using password prompt followed by regular prompt
	writer := &bytes.Buffer{}
	pwReader := &mockPasswordReader{password: []byte("secret")}
	textReader := strings.NewReader("text input\n")

	p := NewPrompter(
		WithReader(textReader),
		WithWriter(writer),
		WithPasswordReader(pwReader),
	)

	// Password prompt
	pwResult, pwErr := p.PasswordPrompt("Password")
	require.NoError(t, pwErr)
	assert.Equal(t, []byte("secret"), pwResult)

	// Regular prompt
	textResult, textErr := p.Prompt("Enter text")
	require.NoError(t, textErr)
	assert.Equal(t, []byte("text input\n"), textResult)
}

func TestPrompter_EmptyMessage(t *testing.T) {
	reader := strings.NewReader("response\n")
	writer := &bytes.Buffer{}

	p := NewPrompter(WithReader(reader), WithWriter(writer))

	result, err := p.Prompt("")

	require.NoError(t, err, "Prompt should handle empty message")
	assert.Equal(t, []byte("response\n"), result)
	assert.Contains(t, writer.String(), userPrompt, "Should still show user prompt")
}

func TestPrompter_MessageWithSpecialChars(t *testing.T) {
	tests := []struct {
		name    string
		message string
	}{
		{"newlines", "Line1\nLine2"},
		{"tabs", "Field1\tField2"},
		{"quotes", `Say "hello"`},
		{"unicode", "Enter your name (Enter your name)"},
		{"brackets", "[Required] Enter value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader("input\n")
			writer := &bytes.Buffer{}

			p := NewPrompter(WithReader(reader), WithWriter(writer))

			result, err := p.Prompt(tt.message)

			require.NoError(t, err)
			assert.Equal(t, []byte("input\n"), result)
			assert.Contains(t, writer.String(), tt.message)
		})
	}
}

// ===== Additional boundary and edge case tests =====

func TestLegacyPrompt_Consistency(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	// Test that Prompt returns consistent results for the same input
	testInput := "consistent\n"

	results := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		reader := strings.NewReader(testInput)
		writer := &bytes.Buffer{}
		mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
		SetDefaultPrompter(mockPrompter)

		results[i] = Prompt("Enter")
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0], results[i],
			"Prompt should return consistent results for identical input")
	}
}

func TestLegacyNoOpPrompt_Consistency(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	// Test that NoOpPrompt returns consistent results for the same input
	testInput := "consistent\n"

	results := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		reader := strings.NewReader(testInput)
		writer := &bytes.Buffer{}
		mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
		SetDefaultPrompter(mockPrompter)

		results[i] = NoOpPrompt()
	}

	// All results should be identical
	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0], results[i],
			"NoOpPrompt should return consistent results for identical input")
	}
}

func TestLegacyPrompt_BoundaryConditions(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "single character",
			input: "a\n",
		},
		{
			name:  "very long input",
			input: strings.Repeat("a", 1000) + "\n",
		},
		{
			name:  "unicode characters",
			input: "hello world\n",
		},
		{
			name:  "tabs and special whitespace",
			input: "hello\t\tworld\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			writer := &bytes.Buffer{}
			mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
			SetDefaultPrompter(mockPrompter)

			result := Prompt("Enter")
			assert.Equal(t, []byte(tt.input), result,
				"Prompt should handle boundary conditions correctly")
		})
	}
}

func TestLegacyNoOpPrompt_BoundaryConditions(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "single character",
			input: "x\n",
		},
		{
			name:  "very long input",
			input: strings.Repeat("b", 1000) + "\n",
		},
		{
			name:  "unicode characters",
			input: "secure key\n",
		},
		{
			name:  "mixed whitespace",
			input: " \t \n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			writer := &bytes.Buffer{}
			mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
			SetDefaultPrompter(mockPrompter)

			result := NoOpPrompt()
			assert.Equal(t, []byte(tt.input), result,
				"NoOpPrompt should handle boundary conditions correctly")
		})
	}
}

func TestLegacyPrompt_EmptyMessage(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	reader := strings.NewReader("test\n")
	writer := &bytes.Buffer{}
	mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
	SetDefaultPrompter(mockPrompter)

	result := Prompt("")

	assert.NotNil(t, result, "Prompt should return a result even with empty message")
	assert.Contains(t, writer.String(), userPrompt,
		"Should display user prompt even with empty message")
}

func TestLegacyPrompt_OutputFormat(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	reader := strings.NewReader("test\n")
	writer := &bytes.Buffer{}
	mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
	SetDefaultPrompter(mockPrompter)

	Prompt("Test message")

	output := writer.String()

	// Verify the output format
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have at least the message and prompt
	assert.GreaterOrEqual(t, len(lines), 1,
		"Output should contain at least one line")

	// First line should contain the message
	assert.Contains(t, lines[0], "Test message",
		"First line should contain the message")

	// Should contain the user prompt
	assert.Contains(t, output, userPrompt,
		"Output should contain the user prompt")
}

func TestLegacyNoOpPrompt_NoOutput(t *testing.T) {
	// Save the original default prompter
	originalPrompter := defaultPrompter
	defer SetDefaultPrompter(originalPrompter)

	reader := strings.NewReader("test\n")
	writer := &bytes.Buffer{}
	mockPrompter := NewPrompter(WithReader(reader), WithWriter(writer))
	SetDefaultPrompter(mockPrompter)

	result := NoOpPrompt()

	assert.NotNil(t, result, "NoOpPrompt should return non-nil result")

	// NoOpPrompt should not display any message or prompt
	assert.Empty(t, writer.String(),
		"NoOpPrompt should not produce output to writer")
}
