package util

import (
	"testing"
)

func TestEscapeFilePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "(STAGING) False Fennel E6",
			expected: `\(STAGING\)\ False\ Fennel\ E6`,
		},
		{
			input:    `Special chars !@#$%^&*()`,
			expected: `Special\ chars\ \!\@\#\$\%\^\&\*\(\)`,
		},
		{
			input:    `NoSpecialChars`,
			expected: `NoSpecialChars`,
		},
		{
			input:    `path/with spaces`,
			expected: `path/with\ spaces`,
		},
		{
			input:    `back\slash\test`,
			expected: `back\\slash\\test`,
		},
	}

	for _, test := range tests {
		result := EscapeFilePath(test.input)
		if result != test.expected {
			t.Errorf("EscapeFilePath(%q) = %q; want %q", test.input, result, test.expected)
		}
	}
}
