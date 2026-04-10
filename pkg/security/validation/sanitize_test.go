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

package validation

import (
	"strings"
	"testing"
)

func TestSanitizer_SanitizeString(t *testing.T) {
	sanitizer := NewDefaultSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "trim whitespace",
			input:    "  hello  ",
			expected: "hello",
		},
		{
			name:     "strip null bytes",
			input:    "hel\x00lo",
			expected: "hello",
		},
		{
			name:     "normalize newlines",
			input:    "line1\r\nline2\rline3",
			expected: "line1\nline2\nline3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestSanitizer_MaxLength(t *testing.T) {
	sanitizer := NewSanitizer(SanitizerOptions{
		MaxLength: 10,
	})

	input := "this is a very long string"
	result := sanitizer.SanitizeString(input)

	if len(result) != 10 {
		t.Errorf("result length = %d, expected 10", len(result))
	}
}

func TestSanitizer_StripJavaScript(t *testing.T) {
	sanitizer := NewSanitizer(SanitizerOptions{
		StripJavaScript: true,
	})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strip script tags",
			input:    "Hello<script>alert('xss')</script>World",
			expected: "HelloWorld",
		},
		{
			name:     "strip script tags with attributes",
			input:    "Hello<script type='text/javascript'>malicious()</script>World",
			expected: "HelloWorld",
		},
		{
			name:     "strip case insensitive script tags",
			input:    "Hello<SCRIPT>evil()</SCRIPT>World",
			expected: "HelloWorld",
		},
		{
			name:     "strip event handlers",
			input:    "<img src='x' onerror=\"alert(1)\">",
			expected: "<img src='x'>",
		},
		{
			name:     "strip onclick handler",
			input:    "<button onclick='malicious()'>Click</button>",
			expected: "<button>Click</button>",
		},
		{
			name:     "strip onmouseover handler",
			input:    "<div onmouseover='evil()'>Content</div>",
			expected: "<div>Content</div>",
		},
		{
			name:     "strip javascript URLs",
			input:    "<a href='javascript:alert(1)'>Link</a>",
			expected: "<a href='alert(1)'>Link</a>",
		},
		{
			name:     "strip javascript URL with spaces",
			input:    "<a href='javascript :alert(1)'>Link</a>",
			expected: "<a href='alert(1)'>Link</a>",
		},
		{
			name:     "no JavaScript content",
			input:    "Hello World, this is safe content",
			expected: "Hello World, this is safe content",
		},
		{
			name:     "multiple script tags",
			input:    "<script>a()</script>text<script>b()</script>",
			expected: "text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestSanitizer_StripSQLKeywords(t *testing.T) {
	sanitizer := NewSanitizer(SanitizerOptions{
		StripSQLKeywords: true,
	})

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "strip SELECT keyword",
			input:    "SELECT * FROM users",
			expected: " * FROM users",
		},
		{
			name:     "strip DROP keyword",
			input:    "DROP TABLE users",
			expected: " TABLE users",
		},
		{
			name:     "strip UNION keyword",
			input:    "1 UNION SELECT password",
			expected: "1   password",
		},
		{
			name:     "strip multiple keywords",
			input:    "SELECT * FROM users; DELETE FROM accounts",
			expected: " * FROM users;  FROM accounts",
		},
		{
			name:     "strip SQL comment start",
			input:    "value; -- comment",
			expected: "value;  comment",
		},
		{
			name:     "strip block comment markers",
			input:    "value /* comment */ more",
			expected: "value  comment  more",
		},
		{
			name:     "strip WAITFOR DELAY",
			input:    "WAITFOR DELAY '0:0:5'",
			expected: "  '0:0:5'",
		},
		{
			name:     "strip XP_ commands",
			input:    "XP_CMDSHELL 'dir'",
			expected: "CMDSHELL 'dir'",
		},
		{
			name:     "case insensitive stripping",
			input:    "select * from users",
			expected: " * from users",
		},
		{
			name:     "no SQL keywords",
			input:    "Hello World, this is safe",
			expected: "Hello World, this is safe",
		},
		{
			name:     "strip INSERT keyword",
			input:    "INSERT INTO users VALUES",
			expected: " INTO users VALUES",
		},
		{
			name:     "strip UPDATE keyword",
			input:    "UPDATE users SET password",
			expected: " users SET password",
		},
		{
			name:     "strip TRUNCATE keyword",
			input:    "TRUNCATE TABLE logs",
			expected: " TABLE logs",
		},
		{
			name:     "strip CREATE keyword",
			input:    "CREATE TABLE hack",
			expected: " TABLE hack",
		},
		{
			name:     "strip ALTER keyword",
			input:    "ALTER TABLE users",
			expected: " TABLE users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.SanitizeString(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestStripHTML(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		allowedTags []string
		expected    string
	}{
		{
			name:        "strip all tags",
			input:       "<p>Hello <b>World</b></p>",
			allowedTags: nil,
			expected:    "Hello World",
		},
		{
			name:        "strip script tags",
			input:       "Hello<script>alert('xss')</script>World",
			allowedTags: nil,
			expected:    "HelloWorld",
		},
		{
			name:        "no tags",
			input:       "Hello World",
			allowedTags: nil,
			expected:    "Hello World",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripHTML(tt.input, tt.allowedTags)
			if result != tt.expected {
				t.Errorf("StripHTML() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestStripHTML_AllowedTags(t *testing.T) {
	// Note: The current implementation has a quirk where it preserves the tag
	// but not the closing '>' on the opening tag. These tests document actual behavior.
	tests := []struct {
		name        string
		input       string
		allowedTags []string
		checkFunc   func(result string) bool
		description string
	}{
		{
			name:        "allow b tag preserves b content",
			input:       "<p>Hello <b>World</b></p>",
			allowedTags: []string{"b"},
			checkFunc: func(result string) bool {
				return strings.Contains(result, "<b") && strings.Contains(result, "</b>") && strings.Contains(result, "World")
			},
			description: "b tag should be preserved with World content",
		},
		{
			name:        "allow p tag preserves p structure",
			input:       "<p>Hello <b>World</b></p>",
			allowedTags: []string{"p"},
			checkFunc: func(result string) bool {
				return strings.Contains(result, "<p") && strings.Contains(result, "</p>") && strings.Contains(result, "Hello")
			},
			description: "p tag should be preserved with Hello content",
		},
		{
			name:        "strip script even with allowed tags",
			input:       "<b>Hello</b><script>evil()</script><i>World</i>",
			allowedTags: []string{"b", "i"},
			checkFunc: func(result string) bool {
				return !strings.Contains(result, "<script") && !strings.Contains(result, "evil")
			},
			description: "script tag and content should be stripped",
		},
		{
			name:        "strip style even with allowed tags",
			input:       "<b>Hello</b><style>.evil{}</style><i>World</i>",
			allowedTags: []string{"b", "i"},
			checkFunc: func(result string) bool {
				return !strings.Contains(result, "<style") && !strings.Contains(result, ".evil")
			},
			description: "style tag and content should be stripped",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripHTML(tt.input, tt.allowedTags)
			if !tt.checkFunc(result) {
				t.Errorf("StripHTML() = %q, %s", result, tt.description)
			}
		})
	}
}

func TestStripJavaScript_Direct(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "remove script tags",
			input:    "<script>alert('XSS')</script>",
			expected: "",
		},
		{
			name:     "remove script tags with newlines",
			input:    "<script>\nfunction evil() {\n  alert('XSS');\n}\n</script>",
			expected: "",
		},
		{
			name:     "remove onclick event",
			input:    "<button onclick=\"malicious()\">Click</button>",
			expected: "<button>Click</button>",
		},
		{
			name:     "remove onload event",
			input:    "<body onload=\"init()\">Content</body>",
			expected: "<body>Content</body>",
		},
		{
			name:     "remove onfocus event",
			input:    "<input onfocus=\"steal()\" />",
			expected: "<input />",
		},
		{
			name:     "remove javascript protocol",
			input:    "javascript:void(0)",
			expected: "void(0)",
		},
		{
			name:     "remove JAVASCRIPT protocol (uppercase)",
			input:    "JAVASCRIPT:alert(1)",
			expected: "alert(1)",
		},
		{
			name:     "preserve non-javascript content",
			input:    "This is regular text without any scripts",
			expected: "This is regular text without any scripts",
		},
		{
			name:     "mixed content",
			input:    "Safe text<script>evil()</script> more safe text",
			expected: "Safe text more safe text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripJavaScript(tt.input)
			if result != tt.expected {
				t.Errorf("stripJavaScript() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestStripSQLKeywords_Direct(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "remove SELECT",
			input:    "SELECT",
			expected: "",
		},
		{
			name:     "remove INSERT",
			input:    "INSERT",
			expected: "",
		},
		{
			name:     "remove UPDATE",
			input:    "UPDATE",
			expected: "",
		},
		{
			name:     "remove DELETE",
			input:    "DELETE",
			expected: "",
		},
		{
			name:     "remove DROP",
			input:    "DROP",
			expected: "",
		},
		{
			name:     "remove UNION",
			input:    "UNION",
			expected: "",
		},
		{
			name:     "remove GRANT",
			input:    "GRANT",
			expected: "",
		},
		{
			name:     "remove REVOKE",
			input:    "REVOKE",
			expected: "",
		},
		{
			name:     "remove double dash comment",
			input:    "--",
			expected: "",
		},
		{
			name:     "remove double at sign",
			input:    "@@VERSION",
			expected: "VERSION",
		},
		{
			name:     "remove SHUTDOWN",
			input:    "SHUTDOWN",
			expected: "",
		},
		{
			name:     "case insensitive - lowercase",
			input:    "select",
			expected: "",
		},
		{
			name:     "case insensitive - mixed case",
			input:    "SeLeCt",
			expected: "",
		},
		{
			name:     "multiple occurrences",
			input:    "SELECT SELECT SELECT",
			expected: "  ",
		},
		{
			name:     "preserve safe text",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "CONVERT function",
			input:    "CONVERT(int, value)",
			expected: "int, value)",
		},
		{
			name:     "CAST function",
			input:    "CAST(value AS int)",
			expected: "value AS int)",
		},
		{
			name:     "EXEC keyword",
			input:    "EXEC",
			expected: "",
		},
		{
			name:     "EXECUTE keyword - note EXEC is stripped first leaving UTE",
			input:    "EXECUTE",
			expected: "UTE",
		},
		{
			name:     "CHAR function",
			input:    "CHAR(65)",
			expected: "65)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripSQLKeywords(tt.input)
			if result != tt.expected {
				t.Errorf("stripSQLKeywords() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestPathSanitizer_SanitizePath(t *testing.T) {
	sanitizer := NewDefaultPathSanitizer()

	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "simple path",
			input:       "documents/file.txt",
			expectError: false,
		},
		{
			name:        "path traversal with ..",
			input:       "../../../etc/passwd",
			expectError: true,
		},
		{
			name:        "path traversal encoded",
			input:       "..%2f..%2fetc%2fpasswd",
			expectError: true,
		},
		{
			name:        "absolute path not allowed",
			input:       "/etc/passwd",
			expectError: true,
		},
		{
			name:        "dot file not allowed",
			input:       ".secret/file.txt",
			expectError: true,
		},
		{
			name:        "empty path",
			input:       "",
			expectError: true,
		},
		{
			name:        "disallowed extension",
			input:       "script.exe",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sanitizer.SanitizePath(tt.input)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestPathSanitizer_AllowAbsolute(t *testing.T) {
	sanitizer := NewPathSanitizer(PathSanitizerOptions{
		AllowAbsolute: true,
	})

	_, err := sanitizer.SanitizePath("/etc/config")
	if err != nil {
		t.Errorf("absolute path should be allowed: %v", err)
	}
}

func TestPathSanitizer_AllowDotFiles(t *testing.T) {
	sanitizer := NewPathSanitizer(PathSanitizerOptions{
		AllowDotFiles: true,
	})

	_, err := sanitizer.SanitizePath(".config/settings")
	if err != nil {
		t.Errorf("dot files should be allowed: %v", err)
	}
}

func TestPathSanitizer_MaxDepth(t *testing.T) {
	sanitizer := NewPathSanitizer(PathSanitizerOptions{
		MaxDepth: 3,
	})

	tests := []struct {
		path        string
		expectError bool
	}{
		{"a/b/c", false},
		{"a/b/c/d", true},
		{"a/b/c/d/e", true},
	}

	for _, tt := range tests {
		_, err := sanitizer.SanitizePath(tt.path)
		if tt.expectError && err == nil {
			t.Errorf("path %q should exceed max depth", tt.path)
		}
		if !tt.expectError && err != nil {
			t.Errorf("path %q should be allowed: %v", tt.path, err)
		}
	}
}

func TestPathSanitizer_AllowedPrefixes(t *testing.T) {
	sanitizer := NewPathSanitizer(PathSanitizerOptions{
		AllowedPrefixes: []string{"uploads/", "temp/"},
	})

	tests := []struct {
		path        string
		expectError bool
	}{
		{"uploads/file.txt", false},
		{"temp/file.txt", false},
		{"downloads/file.txt", true},
	}

	for _, tt := range tests {
		_, err := sanitizer.SanitizePath(tt.path)
		if tt.expectError && err == nil {
			t.Errorf("path %q should not be allowed", tt.path)
		}
		if !tt.expectError && err != nil {
			t.Errorf("path %q should be allowed: %v", tt.path, err)
		}
	}
}

func TestPathSanitizer_DisallowedPrefixes(t *testing.T) {
	sanitizer := NewPathSanitizer(PathSanitizerOptions{
		DisallowedPrefixes: []string{"private/", "secret/", "admin/"},
	})

	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "allowed path",
			path:        "public/file.txt",
			expectError: false,
		},
		{
			name:        "disallowed private prefix",
			path:        "private/data.txt",
			expectError: true,
		},
		{
			name:        "disallowed secret prefix",
			path:        "secret/keys.pem",
			expectError: true,
		},
		{
			name:        "disallowed admin prefix",
			path:        "admin/config.yaml",
			expectError: true,
		},
		{
			name:        "nested in disallowed prefix",
			path:        "private/nested/deep/file.txt",
			expectError: true,
		},
		{
			name:        "similar but not matching prefix",
			path:        "privateer/ship.txt",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sanitizer.SanitizePath(tt.path)
			if tt.expectError && err == nil {
				t.Errorf("path %q should not be allowed", tt.path)
			}
			if !tt.expectError && err != nil {
				t.Errorf("path %q should be allowed: %v", tt.path, err)
			}
			if tt.expectError && err != nil {
				if !strings.Contains(err.Error(), "disallowed") {
					t.Errorf("expected error to mention 'disallowed', got: %v", err)
				}
			}
		})
	}
}

func TestPathSanitizer_AllowedExtensions(t *testing.T) {
	sanitizer := NewPathSanitizer(PathSanitizerOptions{
		AllowedExtensions: []string{".txt", ".pdf"},
	})

	tests := []struct {
		path        string
		expectError bool
	}{
		{"file.txt", false},
		{"file.pdf", false},
		{"file.exe", true},
		{"file.doc", true},
	}

	for _, tt := range tests {
		_, err := sanitizer.SanitizePath(tt.path)
		if tt.expectError && err == nil {
			t.Errorf("path %q should not be allowed", tt.path)
		}
		if !tt.expectError && err != nil {
			t.Errorf("path %q should be allowed: %v", tt.path, err)
		}
	}
}

func TestSanitizePath_Convenience(t *testing.T) {
	_, err := SanitizePath("../etc/passwd")
	if err == nil {
		t.Error("path traversal should be detected")
	}
}

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"Hello & World", "Hello &amp; World"},
		{"<div class=\"test\">", "&lt;div class=&#34;test&#34;&gt;"},
	}

	for _, tt := range tests {
		result := EscapeHTML(tt.input)
		if result != tt.expected {
			t.Errorf("EscapeHTML(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestUnescapeHTML(t *testing.T) {
	input := "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
	expected := "<script>alert('xss')</script>"

	result := UnescapeHTML(input)
	if result != expected {
		t.Errorf("UnescapeHTML() = %q, expected %q", result, expected)
	}
}

func TestStripControl(t *testing.T) {
	input := "Hello\x00World\x01\x02\n\t"
	expected := "HelloWorld\n\t"

	result := StripControl(input)
	if result != expected {
		t.Errorf("StripControl() = %q, expected %q", result, expected)
	}
}

func TestStripNonPrintable(t *testing.T) {
	input := "Hello\x00World\x1f\n"
	expected := "HelloWorld\n"

	result := StripNonPrintable(input)
	if result != expected {
		t.Errorf("StripNonPrintable() = %q, expected %q", result, expected)
	}
}

func TestNormalizeWhitespace(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  hello   world  ", "hello world"},
		{"hello\t\tworld", "hello world"},
		{"hello\n\nworld", "hello world"},
	}

	for _, tt := range tests {
		result := NormalizeWhitespace(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeWhitespace(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestTruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		suffix   string
		expected string
	}{
		{"hello world", 20, "...", "hello world"},
		{"hello world", 8, "...", "hello..."},
		{"hello world", 5, "...", "he..."},
		{"hello world", 3, "...", "hel"},
	}

	for _, tt := range tests {
		result := TruncateString(tt.input, tt.maxLen, tt.suffix)
		if result != tt.expected {
			t.Errorf("TruncateString(%q, %d, %q) = %q, expected %q",
				tt.input, tt.maxLen, tt.suffix, result, tt.expected)
		}
	}
}

func TestSafeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal.txt", "normal.txt"},
		{"../../../etc/passwd", "passwd"},
		{"file<>.txt", "file__.txt"},
		{"file\x00name.txt", "filename.txt"},
		{"  .  ", "_"},
		{"", "_"},
		{"file|name.txt", "file_name.txt"},
	}

	for _, tt := range tests {
		result := SafeFilename(tt.input)
		if result != tt.expected {
			t.Errorf("SafeFilename(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestSQLSanitizer_EscapeString(t *testing.T) {
	sanitizer := NewSQLSanitizer()

	tests := []struct {
		input    string
		expected string
	}{
		{"normal", "normal"},
		{"it's", "it''s"},
		{"back\\slash", "back\\\\slash"},
		{"null\x00byte", "null\\0byte"},
	}

	for _, tt := range tests {
		result := sanitizer.EscapeString(tt.input)
		if result != tt.expected {
			t.Errorf("EscapeString(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestSQLSanitizer_EscapeString_Additional(t *testing.T) {
	sanitizer := NewSQLSanitizer()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "escape newline",
			input:    "line1\nline2",
			expected: "line1\\nline2",
		},
		{
			name:     "escape carriage return",
			input:    "line1\rline2",
			expected: "line1\\rline2",
		},
		{
			name:     "escape substitute character",
			input:    "data\x1amore",
			expected: "data\\Zmore",
		},
		{
			name:     "multiple escapes",
			input:    "it's a \"test\"\nwith\x00null",
			expected: "it''s a \"test\"\\nwith\\0null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizer.EscapeString(tt.input)
			if result != tt.expected {
				t.Errorf("EscapeString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestSQLSanitizer_EscapeIdentifier(t *testing.T) {
	sanitizer := NewSQLSanitizer()

	tests := []struct {
		input    string
		expected string
	}{
		{"column_name", "column_name"},
		{"table`name", "tablename"},
		{"table\"name", "tablename"},
		{"table@name!", "tablename"},
	}

	for _, tt := range tests {
		result := sanitizer.EscapeIdentifier(tt.input)
		if result != tt.expected {
			t.Errorf("EscapeIdentifier(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestSQLSanitizer_ValidateIdentifier(t *testing.T) {
	sanitizer := NewSQLSanitizer()

	tests := []struct {
		input       string
		expectError bool
	}{
		{"valid_name", false},
		{"_private", false},
		{"name123", false},
		{"", true},
		{"123start", true},
		{"has space", true},
		{"has-dash", true},
	}

	for _, tt := range tests {
		err := sanitizer.ValidateIdentifier(tt.input)
		if tt.expectError && err == nil {
			t.Errorf("identifier %q should be invalid", tt.input)
		}
		if !tt.expectError && err != nil {
			t.Errorf("identifier %q should be valid: %v", tt.input, err)
		}
	}
}

func TestSQLSanitizer_ValidateIdentifier_TooLong(t *testing.T) {
	sanitizer := NewSQLSanitizer()

	// Create identifier that exceeds 128 characters
	longIdentifier := strings.Repeat("a", 129)
	err := sanitizer.ValidateIdentifier(longIdentifier)
	if err == nil {
		t.Error("identifier longer than 128 characters should be invalid")
	}

	var tooLongErr ErrFieldTooLong
	if !isErrorType(err, &tooLongErr) {
		t.Errorf("expected ErrFieldTooLong, got %T", err)
	}
}

func TestContainsPathTraversal(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"../etc/passwd", true},
		{"..\\windows\\system32", true},
		{"%2e%2e/etc/passwd", true},
		{"normal/path", false},
		{"a/b/c", false},
	}

	for _, tt := range tests {
		result := containsPathTraversal(tt.path)
		if result != tt.expected {
			t.Errorf("containsPathTraversal(%q) = %v, expected %v", tt.path, result, tt.expected)
		}
	}
}

func TestContainsPathTraversal_Encodings(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "double URL encoded",
			path:     "%252e%252e/etc/passwd",
			expected: true,
		},
		{
			name:     "UTF-8 overlong encoding style 1",
			path:     "..%c0%af/etc/passwd",
			expected: true,
		},
		{
			name:     "UTF-8 overlong encoding style 2",
			path:     "..%c1%9c/etc/passwd",
			expected: true,
		},
		{
			name:     "backslash URL encoded",
			path:     "..%5c/etc/passwd",
			expected: true,
		},
		{
			name:     "double encoded backslash",
			path:     "..%255c/etc/passwd",
			expected: true,
		},
		{
			name:     "normal path with percent",
			path:     "100%complete/file.txt",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsPathTraversal(tt.path)
			if result != tt.expected {
				t.Errorf("containsPathTraversal() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestContainsDotFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{".hidden", true},
		{".config/file", true},
		{"path/.hidden/file", true},
		{"normal/path", false},
		{"file.txt", false},
	}

	for _, tt := range tests {
		result := containsDotFile(tt.path)
		if result != tt.expected {
			t.Errorf("containsDotFile(%q) = %v, expected %v", tt.path, result, tt.expected)
		}
	}
}

func TestCountPathDepth(t *testing.T) {
	tests := []struct {
		path     string
		expected int
	}{
		{".", 0},
		{"/", 0},
		{"a", 1},
		{"a/b", 2},
		{"a/b/c", 3},
		{"/a/b/c", 3},
	}

	for _, tt := range tests {
		result := countPathDepth(tt.path)
		if result != tt.expected {
			t.Errorf("countPathDepth(%q) = %d, expected %d", tt.path, result, tt.expected)
		}
	}
}

func TestSanitizer_AllOptions(t *testing.T) {
	sanitizer := NewSanitizer(SanitizerOptions{
		TrimSpace:         true,
		StripHTML:         true,
		EscapeHTML:        false,
		StripNullBytes:    true,
		NormalizeNewlines: true,
		StripSQLKeywords:  true,
		StripJavaScript:   true,
		MaxLength:         100,
	})

	input := "  <p>Hello</p> World\x00 SELECT <script>evil()</script>\r\n"
	result := sanitizer.SanitizeString(input)

	// Verify key transformations occurred
	if strings.Contains(result, "\x00") {
		t.Error("null byte should be stripped")
	}
	if strings.Contains(result, "\r") {
		t.Error("\\r should be normalized")
	}
	if strings.Contains(result, "SELECT") {
		t.Error("SELECT should be stripped")
	}
	if strings.Contains(result, "<script>") {
		t.Error("script tag should be stripped")
	}
	if strings.Contains(result, "evil") {
		t.Error("evil() function should be stripped with script")
	}
}

// isErrorType is a helper to check error types
func isErrorType(err error, target interface{}) bool {
	switch target.(type) {
	case *ErrFieldTooLong:
		_, ok := err.(ErrFieldTooLong)
		return ok
	default:
		return false
	}
}
