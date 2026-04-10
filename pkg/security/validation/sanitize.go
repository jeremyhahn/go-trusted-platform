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
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Sanitizer provides input sanitization functions
type Sanitizer struct {
	options SanitizerOptions
}

// NewSanitizer creates a new sanitizer with the given options
func NewSanitizer(options SanitizerOptions) *Sanitizer {
	return &Sanitizer{options: options}
}

// NewDefaultSanitizer creates a sanitizer with default options
func NewDefaultSanitizer() *Sanitizer {
	return NewSanitizer(DefaultSanitizerOptions())
}

// SanitizeString sanitizes a string according to configured options
func (s *Sanitizer) SanitizeString(input string) string {
	result := input

	// Strip null bytes first
	if s.options.StripNullBytes {
		result = stripNullBytes(result)
	}

	// Trim whitespace
	if s.options.TrimSpace {
		result = strings.TrimSpace(result)
	}

	// Normalize newlines
	if s.options.NormalizeNewlines {
		result = normalizeNewlines(result)
	}

	// Strip HTML tags
	if s.options.StripHTML {
		result = StripHTML(result, s.options.AllowedTags)
	}

	// Strip JavaScript
	if s.options.StripJavaScript {
		result = stripJavaScript(result)
	}

	// Strip SQL keywords
	if s.options.StripSQLKeywords {
		result = stripSQLKeywords(result)
	}

	// Escape HTML entities
	if s.options.EscapeHTML {
		result = html.EscapeString(result)
	}

	// Truncate to max length
	if s.options.MaxLength > 0 && len(result) > s.options.MaxLength {
		result = result[:s.options.MaxLength]
	}

	return result
}

// stripNullBytes removes null bytes from a string
func stripNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// normalizeNewlines converts all newline variants to \n
func normalizeNewlines(s string) string {
	// Replace \r\n with \n first, then \r with \n
	result := strings.ReplaceAll(s, "\r\n", "\n")
	result = strings.ReplaceAll(result, "\r", "\n")
	return result
}

// HTML patterns for stripping
var (
	// Matches script/style tags with their content
	scriptStylePattern = regexp.MustCompile(`(?i)<(script|style)[^>]*>[\s\S]*?</(script|style)>`)
	// Matches any HTML tag
	htmlTagPattern = regexp.MustCompile(`<[^>]*>`)
)

// StripHTML removes HTML tags from a string, optionally allowing certain tags
func StripHTML(input string, allowedTags []string) string {
	// First strip script and style tags with their content
	result := scriptStylePattern.ReplaceAllString(input, "")

	if len(allowedTags) == 0 {
		return htmlTagPattern.ReplaceAllString(result, "")
	}

	// Build pattern that excludes allowed tags
	for _, tag := range allowedTags {
		// Temporarily replace allowed tags
		openTag := "<" + tag
		closeTag := "</" + tag + ">"
		placeholder := "\x00OPEN_" + tag + "\x00"
		closePlaceholder := "\x00CLOSE_" + tag + "\x00"

		// Handle opening tags with attributes
		openPattern := regexp.MustCompile(`<` + regexp.QuoteMeta(tag) + `(\s[^>]*)?>`)
		result = openPattern.ReplaceAllStringFunc(result, func(match string) string {
			return placeholder + strings.TrimPrefix(strings.TrimSuffix(match, ">"), openTag)
		})
		result = strings.ReplaceAll(result, closeTag, closePlaceholder)
	}

	// Strip remaining HTML
	result = htmlTagPattern.ReplaceAllString(result, "")

	// Restore allowed tags
	for _, tag := range allowedTags {
		placeholder := "\x00OPEN_" + tag + "\x00"
		closePlaceholder := "\x00CLOSE_" + tag + "\x00"
		result = strings.ReplaceAll(result, placeholder, "<"+tag)
		result = strings.ReplaceAll(result, closePlaceholder, "</"+tag+">")
	}

	return result
}

// JavaScript patterns for stripping
var (
	scriptTagPattern    = regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?</script>`)
	onEventPattern      = regexp.MustCompile(`(?i)\s*on\w+\s*=\s*["'][^"']*["']`)
	javascriptURLPatter = regexp.MustCompile(`(?i)javascript\s*:`)
)

// stripJavaScript removes JavaScript content from a string
func stripJavaScript(s string) string {
	result := scriptTagPattern.ReplaceAllString(s, "")
	result = onEventPattern.ReplaceAllString(result, "")
	result = javascriptURLPatter.ReplaceAllString(result, "")
	return result
}

// SQL keywords to strip (common injection patterns)
var sqlKeywords = []string{
	"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION",
	"EXEC", "EXECUTE", "CREATE", "ALTER", "TRUNCATE", "GRANT",
	"REVOKE", "--", ";--", "/*", "*/", "@@", "@",
	"CHAR(", "NCHAR(", "VARCHAR(", "NVARCHAR(", "CONVERT(",
	"CAST(", "WAITFOR", "DELAY", "SHUTDOWN", "XP_",
}

// stripSQLKeywords removes common SQL keywords
func stripSQLKeywords(s string) string {
	result := s
	upper := strings.ToUpper(s)

	for _, keyword := range sqlKeywords {
		idx := strings.Index(upper, keyword)
		for idx >= 0 {
			result = result[:idx] + result[idx+len(keyword):]
			upper = upper[:idx] + upper[idx+len(keyword):]
			idx = strings.Index(upper, keyword)
		}
	}

	return result
}

// PathSanitizer provides path sanitization functions
type PathSanitizer struct {
	options PathSanitizerOptions
}

// NewPathSanitizer creates a new path sanitizer
func NewPathSanitizer(options PathSanitizerOptions) *PathSanitizer {
	return &PathSanitizer{options: options}
}

// NewDefaultPathSanitizer creates a path sanitizer with default options
func NewDefaultPathSanitizer() *PathSanitizer {
	return NewPathSanitizer(DefaultPathSanitizerOptions())
}

// SanitizePath sanitizes a file path to prevent path traversal attacks
func (p *PathSanitizer) SanitizePath(input string) (string, error) {
	if input == "" {
		return "", ErrFieldRequired{Field: "path"}
	}

	// Clean the path first
	cleaned := filepath.Clean(input)

	// Check for path traversal
	if containsPathTraversal(cleaned) {
		return "", ErrPathTraversal{Path: input}
	}

	// Check absolute path
	if filepath.IsAbs(cleaned) && !p.options.AllowAbsolute {
		return "", ErrInvalidValue{Field: "path", Value: input, Reason: "absolute paths not allowed"}
	}

	// Check dot files
	if !p.options.AllowDotFiles && containsDotFile(cleaned) {
		return "", ErrInvalidValue{Field: "path", Value: input, Reason: "dot files not allowed"}
	}

	// Check depth
	if p.options.MaxDepth > 0 {
		depth := countPathDepth(cleaned)
		if depth > p.options.MaxDepth {
			return "", ErrInvalidValue{Field: "path", Value: input, Reason: "path exceeds maximum depth"}
		}
	}

	// Check allowed prefixes
	if len(p.options.AllowedPrefixes) > 0 {
		allowed := false
		for _, prefix := range p.options.AllowedPrefixes {
			if strings.HasPrefix(cleaned, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", ErrInvalidValue{Field: "path", Value: input, Reason: "path prefix not allowed"}
		}
	}

	// Check disallowed prefixes
	for _, prefix := range p.options.DisallowedPrefixes {
		if strings.HasPrefix(cleaned, prefix) {
			return "", ErrInvalidValue{Field: "path", Value: input, Reason: "path prefix is disallowed"}
		}
	}

	// Check extensions
	ext := strings.ToLower(filepath.Ext(cleaned))
	if ext != "" {
		// Check allowed extensions
		if len(p.options.AllowedExtensions) > 0 {
			allowed := false
			for _, allowedExt := range p.options.AllowedExtensions {
				if strings.EqualFold(ext, allowedExt) {
					allowed = true
					break
				}
			}
			if !allowed {
				return "", ErrInvalidValue{Field: "path", Value: input, Reason: "file extension not allowed"}
			}
		}

		// Check disallowed extensions
		for _, disallowedExt := range p.options.DisallowedExtensions {
			if strings.EqualFold(ext, disallowedExt) {
				return "", ErrInvalidValue{Field: "path", Value: input, Reason: "file extension is disallowed"}
			}
		}
	}

	return cleaned, nil
}

// containsPathTraversal checks for path traversal attempts
func containsPathTraversal(path string) bool {
	// Check for .. anywhere in the path
	if strings.Contains(path, "..") {
		return true
	}

	// Check for encoded traversal attempts
	decoded, err := url.QueryUnescape(path)
	if err == nil && strings.Contains(decoded, "..") {
		return true
	}

	// Check for various encodings
	traversalPatterns := []string{
		"..",
		"%2e%2e",
		"%252e%252e",
		"..%c0%af",
		"..%c1%9c",
		"..\\",
		"..%5c",
		"..%255c",
	}

	lower := strings.ToLower(path)
	for _, pattern := range traversalPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// containsDotFile checks if the path contains a dot file/directory
func containsDotFile(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		if len(part) > 1 && part[0] == '.' {
			return true
		}
	}
	return false
}

// countPathDepth counts the depth of a path
func countPathDepth(path string) int {
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == "/" {
		return 0
	}
	parts := strings.Split(filepath.ToSlash(cleaned), "/")
	count := 0
	for _, part := range parts {
		if part != "" && part != "." {
			count++
		}
	}
	return count
}

// SanitizePath is a convenience function for sanitizing paths with default options
func SanitizePath(path string) (string, error) {
	return NewDefaultPathSanitizer().SanitizePath(path)
}

// EscapeHTML escapes HTML special characters
func EscapeHTML(s string) string {
	return html.EscapeString(s)
}

// UnescapeHTML unescapes HTML entities
func UnescapeHTML(s string) string {
	return html.UnescapeString(s)
}

// StripControl removes control characters from a string
func StripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// StripNonPrintable removes non-printable characters from a string
func StripNonPrintable(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// NormalizeWhitespace normalizes whitespace in a string
func NormalizeWhitespace(s string) string {
	// Replace multiple spaces with single space
	spacePattern := regexp.MustCompile(`\s+`)
	return strings.TrimSpace(spacePattern.ReplaceAllString(s, " "))
}

// TruncateString truncates a string to max length with optional suffix
func TruncateString(s string, maxLen int, suffix string) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= len(suffix) {
		return s[:maxLen]
	}
	return s[:maxLen-len(suffix)] + suffix
}

// SafeFilename sanitizes a filename to be safe for filesystem use
func SafeFilename(filename string) string {
	// Remove path separators
	result := filepath.Base(filename)

	// Remove null bytes
	result = stripNullBytes(result)

	// Replace unsafe characters
	unsafeChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	result = unsafeChars.ReplaceAllString(result, "_")

	// Trim spaces and dots from ends
	result = strings.Trim(result, " .")

	// Ensure not empty
	if result == "" {
		result = "_"
	}

	return result
}

// SQLSanitizer provides SQL-specific sanitization
type SQLSanitizer struct{}

// NewSQLSanitizer creates a new SQL sanitizer
func NewSQLSanitizer() *SQLSanitizer {
	return &SQLSanitizer{}
}

// EscapeString escapes a string for use in SQL (for informational use only - use parameterized queries)
func (s *SQLSanitizer) EscapeString(input string) string {
	// This is for logging/display purposes only
	// Always use parameterized queries for actual SQL execution
	result := strings.ReplaceAll(input, "'", "''")
	result = strings.ReplaceAll(result, "\\", "\\\\")
	result = strings.ReplaceAll(result, "\x00", "\\0")
	result = strings.ReplaceAll(result, "\n", "\\n")
	result = strings.ReplaceAll(result, "\r", "\\r")
	result = strings.ReplaceAll(result, "\x1a", "\\Z")
	return result
}

// EscapeIdentifier escapes an identifier for use in SQL
func (s *SQLSanitizer) EscapeIdentifier(input string) string {
	// Remove any existing quotes
	result := strings.ReplaceAll(input, "`", "")
	result = strings.ReplaceAll(result, "\"", "")
	// Only allow alphanumeric and underscore
	safePattern := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	return safePattern.ReplaceAllString(result, "")
}

// ValidateIdentifier validates a SQL identifier
func (s *SQLSanitizer) ValidateIdentifier(input string) error {
	if input == "" {
		return ErrFieldRequired{Field: "identifier"}
	}

	// Check length
	if len(input) > 128 {
		return ErrFieldTooLong{Field: "identifier", MaxLength: 128, Actual: len(input)}
	}

	// Must start with letter or underscore
	if !unicode.IsLetter(rune(input[0])) && input[0] != '_' {
		return ErrInvalidFormat{Field: "identifier", Expected: "must start with letter or underscore"}
	}

	// Only alphanumeric and underscore allowed
	for _, r := range input {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return ErrInvalidFormat{Field: "identifier", Expected: "only alphanumeric and underscore allowed"}
		}
	}

	return nil
}
