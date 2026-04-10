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

// Validator defines the interface for validation implementations
type Validator interface {
	// Validate validates a value and returns an error if invalid
	Validate(value any) error
}

// ValidatorFunc is a function that implements Validator
type ValidatorFunc func(value any) error

// Validate implements Validator
func (f ValidatorFunc) Validate(value any) error {
	return f(value)
}

// ValidationResult holds the result of a validation
type ValidationResult struct {
	// Valid indicates if the validation passed
	Valid bool

	// Errors contains all validation errors
	Errors []ValidationError
}

// IsValid returns true if there are no validation errors
func (r ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// Error returns the first error message or empty string
func (r ValidationResult) Error() string {
	if len(r.Errors) == 0 {
		return ""
	}
	return r.Errors[0].Error()
}

// AddError adds a validation error
func (r *ValidationResult) AddError(err ValidationError) {
	r.Errors = append(r.Errors, err)
	r.Valid = false
}

// Merge merges another result into this one
func (r *ValidationResult) Merge(other ValidationResult) {
	r.Errors = append(r.Errors, other.Errors...)
	if len(r.Errors) > 0 {
		r.Valid = false
	}
}

// NewValidResult creates a valid result
func NewValidResult() ValidationResult {
	return ValidationResult{Valid: true}
}

// NewInvalidResult creates an invalid result with errors
func NewInvalidResult(errors ...ValidationError) ValidationResult {
	return ValidationResult{Valid: false, Errors: errors}
}

// StringConstraints defines constraints for string validation
type StringConstraints struct {
	// Required indicates the field is required
	Required bool

	// MinLength is the minimum length
	MinLength int

	// MaxLength is the maximum length
	MaxLength int

	// Pattern is a regex pattern the value must match
	Pattern string

	// AllowedValues is a list of allowed values
	AllowedValues []string

	// DisallowedChars are characters not allowed
	DisallowedChars string

	// TrimSpace trims whitespace before validation
	TrimSpace bool

	// NoLeadingSpace disallows leading whitespace
	NoLeadingSpace bool

	// NoTrailingSpace disallows trailing whitespace
	NoTrailingSpace bool

	// NoWhitespace disallows any whitespace
	NoWhitespace bool

	// AlphaOnly allows only alphabetic characters
	AlphaOnly bool

	// AlphaNumeric allows only alphanumeric characters
	AlphaNumeric bool

	// NoSpecialChars disallows special characters
	NoSpecialChars bool
}

// NumericConstraints defines constraints for numeric validation
type NumericConstraints struct {
	// Required indicates the field is required
	Required bool

	// Min is the minimum value
	Min *float64

	// Max is the maximum value
	Max *float64

	// AllowNegative allows negative values
	AllowNegative bool

	// AllowZero allows zero value
	AllowZero bool

	// MultipleOf requires the value to be a multiple of this
	MultipleOf *float64
}

// SanitizerOptions configures sanitization behavior
type SanitizerOptions struct {
	// TrimSpace trims leading/trailing whitespace
	TrimSpace bool

	// StripHTML removes HTML tags
	StripHTML bool

	// EscapeHTML escapes HTML entities
	EscapeHTML bool

	// StripNullBytes removes null bytes
	StripNullBytes bool

	// NormalizeNewlines converts all newlines to \n
	NormalizeNewlines bool

	// MaxLength truncates to maximum length
	MaxLength int

	// AllowedTags is a list of allowed HTML tags (when StripHTML is true)
	AllowedTags []string

	// StripSQLKeywords removes SQL keywords
	StripSQLKeywords bool

	// StripJavaScript removes JavaScript content
	StripJavaScript bool
}

// DefaultSanitizerOptions returns default sanitizer options
func DefaultSanitizerOptions() SanitizerOptions {
	return SanitizerOptions{
		TrimSpace:         true,
		StripHTML:         true,
		EscapeHTML:        true,
		StripNullBytes:    true,
		NormalizeNewlines: true,
	}
}

// PathSanitizerOptions configures path sanitization
type PathSanitizerOptions struct {
	// AllowAbsolute allows absolute paths
	AllowAbsolute bool

	// AllowedPrefixes is a list of allowed path prefixes
	AllowedPrefixes []string

	// DisallowedPrefixes is a list of disallowed path prefixes
	DisallowedPrefixes []string

	// MaxDepth is the maximum directory depth allowed
	MaxDepth int

	// AllowDotFiles allows files/dirs starting with .
	AllowDotFiles bool

	// AllowedExtensions is a list of allowed file extensions
	AllowedExtensions []string

	// DisallowedExtensions is a list of disallowed file extensions
	DisallowedExtensions []string
}

// DefaultPathSanitizerOptions returns default path sanitizer options
func DefaultPathSanitizerOptions() PathSanitizerOptions {
	return PathSanitizerOptions{
		AllowAbsolute: false,
		MaxDepth:      10,
		AllowDotFiles: false,
		DisallowedExtensions: []string{
			".exe", ".dll", ".so", ".dylib", ".sh", ".bat", ".cmd",
			".ps1", ".vbs", ".js", ".php", ".py", ".rb", ".pl",
		},
	}
}
