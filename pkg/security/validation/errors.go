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
	"fmt"
	"strings"
)

// ErrValidationFailed is returned when validation fails
type ErrValidationFailed struct {
	Errors []ValidationError
}

func (e ErrValidationFailed) Error() string {
	if len(e.Errors) == 0 {
		return "validation failed"
	}
	if len(e.Errors) == 1 {
		return fmt.Sprintf("validation failed: %s", e.Errors[0].Error())
	}

	msgs := make([]string, len(e.Errors))
	for i, err := range e.Errors {
		msgs[i] = err.Error()
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(msgs, "; "))
}

// ValidationError represents a single validation error
type ValidationError struct {
	Field   string
	Message string
	Code    string
	Value   any
}

func (e ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// ErrFieldRequired is returned when a required field is missing
type ErrFieldRequired struct {
	Field string
}

func (e ErrFieldRequired) Error() string {
	return fmt.Sprintf("field %s is required", e.Field)
}

// ErrFieldTooLong is returned when a field exceeds maximum length
type ErrFieldTooLong struct {
	Field     string
	MaxLength int
	Actual    int
}

func (e ErrFieldTooLong) Error() string {
	return fmt.Sprintf("field %s exceeds maximum length: %d > %d", e.Field, e.Actual, e.MaxLength)
}

// ErrFieldTooShort is returned when a field is below minimum length
type ErrFieldTooShort struct {
	Field     string
	MinLength int
	Actual    int
}

func (e ErrFieldTooShort) Error() string {
	return fmt.Sprintf("field %s is below minimum length: %d < %d", e.Field, e.Actual, e.MinLength)
}

// ErrInvalidFormat is returned when a field has an invalid format
type ErrInvalidFormat struct {
	Field    string
	Expected string
	Actual   string
}

func (e ErrInvalidFormat) Error() string {
	if e.Actual != "" {
		return fmt.Sprintf("field %s has invalid format: expected %s, got %s", e.Field, e.Expected, e.Actual)
	}
	return fmt.Sprintf("field %s has invalid format: expected %s", e.Field, e.Expected)
}

// ErrInvalidValue is returned when a field has an invalid value
type ErrInvalidValue struct {
	Field   string
	Value   any
	Reason  string
	Allowed []string
}

func (e ErrInvalidValue) Error() string {
	if len(e.Allowed) > 0 {
		return fmt.Sprintf("field %s has invalid value: %v, allowed values: %v", e.Field, e.Value, e.Allowed)
	}
	if e.Reason != "" {
		return fmt.Sprintf("field %s has invalid value: %v (%s)", e.Field, e.Value, e.Reason)
	}
	return fmt.Sprintf("field %s has invalid value: %v", e.Field, e.Value)
}

// ErrPathTraversal is returned when path traversal is detected
type ErrPathTraversal struct {
	Path string
}

func (e ErrPathTraversal) Error() string {
	return fmt.Sprintf("path traversal detected: %s", e.Path)
}

// ErrDangerousContent is returned when dangerous content is detected
type ErrDangerousContent struct {
	Field   string
	Type    string
	Content string
}

func (e ErrDangerousContent) Error() string {
	return fmt.Sprintf("dangerous %s content detected in field %s", e.Type, e.Field)
}

// ErrOutOfRange is returned when a numeric value is out of range
type ErrOutOfRange struct {
	Field string
	Min   any
	Max   any
	Value any
}

func (e ErrOutOfRange) Error() string {
	return fmt.Sprintf("field %s value %v is out of range [%v, %v]", e.Field, e.Value, e.Min, e.Max)
}

// ErrInvalidPattern is returned when a value doesn't match required pattern
type ErrInvalidPattern struct {
	Field   string
	Pattern string
	Value   string
}

func (e ErrInvalidPattern) Error() string {
	return fmt.Sprintf("field %s value does not match pattern %s", e.Field, e.Pattern)
}

// ErrInvalidEmail is returned when an email address is invalid
type ErrInvalidEmail struct {
	Email string
}

func (e ErrInvalidEmail) Error() string {
	return fmt.Sprintf("invalid email address: %s", e.Email)
}

// ErrInvalidURL is returned when a URL is invalid
type ErrInvalidURL struct {
	URL    string
	Reason string
}

func (e ErrInvalidURL) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid URL: %s (%s)", e.URL, e.Reason)
	}
	return fmt.Sprintf("invalid URL: %s", e.URL)
}

// ErrInvalidIP is returned when an IP address is invalid
type ErrInvalidIP struct {
	IP string
}

func (e ErrInvalidIP) Error() string {
	return fmt.Sprintf("invalid IP address: %s", e.IP)
}

// ErrSQLInjection is returned when SQL injection is detected
type ErrSQLInjection struct {
	Field   string
	Pattern string
}

func (e ErrSQLInjection) Error() string {
	return fmt.Sprintf("potential SQL injection detected in field %s", e.Field)
}

// ErrXSSDetected is returned when XSS content is detected
type ErrXSSDetected struct {
	Field string
}

func (e ErrXSSDetected) Error() string {
	return fmt.Sprintf("potential XSS content detected in field %s", e.Field)
}
