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
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// StringValidator validates strings according to constraints
type StringValidator struct {
	field       string
	constraints StringConstraints
}

// NewStringValidator creates a new string validator
func NewStringValidator(field string, constraints StringConstraints) *StringValidator {
	return &StringValidator{field: field, constraints: constraints}
}

// Validate validates a string value
func (v *StringValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		if value == nil {
			str = ""
		} else {
			return ErrInvalidValue{Field: v.field, Value: value, Reason: "expected string"}
		}
	}

	// Trim space if configured
	if v.constraints.TrimSpace {
		str = strings.TrimSpace(str)
	}

	// Required check
	if v.constraints.Required && str == "" {
		return ErrFieldRequired{Field: v.field}
	}

	// If empty and not required, skip further checks
	if str == "" {
		return nil
	}

	// Length checks
	if v.constraints.MinLength > 0 && len(str) < v.constraints.MinLength {
		return ErrFieldTooShort{Field: v.field, MinLength: v.constraints.MinLength, Actual: len(str)}
	}
	if v.constraints.MaxLength > 0 && len(str) > v.constraints.MaxLength {
		return ErrFieldTooLong{Field: v.field, MaxLength: v.constraints.MaxLength, Actual: len(str)}
	}

	// Whitespace checks
	if v.constraints.NoLeadingSpace && len(str) > 0 && unicode.IsSpace(rune(str[0])) {
		return ErrInvalidFormat{Field: v.field, Expected: "no leading whitespace"}
	}
	if v.constraints.NoTrailingSpace && len(str) > 0 && unicode.IsSpace(rune(str[len(str)-1])) {
		return ErrInvalidFormat{Field: v.field, Expected: "no trailing whitespace"}
	}
	if v.constraints.NoWhitespace && strings.ContainsAny(str, " \t\n\r") {
		return ErrInvalidFormat{Field: v.field, Expected: "no whitespace"}
	}

	// Character checks
	if v.constraints.AlphaOnly {
		for _, r := range str {
			if !unicode.IsLetter(r) {
				return ErrInvalidFormat{Field: v.field, Expected: "alphabetic characters only"}
			}
		}
	}
	if v.constraints.AlphaNumeric {
		for _, r := range str {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				return ErrInvalidFormat{Field: v.field, Expected: "alphanumeric characters only"}
			}
		}
	}
	if v.constraints.NoSpecialChars {
		for _, r := range str {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '_' && r != '-' {
				return ErrInvalidFormat{Field: v.field, Expected: "no special characters"}
			}
		}
	}

	// Disallowed characters
	if v.constraints.DisallowedChars != "" {
		for _, r := range str {
			if strings.ContainsRune(v.constraints.DisallowedChars, r) {
				return ErrInvalidValue{Field: v.field, Value: string(r), Reason: "character not allowed"}
			}
		}
	}

	// Pattern match
	if v.constraints.Pattern != "" {
		matched, err := regexp.MatchString(v.constraints.Pattern, str)
		if err != nil {
			return ErrInvalidPattern{Field: v.field, Pattern: v.constraints.Pattern, Value: str}
		}
		if !matched {
			return ErrInvalidPattern{Field: v.field, Pattern: v.constraints.Pattern, Value: str}
		}
	}

	// Allowed values
	if len(v.constraints.AllowedValues) > 0 {
		allowed := false
		for _, av := range v.constraints.AllowedValues {
			if str == av {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrInvalidValue{Field: v.field, Value: str, Allowed: v.constraints.AllowedValues}
		}
	}

	return nil
}

// EmailValidator validates email addresses
type EmailValidator struct {
	field string
}

// NewEmailValidator creates a new email validator
func NewEmailValidator(field string) *EmailValidator {
	return &EmailValidator{field: field}
}

// Validate validates an email address
func (v *EmailValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		return ErrInvalidValue{Field: v.field, Value: value, Reason: "expected string"}
	}

	if str == "" {
		return ErrFieldRequired{Field: v.field}
	}

	// Basic format check
	_, err := mail.ParseAddress(str)
	if err != nil {
		return ErrInvalidEmail{Email: str}
	}

	// Additional checks
	if !strings.Contains(str, "@") {
		return ErrInvalidEmail{Email: str}
	}

	parts := strings.Split(str, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ErrInvalidEmail{Email: str}
	}

	// Domain should have at least one dot
	if !strings.Contains(parts[1], ".") {
		return ErrInvalidEmail{Email: str}
	}

	return nil
}

// URLValidator validates URLs
type URLValidator struct {
	field          string
	allowedSchemes []string
	requireHost    bool
}

// NewURLValidator creates a new URL validator
func NewURLValidator(field string, allowedSchemes []string, requireHost bool) *URLValidator {
	return &URLValidator{
		field:          field,
		allowedSchemes: allowedSchemes,
		requireHost:    requireHost,
	}
}

// Validate validates a URL
func (v *URLValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		return ErrInvalidValue{Field: v.field, Value: value, Reason: "expected string"}
	}

	if str == "" {
		return ErrFieldRequired{Field: v.field}
	}

	parsed, err := url.Parse(str)
	if err != nil {
		return ErrInvalidURL{URL: str, Reason: err.Error()}
	}

	// Check scheme
	if len(v.allowedSchemes) > 0 {
		allowed := false
		for _, scheme := range v.allowedSchemes {
			if strings.EqualFold(parsed.Scheme, scheme) {
				allowed = true
				break
			}
		}
		if !allowed {
			return ErrInvalidURL{URL: str, Reason: "scheme not allowed"}
		}
	}

	// Check host
	if v.requireHost && parsed.Host == "" {
		return ErrInvalidURL{URL: str, Reason: "host required"}
	}

	// Block javascript URLs
	if strings.EqualFold(parsed.Scheme, "javascript") {
		return ErrInvalidURL{URL: str, Reason: "javascript URLs not allowed"}
	}

	// Block data URLs (potential XSS vector)
	if strings.EqualFold(parsed.Scheme, "data") {
		return ErrInvalidURL{URL: str, Reason: "data URLs not allowed"}
	}

	return nil
}

// IPValidator validates IP addresses
type IPValidator struct {
	field     string
	allowIPv4 bool
	allowIPv6 bool
}

// NewIPValidator creates a new IP validator
func NewIPValidator(field string, allowIPv4, allowIPv6 bool) *IPValidator {
	return &IPValidator{
		field:     field,
		allowIPv4: allowIPv4,
		allowIPv6: allowIPv6,
	}
}

// Validate validates an IP address
func (v *IPValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		return ErrInvalidValue{Field: v.field, Value: value, Reason: "expected string"}
	}

	if str == "" {
		return ErrFieldRequired{Field: v.field}
	}

	ip := net.ParseIP(str)
	if ip == nil {
		return ErrInvalidIP{IP: str}
	}

	isIPv4 := ip.To4() != nil
	isIPv6 := !isIPv4

	if isIPv4 && !v.allowIPv4 {
		return ErrInvalidIP{IP: str}
	}
	if isIPv6 && !v.allowIPv6 {
		return ErrInvalidIP{IP: str}
	}

	return nil
}

// CIDRValidator validates CIDR notation
type CIDRValidator struct {
	field string
}

// NewCIDRValidator creates a new CIDR validator
func NewCIDRValidator(field string) *CIDRValidator {
	return &CIDRValidator{field: field}
}

// Validate validates a CIDR
func (v *CIDRValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		return ErrInvalidValue{Field: v.field, Value: value, Reason: "expected string"}
	}

	if str == "" {
		return ErrFieldRequired{Field: v.field}
	}

	_, _, err := net.ParseCIDR(str)
	if err != nil {
		return ErrInvalidFormat{Field: v.field, Expected: "CIDR notation (e.g., 192.168.1.0/24)"}
	}

	return nil
}

// UUIDValidator validates UUIDs
type UUIDValidator struct {
	field string
}

// NewUUIDValidator creates a new UUID validator
func NewUUIDValidator(field string) *UUIDValidator {
	return &UUIDValidator{field: field}
}

// UUID patterns
var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	uuidNoDashPatt = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
)

// Validate validates a UUID
func (v *UUIDValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		return ErrInvalidValue{Field: v.field, Value: value, Reason: "expected string"}
	}

	if str == "" {
		return ErrFieldRequired{Field: v.field}
	}

	if !uuidPattern.MatchString(str) && !uuidNoDashPatt.MatchString(str) {
		return ErrInvalidFormat{Field: v.field, Expected: "UUID format"}
	}

	return nil
}

// XSSValidator checks for potential XSS content
type XSSValidator struct {
	field string
}

// NewXSSValidator creates a new XSS validator
func NewXSSValidator(field string) *XSSValidator {
	return &XSSValidator{field: field}
}

// XSS detection patterns
var xssPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)on\w+\s*=`),
	regexp.MustCompile(`(?i)<iframe[^>]*>`),
	regexp.MustCompile(`(?i)<object[^>]*>`),
	regexp.MustCompile(`(?i)<embed[^>]*>`),
	regexp.MustCompile(`(?i)<form[^>]*>`),
	regexp.MustCompile(`(?i)expression\s*\(`),
	regexp.MustCompile(`(?i)url\s*\(`),
	regexp.MustCompile(`(?i)@import`),
	regexp.MustCompile(`(?i)vbscript\s*:`),
	regexp.MustCompile(`(?i)data\s*:`),
}

// Validate checks for XSS content
func (v *XSSValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		return nil
	}

	for _, pattern := range xssPatterns {
		if pattern.MatchString(str) {
			return ErrXSSDetected{Field: v.field}
		}
	}

	return nil
}

// SQLInjectionValidator checks for potential SQL injection
type SQLInjectionValidator struct {
	field string
}

// NewSQLInjectionValidator creates a new SQL injection validator
func NewSQLInjectionValidator(field string) *SQLInjectionValidator {
	return &SQLInjectionValidator{field: field}
}

// SQL injection patterns
var sqlInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)'\s*or\s+'`),
	regexp.MustCompile(`(?i)'\s*or\s+\d+\s*=\s*\d+`),
	regexp.MustCompile(`(?i)'\s*;\s*drop\s+`),
	regexp.MustCompile(`(?i)'\s*;\s*delete\s+`),
	regexp.MustCompile(`(?i)'\s*;\s*insert\s+`),
	regexp.MustCompile(`(?i)'\s*;\s*update\s+`),
	regexp.MustCompile(`(?i)union\s+select`),
	regexp.MustCompile(`(?i)union\s+all\s+select`),
	regexp.MustCompile(`(?i)exec\s*\(`),
	regexp.MustCompile(`(?i)execute\s*\(`),
	regexp.MustCompile(`(?i)--\s*$`),
	regexp.MustCompile(`(?i)/\*.*\*/`),
	regexp.MustCompile(`(?i)xp_cmdshell`),
	regexp.MustCompile(`(?i)waitfor\s+delay`),
	regexp.MustCompile(`(?i)0x[0-9a-f]+`),
	regexp.MustCompile(`(?i)char\s*\(\s*\d+\s*\)`),
}

// Validate checks for SQL injection patterns
func (v *SQLInjectionValidator) Validate(value any) error {
	str, ok := value.(string)
	if !ok {
		return nil
	}

	for _, pattern := range sqlInjectionPatterns {
		if pattern.MatchString(str) {
			return ErrSQLInjection{Field: v.field, Pattern: pattern.String()}
		}
	}

	return nil
}

// CompositeValidator combines multiple validators
type CompositeValidator struct {
	validators []Validator
}

// NewCompositeValidator creates a new composite validator
func NewCompositeValidator(validators ...Validator) *CompositeValidator {
	return &CompositeValidator{validators: validators}
}

// Validate runs all validators and collects errors
func (v *CompositeValidator) Validate(value any) error {
	var errors []ValidationError

	for _, validator := range v.validators {
		if err := validator.Validate(value); err != nil {
			switch e := err.(type) {
			case ValidationError:
				errors = append(errors, e)
			case ErrValidationFailed:
				errors = append(errors, e.Errors...)
			default:
				errors = append(errors, ValidationError{Message: err.Error()})
			}
		}
	}

	if len(errors) > 0 {
		return ErrValidationFailed{Errors: errors}
	}

	return nil
}

// Add adds a validator
func (v *CompositeValidator) Add(validator Validator) *CompositeValidator {
	v.validators = append(v.validators, validator)
	return v
}
