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
	"errors"
	"testing"
)

func TestStringValidator_Required(t *testing.T) {
	validator := NewStringValidator("name", StringConstraints{Required: true})

	tests := []struct {
		value       any
		expectError bool
	}{
		{"hello", false},
		{"", true},
		{nil, true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("value %v should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("value %v should be valid: %v", tt.value, err)
		}
	}
}

func TestStringValidator_Length(t *testing.T) {
	validator := NewStringValidator("password", StringConstraints{
		MinLength: 8,
		MaxLength: 100,
	})

	tests := []struct {
		value       string
		expectError bool
	}{
		{"short", true},
		{"longenough", false},
		{"exactly8", false},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("value %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("value %q should be valid: %v", tt.value, err)
		}
	}
}

func TestStringValidator_TrimSpace(t *testing.T) {
	validator := NewStringValidator("name", StringConstraints{
		Required:  true,
		TrimSpace: true,
	})

	// Empty after trim should fail
	err := validator.Validate("   ")
	if err == nil {
		t.Error("whitespace-only should fail required check after trim")
	}
}

func TestStringValidator_Whitespace(t *testing.T) {
	tests := []struct {
		name        string
		constraints StringConstraints
		value       string
		expectError bool
	}{
		{
			name:        "no leading space - valid",
			constraints: StringConstraints{NoLeadingSpace: true},
			value:       "hello",
			expectError: false,
		},
		{
			name:        "no leading space - invalid",
			constraints: StringConstraints{NoLeadingSpace: true},
			value:       " hello",
			expectError: true,
		},
		{
			name:        "no trailing space - valid",
			constraints: StringConstraints{NoTrailingSpace: true},
			value:       "hello",
			expectError: false,
		},
		{
			name:        "no trailing space - invalid",
			constraints: StringConstraints{NoTrailingSpace: true},
			value:       "hello ",
			expectError: true,
		},
		{
			name:        "no whitespace - valid",
			constraints: StringConstraints{NoWhitespace: true},
			value:       "hello",
			expectError: false,
		},
		{
			name:        "no whitespace - invalid",
			constraints: StringConstraints{NoWhitespace: true},
			value:       "hello world",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewStringValidator("field", tt.constraints)
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestStringValidator_CharacterTypes(t *testing.T) {
	tests := []struct {
		name        string
		constraints StringConstraints
		value       string
		expectError bool
	}{
		{
			name:        "alpha only - valid",
			constraints: StringConstraints{AlphaOnly: true},
			value:       "Hello",
			expectError: false,
		},
		{
			name:        "alpha only - invalid",
			constraints: StringConstraints{AlphaOnly: true},
			value:       "Hello123",
			expectError: true,
		},
		{
			name:        "alphanumeric - valid",
			constraints: StringConstraints{AlphaNumeric: true},
			value:       "Hello123",
			expectError: false,
		},
		{
			name:        "alphanumeric - invalid",
			constraints: StringConstraints{AlphaNumeric: true},
			value:       "Hello-123",
			expectError: true,
		},
		{
			name:        "no special chars - valid",
			constraints: StringConstraints{NoSpecialChars: true},
			value:       "Hello World_123",
			expectError: false,
		},
		{
			name:        "no special chars - invalid",
			constraints: StringConstraints{NoSpecialChars: true},
			value:       "Hello@World",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewStringValidator("field", tt.constraints)
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestStringValidator_Pattern(t *testing.T) {
	validator := NewStringValidator("zipcode", StringConstraints{
		Pattern: `^\d{5}$`,
	})

	tests := []struct {
		value       string
		expectError bool
	}{
		{"12345", false},
		{"1234", true},
		{"123456", true},
		{"abcde", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("value %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("value %q should be valid: %v", tt.value, err)
		}
	}
}

func TestStringValidator_Pattern_Invalid(t *testing.T) {
	validator := NewStringValidator("field", StringConstraints{
		Pattern: `[invalid`,
	})

	err := validator.Validate("test")
	if err == nil {
		t.Error("invalid regex pattern should return error")
	}
}

func TestStringValidator_AllowedValues(t *testing.T) {
	validator := NewStringValidator("status", StringConstraints{
		AllowedValues: []string{"active", "inactive", "pending"},
	})

	tests := []struct {
		value       string
		expectError bool
	}{
		{"active", false},
		{"inactive", false},
		{"pending", false},
		{"unknown", true},
		{"ACTIVE", true}, // case sensitive
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("value %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("value %q should be valid: %v", tt.value, err)
		}
	}
}

func TestStringValidator_DisallowedChars(t *testing.T) {
	validator := NewStringValidator("username", StringConstraints{
		DisallowedChars: "<>&\"'",
	})

	tests := []struct {
		value       string
		expectError bool
	}{
		{"john_doe", false},
		{"john<doe>", true},
		{"john&doe", true},
		{"john\"doe", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("value %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("value %q should be valid: %v", tt.value, err)
		}
	}
}

func TestStringValidator_NonStringValue(t *testing.T) {
	validator := NewStringValidator("name", StringConstraints{})

	err := validator.Validate(123)
	if err == nil {
		t.Error("non-string value should be invalid")
	}
}

func TestStringValidator_EmptyNotRequired(t *testing.T) {
	validator := NewStringValidator("optional", StringConstraints{
		Required:  false,
		MinLength: 5,
	})

	err := validator.Validate("")
	if err != nil {
		t.Errorf("empty string should be valid when not required: %v", err)
	}
}

func TestEmailValidator(t *testing.T) {
	validator := NewEmailValidator("email")

	tests := []struct {
		value       string
		expectError bool
	}{
		{"user@example.com", false},
		{"user.name@example.co.uk", false},
		{"user+tag@example.com", false},
		{"invalid", true},
		{"@example.com", true},
		{"user@", true},
		{"user@example", true},
		{"", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("email %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("email %q should be valid: %v", tt.value, err)
		}
	}
}

func TestEmailValidator_NonString(t *testing.T) {
	validator := NewEmailValidator("email")

	err := validator.Validate(123)
	if err == nil {
		t.Error("non-string value should be invalid")
	}
}

func TestURLValidator(t *testing.T) {
	validator := NewURLValidator("url", []string{"http", "https"}, true)

	tests := []struct {
		value       string
		expectError bool
	}{
		{"https://example.com", false},
		{"http://example.com/path", false},
		{"https://example.com:8080/path?query=1", false},
		{"ftp://example.com", true},   // scheme not allowed
		{"javascript:alert(1)", true}, // dangerous
		{"data:text/html,test", true}, // dangerous
		{"example.com", true},         // no scheme
		{"", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("URL %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("URL %q should be valid: %v", tt.value, err)
		}
	}
}

func TestURLValidator_NonString(t *testing.T) {
	validator := NewURLValidator("url", nil, false)

	err := validator.Validate(123)
	if err == nil {
		t.Error("non-string value should be invalid")
	}
}

func TestURLValidator_RequireHostFalse(t *testing.T) {
	// When requireHost is false but schemes are specified, URLs without schemes
	// will fail schema validation. This test validates that behavior.
	validator := NewURLValidator("url", nil, false) // No scheme restriction

	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{
			name:        "URL with host",
			value:       "https://example.com/path",
			expectError: false,
		},
		{
			name:        "relative path no host required",
			value:       "/path/to/resource",
			expectError: false,
		},
		{
			name:        "path only no host required",
			value:       "path/to/resource",
			expectError: false,
		},
		{
			name:        "fragment only",
			value:       "#anchor",
			expectError: false,
		},
		{
			name:        "query string",
			value:       "?query=value",
			expectError: false,
		},
		{
			name:        "empty URL",
			value:       "",
			expectError: true,
		},
		{
			name:        "javascript blocked even without host requirement",
			value:       "javascript:alert(1)",
			expectError: true,
		},
		{
			name:        "data blocked even without host requirement",
			value:       "data:text/html,<script>",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Errorf("URL %q should be invalid", tt.value)
			}
			if !tt.expectError && err != nil {
				t.Errorf("URL %q should be valid: %v", tt.value, err)
			}
		})
	}
}

func TestURLValidator_NoSchemeRestriction(t *testing.T) {
	validator := NewURLValidator("url", nil, true)

	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{
			name:        "http scheme",
			value:       "http://example.com",
			expectError: false,
		},
		{
			name:        "https scheme",
			value:       "https://example.com",
			expectError: false,
		},
		{
			name:        "ftp scheme",
			value:       "ftp://example.com",
			expectError: false,
		},
		{
			name:        "custom scheme",
			value:       "myapp://action",
			expectError: false,
		},
		{
			name:        "javascript blocked",
			value:       "javascript:alert(1)",
			expectError: true,
		},
		{
			name:        "data blocked",
			value:       "data:text/html,<script>",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Errorf("URL %q should be invalid", tt.value)
			}
			if !tt.expectError && err != nil {
				t.Errorf("URL %q should be valid: %v", tt.value, err)
			}
		})
	}
}

func TestURLValidator_RequireHostTrue(t *testing.T) {
	validator := NewURLValidator("url", nil, true)

	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{
			name:        "URL with host",
			value:       "https://example.com",
			expectError: false,
		},
		{
			name:        "relative path requires host",
			value:       "/path/to/resource",
			expectError: true,
		},
		{
			name:        "path only requires host",
			value:       "path/to/resource",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Errorf("URL %q should be invalid when host required", tt.value)
			}
			if !tt.expectError && err != nil {
				t.Errorf("URL %q should be valid: %v", tt.value, err)
			}
		})
	}
}

func TestIPValidator(t *testing.T) {
	tests := []struct {
		name        string
		allowIPv4   bool
		allowIPv6   bool
		value       string
		expectError bool
	}{
		{"IPv4 allowed", true, false, "192.168.1.1", false},
		{"IPv4 not allowed", false, true, "192.168.1.1", true},
		{"IPv6 allowed", false, true, "::1", false},
		{"IPv6 not allowed", true, false, "::1", true},
		{"both allowed IPv4", true, true, "192.168.1.1", false},
		{"both allowed IPv6", true, true, "2001:db8::1", false},
		{"invalid IP", true, true, "not-an-ip", true},
		{"empty", true, true, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewIPValidator("ip", tt.allowIPv4, tt.allowIPv6)
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func TestIPValidator_NonString(t *testing.T) {
	validator := NewIPValidator("ip", true, true)

	err := validator.Validate(123)
	if err == nil {
		t.Error("non-string value should be invalid")
	}
}

func TestCIDRValidator(t *testing.T) {
	validator := NewCIDRValidator("cidr")

	tests := []struct {
		value       string
		expectError bool
	}{
		{"192.168.1.0/24", false},
		{"10.0.0.0/8", false},
		{"2001:db8::/32", false},
		{"192.168.1.1", true},    // not CIDR
		{"192.168.1.0/33", true}, // invalid prefix
		{"", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("CIDR %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("CIDR %q should be valid: %v", tt.value, err)
		}
	}
}

func TestCIDRValidator_NonString(t *testing.T) {
	validator := NewCIDRValidator("cidr")

	err := validator.Validate(123)
	if err == nil {
		t.Error("non-string value should be invalid")
	}
}

func TestUUIDValidator(t *testing.T) {
	validator := NewUUIDValidator("id")

	tests := []struct {
		value       string
		expectError bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", false},
		{"550e8400e29b41d4a716446655440000", false}, // no dashes
		{"invalid-uuid", true},
		{"550e8400-e29b-41d4-a716-44665544000", true},   // too short
		{"550e8400-e29b-41d4-a716-4466554400001", true}, // too long
		{"", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("UUID %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("UUID %q should be valid: %v", tt.value, err)
		}
	}
}

func TestUUIDValidator_NonString(t *testing.T) {
	validator := NewUUIDValidator("id")

	err := validator.Validate(123)
	if err == nil {
		t.Error("non-string value should be invalid")
	}
}

func TestXSSValidator(t *testing.T) {
	validator := NewXSSValidator("content")

	tests := []struct {
		value       string
		expectError bool
	}{
		{"hello world", false},
		{"<script>alert('xss')</script>", true},
		{"<img onerror=\"alert(1)\">", true},
		{"javascript:alert(1)", true},
		{"<iframe src=\"evil.com\">", true},
		{"expression(alert(1))", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("content %q should be invalid (XSS)", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("content %q should be valid: %v", tt.value, err)
		}
	}
}

func TestXSSValidator_NonString(t *testing.T) {
	validator := NewXSSValidator("content")

	// Non-string should pass (no XSS in non-string)
	err := validator.Validate(123)
	if err != nil {
		t.Errorf("non-string should pass XSS check: %v", err)
	}
}

func TestXSSValidator_AdditionalPatterns(t *testing.T) {
	validator := NewXSSValidator("content")

	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{
			name:        "object tag",
			value:       "<object data=\"malicious.swf\">",
			expectError: true,
		},
		{
			name:        "embed tag",
			value:       "<embed src=\"malicious.swf\">",
			expectError: true,
		},
		{
			name:        "form tag",
			value:       "<form action=\"evil.com\">",
			expectError: true,
		},
		{
			name:        "url function",
			value:       "background: url(javascript:alert(1))",
			expectError: true,
		},
		{
			name:        "import directive",
			value:       "@import url('evil.css');",
			expectError: true,
		},
		{
			name:        "vbscript",
			value:       "vbscript:msgbox('xss')",
			expectError: true,
		},
		{
			name:        "data URL",
			value:       "data:text/html,<script>alert(1)</script>",
			expectError: true,
		},
		{
			name:        "safe content",
			value:       "This is a safe paragraph with normal text.",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Errorf("content should be detected as XSS")
			}
			if !tt.expectError && err != nil {
				t.Errorf("content should be safe: %v", err)
			}
		})
	}
}

func TestSQLInjectionValidator(t *testing.T) {
	validator := NewSQLInjectionValidator("query")

	tests := []struct {
		value       string
		expectError bool
	}{
		{"hello world", false},
		{"' OR '1'='1", true},
		{"'; DROP TABLE users--", true},
		{"'; DELETE FROM users", true},
		{"UNION SELECT * FROM users", true},
		{"xp_cmdshell('dir')", true},
		{"waitfor delay '0:0:10'", true},
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("content %q should be invalid (SQL injection)", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("content %q should be valid: %v", tt.value, err)
		}
	}
}

func TestSQLInjectionValidator_NonString(t *testing.T) {
	validator := NewSQLInjectionValidator("query")

	// Non-string should pass
	err := validator.Validate(123)
	if err != nil {
		t.Errorf("non-string should pass SQL injection check: %v", err)
	}
}

func TestSQLInjectionValidator_AdditionalPatterns(t *testing.T) {
	validator := NewSQLInjectionValidator("input")

	tests := []struct {
		name        string
		value       string
		expectError bool
	}{
		{
			name:        "UNION ALL SELECT",
			value:       "1 UNION ALL SELECT password FROM users",
			expectError: true,
		},
		{
			name:        "exec function",
			value:       "exec(cmd)",
			expectError: true,
		},
		{
			name:        "execute function",
			value:       "execute(sp_sql)",
			expectError: true,
		},
		{
			name:        "SQL comment at end",
			value:       "admin'--",
			expectError: true,
		},
		{
			name:        "block comment",
			value:       "admin /* comment */",
			expectError: true,
		},
		{
			name:        "hex encoding",
			value:       "0x41424344",
			expectError: true,
		},
		{
			name:        "char function",
			value:       "char(65)",
			expectError: true,
		},
		{
			name:        "safe input",
			value:       "John Doe",
			expectError: false,
		},
		{
			name:        "numeric input",
			value:       "12345",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.Validate(tt.value)
			if tt.expectError && err == nil {
				t.Errorf("input should be detected as SQL injection")
			}
			if !tt.expectError && err != nil {
				t.Errorf("input should be safe: %v", err)
			}
		})
	}
}

func TestCompositeValidator(t *testing.T) {
	validator := NewCompositeValidator(
		NewStringValidator("email", StringConstraints{Required: true}),
		NewEmailValidator("email"),
		NewXSSValidator("email"),
	)

	tests := []struct {
		value       string
		expectError bool
	}{
		{"user@example.com", false},
		{"", true},               // fails required
		{"not-an-email", true},   // fails email format
		{"<script>@x.com", true}, // fails XSS
	}

	for _, tt := range tests {
		err := validator.Validate(tt.value)
		if tt.expectError && err == nil {
			t.Errorf("value %q should be invalid", tt.value)
		}
		if !tt.expectError && err != nil {
			t.Errorf("value %q should be valid: %v", tt.value, err)
		}
	}
}

func TestCompositeValidator_Add(t *testing.T) {
	validator := NewCompositeValidator().
		Add(NewStringValidator("field", StringConstraints{Required: true})).
		Add(NewXSSValidator("field"))

	err := validator.Validate("")
	if err == nil {
		t.Error("empty value should fail required check")
	}
}

func TestCompositeValidator_ErrValidationFailed(t *testing.T) {
	// Create a custom validator that returns ErrValidationFailed
	customValidator := ValidatorFunc(func(value any) error {
		return ErrValidationFailed{
			Errors: []ValidationError{
				{Field: "custom", Message: "custom error 1"},
				{Field: "custom", Message: "custom error 2"},
			},
		}
	})

	validator := NewCompositeValidator(
		customValidator,
		NewStringValidator("field", StringConstraints{Required: true}),
	)

	err := validator.Validate("test")
	if err == nil {
		t.Error("expected error from composite validator")
	}

	var validationErr ErrValidationFailed
	if !errors.As(err, &validationErr) {
		t.Errorf("expected ErrValidationFailed, got %T", err)
	}

	// Should have merged errors from the custom validator
	if len(validationErr.Errors) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(validationErr.Errors))
	}
}

func TestCompositeValidator_MixedErrorTypes(t *testing.T) {
	// Validator that returns a generic error
	genericValidator := ValidatorFunc(func(value any) error {
		return errors.New("generic error")
	})

	validator := NewCompositeValidator(
		genericValidator,
		NewStringValidator("field", StringConstraints{MinLength: 100}),
	)

	err := validator.Validate("short")
	if err == nil {
		t.Error("expected error from composite validator")
	}

	var validationErr ErrValidationFailed
	if !errors.As(err, &validationErr) {
		t.Errorf("expected ErrValidationFailed, got %T", err)
	}

	// Should have both errors
	if len(validationErr.Errors) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(validationErr.Errors))
	}
}

func TestCompositeValidator_NoErrors(t *testing.T) {
	validator := NewCompositeValidator(
		NewStringValidator("field", StringConstraints{}),
	)

	err := validator.Validate("valid input")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}
