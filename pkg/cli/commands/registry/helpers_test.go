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

package registry

import (
	"strings"
	"testing"
	"time"
)

func TestValidateImageRef(t *testing.T) {
	validRefs := []string{
		"alpine",
		"alpine:latest",
		"alpine:3.18",
		"myrepo/myimage",
		"myrepo/myimage:v1.0",
		"myrepo/myimage:v1.0.0",
		"registry.example.com/myrepo/myimage",
		"registry.example.com/myrepo/myimage:v1.0",
		"localhost:5000/myimage",
		"localhost:5000/myimage:latest",
		"my-repo/my-image",
		"my.repo/my.image",
		"my_repo/my_image",
	}

	for _, ref := range validRefs {
		t.Run(ref, func(t *testing.T) {
			err := validateImageRef(ref)
			if err != nil {
				t.Errorf("validateImageRef(%q) returned error: %v", ref, err)
			}
		})
	}
}

func TestValidateImageRef_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		reason string
	}{
		{name: "empty", ref: "", reason: "empty reference"},
		{name: "too long", ref: string(make([]byte, 300)), reason: "too long"},
		{name: "uppercase", ref: "INVALID/IMAGE", reason: "uppercase not allowed"},
		{name: "spaces", ref: "invalid image", reason: "spaces not allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateImageRef(tt.ref)
			if err == nil {
				t.Errorf("validateImageRef(%q) should return error for %s", tt.ref, tt.reason)
			}

			if _, ok := err.(ErrInvalidImageReference); !ok {
				t.Errorf("expected ErrInvalidImageReference, got %T", err)
			}
		})
	}
}

func TestFormatTimestamp(t *testing.T) {
	tests := []struct {
		ts       int64
		expected string
	}{
		{0, "N/A"},
		{1609459200, "2021-01-01T00:00:00Z"},
		{1704067200, "2024-01-01T00:00:00Z"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatTimestamp(tt.ts)
			if result != tt.expected {
				t.Errorf("formatTimestamp(%d) = %q, want %q", tt.ts, result, tt.expected)
			}
		})
	}
}

func TestFormatTimePtr(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		result := formatTimePtr(nil)
		if result != "N/A" {
			t.Errorf("formatTimePtr(nil) = %q, want 'N/A'", result)
		}
	})

	t.Run("zero time", func(t *testing.T) {
		var zero time.Time
		result := formatTimePtr(&zero)
		if result != "N/A" {
			t.Errorf("formatTimePtr(zero) = %q, want 'N/A'", result)
		}
	})

	t.Run("valid time", func(t *testing.T) {
		tm := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		result := formatTimePtr(&tm)
		expected := "2024-01-01T00:00:00Z"
		if result != expected {
			t.Errorf("formatTimePtr = %q, want %q", result, expected)
		}
	})
}

func TestFormatBool(t *testing.T) {
	tests := []struct {
		input    bool
		expected string
	}{
		{true, "Yes"},
		{false, "No"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBool(tt.input)
			if result != tt.expected {
				t.Errorf("formatBool(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1024, "1.00 KB"},
		{1536, "1.50 KB"},
		{1048576, "1.00 MB"},
		{1572864, "1.50 MB"},
		{1073741824, "1.00 GB"},
		{1610612736, "1.50 GB"},
		{1099511627776, "1.00 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestFormatHealthStatus(t *testing.T) {
	tests := []struct {
		healthy  bool
		expected string
	}{
		{true, "[HEALTHY]"},
		{false, "[UNHEALTHY]"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatHealthStatus(tt.healthy)
			if result != tt.expected {
				t.Errorf("formatHealthStatus(%v) = %q, want %q", tt.healthy, result, tt.expected)
			}
		})
	}
}

func TestFormatEncryptionStatus(t *testing.T) {
	tests := []struct {
		encrypted bool
		expected  string
	}{
		{true, "Encrypted"},
		{false, "Unencrypted"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatEncryptionStatus(tt.encrypted)
			if result != tt.expected {
				t.Errorf("formatEncryptionStatus(%v) = %q, want %q", tt.encrypted, result, tt.expected)
			}
		})
	}
}

func TestTruncateDigest(t *testing.T) {
	// The truncateDigest function logic:
	// 1. If len <= 19, return as-is
	// 2. If len > 7 && starts with "sha256:", return first 19 chars + "..."
	// 3. Otherwise if len > 12, return first 12 chars + "..."
	// 4. Otherwise return as-is
	tests := []struct {
		name     string
		digest   string
		expected string
	}{
		{
			name:     "short digest",
			digest:   "sha256:abc",
			expected: "sha256:abc",
		},
		{
			name:     "exactly 19 chars passes through",
			digest:   "sha256:abc123def456",
			expected: "sha256:abc123def456",
		},
		{
			name:     "20 chars gets truncated to 19 with ellipsis",
			digest:   "sha256:abc123def4567",
			expected: "sha256:abc123def456...",
		},
		{
			name:     "long sha256 digest",
			digest:   "sha256:abc123def456ghi789jkl012mno345pqr678stu901vwx234yz567ab890cd",
			expected: "sha256:abc123def456...",
		},
		{
			name:     "non-sha256 prefix short",
			digest:   "short",
			expected: "short",
		},
		{
			name:     "non-sha256 prefix 19 chars passes through",
			digest:   "1234567890123456789",
			expected: "1234567890123456789",
		},
		{
			name:     "non-sha256 prefix 20 chars gets truncated to 12",
			digest:   "12345678901234567890",
			expected: "123456789012...",
		},
		{
			name:     "non-sha256 long truncated to 12 chars",
			digest:   "notsha256abc123def456",
			expected: "notsha256abc...",
		},
		{
			name:     "exactly 12 chars non-sha256",
			digest:   "123456789012",
			expected: "123456789012",
		},
		{
			// 13 chars is <= 19, so returns as-is due to first condition
			name:     "13 chars non-sha256 passes through since <= 19",
			digest:   "1234567890123",
			expected: "1234567890123",
		},
		{
			name:     "empty digest",
			digest:   "",
			expected: "",
		},
		{
			name:     "sha256 prefix exactly 7 chars",
			digest:   "sha256:",
			expected: "sha256:",
		},
		{
			// 18 chars is <= 19, so returns as-is
			name:     "18 chars non-sha256 passes through",
			digest:   "123456789012345678",
			expected: "123456789012345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateDigest(tt.digest)
			if result != tt.expected {
				t.Errorf("truncateDigest(%q) = %q, want %q", tt.digest, result, tt.expected)
			}
		})
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		ref          string
		expectedRepo string
		expectedTag  string
	}{
		{
			ref:          "alpine",
			expectedRepo: "alpine",
			expectedTag:  "latest",
		},
		{
			ref:          "alpine:3.18",
			expectedRepo: "alpine",
			expectedTag:  "3.18",
		},
		{
			ref:          "myrepo/myimage",
			expectedRepo: "myrepo/myimage",
			expectedTag:  "latest",
		},
		{
			ref:          "myrepo/myimage:v1.0",
			expectedRepo: "myrepo/myimage",
			expectedTag:  "v1.0",
		},
		{
			ref:          "registry.example.com/myrepo/myimage:v1.0",
			expectedRepo: "registry.example.com/myrepo/myimage",
			expectedTag:  "v1.0",
		},
		{
			ref:          "localhost:5000/myimage:latest",
			expectedRepo: "localhost:5000/myimage",
			expectedTag:  "latest",
		},
		{
			ref:          "myrepo/myimage@sha256:abc123",
			expectedRepo: "myrepo/myimage",
			expectedTag:  "sha256:abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			repo, tag := parseImageRef(tt.ref)
			if repo != tt.expectedRepo {
				t.Errorf("parseImageRef(%q) repo = %q, want %q", tt.ref, repo, tt.expectedRepo)
			}
			if tag != tt.expectedTag {
				t.Errorf("parseImageRef(%q) tag = %q, want %q", tt.ref, tag, tt.expectedTag)
			}
		})
	}
}

func TestFindLastByte(t *testing.T) {
	tests := []struct {
		s        string
		b        byte
		expected int
	}{
		{"hello:world", ':', 5},
		{"hello:world:test", ':', 11},
		{"hello", ':', -1},
		{"", ':', -1},
		{"abc/def/ghi", '/', 7},
		{"abc", 'a', 0},
		{"abc", 'c', 2},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			result := findLastByte(tt.s, tt.b)
			if result != tt.expected {
				t.Errorf("findLastByte(%q, %q) = %d, want %d", tt.s, string(tt.b), result, tt.expected)
			}
		})
	}
}

func TestImageRefRegex(t *testing.T) {
	// Test that the regex is properly compiled
	if imageRefRegex == nil {
		t.Fatal("imageRefRegex should not be nil")
	}

	// Test some patterns that should match
	validPatterns := []string{
		"alpine",
		"alpine:latest",
		"myrepo/myimage",
		"myrepo/myimage:v1.0",
		"localhost:5000/myimage",
		// OCI distribution-spec separators and the longest tag.
		"my__repo/image:v1",
		"my---repo/image:v1",
		"alpine:" + strings.Repeat("a", 128),
	}

	for _, pattern := range validPatterns {
		if !imageRefRegex.MatchString(pattern) {
			t.Errorf("pattern %q should match imageRefRegex", pattern)
		}
	}

	invalidPatterns := []string{
		"my___repo/image:v1",
		"myrepo-/image:v1",
		"gRPC-1792717075-push-basic:v1",
		"alpine:" + strings.Repeat("a", 129),
		"alpine:.v1",
	}

	for _, pattern := range invalidPatterns {
		if imageRefRegex.MatchString(pattern) {
			t.Errorf("pattern %q should not match imageRefRegex", pattern)
		}
	}
}

func TestValidateImageRef_MaxLength(t *testing.T) {
	// Test with exactly 256 characters (should pass)
	ref256 := make([]byte, 256)
	for i := range ref256 {
		ref256[i] = 'a'
	}
	// This will likely fail due to format, but not due to length.
	// We just want to ensure it doesn't panic.
	validateImageRef(string(ref256))

	// Test with 257 characters (should fail due to length)
	ref257 := make([]byte, 257)
	for i := range ref257 {
		ref257[i] = 'a'
	}
	err := validateImageRef(string(ref257))
	if err == nil {
		t.Error("validateImageRef should fail for reference > 256 characters")
	}

	errRef, ok := err.(ErrInvalidImageReference)
	if !ok {
		t.Errorf("expected ErrInvalidImageReference, got %T", err)
	} else if errRef.Reason != "reference too long" {
		t.Errorf("expected reason 'reference too long', got %q", errRef.Reason)
	}
}

func TestParseImageRef_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		ref          string
		expectedRepo string
		expectedTag  string
	}{
		{
			name:         "registry with port only",
			ref:          "localhost:5000/image",
			expectedRepo: "localhost:5000/image",
			expectedTag:  "latest",
		},
		{
			name:         "multiple colons - port and tag",
			ref:          "localhost:5000/image:v1",
			expectedRepo: "localhost:5000/image",
			expectedTag:  "v1",
		},
		{
			name:         "digest reference with at symbol",
			ref:          "repo@sha256:abc",
			expectedRepo: "repo",
			expectedTag:  "sha256:abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, tag := parseImageRef(tt.ref)
			if repo != tt.expectedRepo {
				t.Errorf("parseImageRef(%q) repo = %q, want %q", tt.ref, repo, tt.expectedRepo)
			}
			if tag != tt.expectedTag {
				t.Errorf("parseImageRef(%q) tag = %q, want %q", tt.ref, tag, tt.expectedTag)
			}
		})
	}
}

func TestFindLastByte_AdditionalCases(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		b        byte
		expected int
	}{
		{
			name:     "single character string match",
			s:        "a",
			b:        'a',
			expected: 0,
		},
		{
			name:     "single character string no match",
			s:        "a",
			b:        'b',
			expected: -1,
		},
		{
			name:     "byte at end",
			s:        "hello/",
			b:        '/',
			expected: 5,
		},
		{
			name:     "byte at start",
			s:        "/hello",
			b:        '/',
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := findLastByte(tt.s, tt.b)
			if result != tt.expected {
				t.Errorf("findLastByte(%q, %q) = %d, want %d", tt.s, string(tt.b), result, tt.expected)
			}
		})
	}
}

func TestFormatBytes_AdditionalCases(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{
			name:     "just under KB",
			bytes:    1023,
			expected: "1023 B",
		},
		{
			name:     "just under MB",
			bytes:    1048575,
			expected: "1024.00 KB",
		},
		{
			name:     "just under GB",
			bytes:    1073741823,
			expected: "1024.00 MB",
		},
		{
			name:     "just under TB",
			bytes:    1099511627775,
			expected: "1024.00 GB",
		},
		{
			name:     "large TB value",
			bytes:    5497558138880,
			expected: "5.00 TB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}
