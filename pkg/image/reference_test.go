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

package image

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseReference(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  *ImageReference
		expectErr bool
	}{
		{
			name:  "full reference with registry and tag",
			input: "gcr.io/my-project/my-image:v1.0.0",
			expected: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-project/my-image",
				Tag:        "v1.0.0",
			},
		},
		{
			name:  "full reference with registry and digest",
			input: "gcr.io/my-project/my-image@sha256:abc123def456",
			expected: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-project/my-image",
				Digest:     "sha256:abc123def456",
			},
		},
		{
			name:  "docker hub with organization",
			input: "myorg/myimage:latest",
			expected: &ImageReference{
				Registry:   "docker.io",
				Repository: "myorg/myimage",
				Tag:        "latest",
			},
		},
		{
			name:  "docker hub official image",
			input: "nginx:1.21",
			expected: &ImageReference{
				Registry:   "docker.io",
				Repository: "library/nginx",
				Tag:        "1.21",
			},
		},
		{
			name:  "docker hub official image no tag",
			input: "nginx",
			expected: &ImageReference{
				Registry:   "docker.io",
				Repository: "library/nginx",
				Tag:        "latest",
			},
		},
		{
			name:  "localhost registry",
			input: "localhost:5000/myimage:test",
			expected: &ImageReference{
				Registry:   "localhost:5000",
				Repository: "myimage",
				Tag:        "test",
			},
		},
		{
			name:  "registry with port",
			input: "registry.example.com:5000/path/to/image:v2",
			expected: &ImageReference{
				Registry:   "registry.example.com:5000",
				Repository: "path/to/image",
				Tag:        "v2",
			},
		},
		{
			name:  "complex digest",
			input: "myregistry.io/myimage@sha512:abcdef123456789",
			expected: &ImageReference{
				Registry:   "myregistry.io",
				Repository: "myimage",
				Digest:     "sha512:abcdef123456789",
			},
		},
		{
			name:      "empty reference",
			input:     "",
			expectErr: true,
		},
		{
			name:      "whitespace only",
			input:     "   ",
			expectErr: true,
		},
		{
			name:      "invalid digest format",
			input:     "nginx@invalid",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseReference(tt.input)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected.Registry, result.Registry)
			assert.Equal(t, tt.expected.Repository, result.Repository)
			assert.Equal(t, tt.expected.Tag, result.Tag)
			assert.Equal(t, tt.expected.Digest, result.Digest)
		})
	}
}

func TestImageReference_String(t *testing.T) {
	tests := []struct {
		name     string
		ref      *ImageReference
		expected string
	}{
		{
			name: "with registry and tag",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-project/my-image",
				Tag:        "v1.0.0",
			},
			expected: "gcr.io/my-project/my-image:v1.0.0",
		},
		{
			name: "with registry and digest",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-project/my-image",
				Digest:     "sha256:abc123",
			},
			expected: "gcr.io/my-project/my-image@sha256:abc123",
		},
		{
			name: "with both tag and digest (digest preferred)",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-image",
				Tag:        "v1.0.0",
				Digest:     "sha256:abc123",
			},
			expected: "gcr.io/my-image@sha256:abc123",
		},
		{
			name: "no registry",
			ref: &ImageReference{
				Repository: "myimage",
				Tag:        "latest",
			},
			expected: "myimage:latest",
		},
		{
			name: "no tag or digest",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "myimage",
			},
			expected: "gcr.io/myimage",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ref.String())
		})
	}
}

func TestImageReference_DigestString(t *testing.T) {
	tests := []struct {
		name     string
		ref      *ImageReference
		expected string
	}{
		{
			name: "with digest",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-image",
				Digest:     "sha256:abc123",
			},
			expected: "gcr.io/my-image@sha256:abc123",
		},
		{
			name: "without digest",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-image",
				Tag:        "v1.0.0",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ref.DigestString())
		})
	}
}

func TestImageReference_TagString(t *testing.T) {
	tests := []struct {
		name     string
		ref      *ImageReference
		expected string
	}{
		{
			name: "with tag",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-image",
				Tag:        "v1.0.0",
			},
			expected: "gcr.io/my-image:v1.0.0",
		},
		{
			name: "without tag",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-image",
				Digest:     "sha256:abc123",
			},
			expected: "gcr.io/my-image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ref.TagString())
		})
	}
}

func TestImageReference_WithDigest(t *testing.T) {
	ref := &ImageReference{
		Registry:   "gcr.io",
		Repository: "my-image",
		Tag:        "v1.0.0",
	}

	newRef, err := ref.WithDigest("sha256:abc123def456")
	require.NoError(t, err)

	assert.Equal(t, "gcr.io", newRef.Registry)
	assert.Equal(t, "my-image", newRef.Repository)
	assert.Equal(t, "", newRef.Tag)
	assert.Equal(t, "sha256:abc123def456", newRef.Digest)

	// Original should be unchanged
	assert.Equal(t, "v1.0.0", ref.Tag)
}

func TestImageReference_WithDigest_Invalid(t *testing.T) {
	ref := &ImageReference{
		Registry:   "gcr.io",
		Repository: "my-image",
		Tag:        "v1.0.0",
	}

	_, err := ref.WithDigest("invalid")
	assert.Error(t, err)
}

func TestImageReference_WithTag(t *testing.T) {
	ref := &ImageReference{
		Registry:   "gcr.io",
		Repository: "my-image",
		Digest:     "sha256:abc123",
	}

	newRef, err := ref.WithTag("v2.0.0")
	require.NoError(t, err)

	assert.Equal(t, "gcr.io", newRef.Registry)
	assert.Equal(t, "my-image", newRef.Repository)
	assert.Equal(t, "v2.0.0", newRef.Tag)
	assert.Equal(t, "", newRef.Digest)

	// Original should be unchanged
	assert.Equal(t, "sha256:abc123", ref.Digest)
}

func TestImageReference_WithTag_Invalid(t *testing.T) {
	ref := &ImageReference{
		Registry:   "gcr.io",
		Repository: "my-image",
	}

	// Tags cannot start with hyphen
	_, err := ref.WithTag("-invalid")
	assert.Error(t, err)
}

func TestImageReference_SignatureTag(t *testing.T) {
	tests := []struct {
		name     string
		ref      *ImageReference
		expected string
	}{
		{
			name: "with sha256 digest",
			ref: &ImageReference{
				Repository: "my-image",
				Digest:     "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			expected: "sha256-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.sig",
		},
		{
			name: "with sha384 digest",
			ref: &ImageReference{
				Repository: "my-image",
				Digest:     "sha384:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678",
			},
			expected: "sha256-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.sig",
		},
		{
			name: "with sha512 digest",
			ref: &ImageReference{
				Repository: "my-image",
				Digest:     "sha512:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			expected: "sha256-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.sig",
		},
		{
			name: "with long digest truncation",
			ref: &ImageReference{
				Repository: "my-image",
				Digest:     "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			},
			expected: "sha256-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890.sig",
		},
		{
			name: "with tag",
			ref: &ImageReference{
				Repository: "my-image",
				Tag:        "v1.0.0",
			},
			expected: "v1.0.0.sig",
		},
		{
			name: "no tag or digest",
			ref: &ImageReference{
				Repository: "my-image",
			},
			expected: "latest.sig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ref.SignatureTag())
		})
	}
}

func TestImageReference_Validate(t *testing.T) {
	tests := []struct {
		name      string
		ref       *ImageReference
		expectErr bool
	}{
		{
			name: "valid with tag",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-image",
				Tag:        "v1.0.0",
			},
			expectErr: false,
		},
		{
			name: "valid with digest",
			ref: &ImageReference{
				Registry:   "gcr.io",
				Repository: "my-image",
				Digest:     "sha256:abc123",
			},
			expectErr: false,
		},
		{
			name: "empty repository",
			ref: &ImageReference{
				Registry: "gcr.io",
				Tag:      "v1.0.0",
			},
			expectErr: true,
		},
		{
			name: "invalid digest",
			ref: &ImageReference{
				Repository: "my-image",
				Digest:     "invalid",
			},
			expectErr: true,
		},
		{
			name: "invalid tag",
			ref: &ImageReference{
				Repository: "my-image",
				Tag:        "-invalid",
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ref.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestImageReference_Equal(t *testing.T) {
	ref1 := &ImageReference{
		Registry:   "gcr.io",
		Repository: "my-image",
		Tag:        "v1.0.0",
	}

	ref2 := &ImageReference{
		Registry:   "gcr.io",
		Repository: "my-image",
		Tag:        "v1.0.0",
	}

	ref3 := &ImageReference{
		Registry:   "gcr.io",
		Repository: "my-image",
		Tag:        "v2.0.0",
	}

	assert.True(t, ref1.Equal(ref2))
	assert.False(t, ref1.Equal(ref3))
	assert.False(t, ref1.Equal(nil))
}

func TestIsValidDigest(t *testing.T) {
	tests := []struct {
		digest   string
		expected bool
	}{
		{"sha256:abc123def456", true},
		{"sha512:abc123def456789", true},
		{"sha256+b64u:abc123", true},
		{"invalid", false},
		{"sha256:", false},
		{":abc123", false},
		{"", false},
		{"sha256:ABC123", false}, // uppercase not allowed
	}

	for _, tt := range tests {
		t.Run(tt.digest, func(t *testing.T) {
			assert.Equal(t, tt.expected, isValidDigest(tt.digest))
		})
	}
}

func TestIsValidTag(t *testing.T) {
	tests := []struct {
		tag      string
		expected bool
	}{
		{"latest", true},
		{"v1.0.0", true},
		{"v1.0.0-alpha.1", true},
		{"1.0", true},
		{"_private", true},
		{"-invalid", false},
		{".invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			assert.Equal(t, tt.expected, isValidTag(tt.tag))
		})
	}
}

func TestIsValidTag_TooLong(t *testing.T) {
	// Tags can be at most 128 characters
	longTag := strings.Repeat("a", 129)
	assert.False(t, isValidTag(longTag))

	validLongTag := strings.Repeat("a", 128)
	assert.True(t, isValidTag(validLongTag))
}

func TestNormalizeReference(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"nginx", "docker.io/library/nginx:latest"},
		{"myorg/myimage:v1", "docker.io/myorg/myimage:v1"},
		{"gcr.io/project/image:tag", "gcr.io/project/image:tag"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := NormalizeReference(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeReference_Invalid(t *testing.T) {
	_, err := NormalizeReference("")
	assert.Error(t, err)
}

func TestExtractDigestAlgorithm(t *testing.T) {
	tests := []struct {
		digest   string
		expected DigestAlgorithm
	}{
		{"sha256:abc123", DigestSHA256},
		{"sha384:abc123", DigestSHA384},
		{"sha512:abc123", DigestSHA512},
		{"unknown:abc123", ""},
		{"noprefix", ""},
	}

	for _, tt := range tests {
		t.Run(tt.digest, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractDigestAlgorithm(tt.digest))
		})
	}
}

func TestExtractDigestHex(t *testing.T) {
	tests := []struct {
		digest   string
		expected string
	}{
		{"sha256:abc123", "abc123"},
		{"sha512:def456", "def456"},
		{"noprefix", "noprefix"},
	}

	for _, tt := range tests {
		t.Run(tt.digest, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractDigestHex(tt.digest))
		})
	}
}

func TestIsRegistry(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"gcr.io", true},
		{"registry.example.com", true},
		{"localhost:5000", true},
		{"localhost", true},
		{"myorg", false},
		{"nginx", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, isRegistry(tt.input))
		})
	}
}

func TestParseReference_Roundtrip(t *testing.T) {
	refs := []string{
		"gcr.io/project/image:v1.0.0",
		"docker.io/library/nginx:latest",
		"myregistry.io/path/to/image@sha256:abcdef123456",
		"localhost:5000/test:dev",
	}

	for _, ref := range refs {
		t.Run(ref, func(t *testing.T) {
			parsed, err := ParseReference(ref)
			require.NoError(t, err)

			// String() should produce parseable output
			reparsed, err := ParseReference(parsed.String())
			require.NoError(t, err)

			assert.True(t, parsed.Equal(reparsed))
		})
	}
}
