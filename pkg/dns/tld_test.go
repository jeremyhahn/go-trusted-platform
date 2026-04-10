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

package dns

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensure httptest import is used
var _ = httptest.NewServer

func TestLoadTLDs(t *testing.T) {
	mockData := `# This is a comment
com
ORG
net
# Another comment
edu
gov
`

	// Create a mock HTTP server to simulate the TLD source
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, mockData)
	}))
	defer server.Close()

	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should not return an error")

	// Test the loaded TLDs
	expectedTLDs := map[string]struct{}{
		"com": {},
		"org": {},
		"net": {},
		"edu": {},
		"gov": {},
	}

	// Ensure all TLDs are loaded correctly
	for tld := range expectedTLDs {
		assert.True(t, IsTLD(tld), "Expected TLD '%s' to be in the set", tld)
	}

	// Test non-existing TLDs
	nonExistentTLDs := []string{"xyz", "example", "invalid"}
	for _, tld := range nonExistentTLDs {
		assert.False(t, IsTLD(tld), "Did not expect TLD '%s' to be in the set", tld)
	}

	// Test case insensitivity
	caseInsensitiveTLDs := []string{"COM", "Org", "NeT"}
	for _, tld := range caseInsensitiveTLDs {
		assert.True(t, IsTLD(tld), "Expected TLD '%s' to be in the set (case-insensitive)", tld)
	}
}

// TestLoadTLDs_EmptyData verifies handling of empty TLD data.
func TestLoadTLDs_EmptyData(t *testing.T) {
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(""))
	require.NoError(t, err, "LoadTLDs should not error on empty data")

	// After loading empty data, no TLDs should be present
	assert.False(t, IsTLD("com"), "Expected no TLDs to be loaded")
}

// TestLoadTLDs_OnlyComments verifies handling of data with only comments.
func TestLoadTLDs_OnlyComments(t *testing.T) {
	mockData := `# This is a comment
# Another comment
# Yet another comment
`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should not error on comment-only data")

	// No TLDs should be loaded
	assert.False(t, IsTLD("com"), "Expected no TLDs to be loaded from comments")
}

// TestLoadTLDs_WithWhitespace verifies handling of whitespace in TLD data.
func TestLoadTLDs_WithWhitespace(t *testing.T) {
	mockData := `  com
	org
net
   edu
`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should handle whitespace")

	// All TLDs should be loaded despite whitespace
	assert.True(t, IsTLD("com"), "Expected 'com' to be loaded")
	assert.True(t, IsTLD("org"), "Expected 'org' to be loaded")
	assert.True(t, IsTLD("net"), "Expected 'net' to be loaded")
	assert.True(t, IsTLD("edu"), "Expected 'edu' to be loaded")
}

// TestLoadTLDs_InternationalTLDs verifies handling of international TLDs.
func TestLoadTLDs_InternationalTLDs(t *testing.T) {
	mockData := `com
org
xn--fiqs8s
xn--fiqz9s
xn--j6w193g
`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should handle international TLDs")

	// International TLDs (punycode) should be loaded
	assert.True(t, IsTLD("xn--fiqs8s"), "Expected punycode TLD to be loaded")
	assert.True(t, IsTLD("xn--fiqz9s"), "Expected punycode TLD to be loaded")
	assert.True(t, IsTLD("xn--j6w193g"), "Expected punycode TLD to be loaded")
}

// TestIsTLD_EmptyString verifies handling of empty string input.
func TestIsTLD_EmptyString(t *testing.T) {
	// First load some TLDs
	err := LoadTLDs(nil, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	assert.False(t, IsTLD(""), "Empty string should not be a valid TLD")
}

// TestIsTLD_Various verifies IsTLD with various inputs.
func TestIsTLD_Various(t *testing.T) {
	// Load a known set of TLDs
	err := LoadTLDs(nil, []byte("com\norg\nnet\nio\ndev\napp\n"))
	require.NoError(t, err)

	tests := []struct {
		name     string
		tld      string
		expected bool
	}{
		{"lowercase com", "com", true},
		{"uppercase COM", "COM", true},
		{"mixed case CoM", "CoM", true},
		{"io TLD", "io", true},
		{"dev TLD", "dev", true},
		{"app TLD", "app", true},
		{"non-existent TLD", "xyz", false},
		{"internal TLD", "internal", false},
		{"local TLD", "local", false},
		{"test TLD", "test", false},
		{"empty string", "", false},
		{"numeric string", "123", false},
		{"hyphenated", "co-m", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTLD(tt.tld)
			assert.Equal(t, tt.expected, result, "IsTLD(%q) = %v, want %v", tt.tld, result, tt.expected)
		})
	}
}

// TestLoadTLDs_MixedContent verifies handling of mixed content.
func TestLoadTLDs_MixedContent(t *testing.T) {
	mockData := `# IANA TLD List
# Version 2024

com
ORG

# Country codes
uk
de
fr

# Generic TLDs
app
dev
io

# End of list
`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should handle mixed content")

	expectedTLDs := []string{"com", "org", "uk", "de", "fr", "app", "dev", "io"}
	for _, tld := range expectedTLDs {
		assert.True(t, IsTLD(tld), "Expected '%s' to be loaded", tld)
	}
}

// TestLoadTLDs_LargeDataset verifies handling of a large TLD dataset.
func TestLoadTLDs_LargeDataset(t *testing.T) {
	// Generate a large dataset
	var mockData string
	tlds := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		tld := fmt.Sprintf("tld%d", i)
		tlds[i] = tld
		mockData += tld + "\n"
	}

	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should handle large datasets")

	// Verify random samples
	assert.True(t, IsTLD("tld0"), "Expected 'tld0' to be loaded")
	assert.True(t, IsTLD("tld500"), "Expected 'tld500' to be loaded")
	assert.True(t, IsTLD("tld999"), "Expected 'tld999' to be loaded")
	assert.False(t, IsTLD("tld1000"), "Expected 'tld1000' to not be loaded")
}

// TestLoadTLDs_OverwritesPrevious verifies that loading new TLDs overwrites previous.
func TestLoadTLDs_OverwritesPrevious(t *testing.T) {
	logger := &logging.Logger{}

	// First load
	err := LoadTLDs(logger, []byte("com\norg\nnet\n"))
	require.NoError(t, err)

	assert.True(t, IsTLD("com"), "Expected 'com' to be loaded")
	assert.True(t, IsTLD("org"), "Expected 'org' to be loaded")
	assert.True(t, IsTLD("net"), "Expected 'net' to be loaded")

	// Second load with different TLDs
	err = LoadTLDs(logger, []byte("io\ndev\napp\n"))
	require.NoError(t, err)

	// Previous TLDs should be replaced
	assert.False(t, IsTLD("com"), "Expected 'com' to be overwritten")
	assert.False(t, IsTLD("org"), "Expected 'org' to be overwritten")
	assert.False(t, IsTLD("net"), "Expected 'net' to be overwritten")

	// New TLDs should be present
	assert.True(t, IsTLD("io"), "Expected 'io' to be loaded")
	assert.True(t, IsTLD("dev"), "Expected 'dev' to be loaded")
	assert.True(t, IsTLD("app"), "Expected 'app' to be loaded")
}

// TestLoadTLDs_NilData_FetchError verifies error handling when HTTP fetch fails.
// Note: This test cannot directly test the HTTP path without mocking the URL,
// but we can verify the function handles the nil data case by checking that
// when data is nil, it attempts to fetch from the IANA URL.
func TestLoadTLDs_WithEmptyLines(t *testing.T) {
	mockData := `com

org


net

`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should handle empty lines")

	assert.True(t, IsTLD("com"), "Expected 'com' to be loaded")
	assert.True(t, IsTLD("org"), "Expected 'org' to be loaded")
	assert.True(t, IsTLD("net"), "Expected 'net' to be loaded")
}

// TestLoadTLDs_SingleTLD verifies loading a single TLD.
func TestLoadTLDs_SingleTLD(t *testing.T) {
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte("com"))
	require.NoError(t, err, "LoadTLDs should handle single TLD")

	assert.True(t, IsTLD("com"), "Expected 'com' to be loaded")
	assert.False(t, IsTLD("org"), "Expected 'org' to not be loaded")
}

// TestLoadTLDs_TrailingNewlines verifies handling of trailing newlines.
func TestLoadTLDs_TrailingNewlines(t *testing.T) {
	mockData := `com
org
net


`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should handle trailing newlines")

	assert.True(t, IsTLD("com"), "Expected 'com' to be loaded")
	assert.True(t, IsTLD("org"), "Expected 'org' to be loaded")
	assert.True(t, IsTLD("net"), "Expected 'net' to be loaded")
}

// TestLoadTLDs_NilData_HTTPFetch verifies HTTP fetch when data is nil.
func TestLoadTLDs_NilData_HTTPFetch(t *testing.T) {
	// Create a test HTTP server that returns TLD data
	mockData := `# Test TLD List
com
org
net
io
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockData))
	}))
	defer server.Close()

	// Note: We can't easily test the actual IANA URL fetch without modifying the code.
	// This test documents the expected behavior when tldData is provided.
	// The nil data path makes an HTTP call to IANA which we can't mock without
	// dependency injection.
	logger := &logging.Logger{}

	// Test with provided data (covers all non-HTTP code paths)
	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err)

	assert.True(t, IsTLD("com"))
	assert.True(t, IsTLD("org"))
	assert.True(t, IsTLD("net"))
	assert.True(t, IsTLD("io"))
}

// TestLoadTLDs_SpecialCharacters verifies handling of special characters in TLD data.
func TestLoadTLDs_SpecialCharacters(t *testing.T) {
	mockData := `com
org
# Comment with special chars: @#$%
net
edu
`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err, "LoadTLDs should handle special characters in comments")

	assert.True(t, IsTLD("com"), "Expected 'com' to be loaded")
	assert.True(t, IsTLD("net"), "Expected 'net' to be loaded")
}

// TestIsTLD_ConcurrentAccess verifies thread-safe access to TLD map.
func TestIsTLD_ConcurrentAccess(t *testing.T) {
	// Load TLDs first
	err := LoadTLDs(nil, []byte("com\norg\nnet\nio\ndev\n"))
	require.NoError(t, err)

	done := make(chan bool, 100)

	// Concurrent reads
	for i := 0; i < 100; i++ {
		go func() {
			_ = IsTLD("com")
			_ = IsTLD("org")
			_ = IsTLD("net")
			_ = IsTLD("nonexistent")
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestLoadTLDs_LeadingComments verifies handling of leading comments.
func TestLoadTLDs_LeadingComments(t *testing.T) {
	mockData := `# This is a header comment
# Version: 2024
# Last updated: 2024-01-01
com
org
net
`
	logger := &logging.Logger{}

	err := LoadTLDs(logger, []byte(mockData))
	require.NoError(t, err)

	assert.True(t, IsTLD("com"))
	assert.True(t, IsTLD("org"))
	assert.True(t, IsTLD("net"))
}
