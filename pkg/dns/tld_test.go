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
