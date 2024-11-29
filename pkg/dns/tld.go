package dns

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

var (
	ianaTLDs map[string]bool
)

// Loads and processes the provided tldData as a plain text file
// with each TLD on it's own line. If the tldData is not provided,
// the TLD list from data.iana.org will be used as a default.
func LoadTLDs(logger *logging.Logger, tldData []byte) error {

	if tldData == nil {

		url := "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed to fetch TLD list: %w", err)
		}
		defer resp.Body.Close()

		tldData, err = io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read TLD list: %w", err)
		}

	}

	tldSet := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(tldData)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		// Store TLDs in lowercase
		tldSet[strings.ToLower(line)] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading TLD list: %w", err)
	}

	// Create a memory packed map without any extra space from
	// dynamic resizing to cache for the life of the process
	ianaTLDs = make(map[string]bool, len(tldSet))
	for tld, _ := range tldSet {
		ianaTLDs[tld] = true
	}

	return nil
}

// IsTLD checks if a given TLD exists in the map (case-insensitively).
func IsTLD(tld string) bool {
	_, exists := ianaTLDs[strings.ToLower(tld)]
	return exists
}
