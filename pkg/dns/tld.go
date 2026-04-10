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
	for tld := range tldSet {
		ianaTLDs[tld] = true
	}

	return nil
}

// IsTLD checks if a given TLD exists in the map (case-insensitively).
func IsTLD(tld string) bool {
	_, exists := ianaTLDs[strings.ToLower(tld)]
	return exists
}
