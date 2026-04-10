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

package webservice

import (
	"os"
	"regexp"
	"strings"
)

func sanitizeHost(host string) string {
	sanitized := strings.ToLower(host)
	sanitized = strings.TrimSpace(sanitized)
	if strings.Contains(sanitized, ":") {
		sanitized = strings.Split(sanitized, ":")[0]
	}
	if !isValidHostname(sanitized) {
		return ""
	}
	return sanitized
}

func isValidHostname(hostname string) bool {
	validHostnamePattern := `^[a-z0-9-]+(\.[a-z0-9-]+)*$`
	matched, _ := regexp.MatchString(validHostnamePattern, hostname)
	return matched
}

func isFileAccessible(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
