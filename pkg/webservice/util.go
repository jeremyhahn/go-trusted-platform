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
