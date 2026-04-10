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

package bootstrap

import (
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// secretInfo holds information about a discovered secret in configuration
type secretInfo struct {
	path string
	uri  string
	line int
}

// scanConfigForSecrets scans YAML configuration data for secret URIs
func scanConfigForSecrets(data []byte) []secretInfo {
	var secrets []secretInfo

	// Patterns for detecting secret URIs
	uriPatterns := []string{
		bootstrap.SchemeKMS,
		bootstrap.SchemeRemoteKMS,
		bootstrap.SchemeEnv,
		bootstrap.SchemeAutoGen,
		bootstrap.SchemeEncrypted,
	}

	// Build regex to match URIs in YAML values
	// Matches: key: "uri://..." or key: uri://...
	for _, scheme := range uriPatterns {
		// Escape special regex characters in scheme
		escapedScheme := regexp.QuoteMeta(scheme)
		// Pattern matches: key: "scheme://path" or key: scheme://path
		pattern := regexp.MustCompile(`(?m)^(\s*)([a-zA-Z0-9_-]+):\s*["']?(` + escapedScheme + `[^"'\s\n]+)["']?`)

		matches := pattern.FindAllSubmatch(data, -1)
		for _, match := range matches {
			if len(match) >= 4 {
				path := string(match[2])
				uri := string(match[3])
				secrets = append(secrets, secretInfo{
					path: path,
					uri:  uri,
				})
			}
		}
	}

	// Also scan for nested paths using more sophisticated YAML parsing
	secrets = append(secrets, scanNestedSecrets(data)...)

	// Deduplicate
	seen := make(map[string]bool)
	var unique []secretInfo
	for _, s := range secrets {
		key := s.path + ":" + s.uri
		if !seen[key] {
			seen[key] = true
			unique = append(unique, s)
		}
	}

	return unique
}

// scanNestedSecrets performs a more thorough scan for nested secret URIs
func scanNestedSecrets(data []byte) []secretInfo {
	var secrets []secretInfo

	lines := strings.Split(string(data), "\n")
	var pathStack []string
	var indentStack []int

	for lineNum, line := range lines {
		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Calculate indentation
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Pop path stack for decreased indentation
		for len(indentStack) > 0 && indent <= indentStack[len(indentStack)-1] {
			pathStack = pathStack[:len(pathStack)-1]
			indentStack = indentStack[:len(indentStack)-1]
		}

		// Parse key-value pairs
		if strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				// Remove quotes from value
				value = strings.Trim(value, `"'`)

				// Check if value is a secret URI
				if isSecretURI(value) {
					fullPath := buildPath(pathStack, key)
					secrets = append(secrets, secretInfo{
						path: fullPath,
						uri:  value,
						line: lineNum + 1,
					})
				}

				// If value is empty, this might be a parent key
				if value == "" || strings.HasPrefix(value, "|") || strings.HasPrefix(value, ">") {
					pathStack = append(pathStack, key)
					indentStack = append(indentStack, indent)
				}
			}
		}
	}

	return secrets
}

// buildPath constructs a dot-notation path from the path stack and current key
func buildPath(stack []string, key string) string {
	if len(stack) == 0 {
		return key
	}
	return strings.Join(stack, ".") + "." + key
}

// isSecretURI checks if a string is a secret URI
func isSecretURI(s string) bool {
	return strings.HasPrefix(s, bootstrap.SchemeKMS) ||
		strings.HasPrefix(s, bootstrap.SchemeRemoteKMS) ||
		strings.HasPrefix(s, bootstrap.SchemeEnv) ||
		strings.HasPrefix(s, bootstrap.SchemeAutoGen) ||
		strings.HasPrefix(s, bootstrap.SchemeEncrypted)
}

// maskSecretURI masks sensitive parts of a secret URI for display
func maskSecretURI(uri string) string {
	schemes := []string{
		bootstrap.SchemeKMS,
		bootstrap.SchemeRemoteKMS,
		bootstrap.SchemeEnv,
		bootstrap.SchemeAutoGen,
		bootstrap.SchemeEncrypted,
	}

	for _, scheme := range schemes {
		if strings.HasPrefix(uri, scheme) {
			// Keep the scheme and first path segment visible
			path := strings.TrimPrefix(uri, scheme)
			parts := strings.SplitN(path, "/", 3)
			if len(parts) >= 2 {
				return scheme + parts[0] + "/" + parts[1] + "/***"
			}
			return scheme + "***"
		}
	}

	return "***"
}

// buildKMSURI constructs a KMS URI from a config path
func buildKMSURI(configPath string) string {
	return bootstrap.SchemeKMS + buildKMSPath(configPath)
}

// buildKMSPath constructs a KMS storage path from a config path
func buildKMSPath(configPath string) string {
	// Convert dot notation to path notation
	// e.g., "database.password" -> "config/database/password"
	pathPart := strings.ReplaceAll(configPath, ".", "/")
	pathPart = strings.ReplaceAll(pathPart, "[", "/")
	pathPart = strings.ReplaceAll(pathPart, "]", "")
	return "config/" + pathPart
}

// resolveSecretValue resolves a secret URI using the appropriate resolver
// NOTE: KMS secrets resolution is not yet implemented in the platform
func resolveSecretValue(ctx context.Context, client platform.Client, uri string) ([]byte, error) {
	scheme := detectScheme(uri)

	switch scheme {
	case "kms":
		// KMS secrets service is not yet implemented in the platform
		return nil, ErrSecretsNotImplemented{}

	case "env":
		// Resolve environment variable
		varName := strings.TrimPrefix(uri, bootstrap.SchemeEnv)
		value := os.Getenv(varName)
		if value == "" {
			return nil, bootstrap.ErrEnvVarNotFound{Name: varName}
		}
		return []byte(value), nil

	case "autogen":
		// Auto-generate secret based on spec
		// For CLI verification, we return a placeholder since actual generation
		// should only happen during bootstrap
		return []byte("(auto-generated)"), nil

	case "remote-kms":
		// Remote KMS resolution requires additional configuration
		// This would typically use a remote KMS client
		return nil, ErrResolverNotAvailable{Scheme: scheme}

	case "encrypted":
		// Encrypted secrets require decryption key
		return nil, ErrResolverNotAvailable{Scheme: scheme}

	default:
		return nil, ErrInvalidSecretURI{URI: uri, Reason: "unknown scheme"}
	}
}

// joinMACs renders a slice of MAC addresses for table output. Empty / nil
// slices return the empty string. Multi-MAC nodes are shown as a
// comma-separated list which the table column widths accommodate. Used by
// discover/run/status commands so the renderers don't have to know about the
// internal slice shape.
func joinMACs(macs []string) string {
	if len(macs) == 0 {
		return ""
	}
	if len(macs) == 1 {
		return macs[0]
	}
	return strings.Join(macs, ",")
}

// createLogger creates a logger for bootstrap operations
func createLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	return slog.New(slog.NewTextHandler(io.Discard, opts))
}
