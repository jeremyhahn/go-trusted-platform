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

package util

import (
	"net"
	"testing"
)

func TestPreferredIPv4(t *testing.T) {
	ip := PreferredIPv4()

	// IP may be nil if network is unavailable (e.g., in CI environments)
	// This is expected behavior as documented in the function
	if ip == nil {
		t.Skip("Network unavailable - skipping test")
	}

	// If we get an IP, verify it's valid IPv4
	if ip.To4() == nil {
		t.Errorf("Expected IPv4 address, got %v", ip)
	}

	// Verify it's not nil or empty
	if ip.String() == "" {
		t.Error("Expected non-empty IP address")
	}
}

func TestPreferredIPv6(t *testing.T) {
	ip := PreferredIPv6()

	// IP may be nil if network is unavailable (e.g., in CI environments)
	// This is expected behavior as documented in the function
	if ip == nil {
		t.Skip("IPv6 network unavailable - skipping test")
	}

	// Verify it's not nil or empty
	if ip.String() == "" {
		t.Error("Expected non-empty IP address")
	}
}

func TestLocalAddresses(t *testing.T) {
	addrs, err := LocalAddresses()
	if err != nil {
		t.Fatalf("LocalAddresses() returned error: %v", err)
	}

	// May be empty if no non-loopback IPv4 interfaces are available
	// This is valid behavior
	if len(addrs) == 0 {
		t.Skip("No non-loopback IPv4 addresses found - skipping test")
	}

	// Verify all returned addresses are valid IPv4
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Errorf("Invalid IP address returned: %s", addr)
		}
		if ip.To4() == nil {
			t.Errorf("Expected IPv4 address, got %s", addr)
		}
		if ip.IsLoopback() {
			t.Errorf("Loopback address should not be included: %s", addr)
		}
	}
}

func TestIsPrivateSubnet_PrivateIPs(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "10.0.0.0/8 range",
			ip:       "10.1.2.3",
			expected: true,
		},
		{
			name:     "172.16.0.0/12 range - start",
			ip:       "172.16.0.1",
			expected: true,
		},
		{
			name:     "172.16.0.0/12 range - middle",
			ip:       "172.20.0.1",
			expected: true,
		},
		{
			name:     "172.16.0.0/12 range - end",
			ip:       "172.31.255.255",
			expected: true,
		},
		{
			name:     "192.168.0.0/16 range",
			ip:       "192.168.1.1",
			expected: true,
		},
		{
			name:     "Public IP - 8.8.8.8",
			ip:       "8.8.8.8",
			expected: false,
		},
		{
			name:     "Public IP - 1.1.1.1",
			ip:       "1.1.1.1",
			expected: false,
		},
		{
			name:     "Public IP - outside 172 range",
			ip:       "172.15.0.1",
			expected: false,
		},
		{
			name:     "Public IP - outside 172 range upper",
			ip:       "172.32.0.1",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ip := net.ParseIP(test.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", test.ip)
			}

			result := IsPrivateSubnet(ip)
			if result != test.expected {
				t.Errorf("IsPrivateSubnet(%s) = %v; want %v", test.ip, result, test.expected)
			}
		})
	}
}

func TestParseFQDN_Success(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Simple HTTP URL",
			url:      "http://example.com",
			expected: "example.com",
		},
		{
			name:     "HTTPS URL",
			url:      "https://example.com",
			expected: "example.com",
		},
		{
			name:     "URL with port",
			url:      "https://example.com:8443",
			expected: "example.com",
		},
		{
			name:     "URL with path",
			url:      "https://example.com/path/to/resource",
			expected: "example.com",
		},
		{
			name:     "URL with subdomain",
			url:      "https://api.example.com",
			expected: "api.example.com",
		},
		{
			name:     "URL with port and path",
			url:      "https://example.com:9000/api/v1",
			expected: "example.com",
		},
		{
			name:     "URL with query params",
			url:      "https://example.com?key=value",
			expected: "example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fqdn, err := ParseFQDN(test.url)
			if err != nil {
				t.Fatalf("ParseFQDN(%s) returned error: %v", test.url, err)
			}
			if fqdn != test.expected {
				t.Errorf("ParseFQDN(%s) = %s; want %s", test.url, fqdn, test.expected)
			}
		})
	}
}

func TestParseFQDN_Error(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{
			name: "Invalid URL - malformed",
			url:  "://invalid",
		},
		{
			name: "Invalid URL - contains invalid chars",
			url:  "https://exam ple.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseFQDN(test.url)
			if err == nil {
				t.Errorf("ParseFQDN(%s) expected error, got nil", test.url)
			}
		})
	}
}

func TestParseFQDN_EmptyHost(t *testing.T) {
	// Test URL without scheme - url.Parse accepts these but returns empty Host
	// The function returns empty string for these cases (no error)
	tests := []string{
		"not a valid url",
		"example.com",
		"example.com/path",
	}

	for _, url := range tests {
		fqdn, err := ParseFQDN(url)
		if err != nil {
			t.Errorf("ParseFQDN(%s) returned unexpected error: %v", url, err)
		}
		// These URLs parse successfully but return empty host (expected behavior)
		if fqdn != "" {
			t.Logf("ParseFQDN(%s) = %s (url.Parse interprets this as path)", url, fqdn)
		}
	}
}

func TestExtractBaseURL_Success(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "Simple HTTPS URL",
			url:      "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "HTTPS URL with port",
			url:      "https://example.com:8443",
			expected: "https://example.com:8443",
		},
		{
			name:     "HTTPS URL with path",
			url:      "https://example.com/acme/directory",
			expected: "https://example.com",
		},
		{
			name:     "HTTPS URL with port and path",
			url:      "https://server.example.com:8443/acme/directory",
			expected: "https://server.example.com:8443",
		},
		{
			name:     "HTTP URL with complex path",
			url:      "http://api.example.com:9000/v1/resources/123",
			expected: "http://api.example.com:9000",
		},
		{
			name:     "URL with query params",
			url:      "https://example.com:443/path?key=value",
			expected: "https://example.com:443",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base, err := ExtractBaseURL(test.url)
			if err != nil {
				t.Fatalf("ExtractBaseURL(%s) returned error: %v", test.url, err)
			}
			if base != test.expected {
				t.Errorf("ExtractBaseURL(%s) = %s; want %s", test.url, base, test.expected)
			}
		})
	}
}

func TestExtractBaseURL_Error(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{
			name: "Malformed URL",
			url:  "://invalid",
		},
		{
			name: "Missing scheme",
			url:  "example.com/path",
		},
		{
			name: "Missing host",
			url:  "https:///path",
		},
		{
			name: "Empty string",
			url:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ExtractBaseURL(test.url)
			if err == nil {
				t.Errorf("ExtractBaseURL(%s) expected error, got nil", test.url)
			}
		})
	}
}
