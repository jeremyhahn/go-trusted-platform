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
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Performs a logical UDP connection to an endpoint
// that does not need to exist and returns the local
// IP address that was used to perform the connection.
// Returns nil if network is unavailable (e.g., in initramfs before network init).
func PreferredIPv4() net.IP {
	conn, err := net.Dial("udp", "1.2.3.4:80")
	if err != nil {
		// Network unavailable - this is normal in initramfs
		// Return nil instead of crashing the process
		return nil
	}
	defer func() { _ = conn.Close() }()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// Performs a logical UDP connection to an endpoint
// that does not need to exist and returns the local
// IP address that was used to perform the connection.
// Returns nil if network is unavailable (e.g., in initramfs before network init).
func PreferredIPv6() net.IP {
	conn, err := net.Dial("udp", "[::1]:80")
	if err != nil {
		// Network unavailable - this is normal in initramfs
		// Return nil instead of crashing the process
		return nil
	}
	defer func() { _ = conn.Close() }()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// Parses a list of usable local IP addresses
func LocalAddresses() ([]string, error) {
	ips := make([]string, 0)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			ips = append(ips, ipNet.IP.String())
		}
	}
	return ips, nil
}

// Returns true if the provided IP falls within a private address range
func IsPrivateSubnet(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// Returns the Fully Qualified Domain Name for a given URL
func ParseFQDN(anyURL string) (string, error) {
	parsedURL, err := url.Parse(anyURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	host := parsedURL.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0] // Remove port if present
	}
	return host, nil
}

// ExtractBaseURL extracts the base URL (scheme + host) from a full URL.
// For example, "https://server.example.com:8443/acme/directory" returns
// "https://server.example.com:8443".
func ExtractBaseURL(fullURL string) (string, error) {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return "", fmt.Errorf("URL missing scheme or host: %s", fullURL)
	}
	return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host), nil
}
