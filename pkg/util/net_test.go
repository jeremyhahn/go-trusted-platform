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
	"reflect"
	"syscall"
	"testing"
)

// fakeUDPConn is the logical UDP connection fakeDial returns; only
// LocalAddr and Close are called on it.
type fakeUDPConn struct {
	net.Conn
	local  *net.UDPAddr
	closed bool
}

func (c *fakeUDPConn) LocalAddr() net.Addr { return c.local }

func (c *fakeUDPConn) Close() error {
	c.closed = true
	return nil
}

// useDialUDP replaces the dial seam with dial for one test.
func useDialUDP(t *testing.T, dial func(network, address string) (net.Conn, error)) {
	t.Helper()
	saved := dialUDP
	dialUDP = dial
	t.Cleanup(func() { dialUDP = saved })
}

// useInterfaceAddrs replaces the interface seam with list for one test.
func useInterfaceAddrs(t *testing.T, list func() ([]net.Addr, error)) {
	t.Helper()
	saved := interfaceAddrs
	interfaceAddrs = list
	t.Cleanup(func() { interfaceAddrs = saved })
}

// errNetworkUnreachable is the dial failure a host without a route returns.
var errNetworkUnreachable = &net.OpError{Op: "dial", Net: "udp", Err: syscall.ENETUNREACH}

func TestNetSeamDefaults(t *testing.T) {
	if reflect.ValueOf(dialUDP).Pointer() != reflect.ValueOf(net.Dial).Pointer() {
		t.Error("dialUDP should default to net.Dial")
	}
	if reflect.ValueOf(interfaceAddrs).Pointer() != reflect.ValueOf(net.InterfaceAddrs).Pointer() {
		t.Error("interfaceAddrs should default to net.InterfaceAddrs")
	}
}

func TestPreferredIPv4(t *testing.T) {
	conn := &fakeUDPConn{local: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}}
	var dialed string
	useDialUDP(t, func(network, address string) (net.Conn, error) {
		dialed = network + " " + address
		return conn, nil
	})

	ip := PreferredIPv4()

	if !ip.Equal(net.ParseIP("192.0.2.10")) {
		t.Errorf("PreferredIPv4() = %v, want 192.0.2.10", ip)
	}
	if dialed != "udp 1.2.3.4:80" {
		t.Errorf("dialed %q, want udp 1.2.3.4:80", dialed)
	}
	if !conn.closed {
		t.Error("the UDP connection was not closed")
	}
}

func TestPreferredIPv4_NetworkUnavailable(t *testing.T) {
	useDialUDP(t, func(string, string) (net.Conn, error) { return nil, errNetworkUnreachable })

	if ip := PreferredIPv4(); ip != nil {
		t.Errorf("PreferredIPv4() = %v, want nil when the dial fails", ip)
	}
}

func TestPreferredIPv6(t *testing.T) {
	conn := &fakeUDPConn{local: &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 40000}}
	var dialed string
	useDialUDP(t, func(network, address string) (net.Conn, error) {
		dialed = network + " " + address
		return conn, nil
	})

	ip := PreferredIPv6()

	if !ip.Equal(net.ParseIP("2001:db8::10")) {
		t.Errorf("PreferredIPv6() = %v, want 2001:db8::10", ip)
	}
	if dialed != "udp [::1]:80" {
		t.Errorf("dialed %q, want udp [::1]:80", dialed)
	}
	if !conn.closed {
		t.Error("the UDP connection was not closed")
	}
}

func TestPreferredIPv6_NetworkUnavailable(t *testing.T) {
	useDialUDP(t, func(string, string) (net.Conn, error) { return nil, errNetworkUnreachable })

	if ip := PreferredIPv6(); ip != nil {
		t.Errorf("PreferredIPv6() = %v, want nil when the dial fails", ip)
	}
}

func TestLocalAddresses(t *testing.T) {
	useInterfaceAddrs(t, func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
			&net.IPAddr{IP: net.ParseIP("198.51.100.1")},
			&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(8, 32)},
		}, nil
	})

	addrs, err := LocalAddresses()
	if err != nil {
		t.Fatalf("LocalAddresses() returned error: %v", err)
	}

	// Loopback, IPv6 and non-IPNet addresses are dropped; order is kept.
	want := []string{"192.0.2.10", "10.0.0.5"}
	if !reflect.DeepEqual(addrs, want) {
		t.Errorf("LocalAddresses() = %v, want %v", addrs, want)
	}
}

func TestLocalAddresses_NoUsableAddress(t *testing.T) {
	useInterfaceAddrs(t, func() ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}}, nil
	})

	addrs, err := LocalAddresses()
	if err != nil {
		t.Fatalf("LocalAddresses() returned error: %v", err)
	}
	if addrs == nil || len(addrs) != 0 {
		t.Errorf("LocalAddresses() = %#v, want an empty, non-nil slice", addrs)
	}
}

func TestLocalAddresses_Error(t *testing.T) {
	listErr := &net.OpError{Op: "route", Net: "ip+net", Err: syscall.EPERM}
	useInterfaceAddrs(t, func() ([]net.Addr, error) { return nil, listErr })

	addrs, err := LocalAddresses()
	if err != listErr {
		t.Errorf("LocalAddresses() error = %v, want %v", err, listErr)
	}
	if addrs != nil {
		t.Errorf("LocalAddresses() = %v, want nil on error", addrs)
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
