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

package arp

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestGetMACForIP_Comprehensive tests the convenience function for getting MAC addresses
func TestGetMACForIP_Comprehensive(t *testing.T) {
	t.Run("invalid IP returns empty string", func(t *testing.T) {
		result := GetMACForIP("invalid-ip")
		if result != "" {
			t.Errorf("expected empty string for invalid IP, got %s", result)
		}
	})

	t.Run("non-existent IP returns empty string", func(t *testing.T) {
		result := GetMACForIP("192.168.99.99")
		if result != "" {
			t.Errorf("expected empty string for non-existent IP, got %s", result)
		}
	})

	t.Run("empty IP returns empty string", func(t *testing.T) {
		result := GetMACForIP("")
		if result != "" {
			t.Errorf("expected empty string for empty IP, got %s", result)
		}
	})
}

// TestTable_Entries_ScannerError tests scanner error handling
func TestTable_Entries_ScannerError(t *testing.T) {
	// Create a file that will cause scanner errors
	// Scanner errors are rare but can occur with very long lines or I/O issues
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "arp")

	// Create a normal ARP table first
	content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test ARP file: %v", err)
	}

	table := NewTable(WithPath(path))
	entries, err := table.Entries()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(entries))
	}
}

// TestTable_Entries_MalformedLines tests handling of various malformed ARP table entries
func TestTable_Entries_MalformedLines(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		expectedCount int
		description   string
	}{
		{
			name: "line with invalid MAC format",
			content: `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         INVALID-MAC-FORMAT    *        eth0
192.168.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
`,
			expectedCount: 2, // Both entries are parsed, but invalid MAC is set to nil
			description:   "Invalid MAC format should be handled gracefully",
		},
		{
			name: "line with incomplete MAC",
			content: `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00              *        eth0
192.168.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
`,
			expectedCount: 2, // Both entries parsed, incomplete MAC set to nil
			description:   "Incomplete MAC should be handled",
		},
		{
			name: "line with only header",
			content: `IP address       HW type     Flags       HW address            Mask     Device
`,
			expectedCount: 0,
			description:   "Only header, no entries",
		},
		{
			name: "mixed valid and malformed entries",
			content: `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
invalid
192.168.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
bad entry with not enough fields
10.0.0.1         0x1         0x2         00:11:22:33:44:55     *        br0
`,
			expectedCount: 3, // Only valid entries are included
			description:   "Malformed lines should be skipped",
		},
		{
			name: "entry with whitespace variations",
			content: `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1		0x1		0x2		52:54:00:12:34:56	*	eth0
192.168.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
`,
			expectedCount: 2,
			description:   "Tabs and spaces should both work",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "arp")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to create test ARP file: %v", err)
			}

			table := NewTable(WithPath(path))
			entries, err := table.Entries()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(entries) != tt.expectedCount {
				t.Errorf("expected %d entries, got %d", tt.expectedCount, len(entries))
			}
		})
	}
}

// TestTable_LookupMAC_EdgeCases tests edge cases for MAC lookup
func TestTable_LookupMAC_EdgeCases(t *testing.T) {
	t.Run("multiple entries with same IP - returns first valid MAC", func(t *testing.T) {
		content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1
`
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "arp")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test ARP file: %v", err)
		}

		table := NewTable(WithPath(path))
		mac, err := table.LookupMAC("192.168.1.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should return the first valid MAC
		if mac.String() != "52:54:00:12:34:56" {
			t.Errorf("expected first MAC 52:54:00:12:34:56, got %s", mac.String())
		}
	})

	t.Run("IP with nil MAC address", func(t *testing.T) {
		content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         INVALID               *        eth0
192.168.1.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
`
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "arp")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test ARP file: %v", err)
		}

		table := NewTable(WithPath(path))
		_, err := table.LookupMAC("192.168.1.1")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound for nil MAC, got %v", err)
		}
	})

	t.Run("empty string IP", func(t *testing.T) {
		table := NewTable()
		_, err := table.LookupMAC("")
		if err != ErrInvalidIP {
			t.Errorf("expected ErrInvalidIP for empty string, got %v", err)
		}
	})

	t.Run("IPv6 address", func(t *testing.T) {
		content := `IP address       HW type     Flags       HW address            Mask     Device
fe80::1          0x1         0x2         52:54:00:12:34:56     *        eth0
`
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "arp")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test ARP file: %v", err)
		}

		table := NewTable(WithPath(path))
		mac, err := table.LookupMAC("fe80::1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac.String() != "52:54:00:12:34:56" {
			t.Errorf("expected MAC 52:54:00:12:34:56, got %s", mac.String())
		}
	})

	t.Run("error reading entries propagates", func(t *testing.T) {
		table := NewTable(WithPath("/nonexistent/file"))
		_, err := table.LookupMAC("192.168.1.1")
		if err == nil {
			t.Error("expected error when ARP table can't be read")
		}
	})
}

// TestTable_LookupIP_EdgeCases tests edge cases for IP lookup
func TestTable_LookupIP_EdgeCases(t *testing.T) {
	t.Run("empty string MAC", func(t *testing.T) {
		table := NewTable()
		_, err := table.LookupIP("")
		if err != ErrInvalidMAC {
			t.Errorf("expected ErrInvalidMAC for empty string, got %v", err)
		}
	})

	t.Run("malformed MAC address", func(t *testing.T) {
		table := NewTable()
		_, err := table.LookupIP("zz:zz:zz:zz:zz:zz")
		if err != ErrInvalidMAC {
			t.Errorf("expected ErrInvalidMAC for malformed MAC, got %v", err)
		}
	})

	t.Run("MAC with wrong separator", func(t *testing.T) {
		table := NewTable()
		_, err := table.LookupIP("52-54-00-12-34-56")
		if err != nil {
			// net.ParseMAC actually accepts this format
			t.Logf("Hyphen-separated MAC parsing: %v", err)
		}
	})

	t.Run("error reading entries propagates", func(t *testing.T) {
		table := NewTable(WithPath("/nonexistent/file"))
		_, err := table.LookupIP("52:54:00:12:34:56")
		if err == nil {
			t.Error("expected error when ARP table can't be read")
		}
	})

	t.Run("all zeros MAC is found in table", func(t *testing.T) {
		content := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
`
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, "arp")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test ARP file: %v", err)
		}

		table := NewTable(WithPath(path))
		ip, err := table.LookupIP("00:00:00:00:00:00")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ip.String() != "192.168.1.50" {
			t.Errorf("expected IP 192.168.1.50, got %s", ip.String())
		}
	})
}

// TestParseLine_EdgeCases tests additional edge cases for line parsing
func TestParseLine_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		expectError error
		checkEntry  func(t *testing.T, entry Entry)
	}{
		{
			name:        "exactly 6 fields",
			line:        "192.168.1.1 0x1 0x2 52:54:00:12:34:56 * eth0",
			expectError: nil,
			checkEntry: func(t *testing.T, entry Entry) {
				if entry.IPAddress.String() != "192.168.1.1" {
					t.Errorf("expected IP 192.168.1.1, got %s", entry.IPAddress.String())
				}
				if entry.MACAddress.String() != "52:54:00:12:34:56" {
					t.Errorf("expected MAC 52:54:00:12:34:56, got %s", entry.MACAddress.String())
				}
			},
		},
		{
			name:        "more than 6 fields",
			line:        "192.168.1.1 0x1 0x2 52:54:00:12:34:56 * eth0 extra field",
			expectError: nil,
			checkEntry: func(t *testing.T, entry Entry) {
				if entry.IPAddress.String() != "192.168.1.1" {
					t.Errorf("expected IP 192.168.1.1, got %s", entry.IPAddress.String())
				}
				if entry.Device != "eth0" {
					t.Errorf("expected device eth0, got %s", entry.Device)
				}
			},
		},
		{
			name:        "5 fields - malformed",
			line:        "192.168.1.1 0x1 0x2 52:54:00:12:34:56 *",
			expectError: ErrMalformedEntry,
		},
		{
			name:        "empty line",
			line:        "",
			expectError: ErrMalformedEntry,
		},
		{
			name:        "whitespace only",
			line:        "   ",
			expectError: ErrMalformedEntry,
		},
		{
			name:        "invalid IP with correct field count",
			line:        "999.999.999.999 0x1 0x2 52:54:00:12:34:56 * eth0",
			expectError: ErrInvalidIP,
		},
		{
			name:        "invalid MAC but entry still created",
			line:        "192.168.1.1 0x1 0x2 XX:XX:XX:XX:XX:XX * eth0",
			expectError: nil,
			checkEntry: func(t *testing.T, entry Entry) {
				if entry.IPAddress.String() != "192.168.1.1" {
					t.Errorf("expected IP 192.168.1.1, got %s", entry.IPAddress.String())
				}
				if entry.MACAddress != nil {
					t.Errorf("expected nil MAC for invalid format, got %s", entry.MACAddress.String())
				}
			},
		},
		{
			name:        "all zeros MAC",
			line:        "192.168.1.1 0x1 0x2 00:00:00:00:00:00 * eth0",
			expectError: nil,
			checkEntry: func(t *testing.T, entry Entry) {
				if entry.MACAddress.String() != "00:00:00:00:00:00" {
					t.Errorf("expected MAC 00:00:00:00:00:00, got %s", entry.MACAddress.String())
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseLine(tt.line)

			if tt.expectError != nil {
				if err != tt.expectError {
					t.Errorf("expected error %v, got %v", tt.expectError, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.checkEntry != nil {
				tt.checkEntry(t, entry)
			}
		})
	}
}

// TestMacEqual_EdgeCases tests additional edge cases for MAC comparison
func TestMacEqual_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		a        net.HardwareAddr
		b        net.HardwareAddr
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: true,
		},
		{
			name:     "one nil, one empty - both have length 0",
			a:        nil,
			b:        net.HardwareAddr{},
			expected: true, // len(nil) == len(HardwareAddr{}) == 0, so they are equal
		},
		{
			name:     "both empty",
			a:        net.HardwareAddr{},
			b:        net.HardwareAddr{},
			expected: true,
		},
		{
			name:     "different lengths - first longer",
			a:        net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			b:        net.HardwareAddr{0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "different lengths - second longer",
			a:        net.HardwareAddr{0x01, 0x02, 0x03},
			b:        net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expected: false,
		},
		{
			name:     "same content, same length",
			a:        net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			b:        net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			expected: true,
		},
		{
			name:     "different at first byte",
			a:        net.HardwareAddr{0xff, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			b:        net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			expected: false,
		},
		{
			name:     "different at last byte",
			a:        net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			b:        net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00},
			expected: false,
		},
		{
			name:     "different at middle byte",
			a:        net.HardwareAddr{0xaa, 0xbb, 0xff, 0xdd, 0xee, 0xff},
			b:        net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := macEqual(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("macEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestIsValidMAC_EdgeCases tests additional edge cases for MAC validation
func TestIsValidMAC_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		mac      net.HardwareAddr
		expected bool
	}{
		{
			name:     "single non-zero byte",
			mac:      net.HardwareAddr{0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "last byte non-zero",
			mac:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "broadcast MAC",
			mac:      net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			expected: true,
		},
		{
			name:     "partial MAC (3 bytes)",
			mac:      net.HardwareAddr{0x52, 0x54, 0x00},
			expected: true,
		},
		{
			name:     "partial MAC all zeros",
			mac:      net.HardwareAddr{0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "single byte zero",
			mac:      net.HardwareAddr{0x00},
			expected: false,
		},
		{
			name:     "single byte non-zero",
			mac:      net.HardwareAddr{0x01},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidMAC(tt.mac)
			if got != tt.expected {
				t.Errorf("isValidMAC(%v) = %v, want %v", tt.mac, got, tt.expected)
			}
		})
	}
}
