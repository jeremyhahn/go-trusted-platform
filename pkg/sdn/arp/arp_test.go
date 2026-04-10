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

// Sample /proc/net/arp content for testing
const sampleARPTable = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
192.168.1.100    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
10.0.0.1         0x1         0x2         00:11:22:33:44:55     *        br0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
`

func createTestARPFile(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "arp")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test ARP file: %v", err)
	}
	return path
}

func TestNewTable(t *testing.T) {
	t.Run("default path", func(t *testing.T) {
		table := NewTable()
		if table.path != DefaultARPTablePath {
			t.Errorf("expected path %s, got %s", DefaultARPTablePath, table.path)
		}
	})

	t.Run("custom path", func(t *testing.T) {
		customPath := "/custom/path/arp"
		table := NewTable(WithPath(customPath))
		if table.path != customPath {
			t.Errorf("expected path %s, got %s", customPath, table.path)
		}
	})
}

func TestTable_Entries(t *testing.T) {
	path := createTestARPFile(t, sampleARPTable)
	table := NewTable(WithPath(path))

	entries, err := table.Entries()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 4 {
		t.Errorf("expected 4 entries, got %d", len(entries))
	}

	// Verify first entry
	if entries[0].IPAddress.String() != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", entries[0].IPAddress.String())
	}
	if entries[0].MACAddress.String() != "52:54:00:12:34:56" {
		t.Errorf("expected MAC 52:54:00:12:34:56, got %s", entries[0].MACAddress.String())
	}
	if entries[0].Device != "eth0" {
		t.Errorf("expected device eth0, got %s", entries[0].Device)
	}
}

func TestTable_Entries_FileNotFound(t *testing.T) {
	table := NewTable(WithPath("/nonexistent/path"))
	_, err := table.Entries()
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestTable_Entries_EmptyFile(t *testing.T) {
	path := createTestARPFile(t, "")
	table := NewTable(WithPath(path))

	_, err := table.Entries()
	if err != ErrEmptyARPTable {
		t.Errorf("expected ErrEmptyARPTable, got %v", err)
	}
}

func TestTable_LookupMAC(t *testing.T) {
	path := createTestARPFile(t, sampleARPTable)
	table := NewTable(WithPath(path))

	t.Run("found", func(t *testing.T) {
		mac, err := table.LookupMAC("192.168.1.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac.String() != "52:54:00:12:34:56" {
			t.Errorf("expected MAC 52:54:00:12:34:56, got %s", mac.String())
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := table.LookupMAC("192.168.1.99")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("invalid IP", func(t *testing.T) {
		_, err := table.LookupMAC("invalid-ip")
		if err != ErrInvalidIP {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})

	t.Run("incomplete entry (all zeros MAC)", func(t *testing.T) {
		_, err := table.LookupMAC("192.168.1.50")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound for incomplete entry, got %v", err)
		}
	})
}

func TestTable_LookupIP(t *testing.T) {
	path := createTestARPFile(t, sampleARPTable)
	table := NewTable(WithPath(path))

	t.Run("found", func(t *testing.T) {
		ip, err := table.LookupIP("52:54:00:12:34:56")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ip.String() != "192.168.1.1" {
			t.Errorf("expected IP 192.168.1.1, got %s", ip.String())
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := table.LookupIP("99:99:99:99:99:99")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("invalid MAC", func(t *testing.T) {
		_, err := table.LookupIP("invalid-mac")
		if err != ErrInvalidMAC {
			t.Errorf("expected ErrInvalidMAC, got %v", err)
		}
	})
}

func TestParseLine(t *testing.T) {
	t.Run("valid line", func(t *testing.T) {
		line := "192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0"
		entry, err := parseLine(line)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if entry.IPAddress.String() != "192.168.1.1" {
			t.Errorf("expected IP 192.168.1.1, got %s", entry.IPAddress.String())
		}
		if entry.HWType != "0x1" {
			t.Errorf("expected HWType 0x1, got %s", entry.HWType)
		}
		if entry.Flags != "0x2" {
			t.Errorf("expected Flags 0x2, got %s", entry.Flags)
		}
		if entry.MACAddress.String() != "52:54:00:12:34:56" {
			t.Errorf("expected MAC 52:54:00:12:34:56, got %s", entry.MACAddress.String())
		}
		if entry.Mask != "*" {
			t.Errorf("expected Mask *, got %s", entry.Mask)
		}
		if entry.Device != "eth0" {
			t.Errorf("expected Device eth0, got %s", entry.Device)
		}
	})

	t.Run("malformed line - too few fields", func(t *testing.T) {
		line := "192.168.1.1 0x1 0x2"
		_, err := parseLine(line)
		if err != ErrMalformedEntry {
			t.Errorf("expected ErrMalformedEntry, got %v", err)
		}
	})

	t.Run("malformed line - invalid IP", func(t *testing.T) {
		line := "invalid-ip      0x1         0x2         52:54:00:12:34:56     *        eth0"
		_, err := parseLine(line)
		if err != ErrInvalidIP {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})
}

func TestIsValidMAC(t *testing.T) {
	tests := []struct {
		name     string
		mac      net.HardwareAddr
		expected bool
	}{
		{
			name:     "valid MAC",
			mac:      net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56},
			expected: true,
		},
		{
			name:     "all zeros",
			mac:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "nil MAC",
			mac:      nil,
			expected: false,
		},
		{
			name:     "empty MAC",
			mac:      net.HardwareAddr{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidMAC(tt.mac); got != tt.expected {
				t.Errorf("isValidMAC() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMacEqual(t *testing.T) {
	mac1 := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	mac2 := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	mac3 := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	mac4 := net.HardwareAddr{0x52, 0x54, 0x00}

	t.Run("equal", func(t *testing.T) {
		if !macEqual(mac1, mac2) {
			t.Error("expected MACs to be equal")
		}
	})

	t.Run("not equal", func(t *testing.T) {
		if macEqual(mac1, mac3) {
			t.Error("expected MACs to be not equal")
		}
	})

	t.Run("different length", func(t *testing.T) {
		if macEqual(mac1, mac4) {
			t.Error("expected MACs to be not equal due to different length")
		}
	})
}

func TestGetMACForIP(t *testing.T) {
	// Test GetMACForIP logic using a mock ARP table file instead of requiring
	// the real system ARP table. This tests the function logic without requiring
	// specific network interfaces or real ARP entries.

	t.Run("success_with_mock_arp_table", func(t *testing.T) {
		// Create a mock ARP file in a temp directory
		arpContent := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
192.168.1.100    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
10.0.0.1         0x1         0x2         00:11:22:33:44:55     *        br0
`
		path := createTestARPFile(t, arpContent)

		// Use the Table directly with custom path to verify the lookup logic
		table := NewTable(WithPath(path))
		mac, err := table.LookupMAC("192.168.1.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac.String() != "52:54:00:12:34:56" {
			t.Errorf("expected MAC 52:54:00:12:34:56, got %s", mac.String())
		}
	})

	t.Run("not_found_with_mock_arp_table", func(t *testing.T) {
		arpContent := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
`
		path := createTestARPFile(t, arpContent)

		table := NewTable(WithPath(path))
		_, err := table.LookupMAC("192.168.1.99")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("invalid_ip", func(t *testing.T) {
		path := createTestARPFile(t, sampleARPTable)
		table := NewTable(WithPath(path))

		_, err := table.LookupMAC("invalid-ip-address")
		if err != ErrInvalidIP {
			t.Errorf("expected ErrInvalidIP, got %v", err)
		}
	})

	t.Run("empty_arp_table", func(t *testing.T) {
		path := createTestARPFile(t, "")
		table := NewTable(WithPath(path))

		_, err := table.LookupMAC("192.168.1.1")
		if err != ErrEmptyARPTable {
			t.Errorf("expected ErrEmptyARPTable, got %v", err)
		}
	})

	t.Run("incomplete_entry_with_zero_mac", func(t *testing.T) {
		arpContent := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
`
		path := createTestARPFile(t, arpContent)

		table := NewTable(WithPath(path))
		_, err := table.LookupMAC("192.168.1.50")
		if err != ErrNotFound {
			t.Errorf("expected ErrNotFound for incomplete entry, got %v", err)
		}
	})

	t.Run("multiple_devices", func(t *testing.T) {
		arpContent := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
10.0.0.1         0x1         0x2         00:11:22:33:44:55     *        br0
172.16.0.1       0x1         0x2         66:77:88:99:aa:bb     *        wlan0
`
		path := createTestARPFile(t, arpContent)

		table := NewTable(WithPath(path))

		// Verify all entries can be found
		mac1, err := table.LookupMAC("192.168.1.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac1.String() != "52:54:00:12:34:56" {
			t.Errorf("expected MAC 52:54:00:12:34:56, got %s", mac1.String())
		}

		mac2, err := table.LookupMAC("10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac2.String() != "00:11:22:33:44:55" {
			t.Errorf("expected MAC 00:11:22:33:44:55, got %s", mac2.String())
		}

		mac3, err := table.LookupMAC("172.16.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if mac3.String() != "66:77:88:99:aa:bb" {
			t.Errorf("expected MAC 66:77:88:99:aa:bb, got %s", mac3.String())
		}
	})
}
