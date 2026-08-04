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
	"bufio"
	"net"
	"os"
	"strings"
)

// Default path to the Linux ARP table
const DefaultARPTablePath = "/proc/net/arp"

// Entry represents a single ARP table entry
type Entry struct {
	IPAddress  net.IP
	HWType     string
	Flags      string
	MACAddress net.HardwareAddr
	Mask       string
	Device     string
}

// Table provides methods to query the system ARP table
type Table struct {
	path string
}

// TableOption configures the ARP table reader
type TableOption func(*Table)

// WithPath sets a custom path to the ARP table (for testing)
func WithPath(path string) TableOption {
	return func(t *Table) {
		t.path = path
	}
}

// NewTable creates a new ARP table reader
func NewTable(opts ...TableOption) *Table {
	t := &Table{
		path: DefaultARPTablePath,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// Entries returns all entries from the ARP table
func (t *Table) Entries() ([]Entry, error) {
	file, err := os.Open(t.path)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrOpenARPTable, Cause: err}
	}
	defer func() { _ = file.Close() }()

	var entries []Entry
	scanner := bufio.NewScanner(file)

	// Skip header line
	if !scanner.Scan() {
		return nil, ErrEmptyARPTable
	}

	for scanner.Scan() {
		line := scanner.Text()
		entry, err := parseLine(line)
		if err != nil {
			// Skip malformed lines
			continue
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrReadARPTable, Cause: err}
	}

	return entries, nil
}

// LookupMAC looks up the MAC address for a given IP address
func (t *Table) LookupMAC(ipAddr string) (net.HardwareAddr, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return nil, ErrInvalidIP
	}

	entries, err := t.Entries()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IPAddress.Equal(ip) {
			// Check if MAC is valid (not all zeros or incomplete)
			if isValidMAC(entry.MACAddress) {
				return entry.MACAddress, nil
			}
		}
	}

	return nil, ErrNotFound
}

// LookupIP looks up the IP address for a given MAC address
func (t *Table) LookupIP(macAddr string) (net.IP, error) {
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return nil, ErrInvalidMAC
	}

	entries, err := t.Entries()
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if macEqual(entry.MACAddress, mac) {
			return entry.IPAddress, nil
		}
	}

	return nil, ErrNotFound
}

// parseLine parses a single line from /proc/net/arp
// Format: IP address       HW type     Flags       HW address            Mask     Device
// Example: 192.168.1.1      0x1         0x2         52:54:00:12:34:56     *        eth0
func parseLine(line string) (Entry, error) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return Entry{}, ErrMalformedEntry
	}

	ip := net.ParseIP(fields[0])
	if ip == nil {
		return Entry{}, ErrInvalidIP
	}

	mac, err := net.ParseMAC(fields[3])
	if err != nil {
		// MAC might be "00:00:00:00:00:00" or incomplete
		// Still try to use it if possible
		mac = nil
	}

	return Entry{
		IPAddress:  ip,
		HWType:     fields[1],
		Flags:      fields[2],
		MACAddress: mac,
		Mask:       fields[4],
		Device:     fields[5],
	}, nil
}

// isValidMAC checks if a MAC address is valid (not all zeros or nil)
func isValidMAC(mac net.HardwareAddr) bool {
	if len(mac) == 0 {
		return false
	}

	// Check if MAC is all zeros (incomplete entry)
	allZeros := true
	for _, b := range mac {
		if b != 0 {
			allZeros = false
			break
		}
	}

	return !allZeros
}

// macEqual compares two MAC addresses
func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GetMACForIP is a convenience function that returns the MAC address string for an IP
// Returns empty string if not found
func GetMACForIP(ipAddr string) string {
	table := NewTable()
	mac, err := table.LookupMAC(ipAddr)
	if err != nil {
		return ""
	}
	return mac.String()
}
