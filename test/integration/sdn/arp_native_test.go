//go:build integration

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

package sdn

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/arp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNativeARP_ReadTable tests reading the real /proc/net/arp table
func TestNativeARP_ReadTable(t *testing.T) {
	table := arp.NewTable()
	require.NotNil(t, table, "ARP table should be created")

	entries, err := table.Entries()
	require.NoError(t, err, "Should be able to read ARP table")

	// Note: ARP table might be empty in a fresh container, but the read should succeed
	// even if there are no entries
	t.Logf("Found %d ARP entries", len(entries))

	for i, entry := range entries {
		t.Logf("Entry %d: IP=%s MAC=%s Device=%s Flags=%s",
			i, entry.IPAddress, entry.MACAddress, entry.Device, entry.Flags)

		assert.NotNil(t, entry.IPAddress, "IP address should not be nil")
		assert.NotEmpty(t, entry.Device, "Device should not be empty")
	}
}

// TestNativeARP_Entries tests getting all ARP entries
func TestNativeARP_Entries(t *testing.T) {
	requireCommand(t, "ping")

	// First, ping the gateway to ensure we have at least one ARP entry
	gateway := setupTestGateway(t)

	// Ping gateway to populate ARP table
	pingHost(t, gateway)

	table := arp.NewTable()
	entries, err := table.Entries()
	require.NoError(t, err, "Should be able to get entries")

	// After pinging gateway, we should have at least one entry
	require.Greater(t, len(entries), 0, "Should have at least one ARP entry after ping")

	// Validate entries structure
	for _, entry := range entries {
		assert.NotNil(t, entry.IPAddress, "IP address should not be nil")
		assert.NotEmpty(t, entry.Device, "Device should not be empty")
		assert.NotEmpty(t, entry.HWType, "HW type should not be empty")
		assert.NotEmpty(t, entry.Flags, "Flags should not be empty")
	}
}

// TestNativeARP_LookupAfterPing tests that pinging creates an ARP entry that we can lookup
func TestNativeARP_LookupAfterPing(t *testing.T) {
	requireCommand(t, "ping")

	// Get the test-owned gateway
	gateway := setupTestGateway(t)

	t.Logf("Test gateway: %s", gateway)

	// Ping the gateway to ensure ARP entry exists
	pingHost(t, gateway)

	waitForARPEntry(t, gateway)

	// Lookup MAC address using our pure Go ARP client
	table := arp.NewTable()
	mac, err := table.LookupMAC(gateway)
	require.NoError(t, err, "Should be able to lookup gateway MAC after ping")
	require.NotNil(t, mac, "MAC address should not be nil")
	require.True(t, len(mac) > 0, "MAC address should not be empty")

	t.Logf("Gateway %s has MAC address: %s", gateway, mac.String())

	// Verify MAC address format (should be 6 bytes for Ethernet)
	assert.Equal(t, 6, len(mac), "MAC address should be 6 bytes")

	// Verify MAC is not all zeros (invalid entry)
	allZeros := true
	for _, b := range mac {
		if b != 0 {
			allZeros = false
			break
		}
	}
	assert.False(t, allZeros, "MAC address should not be all zeros")
}

// TestNativeARP_LookupLocalhost tests localhost handling
func TestNativeARP_LookupLocalhost(t *testing.T) {
	table := arp.NewTable()

	// Localhost (127.0.0.1) typically won't have an ARP entry
	// because it's handled by the loopback interface
	mac, err := table.LookupMAC("127.0.0.1")

	// We expect either an error (not found) or no entry
	if err != nil {
		assert.ErrorIs(t, err, arp.ErrNotFound, "Should get 'not found' error for localhost")
		t.Logf("Localhost correctly not found in ARP table: %v", err)
	} else if mac != nil {
		// Some systems might have a loopback entry
		t.Logf("Localhost found in ARP table with MAC: %s", mac.String())
	}
}

// TestNativeARP_LookupNotFound tests looking up a non-existent IP
func TestNativeARP_LookupNotFound(t *testing.T) {
	table := arp.NewTable()

	// Use an IP that's unlikely to exist in the ARP table
	// Using a link-local address that we haven't communicated with
	nonExistentIP := "169.254.123.234"

	mac, err := table.LookupMAC(nonExistentIP)
	assert.Error(t, err, "Should get error for non-existent IP")
	assert.ErrorIs(t, err, arp.ErrNotFound, "Should get 'not found' error")
	assert.Nil(t, mac, "MAC should be nil for non-existent IP")

	t.Logf("Correctly got 'not found' error for %s", nonExistentIP)
}

// TestNativeARP_MultipleEntries tests handling multiple ARP entries
func TestNativeARP_MultipleEntries(t *testing.T) {
	requireCommand(t, "ping")

	// Get gateway
	gateway := setupTestGateway(t)

	// Ping gateway
	pingHost(t, gateway)

	// Try to ping a DNS server to get another entry
	dnsServer := "8.8.8.8"
	pingHost(t, dnsServer)

	// Only the on-link gateway gets an ARP entry; the DNS server is routed
	waitForARPEntry(t, gateway)

	table := arp.NewTable()
	entries, err := table.Entries()
	require.NoError(t, err, "Should be able to get entries")

	t.Logf("Total ARP entries: %d", len(entries))

	// Create a map of IPs we've seen
	ipMap := make(map[string]bool)
	for _, entry := range entries {
		ipStr := entry.IPAddress.String()
		ipMap[ipStr] = true
		t.Logf("ARP Entry: IP=%s, MAC=%s, Device=%s",
			ipStr, entry.MACAddress, entry.Device)
	}

	// Check if we can lookup each entry
	for ip := range ipMap {
		mac, err := table.LookupMAC(ip)
		if err != nil {
			// Some entries might have invalid MACs (incomplete)
			t.Logf("Could not lookup MAC for %s: %v", ip, err)
		} else {
			t.Logf("Successfully looked up %s -> %s", ip, mac.String())
			assert.NotNil(t, mac, "MAC should not be nil for successful lookup")
		}
	}

	// We should have at least the gateway
	assert.Contains(t, ipMap, gateway, "ARP table should contain gateway")
}

// TestNativeARP_LookupIP tests reverse lookup (MAC to IP)
func TestNativeARP_LookupIP(t *testing.T) {
	requireCommand(t, "ping")

	// Get gateway and ping it
	gateway := setupTestGateway(t)

	pingHost(t, gateway)
	waitForARPEntry(t, gateway)

	table := arp.NewTable()

	// First get the MAC for the gateway
	mac, err := table.LookupMAC(gateway)
	require.NoError(t, err, "Should be able to lookup gateway MAC")
	require.NotNil(t, mac, "Gateway MAC should not be nil")

	macStr := mac.String()
	t.Logf("Gateway %s has MAC: %s", gateway, macStr)

	// Now do reverse lookup
	ip, err := table.LookupIP(macStr)
	require.NoError(t, err, "Should be able to lookup IP by MAC")
	require.NotNil(t, ip, "IP should not be nil")

	// The IP should match the gateway
	assert.Equal(t, gateway, ip.String(), "Reverse lookup should return original gateway IP")
	t.Logf("Successfully performed reverse lookup: %s -> %s", macStr, ip.String())
}

// TestNativeARP_InvalidIP tests error handling for invalid IP addresses
func TestNativeARP_InvalidIP(t *testing.T) {
	table := arp.NewTable()

	testCases := []struct {
		name string
		ip   string
	}{
		{"Empty string", ""},
		{"Invalid format", "not.an.ip.address"},
		{"Too many octets", "192.168.1.1.1"},
		{"Invalid characters", "192.168.1.abc"},
		{"Out of range", "256.256.256.256"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mac, err := table.LookupMAC(tc.ip)
			assert.Error(t, err, "Should get error for invalid IP: %s", tc.ip)
			assert.ErrorIs(t, err, arp.ErrInvalidIP, "Should get 'invalid IP' error")
			assert.Nil(t, mac, "MAC should be nil for invalid IP")
		})
	}
}

// TestNativeARP_InvalidMAC tests error handling for invalid MAC addresses
func TestNativeARP_InvalidMAC(t *testing.T) {
	table := arp.NewTable()

	testCases := []struct {
		name string
		mac  string
	}{
		{"Empty string", ""},
		{"Invalid format", "not:a:mac:address"},
		{"Too few octets", "00:11:22"},
		{"Invalid characters", "00:11:22:33:44:gg"},
		{"Wrong separator", "00-11-22-33-44-55-66"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip, err := table.LookupIP(tc.mac)
			assert.Error(t, err, "Should get error for invalid MAC: %s", tc.mac)
			assert.ErrorIs(t, err, arp.ErrInvalidMAC, "Should get 'invalid MAC' error")
			assert.Nil(t, ip, "IP should be nil for invalid MAC")
		})
	}
}

// TestNativeARP_GetMACForIP tests the convenience function
func TestNativeARP_GetMACForIP(t *testing.T) {
	requireCommand(t, "ping")

	// Get gateway and ping it
	gateway := setupTestGateway(t)

	pingHost(t, gateway)
	waitForARPEntry(t, gateway)

	// Use convenience function
	macStr := arp.GetMACForIP(gateway)
	assert.NotEmpty(t, macStr, "Should get MAC address for gateway")

	// Validate MAC format
	mac, err := net.ParseMAC(macStr)
	require.NoError(t, err, "Returned MAC should be valid")
	assert.Equal(t, 6, len(mac), "MAC should be 6 bytes")

	t.Logf("Convenience function returned: %s -> %s", gateway, macStr)

	// Test with non-existent IP
	macStr = arp.GetMACForIP("169.254.123.234")
	assert.Empty(t, macStr, "Should get empty string for non-existent IP")
}

// Helper Functions

// arpGatewaySeq numbers the gateways setupTestGateway creates, so tests that
// run in parallel or repeatedly never share a namespace or a subnet.
var arpGatewaySeq atomic.Uint32

// setupTestGateway creates a gateway the test owns: a network namespace
// joined to the root namespace by a veth pair on a 198.19.n.0/30 benchmark
// subnet. It returns the gateway address in the namespace, which answers ARP
// for the root namespace, and removes everything when the test ends. The
// test therefore needs no default route or outside network.
func setupTestGateway(t *testing.T) string {
	t.Helper()
	requireRoot(t)
	requireCommand(t, "ip")

	// Wrap the sequence into the third octet; cleanup frees each subnet
	// long before it comes round again.
	n := arpGatewaySeq.Add(1) % 256
	ns := fmt.Sprintf("arpgw-%d", n)
	hostIf := fmt.Sprintf("arpgw-h%d", n)
	peerIf := fmt.Sprintf("arpgw-p%d", n)
	hostCIDR := fmt.Sprintf("198.19.%d.1/30", n)
	gateway := fmt.Sprintf("198.19.%d.2", n)

	// Remove leftovers from an aborted earlier run before creating them.
	runCmdQuiet("ip", "link", "del", hostIf)
	runCmdQuiet("ip", "netns", "del", ns)
	t.Cleanup(func() {
		runCmdQuiet("ip", "link", "del", hostIf)
		runCmdQuiet("ip", "netns", "del", ns)
	})

	runCmd(t, "ip", "netns", "add", ns)
	runCmd(t, "ip", "link", "add", hostIf, "type", "veth", "peer", "name", peerIf)
	runCmd(t, "ip", "link", "set", peerIf, "netns", ns)
	runCmd(t, "ip", "addr", "add", hostCIDR, "dev", hostIf)
	runCmd(t, "ip", "link", "set", hostIf, "up")
	runCmd(t, "ip", "-n", ns, "link", "set", "lo", "up")
	runCmd(t, "ip", "-n", ns, "addr", "add", gateway+"/30", "dev", peerIf)
	runCmd(t, "ip", "-n", ns, "link", "set", peerIf, "up")

	return gateway
}

// pingHost pings a host to populate the ARP cache
func pingHost(t *testing.T, host string) {
	t.Helper()

	// Use -c 1 for one ping, -W 2 for 2 second timeout
	cmd := exec.Command("ping", "-c", "1", "-W", "2", host)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Logf("Ping to %s failed (this might be expected): %v", host, err)
		t.Logf("stdout: %s", stdout.String())
		t.Logf("stderr: %s", stderr.String())
	} else {
		t.Logf("Successfully pinged %s", host)
	}
}

// arpEntryTimeout bounds the wait for a pinged host to appear in the ARP cache.
const arpEntryTimeout = 5 * time.Second

// waitForARPEntry waits until the kernel ARP cache resolves ip. A timeout is
// only logged: the caller's own lookup asserts on the entry.
func waitForARPEntry(t *testing.T, ip string) {
	t.Helper()

	resolved := func() bool {
		_, err := arp.NewTable().LookupMAC(ip)
		return err == nil
	}
	if err := testenv.WaitUntil(t.Context(), arpEntryTimeout, "ARP entry for "+ip, resolved); err != nil {
		t.Logf("%v", err)
	}
}
