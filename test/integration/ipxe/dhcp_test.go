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

//go:build integration

package ipxe

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// DHCP Protocol Tests
// =============================================================================

// TestDHCPDiscoverOffer tests the DHCP DISCOVER -> OFFER flow.
func TestDHCPDiscoverOffer(t *testing.T) {
	SkipIfNoDHCP(t)
	if err := CheckNetworkPrivileges(); err != nil {
		t.Fatalf("missing prerequisite: %v", err)
	}

	ctx, cancel := DHCPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	clientMAC := GenerateRandomMAC()

	t.Run("PXEClientDiscover", func(t *testing.T) {
		offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
		require.NoError(t, err, "DHCP DISCOVER should succeed")
		require.NotNil(t, offer, "OFFER should not be nil")

		// Verify offered IP is in range
		AssertValidIP(t, offer.YourIPAddr, "offered IP")
		AssertIPInRange(t, offer.YourIPAddr, cfg.DHCPRangeStart, cfg.DHCPRangeEnd, "offered IP")

		// Verify server IP
		assert.Equal(t, cfg.ServerIP.String(), offer.ServerIPAddr.String(), "server IP should match")

		// Verify PXE options are present
		assert.NotEmpty(t, offer.BootFileName, "boot filename should be set for PXE client")
	})

	t.Run("iPXEClientDiscover", func(t *testing.T) {
		ipxeMAC := GenerateRandomMAC()
		offer, err := sendDHCPDiscover(ctx, cfg, ipxeMAC, ArchEFIx64, true, true)
		require.NoError(t, err, "DHCP DISCOVER from iPXE should succeed")
		require.NotNil(t, offer, "OFFER should not be nil")

		// iPXE clients should get the HTTP script URL instead of TFTP boot file
		AssertValidIP(t, offer.YourIPAddr, "offered IP for iPXE")
	})

	t.Run("NonPXEClientIgnored", func(t *testing.T) {
		nonPXEMAC := GenerateRandomMAC()

		// Create a non-PXE DHCP discover (no PXE vendor class)
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		_, err := sendDHCPDiscover(ctx, cfg, nonPXEMAC, 0, false, false)
		// Non-PXE clients should be ignored by the PXE server
		assert.Error(t, err, "non-PXE client should timeout or be ignored")
	})
}

// TestDHCPRequestAck tests the DHCP REQUEST -> ACK flow.
func TestDHCPRequestAck(t *testing.T) {
	SkipIfNoDHCP(t)
	if err := CheckNetworkPrivileges(); err != nil {
		t.Fatalf("missing prerequisite: %v", err)
	}

	ctx, cancel := DHCPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()
	clientMAC := GenerateRandomMAC()

	// First get an offer
	offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
	require.NoError(t, err, "DHCP DISCOVER should succeed")
	require.NotNil(t, offer, "OFFER should not be nil")

	t.Run("ValidRequest", func(t *testing.T) {
		ack, err := sendDHCPRequest(ctx, cfg, clientMAC, offer)
		require.NoError(t, err, "DHCP REQUEST should succeed")
		require.NotNil(t, ack, "ACK should not be nil")

		// Verify ACK contents match offer
		assert.Equal(t, offer.YourIPAddr.String(), ack.YourIPAddr.String(), "ACK IP should match OFFER")
		assert.NotEmpty(t, ack.BootFileName, "boot filename should be set in ACK")
	})

	t.Run("LeaseRenewal", func(t *testing.T) {
		// Request same IP again to simulate renewal
		ack, err := sendDHCPRequest(ctx, cfg, clientMAC, offer)
		require.NoError(t, err, "Lease renewal should succeed")
		require.NotNil(t, ack, "ACK should not be nil")

		assert.Equal(t, offer.YourIPAddr.String(), ack.YourIPAddr.String(), "Renewed IP should match")
	})
}

// TestDHCPPXEOptions tests that PXE-specific DHCP options are correctly set.
func TestDHCPPXEOptions(t *testing.T) {
	SkipIfNoDHCP(t)
	if err := CheckNetworkPrivileges(); err != nil {
		t.Fatalf("missing prerequisite: %v", err)
	}

	ctx, cancel := DHCPTestContext()
	defer cancel()

	cfg := GetTestServerConfig()

	t.Run("EFIx64BootFile", func(t *testing.T) {
		clientMAC := GenerateRandomMAC()
		offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
		require.NoError(t, err, "DHCP DISCOVER should succeed")
		require.NotNil(t, offer, "OFFER should not be nil")

		// Non-iPXE PXE clients should get the iPXE firmware filename
		assert.Contains(t, offer.BootFileName, "ipxe.efi", "EFI x64 client should get ipxe.efi")
	})

	t.Run("iPXEClientGetsScriptURL", func(t *testing.T) {
		clientMAC := GenerateRandomMAC()
		offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, true)
		require.NoError(t, err, "DHCP DISCOVER should succeed for iPXE client")
		require.NotNil(t, offer, "OFFER should not be nil")

		// iPXE clients should get HTTP script URL
		assert.Contains(t, offer.BootFileName, "http://", "iPXE client should get HTTP URL")
		assert.Contains(t, offer.BootFileName, "/boot.ipxe", "iPXE client should get boot.ipxe script URL")
	})

	t.Run("TFTPServerOption", func(t *testing.T) {
		clientMAC := GenerateRandomMAC()
		offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
		require.NoError(t, err, "DHCP DISCOVER should succeed")
		require.NotNil(t, offer, "OFFER should not be nil")

		// TFTP server IP should be set for non-iPXE clients
		assert.Equal(t, cfg.ServerIP.String(), offer.ServerIPAddr.String(), "TFTP server IP should be set")
	})
}

// TestDHCPMultipleClients tests handling multiple concurrent DHCP clients.
func TestDHCPMultipleClients(t *testing.T) {
	SkipIfNoDHCP(t)
	if err := CheckNetworkPrivileges(); err != nil {
		t.Fatalf("missing prerequisite: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := GetTestServerConfig()
	numClients := 5

	t.Run("ConcurrentDiscoverRequests", func(t *testing.T) {
		type result struct {
			mac   net.HardwareAddr
			offer *dhcpv4.DHCPv4
			err   error
		}

		results := make(chan result, numClients)

		// Send DISCOVER from multiple clients concurrently
		for i := 0; i < numClients; i++ {
			mac := GenerateTestMAC(i)
			go func(m net.HardwareAddr) {
				offer, err := sendDHCPDiscover(ctx, cfg, m, ArchEFIx64, true, false)
				results <- result{mac: m, offer: offer, err: err}
			}(mac)
		}

		// Collect results
		offeredIPs := make(map[string]bool)
		for i := 0; i < numClients; i++ {
			r := <-results
			if r.err != nil {
				t.Errorf("DISCOVER failed for %v: %v", r.mac, r.err)
				continue
			}

			ip := r.offer.YourIPAddr.String()
			if offeredIPs[ip] {
				t.Errorf("Duplicate IP offered: %s", ip)
			}
			offeredIPs[ip] = true

			// Verify IP is in range
			AssertIPInRange(t, r.offer.YourIPAddr, cfg.DHCPRangeStart, cfg.DHCPRangeEnd, "offered IP")
		}

		// Verify all clients got unique IPs
		assert.Equal(t, numClients, len(offeredIPs), "All clients should get unique IPs")
	})

	t.Run("LeaseReuse", func(t *testing.T) {
		// Same MAC should get same IP on repeated requests
		clientMAC := GenerateRandomMAC()

		offer1, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
		require.NoError(t, err, "First DISCOVER should succeed")

		offer2, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
		require.NoError(t, err, "Second DISCOVER should succeed")

		assert.Equal(t, offer1.YourIPAddr.String(), offer2.YourIPAddr.String(),
			"Same MAC should get same IP")
	})
}

// =============================================================================
// DHCP Helper Functions
// =============================================================================

// sendDHCPDiscover sends a DHCP DISCOVER packet and waits for an OFFER.
func sendDHCPDiscover(ctx context.Context, cfg TestServerConfig, clientMAC net.HardwareAddr,
	clientArch uint16, isPXE, isIPXE bool) (*dhcpv4.DHCPv4, error) {

	// Create DHCP DISCOVER packet
	discover, err := dhcpv4.NewDiscovery(clientMAC)
	if err != nil {
		return nil, fmt.Errorf("failed to create DISCOVER: %w", err)
	}

	// Add PXE client options if requested
	if isPXE {
		// Add vendor class identifier (option 60)
		discover.UpdateOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00007:UNDI:003010"))

		// Add client architecture (option 93)
		archData := []byte{byte(clientArch >> 8), byte(clientArch)}
		discover.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, archData))
	}

	// Add iPXE user class if requested
	if isIPXE {
		discover.UpdateOption(dhcpv4.OptUserClass("iPXE"))
	}

	// Create UDP connection
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Send to DHCP server
	serverAddr := &net.UDPAddr{
		IP:   cfg.ServerIP,
		Port: 67,
	}

	_, err = conn.WriteTo(discover.ToBytes(), serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send DISCOVER: %w", err)
	}

	// Wait for OFFER
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to receive response: %w", err)
		}

		offer, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue // Ignore malformed packets
		}

		// Verify it is our OFFER
		if offer.TransactionID != discover.TransactionID {
			continue
		}

		if offer.MessageType() == dhcpv4.MessageTypeOffer {
			return offer, nil
		}
	}
}

// sendDHCPRequest sends a DHCP REQUEST packet and waits for an ACK.
func sendDHCPRequest(ctx context.Context, cfg TestServerConfig, clientMAC net.HardwareAddr,
	offer *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {

	// Create DHCP REQUEST packet
	request, err := dhcpv4.NewRequestFromOffer(offer)
	if err != nil {
		return nil, fmt.Errorf("failed to create REQUEST: %w", err)
	}

	// Create UDP connection
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	// Set deadline
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Send to DHCP server
	serverAddr := &net.UDPAddr{
		IP:   cfg.ServerIP,
		Port: 67,
	}

	_, err = conn.WriteTo(request.ToBytes(), serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send REQUEST: %w", err)
	}

	// Wait for ACK
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to receive response: %w", err)
		}

		ack, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			continue // Ignore malformed packets
		}

		// Verify it is our ACK
		if ack.TransactionID != request.TransactionID {
			continue
		}

		if ack.MessageType() == dhcpv4.MessageTypeAck {
			return ack, nil
		}

		if ack.MessageType() == dhcpv4.MessageTypeNak {
			return nil, fmt.Errorf("received DHCP NAK")
		}
	}
}

// =============================================================================
// DHCP Error Scenario Tests
// =============================================================================

// TestDHCPErrorScenarios tests various DHCP error conditions.
func TestDHCPErrorScenarios(t *testing.T) {
	SkipIfNoDHCP(t)
	if err := CheckNetworkPrivileges(); err != nil {
		t.Fatalf("missing prerequisite: %v", err)
	}

	cfg := GetTestServerConfig()

	t.Run("InvalidMACAddress", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Zero MAC should be rejected or ignored
		zeroMAC := net.HardwareAddr{0, 0, 0, 0, 0, 0}
		_, err := sendDHCPDiscover(ctx, cfg, zeroMAC, ArchEFIx64, true, false)
		// Expect timeout or error since zero MAC is invalid
		assert.Error(t, err, "Zero MAC should fail")
	})

	t.Run("ServerUnreachable", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Use unreachable server IP
		badCfg := cfg
		badCfg.ServerIP = net.ParseIP("10.255.255.254")

		clientMAC := GenerateRandomMAC()
		_, err := sendDHCPDiscover(ctx, badCfg, clientMAC, ArchEFIx64, true, false)
		assert.Error(t, err, "Unreachable server should timeout")
	})
}
