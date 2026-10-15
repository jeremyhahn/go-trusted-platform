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
	"syscall"
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
	cfg := GetTestServerConfig()
	RequireDHCPServer(t, cfg)

	ctx, cancel := DHCPTestContext()
	defer cancel()

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
	cfg := GetTestServerConfig()
	RequireDHCPServer(t, cfg)

	ctx, cancel := DHCPTestContext()
	defer cancel()

	clientMAC := GenerateRandomMAC()

	// First get an offer
	offer, err := sendDHCPDiscover(ctx, cfg, clientMAC, ArchEFIx64, true, false)
	require.NoError(t, err, "DHCP DISCOVER should succeed")
	require.NotNil(t, offer, "OFFER should not be nil")

	t.Run("ValidRequest", func(t *testing.T) {
		ack, err := sendDHCPRequest(ctx, cfg, offer, ArchEFIx64)
		require.NoError(t, err, "DHCP REQUEST should succeed")
		require.NotNil(t, ack, "ACK should not be nil")

		// Verify ACK contents match offer
		assert.Equal(t, offer.YourIPAddr.String(), ack.YourIPAddr.String(), "ACK IP should match OFFER")
		assert.NotEmpty(t, ack.BootFileName, "boot filename should be set in ACK")
	})

	t.Run("LeaseRenewal", func(t *testing.T) {
		// Request same IP again to simulate renewal
		ack, err := sendDHCPRequest(ctx, cfg, offer, ArchEFIx64)
		require.NoError(t, err, "Lease renewal should succeed")
		require.NotNil(t, ack, "ACK should not be nil")

		assert.Equal(t, offer.YourIPAddr.String(), ack.YourIPAddr.String(), "Renewed IP should match")
	})
}

// TestDHCPPXEOptions tests that PXE-specific DHCP options are correctly set.
func TestDHCPPXEOptions(t *testing.T) {
	cfg := GetTestServerConfig()
	RequireDHCPServer(t, cfg)

	ctx, cancel := DHCPTestContext()
	defer cancel()

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
	cfg := GetTestServerConfig()
	RequireDHCPServer(t, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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

	discover, err := dhcpv4.NewDiscovery(clientMAC, dhcpClientOptions(clientArch, isPXE, isIPXE)...)
	if err != nil {
		return nil, &DHCPExchangeError{Step: "build DISCOVER", Err: err}
	}
	return exchangeDHCP(ctx, cfg, discover, dhcpv4.MessageTypeOffer)
}

// sendDHCPRequest sends a DHCP REQUEST packet and waits for an ACK.
func sendDHCPRequest(ctx context.Context, cfg TestServerConfig, offer *dhcpv4.DHCPv4,
	clientArch uint16) (*dhcpv4.DHCPv4, error) {

	// A PXE firmware repeats its vendor class and architecture on the
	// REQUEST; the server ignores a REQUEST without them.
	request, err := dhcpv4.NewRequestFromOffer(offer, dhcpClientOptions(clientArch, true, false)...)
	if err != nil {
		return nil, &DHCPExchangeError{Step: "build REQUEST", Err: err}
	}
	return exchangeDHCP(ctx, cfg, request, dhcpv4.MessageTypeAck)
}

// dhcpClientOptions returns the options a PXE firmware, or iPXE chained
// from it, puts on its DISCOVER and REQUEST.
func dhcpClientOptions(clientArch uint16, isPXE, isIPXE bool) []dhcpv4.Modifier {
	var options []dhcpv4.Modifier
	if isPXE {
		archData := []byte{byte(clientArch >> 8), byte(clientArch)}
		options = append(options,
			dhcpv4.WithOption(dhcpv4.OptClassIdentifier("PXEClient:Arch:00007:UNDI:003010")),
			dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, archData)),
		)
	}
	if isIPXE {
		options = append(options, dhcpv4.WithOption(dhcpv4.OptUserClass("iPXE")))
	}
	return options
}

// exchangeDHCP sends msg to the suite's DHCP server and returns the first
// reply of type want that carries msg's transaction ID.
//
// The client listens where a real one does, 0.0.0.0:68: the server
// broadcasts its replies to 255.255.255.255:68, never back to the source
// port. SO_REUSEADDR lets concurrent clients share the port; each sees
// every reply and keeps only its own.
func exchangeDHCP(ctx context.Context, cfg TestServerConfig, msg *dhcpv4.DHCPv4,
	want dhcpv4.MessageType) (*dhcpv4.DHCPv4, error) {

	listener := net.ListenConfig{Control: reuseAddrControl}
	conn, err := listener.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", DHCPClientPort))
	if err != nil {
		return nil, &DHCPExchangeError{Step: "listen for " + want.String(), Err: err}
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultDHCPTimeout)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, &DHCPExchangeError{Step: "set deadline", Err: err}
	}

	server := &net.UDPAddr{IP: cfg.ServerIP, Port: cfg.DHCPPort}
	if _, err := conn.WriteTo(msg.ToBytes(), server); err != nil {
		return nil, &DHCPExchangeError{Step: "send " + msg.MessageType().String(), Err: err}
	}

	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, &DHCPExchangeError{Step: "await " + want.String(), Err: err}
		}

		reply, err := dhcpv4.FromBytes(buf[:n])
		if err != nil || reply.TransactionID != msg.TransactionID {
			continue // not DHCP, or another client's reply
		}

		switch reply.MessageType() {
		case want:
			return reply, nil
		case dhcpv4.MessageTypeNak:
			return nil, &DHCPExchangeError{Step: "await " + want.String(), Err: ErrDHCPNak}
		}
	}
}

// reuseAddrControl sets SO_REUSEADDR so concurrent clients can all bind :68.
func reuseAddrControl(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return sockErr
}

// =============================================================================
// DHCP Error Scenario Tests
// =============================================================================

// TestDHCPErrorScenarios tests various DHCP error conditions.
func TestDHCPErrorScenarios(t *testing.T) {
	cfg := GetTestServerConfig()
	RequireDHCPServer(t, cfg)

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
