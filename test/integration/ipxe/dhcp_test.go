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
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

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
