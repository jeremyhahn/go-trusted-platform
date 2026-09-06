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

//go:build linux

package arp

import (
	"net"

	"github.com/mdlayher/packet"
	"golang.org/x/sys/unix"
)

// rawProbeTransport opens AF_PACKET sockets filtered to ARP. It needs
// CAP_NET_RAW; without it Open fails and the caller decides what an
// unavailable probe means.
type rawProbeTransport struct{}

// NewRawProbeTransport returns the production probe transport: a raw
// AF_PACKET socket bound to the probed interface and filtered to the ARP
// EtherType. Nothing is executed and no external tool is invoked.
func NewRawProbeTransport() ProbeTransport { return &rawProbeTransport{} }

// Open binds a raw ARP socket to the named interface.
func (t *rawProbeTransport) Open(name string) (ProbeSession, error) {
	if name == "" {
		return nil, ErrInvalidInterface
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidInterface, Cause: err}
	}
	if len(ifi.HardwareAddr) != hardwareAddrLen {
		return nil, ErrInvalidMAC
	}

	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ARP, nil)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrProbeSocket, Cause: err}
	}

	session, err := NewProbeSession(conn, ifi.HardwareAddr, &packet.Addr{HardwareAddr: broadcastHardwareAddr})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return session, nil
}
