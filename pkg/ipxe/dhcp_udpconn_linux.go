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

package ipxe

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// dhcpServerSocketControl configures a DHCP server's UDP socket before it
// binds. Two options, both load-bearing for a real client on a real host:
//
//   - SO_BROADCAST. Without it the kernel refuses to transmit to the
//     limited broadcast 255.255.255.255 — and refuses SILENTLY on a
//     connected-less UDP socket: WriteTo returns nil and the frame never
//     reaches the wire. RFC 2131 §4.1 requires replies to an addressless
//     client to go to exactly that address (a client with no netmask cannot
//     hear the subnet-directed form), so a DHCP server that cannot send to
//     it cannot serve a strict client. Go's net.ListenUDP does not set it.
//   - SO_BINDTODEVICE, when an interface is named. A DHCP server is a
//     per-segment service; on a multi-homed host a socket bound to 0.0.0.0
//     lets the kernel route the broadcast out whichever interface the
//     routing table prefers, which is the default route, not the
//     provisioning segment.
//
// Measured on a dual-homed deployer serving a Supermicro X10 UEFI PXE
// client: four DISCOVERs, four "Sent DHCP Offer" log lines, zero Offers on
// the wire, zero REQUESTs (#649). Setting these two options is what made
// the Offer appear.
func dhcpServerSocketControl(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1); e != nil {
				sockErr = &SocketOptionError{Option: "SO_BROADCAST", Err: e}
				return
			}
			if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
				sockErr = &SocketOptionError{Option: "SO_REUSEADDR", Err: e}
				return
			}
			if iface != "" {
				if e := unix.BindToDevice(int(fd), iface); e != nil {
					sockErr = &SocketOptionError{Option: "SO_BINDTODEVICE(" + iface + ")", Err: e}
					return
				}
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}
}
