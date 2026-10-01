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

package rpinetboot

import (
	"context"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// dialDHCPClient opens the bootloader's DHCP client socket: UDP port 68
// on every address, bound to iface so the broadcast leaves and returns on
// that interface, with SO_BROADCAST for the limited broadcast and
// SO_REUSEADDR so a host's own DHCP client on port 68 does not block it.
// Binding to a device needs CAP_NET_RAW.
func dialDHCPClient(iface string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1); e != nil {
				sockErr = &SocketError{Option: "SO_BROADCAST", Err: e}
				return
			}
			if e := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); e != nil {
				sockErr = &SocketError{Option: "SO_REUSEADDR", Err: e}
				return
			}
			if iface != "" {
				if e := unix.BindToDevice(int(fd), iface); e != nil {
					sockErr = &SocketError{Option: "SO_BINDTODEVICE(" + iface + ")", Err: e}
					return
				}
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}}
	return lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(dhcpClientPort)))
}
