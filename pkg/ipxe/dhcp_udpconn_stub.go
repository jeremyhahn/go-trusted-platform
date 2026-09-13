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

//go:build !linux

package ipxe

import "syscall"

// dhcpServerSocketControl is a no-op off Linux: the DHCP server only
// serves real clients from a Linux deployer, and the interface binding it
// performs there (SO_BINDTODEVICE) has no portable equivalent. Tests on
// other platforms exercise the packet logic through the mock connection.
func dhcpServerSocketControl(string) func(network, address string, c syscall.RawConn) error {
	return nil
}
