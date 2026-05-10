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

/*
Package tunnel provides GRE/IPIP tunnel lifecycle management using Linux netlink.

This package manages point-to-point GRE tunnels for use in BGP transit topologies
where gatewayd peers with remote VPS nodes via iBGP over GRE tunnels. It supports
GRE, GRE6, and IPIP tunnel types with configurable MTU, TTL, and optional GRE keys.

All operations are idempotent: EnsureTunnel creates a tunnel if it does not exist,
or updates it if the configuration has changed. RemoveTunnel is a no-op if the
tunnel does not exist.

Thread Safety:

All Manager operations are safe for concurrent use. The manager tracks all tunnels
it creates and removes them on Close.

Permissions:

Tunnel creation and deletion require CAP_NET_ADMIN. Unit tests mock the netlink
layer via the netlinkOps interface to avoid requiring root privileges.

Usage:

	mgr := tunnel.NewManager(logger)
	defer mgr.Close()

	err := mgr.EnsureTunnel(ctx, tunnel.TunnelConfig{
		Name:     "gre1",
		Type:     "gre",
		Local:    "99.12.246.36",
		Remote:   "45.63.110.165",
		TunnelIP: "10.255.0.1/30",
		MTU:      1400,
		TTL:      64,
	})
*/
package tunnel
