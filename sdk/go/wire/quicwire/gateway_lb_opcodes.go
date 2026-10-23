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

package quicwire

// Load balancer sub-opcodes carried in payload[0] under OpGatewayCategory
// (0x2F). Gateway's own sub-opcodes end at 0x14 and the proxy service owns
// 0x20-0x2D, so the load balancer claims the next clean free sub-range
// 0x30-0x35.
const (
	// OpGatewayLBAddVIP installs a load-balanced virtual IP.
	OpGatewayLBAddVIP byte = 0x30

	// OpGatewayLBRemoveVIP tears down a virtual IP.
	OpGatewayLBRemoveVIP byte = 0x31

	// OpGatewayLBGetVIP returns one VIP's status.
	OpGatewayLBGetVIP byte = 0x32

	// OpGatewayLBListVIPs returns every VIP's status.
	OpGatewayLBListVIPs byte = 0x33

	// OpGatewayLBSetVIPBackends replaces a VIP's backend set.
	OpGatewayLBSetVIPBackends byte = 0x34

	// OpGatewayLBStatus returns the load balancer service health.
	OpGatewayLBStatus byte = 0x35
)
