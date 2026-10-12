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

// Performance verification sub-opcodes carried in payload[0] under
// OpGatewayCategory (0x2F). Gateway owns 0x00-0x14, the proxy service
// owns 0x20-0x2D, and the load balancer owns 0x30-0x35, so perf claims
// the next free sub-range 0x36-0x38.
const (
	// OpGatewayPerfFlows measures real flow-programming throughput.
	OpGatewayPerfFlows byte = 0x36

	// OpGatewayPerfDatapath reads live datapath counters.
	OpGatewayPerfDatapath byte = 0x37

	// OpGatewayPerfConntrack summarizes the conntrack table.
	OpGatewayPerfConntrack byte = 0x38
)
