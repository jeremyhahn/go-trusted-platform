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

// Gateway operation codes (using extended opcode space)
// These opcodes are defined here to avoid conflicts with existing protocol.go allocations
const (
	OpGatewayStatus          byte = 0x01 // Extended gateway opcode category marker
	OpGatewaySetMode         byte = 0x02
	OpGatewayBGPStatus       byte = 0x03
	OpGatewayBGPPeers        byte = 0x04
	OpGatewayAnnouncePrefix  byte = 0x05
	OpGatewayWithdrawPrefix  byte = 0x06
	OpGatewayListPrefixes    byte = 0x07
	OpGatewayListIPAMPools   byte = 0x08
	OpGatewayAllocateIP      byte = 0x09
	OpGatewayReleaseIP       byte = 0x0A
	OpGatewayListAllocations byte = 0x0B
	OpGatewayCreateIPAMPool  byte = 0x0C
	OpGatewayDeleteIPAMPool  byte = 0x0D
	OpGatewayGetIPAMPool     byte = 0x0E
	OpGatewayUpdateIPAMPool  byte = 0x0F

	// Telemetry snapshot operations (0x15-0x16): the whole datapath
	// picture one gatewayd reports — sessions, BFD, tunnels, uplink policy
	// routes, host filter, NAT and the base pipeline (#594).
	OpGatewaySnapshot          byte = 0x15
	OpGatewayListSnapshots     byte = 0x16
	OpGatewayAdmittedVTEP      byte = 0x17
	OpGatewayListAdmittedVTEPs byte = 0x18

	// Network Zone Operations (0x10-0x13). 0x14 was the retired
	// assign-network-to-zone operation (networks are zones since #708);
	// it is never reused.
	OpGatewayListNetworkZones  byte = 0x10
	OpGatewayCreateNetworkZone byte = 0x11
	OpGatewayUpdateNetworkZone byte = 0x12
	OpGatewayDeleteNetworkZone byte = 0x13
)
