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

// NTP (time synchronization) category opcode.
//
// The single-byte QUIC opcode space is otherwise fully allocated, so NTP
// reclaims 0x50 — the head of the never-implemented OpProv* range, whose
// provisioning surface actually ships under OpProvisioningCategory (0xCF).
// This follows the same precedent as OpAttestCollectHost (repurposed from the
// never-implemented OpAttestGetEK) and OpVMExtendedCategory (repurposed from
// OpVMDeactivate).
//
// The category pattern multiplexes every NTPService operation under one
// top-level opcode: payload[0] selects the sub-operation and payload[1:]
// carries the MessagePack-encoded platform.v1 request. The server-side
// dispatcher lives at pkg/api/daemon/quic_ntp.go::handleNTPCategory.
//
// 0x51 is OpIAMCategory (iam_opcodes.go), 0x52 is OpVPNCategory
// (vpn_opcodes.go); 0x53-0x55 remain reserved.
const (
	// OpNTPCategory multiplexes the time-synchronization sub-operations.
	OpNTPCategory byte = 0x50
)

// NTP sub-opcodes for the OpNTPCategory (0x50) category opcode. These
// constants are the canonical wire-format definition and are consumed by the
// SDK QUIC adapter (sdk/go/transport/quic/adapter.go).
const (
	// NTPSubGetStatus returns the node's synchronization state.
	NTPSubGetStatus byte = 0x01

	// NTPSubListSources returns the configured sources and their state.
	NTPSubListSources byte = 0x02

	// NTPSubStep forces an immediate clock correction.
	NTPSubStep byte = 0x03
)
