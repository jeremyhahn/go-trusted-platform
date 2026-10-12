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

// Switch sub-opcodes for the OpSwitchCategory (0xCC) category opcode.
//
// The category pattern multiplexes all SwitchService operations under a
// single top-level opcode. The first byte of the request payload selects
// the sub-operation; the remaining bytes are the MessagePack-encoded
// sub-request. The server-side dispatcher lives at
// pkg/api/daemon/quic_switch.go::handleSwitchCategory.
//
// These constants are the canonical wire-format definitions and are
// consumed by the SDK QUIC adapter (sdk/go/transport/quic/adapter.go).
// The daemon mirrors them in pkg/api/daemon/quic_switch.go for legacy
// reasons; both must stay in sync.
const (
	SwitchSubListPorts     byte = 0x01
	SwitchSubGetPortStatus byte = 0x02
	SwitchSubSetPortVLAN   byte = 0x03
	SwitchSubEnablePort    byte = 0x04
	SwitchSubDisablePort   byte = 0x05
)
