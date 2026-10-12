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

// Overlay operation codes (using extended opcode space)
// These opcodes are defined here to avoid conflicts with existing protocol.go allocations
const (
	OpOverlayStatus    byte = 0x01 // Extended overlay opcode category marker
	OpOverlayListVTEPs byte = 0x02
	OpOverlayGetVTEP   byte = 0x03
	OpOverlayListVNIs  byte = 0x04
	OpOverlayCreateVNI byte = 0x05
	OpOverlayDeleteVNI byte = 0x06
	OpOverlayListTunns byte = 0x07
	OpOverlayListMACs  byte = 0x08
	OpOverlayForgetMAC byte = 0x09
)
