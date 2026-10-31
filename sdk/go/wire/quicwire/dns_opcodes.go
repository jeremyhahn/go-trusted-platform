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

// DNS sub-opcodes, carried in payload[0] under OpDNSCategory (0x61) with the
// MessagePack-encoded platform.v1 request in payload[1:]. They start at 0x30
// and the range 0x30-0x3F is reserved for DNS operations the flat block
// (0x20-0x2C) has no room for. The retired flat opcodes 0x2B and 0x2D are not
// reused here or anywhere else.
const (
	// OpDNSUpdateZone changes a zone's TTL and description
	// (gRPC DNSService.UpdateZone).
	OpDNSUpdateZone byte = 0x30
)
