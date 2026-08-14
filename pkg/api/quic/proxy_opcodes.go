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

package quic

// Reverse-proxy configuration sub-opcodes.
//
// The single-byte top-level opcode space (0x00-0xFF) is fully allocated
// (see the allocation note above the KMS ranges in protocol.go; the
// nominal 0xD1 slot is OpKMSDecrypt inside the 0xD0-0xDA KMS crypto
// range). New services therefore multiplex as sub-opcodes under an
// existing category opcode. Proxy configuration is gateway data-plane
// state that gatewayd instances sync, so it multiplexes under
// OpGatewayCategory (0x2F) in the 0x20-0x2D sub-range, following the
// same convention as EAB (0x10-0x1A) and device profile assignment
// (0x20-0x21) under OpProvisioningCategory (0xCF). Gateway's own
// sub-opcodes end at 0x14, leaving 0x20-0x2D free.
const (
	// OpProxyCategory is the wire opcode carrying proxy sub-operations.
	// It aliases OpGatewayCategory: payload[0] selects the sub-opcode
	// and payload[1:] carries the msgpack-encoded request, keyed on Go
	// field names of the platform.v1 protobuf messages.
	OpProxyCategory byte = OpGatewayCategory
)

// Proxy sub-opcodes carried in payload[0] under OpProxyCategory (0x2F).
const (
	// ProxySubRouteCreate creates a proxy route.
	ProxySubRouteCreate byte = 0x20
	// ProxySubRouteGet retrieves a proxy route by ID.
	ProxySubRouteGet byte = 0x21
	// ProxySubRouteUpdate replaces an existing proxy route.
	ProxySubRouteUpdate byte = 0x22
	// ProxySubRouteDelete removes a proxy route by ID.
	ProxySubRouteDelete byte = 0x23
	// ProxySubRouteList lists all proxy routes.
	ProxySubRouteList byte = 0x24
	// ProxySubPoolCreate creates a backend pool.
	ProxySubPoolCreate byte = 0x25
	// ProxySubPoolGet retrieves a backend pool by ID.
	ProxySubPoolGet byte = 0x26
	// ProxySubPoolUpdate replaces an existing backend pool.
	ProxySubPoolUpdate byte = 0x27
	// ProxySubPoolDelete removes a backend pool by ID.
	ProxySubPoolDelete byte = 0x28
	// ProxySubPoolList lists all backend pools.
	ProxySubPoolList byte = 0x29
	// ProxySubConfigGet returns the full merged config plus version.
	ProxySubConfigGet byte = 0x2A
	// ProxySubStatusGet reports the configuration store status.
	ProxySubStatusGet byte = 0x2B
	// ProxySubReload bumps the config version.
	ProxySubReload byte = 0x2C
	// ProxySubZoneMatrix returns the SDN zone matrix.
	ProxySubZoneMatrix byte = 0x2D
)
