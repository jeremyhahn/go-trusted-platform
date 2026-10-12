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

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// init registers the LDevID (IEEE 802.1AR) create RPC on the QUIC transport.
//
// The single-byte QUIC opcode namespace is fully allocated, so LDevID reuses
// the physical-TPM category opcode (OpTPM2Category, 0x99) with the LDevID
// sub-opcode (SubOpTPM2LDevIDCSR, 0x1D) carried in payload[0] — the same
// framing the server-side daemon.handleTPM2Category interception decodes. The
// request/reply are the pb CreateLDevIDRequest / CreateLDevIDResponse encoded
// by the protocol codec (pb Go field names).
//
// This file name sorts before adapter.go so its init runs before the
// adapter's category-invariant assertion, which then validates that this new
// category-routed method has its required sub-opcode mapping.
func init() {
	grpcMethodToOpcodeMap[platformv1.IDevIDService_CreateLDevID_FullMethodName] = quicwire.OpTPM2Category
	categorySubOpcodeMap[platformv1.IDevIDService_CreateLDevID_FullMethodName] = quicwire.SubOpTPM2LDevIDCSR
}
