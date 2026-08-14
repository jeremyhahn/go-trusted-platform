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
	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// NTP (time synchronization) QUIC wire mapping.
//
// Every NTPService method multiplexes under OpNTPCategory (0x50) with the
// sub-opcode in payload[0]. All three requests are empty messages, so the
// adapter sends only the sub-opcode byte and the daemon dispatcher
// (pkg/api/daemon/quic_ntp.go::handleNTPCategory) tolerates a zero-length
// sub-payload.
//
// Responses are the generated platform.v1 messages encoded verbatim, so the
// MessagePack keys — which are Go FIELD NAMES, not proto JSON names — match
// on both sides by construction.

// ntpMethodOpcodes routes NTPService methods to the category opcode.
var ntpMethodOpcodes = map[string]byte{
	platformv1.NTPService_GetStatus_FullMethodName:   quicapi.OpNTPCategory,
	platformv1.NTPService_ListSources_FullMethodName: quicapi.OpNTPCategory,
	platformv1.NTPService_Step_FullMethodName:        quicapi.OpNTPCategory,
}

// ntpSubOpcodes routes NTPService methods to their sub-opcode byte.
var ntpSubOpcodes = map[string]byte{
	platformv1.NTPService_GetStatus_FullMethodName:   quicapi.NTPSubGetStatus,
	platformv1.NTPService_ListSources_FullMethodName: quicapi.NTPSubListSources,
	platformv1.NTPService_Step_FullMethodName:        quicapi.NTPSubStep,
}

// ntpEmptyBodyMethods marks every NTP method as carrying no request body.
var ntpEmptyBodyMethods = map[string]struct{}{
	platformv1.NTPService_GetStatus_FullMethodName:   {},
	platformv1.NTPService_ListSources_FullMethodName: {},
	platformv1.NTPService_Step_FullMethodName:        {},
}

// init merges the NTP wire mapping into the shared adapter tables. The file
// name sorts before adapter.go so this init runs before the adapter's
// category-invariant assertion, which then validates that every
// category-routed NTP method has its required sub-opcode mapping.
func init() {
	categoryOpcodes[quicapi.OpNTPCategory] = struct{}{}
	for method, opcode := range ntpMethodOpcodes {
		grpcMethodToOpcodeMap[method] = opcode
	}
	for method, sub := range ntpSubOpcodes {
		categorySubOpcodeMap[method] = sub
	}
	for method := range ntpEmptyBodyMethods {
		categoryEmptyBodyMethods[method] = struct{}{}
	}
}
