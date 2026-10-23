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

// VPN control-plane QUIC wire mapping.
//
// Every VPNService method multiplexes under OpVPNCategory (0x52) with the
// sub-opcode in payload[0] and the MessagePack-encoded platform.v1 request in
// payload[1:]. The daemon dispatcher
// (pkg/api/daemon/quic_vpn.go::handleVPNCategory) decodes the same generated
// types, so the MessagePack keys match on both sides by construction.

// vpnSubOpcodes routes VPNService methods to their sub-opcode byte.
var vpnSubOpcodes = map[string]byte{
	platformv1.VPNService_EnrolPeer_FullMethodName:           quicwire.VPNSubEnrolPeer,
	platformv1.VPNService_ListPeers_FullMethodName:           quicwire.VPNSubListPeers,
	platformv1.VPNService_RevokePeer_FullMethodName:          quicwire.VPNSubRevokePeer,
	platformv1.VPNService_GetStatus_FullMethodName:           quicwire.VPNSubGetStatus,
	platformv1.VPNService_GetPosturePolicy_FullMethodName:    quicwire.VPNSubGetPosturePolicy,
	platformv1.VPNService_SetPosturePolicy_FullMethodName:    quicwire.VPNSubSetPosturePolicy,
	platformv1.VPNService_DeletePosturePolicy_FullMethodName: quicwire.VPNSubDeletePosturePolicy,
	platformv1.VPNService_ListPosturePolicies_FullMethodName: quicwire.VPNSubListPosturePolicies,
}

// init merges the VPN wire mapping into the shared adapter tables. The file
// name sorts before adapter.go so this init runs before the adapter's
// category-invariant assertion.
func init() {
	categoryOpcodes[quicwire.OpVPNCategory] = struct{}{}
	for method, sub := range vpnSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpVPNCategory
		categorySubOpcodeMap[method] = sub
	}
}
