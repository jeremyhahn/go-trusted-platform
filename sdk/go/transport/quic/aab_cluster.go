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

// Cluster QUIC wire mapping.
//
// Every ClusterService method multiplexes under OpClusterCategory (0x90) with
// the sub-opcode in payload[0] and the generated platform.v1 request in
// payload[1:]. The daemon dispatcher is
// pkg/api/daemon/quic_cluster.go::handleClusterCategory, which calls the same
// ClusterService servicer gRPC uses.
//
// Responses are the generated platform.v1 messages encoded verbatim, so the
// MessagePack keys — which are Go FIELD NAMES, not proto JSON names — match
// on both sides by construction.

// clusterSubOpcodes routes each ClusterService method to its sub-opcode byte.
var clusterSubOpcodes = map[string]byte{
	platformv1.ClusterService_Bootstrap_FullMethodName: quicwire.ClusterSubBootstrap,
	platformv1.ClusterService_Join_FullMethodName:      quicwire.ClusterSubJoin,
	platformv1.ClusterService_Leave_FullMethodName:     quicwire.ClusterSubLeave,
	platformv1.ClusterService_GetStatus_FullMethodName: quicwire.ClusterSubGetStatus,
	platformv1.ClusterService_ListNodes_FullMethodName: quicwire.ClusterSubListNodes,
}

// init merges the cluster wire mapping into the shared adapter tables. The
// file name sorts before adapter.go so this init runs before the adapter's
// category-invariant assertion.
func init() {
	categoryOpcodes[quicwire.OpClusterCategory] = struct{}{}
	for method, sub := range clusterSubOpcodes {
		grpcMethodToOpcodeMap[method] = quicwire.OpClusterCategory
		categorySubOpcodeMap[method] = sub
	}
}
