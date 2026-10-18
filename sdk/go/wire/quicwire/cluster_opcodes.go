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

// Cluster category opcode.
//
// The single-byte QUIC opcode space is otherwise fully allocated, so the
// cluster category reclaims 0x90 — the head of the never-implemented OpJWT*
// range, whose token issuance actually ships as OpIAMTokenCreate (0xF9). This
// follows the precedent of OpNTPCategory (0x50, reclaimed from OpProv*).
//
// The category pattern multiplexes every ClusterService operation under one
// top-level opcode: payload[0] selects the sub-operation and payload[1:]
// carries the MessagePack-encoded platform.v1 request. The server-side
// dispatcher lives at pkg/api/daemon/quic_cluster.go::handleClusterCategory.
const (
	// OpClusterCategory multiplexes the ClusterService sub-operations.
	OpClusterCategory byte = 0x90
)

// Cluster sub-opcodes for the OpClusterCategory (0x90) category opcode. These
// constants are the canonical wire-format definition and are consumed by the
// SDK QUIC adapter (sdk/go/transport/quic/aab_cluster.go).
const (
	// ClusterSubBootstrap forms a new single-node cluster.
	ClusterSubBootstrap byte = 0x01

	// ClusterSubJoin joins an existing cluster through its seeds.
	ClusterSubJoin byte = 0x02

	// ClusterSubLeave removes this node from the cluster.
	ClusterSubLeave byte = 0x03

	// ClusterSubGetStatus returns the cluster state as this node sees it.
	ClusterSubGetStatus byte = 0x04

	// ClusterSubListNodes returns the cluster membership.
	ClusterSubListNodes byte = 0x05
)
