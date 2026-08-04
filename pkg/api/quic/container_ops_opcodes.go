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

// Operational container opcodes (Exec, Metrics). Like the other container
// opcodes these are carried only as compute extended category (0x69)
// sub-opcodes in payload[0], never at the top level of the daemon dispatcher,
// so their byte values live in the container sub-opcode namespace and only need
// to be unique among containerSubOpcodes — the same overlap the existing
// container opcodes (0xFC-0xFF, 0x6F, 0xAE, 0xAF, 0xEC) already rely on.
//
// Both operations are unary: they decode the platform.v1 pb request and
// delegate to the shared *ComputeGRPCService (see handleContainerPB). The
// interactive AttachContainer verb is server-streaming and is NOT assigned a
// QUIC opcode — the unary QUIC request/response transport has no NewStream
// primitive for a fanned console stream, so attach stays daemon-native.
const (
	// OpContainerExec executes a command inside a running container.
	OpContainerExec byte = 0xCA

	// OpContainerMetrics reads a container's resource-usage metrics.
	OpContainerMetrics byte = 0xCB
)

// init registers the operational container opcodes as compute extended
// category sub-opcodes so the daemon dispatcher routes them to the container
// handler alongside the pre-existing verbs.
func init() {
	containerSubOpcodes[OpContainerExec] = true
	containerSubOpcodes[OpContainerMetrics] = true
}
