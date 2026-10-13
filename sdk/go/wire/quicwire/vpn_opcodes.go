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

// VPN category opcode.
//
// VPNService (peer enrolment, session status and tenant posture policies)
// multiplexes under one category: payload[0] selects the sub-operation and
// payload[1:] carries the MessagePack-encoded platform.v1 request. The
// server-side dispatcher lives at
// pkg/api/daemon/quic_vpn.go::handleVPNCategory.
//
// The opcode space is otherwise fully allocated, so this takes 0x52 from the
// block reserved after OpNTPCategory.
const (
	// OpVPNCategory multiplexes the VPN control-plane sub-operations.
	OpVPNCategory byte = 0x52
)

// VPN sub-opcodes for the OpVPNCategory (0x52) category opcode. These
// constants are the canonical wire-format definition and are consumed by the
// SDK QUIC adapter (sdk/go/transport/quic/aab_vpn.go).
const (
	// VPNSubEnrolPeer enrols a device as a VPN peer of a tenant.
	VPNSubEnrolPeer byte = 0x01

	// VPNSubListPeers lists the enrolled VPN peers.
	VPNSubListPeers byte = 0x02

	// VPNSubRevokePeer revokes a VPN peer enrolment.
	VPNSubRevokePeer byte = 0x03

	// VPNSubGetStatus reports the VPN session state from gateway telemetry.
	VPNSubGetStatus byte = 0x04

	// VPNSubGetPosturePolicy returns one tenant posture policy.
	VPNSubGetPosturePolicy byte = 0x05

	// VPNSubSetPosturePolicy creates or replaces a tenant posture policy.
	VPNSubSetPosturePolicy byte = 0x06

	// VPNSubDeletePosturePolicy deletes a tenant posture policy.
	VPNSubDeletePosturePolicy byte = 0x07

	// VPNSubListPosturePolicies lists the tenant posture policies.
	VPNSubListPosturePolicies byte = 0x08
)
