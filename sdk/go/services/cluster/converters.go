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

package cluster

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// NodeRoleFromProto converts a proto NodeRole to a domain NodeRole.
func NodeRoleFromProto(r platformv1.NodeRole) NodeRole {
	switch r {
	case platformv1.NodeRole_NODE_ROLE_LEADER:
		return NodeRoleLeader
	case platformv1.NodeRole_NODE_ROLE_FOLLOWER:
		return NodeRoleFollower
	case platformv1.NodeRole_NODE_ROLE_CANDIDATE:
		return NodeRoleCandidate
	case platformv1.NodeRole_NODE_ROLE_OBSERVER:
		return NodeRoleObserver
	default:
		return NodeRoleUnknown
	}
}

// NodeStateFromProto converts a proto NodeState to a domain NodeState.
func NodeStateFromProto(s platformv1.NodeState) NodeState {
	switch s {
	case platformv1.NodeState_NODE_STATE_ACTIVE:
		return NodeStateActive
	case platformv1.NodeState_NODE_STATE_JOINING:
		return NodeStateJoining
	case platformv1.NodeState_NODE_STATE_LEAVING:
		return NodeStateLeaving
	case platformv1.NodeState_NODE_STATE_LEFT:
		return NodeStateLeft
	case platformv1.NodeState_NODE_STATE_FAILED:
		return NodeStateFailed
	case platformv1.NodeState_NODE_STATE_UNREACHABLE:
		return NodeStateUnreachable
	default:
		return NodeStateUnknown
	}
}

// ClusterStateFromProto converts a proto ClusterState to a domain ClusterState.
func ClusterStateFromProto(s platformv1.ClusterState) ClusterState {
	switch s {
	case platformv1.ClusterState_CLUSTER_STATE_HEALTHY:
		return ClusterStateHealthy
	default:
		return ClusterStateUnhealthy
	}
}
