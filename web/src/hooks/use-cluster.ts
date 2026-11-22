"use client";

/**
 * The cluster hook: GetStatus, ListNodes, Bootstrap, Join and Leave on
 * `/api/v1/cluster/*`, served on the console listener by
 * pkg/api/rest/cluster_handlers.go and on the daemon by cluster_rest.go.
 *
 * It calls the SDK API client directly, as use-ntp.ts does, because the SDK
 * has no platform cluster service. The server answers the proto structs
 * through encoding/json, so fields are snake_case, enums are numbers and
 * timestamps are `{seconds, nanos}`. On main every route answers 503 until a
 * cluster servicer is wired (#2140).
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

export interface ProtoTimestamp {
  seconds?: number | string;
  nanos?: number;
}

/** platform.v1.ClusterState */
export enum ClusterState {
  Unspecified = 0,
  Initializing = 1,
  Healthy = 2,
  Degraded = 3,
  Unavailable = 4,
  Partitioned = 5,
}

/** platform.v1.NodeRole */
export enum NodeRole {
  Unspecified = 0,
  Leader = 1,
  Follower = 2,
  Candidate = 3,
  Observer = 4,
}

/** platform.v1.NodeState */
export enum NodeState {
  Unspecified = 0,
  Joining = 1,
  Active = 2,
  Leaving = 3,
  Left = 4,
  Failed = 5,
  Unreachable = 6,
}

export interface ClusterNode {
  id?: string;
  name?: string;
  address?: string;
  port?: number;
  role?: NodeRole;
  state?: NodeState;
  health?: number;
  version?: string;
  joined_at?: ProtoTimestamp;
  last_heartbeat?: ProtoTimestamp;
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

export interface ClusterInfo {
  id?: string;
  name?: string;
  state?: ClusterState;
  leader_id?: string;
  leader_address?: string;
  total_nodes?: number;
  healthy_nodes?: number;
  term?: number | string;
  created_at?: ProtoTimestamp;
  last_election?: ProtoTimestamp;
  metadata?: Record<string, string>;
}

export interface OperationStatus {
  success?: boolean;
  message?: string;
}

export interface ClusterStatusResponse {
  cluster?: ClusterInfo;
  local_node?: ClusterNode;
  nodes?: ClusterNode[];
  timestamp?: ProtoTimestamp;
}

export interface ClusterNodesResponse {
  nodes?: ClusterNode[];
  total?: number;
}

/** The daemon ignores the proto's other fields (pkg/api/daemon/cluster_grpc_backend.go:95-170). */
export interface BootstrapClusterRequest {
  cluster_name?: string;
  node_name?: string;
}

/** The daemon ignores the proto's other fields (pkg/api/daemon/cluster_grpc_backend.go:95-170). */
export interface JoinClusterRequest {
  node_name?: string;
  seed_addresses?: string[];
}

export interface ClusterMembershipResponse {
  status?: OperationStatus;
  cluster?: ClusterInfo;
  node?: ClusterNode;
}

/** The daemon ignores the proto's other fields (pkg/api/daemon/cluster_grpc_backend.go:95-170). */
export interface LeaveClusterRequest {
  node_id?: string;
  timeout_seconds?: number;
}

export interface LeaveClusterResponse {
  status?: OperationStatus;
}

const CLUSTER_STATE_LABELS: Record<number, string> = {
  [ClusterState.Initializing]: "Initializing",
  [ClusterState.Healthy]: "Healthy",
  [ClusterState.Degraded]: "Degraded",
  [ClusterState.Unavailable]: "Unavailable",
  [ClusterState.Partitioned]: "Partitioned",
};

const NODE_ROLE_LABELS: Record<number, string> = {
  [NodeRole.Leader]: "Leader",
  [NodeRole.Follower]: "Follower",
  [NodeRole.Candidate]: "Candidate",
  [NodeRole.Observer]: "Observer",
};

const NODE_STATE_LABELS: Record<number, string> = {
  [NodeState.Joining]: "Joining",
  [NodeState.Active]: "Active",
  [NodeState.Leaving]: "Leaving",
  [NodeState.Left]: "Left",
  [NodeState.Failed]: "Failed",
  [NodeState.Unreachable]: "Unreachable",
};

export function clusterStateLabel(s?: ClusterState): string {
  return (s !== undefined && CLUSTER_STATE_LABELS[s]) || "Unknown";
}

export function nodeRoleLabel(r?: NodeRole): string {
  return (r !== undefined && NODE_ROLE_LABELS[r]) || "Unknown";
}

export function nodeStateLabel(s?: NodeState): string {
  return (s !== undefined && NODE_STATE_LABELS[s]) || "Unknown";
}

const CLUSTER_BASE = "/v1/cluster";

type Body = Record<string, unknown>;

export function useCluster() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    // No cluster call retries. A 503 "cluster service not configured" is not
    // transient, and a membership write whose response was lost may already
    // have been applied: replaying it would answer "already joined" for a
    // write that succeeded.
    return {
      getStatus: () => api.get<ClusterStatusResponse>(`${CLUSTER_BASE}/status`, { retry: { enabled: false } }),
      listNodes: () => api.get<ClusterNodesResponse>(`${CLUSTER_BASE}/nodes`, { retry: { enabled: false } }),
      bootstrap: (req: BootstrapClusterRequest) =>
        api.post<ClusterMembershipResponse>(`${CLUSTER_BASE}/bootstrap`, req as unknown as Body, { retry: { enabled: false } }),
      join: (req: JoinClusterRequest) =>
        api.post<ClusterMembershipResponse>(`${CLUSTER_BASE}/join`, req as unknown as Body, { retry: { enabled: false } }),
      leave: (req: LeaveClusterRequest) =>
        api.post<LeaveClusterResponse>(`${CLUSTER_BASE}/leave`, req as unknown as Body, { retry: { enabled: false } }),
    };
  }, [client]);
}
