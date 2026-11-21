/**
 * Platform cluster service
 *
 * Calls the daemon's platform cluster routes (`/api/v1/cluster/*`,
 * pkg/api/daemon/cluster_rest.go). These are not the quicbaas cluster routes
 * (`client.cluster`, `/v1/quicbaas/cluster/*`).
 *
 * The server writes the proto structs through encoding/json: fields are
 * snake_case, enums are numbers and timestamps are `{seconds, nanos}`.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Cluster health state. */
export enum PlatformClusterState {
  Unspecified = 0,
  Initializing = 1,
  Healthy = 2,
  Degraded = 3,
  Unavailable = 4,
  Partitioned = 5,
}

/** A node's consensus role. */
export enum PlatformClusterNodeRole {
  Unspecified = 0,
  Leader = 1,
  Follower = 2,
  Candidate = 3,
  Observer = 4,
}

/** A node's membership state. */
export enum PlatformClusterNodeState {
  Unspecified = 0,
  Joining = 1,
  Active = 2,
  Leaving = 3,
  Left = 4,
  Failed = 5,
  Unreachable = 6,
}

/** A protobuf timestamp as encoding/json writes it. */
export interface PlatformClusterTimestamp {
  seconds?: number | string;
  nanos?: number;
}

/** One cluster member. */
export interface PlatformClusterNode {
  id?: string;
  name?: string;
  address?: string;
  port?: number;
  role?: PlatformClusterNodeRole;
  state?: PlatformClusterNodeState;
  health?: number;
  version?: string;
  joined_at?: PlatformClusterTimestamp;
  last_heartbeat?: PlatformClusterTimestamp;
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

/** Cluster-wide information. */
export interface PlatformClusterInfo {
  id?: string;
  name?: string;
  state?: PlatformClusterState;
  leader_id?: string;
  leader_address?: string;
  total_nodes?: number;
  healthy_nodes?: number;
  term?: number | string;
  created_at?: PlatformClusterTimestamp;
  last_election?: PlatformClusterTimestamp;
  metadata?: Record<string, string>;
}

export interface PlatformClusterStatusResponse {
  cluster?: PlatformClusterInfo;
  local_node?: PlatformClusterNode;
  nodes?: PlatformClusterNode[];
  timestamp?: PlatformClusterTimestamp;
}

export interface PlatformClusterNodesResponse {
  nodes?: PlatformClusterNode[];
  total?: number;
}

export interface PlatformClusterBootstrapRequest {
  cluster_name?: string;
  node_name?: string;
  bind_address?: string;
  bind_port?: number;
  advertise_address?: string;
  advertise_port?: number;
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

export interface PlatformClusterJoinRequest {
  node_name?: string;
  bind_address?: string;
  bind_port?: number;
  advertise_address?: string;
  advertise_port?: number;
  seed_addresses?: string[];
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

/** Operation outcome carried by membership responses. */
export interface PlatformClusterOperationStatus {
  success?: boolean;
  message?: string;
}

export interface PlatformClusterMembershipResponse {
  status?: PlatformClusterOperationStatus;
  cluster?: PlatformClusterInfo;
  node?: PlatformClusterNode;
}

export interface PlatformClusterLeaveRequest {
  node_id?: string;
  force?: boolean;
  timeout_seconds?: number;
}

export interface PlatformClusterLeaveResponse {
  status?: PlatformClusterOperationStatus;
}

/**
 * Platform cluster service class
 *
 * Every route answers 503 until the daemon wires a cluster servicer; the
 * service returns the ApiResponse as the transport gives it.
 *
 * @example
 * ```typescript
 * const status = await client.platformCluster.getStatus();
 * const nodes = await client.platformCluster.listNodes();
 * await client.platformCluster.join({ node_name: 'node-1', seed_addresses: ['seed-a:7001'] });
 * ```
 */
export class PlatformClusterService extends BaseService {
  /**
   * Creates a new platform cluster service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/cluster');
  }

  /**
   * Get the cluster status, the local node and the members
   */
  async getStatus(): Promise<ApiResponse<PlatformClusterStatusResponse>> {
    return this.client.get<PlatformClusterStatusResponse>(this.buildUrl('/status'));
  }

  /**
   * List the cluster members
   */
  async listNodes(): Promise<ApiResponse<PlatformClusterNodesResponse>> {
    return this.client.get<PlatformClusterNodesResponse>(this.buildUrl('/nodes'));
  }

  /**
   * Bootstrap a new cluster on this node
   */
  async bootstrap(
    request: PlatformClusterBootstrapRequest
  ): Promise<ApiResponse<PlatformClusterMembershipResponse>> {
    return this.client.post<PlatformClusterMembershipResponse>(this.buildUrl('/bootstrap'), request);
  }

  /**
   * Join this node to an existing cluster through its seed addresses
   */
  async join(request: PlatformClusterJoinRequest): Promise<ApiResponse<PlatformClusterMembershipResponse>> {
    return this.client.post<PlatformClusterMembershipResponse>(this.buildUrl('/join'), request);
  }

  /**
   * Remove a node from the cluster
   */
  async leave(request: PlatformClusterLeaveRequest): Promise<ApiResponse<PlatformClusterLeaveResponse>> {
    return this.client.post<PlatformClusterLeaveResponse>(this.buildUrl('/leave'), request);
  }
}
