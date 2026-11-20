/**
 * Cluster Service
 *
 * ClusterService over REST (/v1/cluster): status, nodes, bootstrap, join and
 * leave (#2043). Bodies are protojson (lowerCamelCase field names, enum names
 * as strings).
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';

/** Result status the cluster writes report beside their payload. */
export interface ClusterOperationStatus {
  success?: boolean;
  message?: string;
  code?: number | string;
}

/** One node of the cluster (proto ClusterNode). */
export interface ClusterNode {
  id: string;
  name?: string;
  address?: string;
  port?: number;
  /** NODE_ROLE_* enum name. */
  role?: string;
  /** NODE_STATE_* enum name. */
  state?: string;
  health?: unknown;
  version?: string;
  joinedAt?: string;
  lastHeartbeat?: string;
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

/** Cluster-wide information (proto ClusterInfo). */
export interface ClusterInfo {
  id: string;
  name?: string;
  /** CLUSTER_STATE_* enum name. */
  state?: string;
  leaderId?: string;
  leaderAddress?: string;
  totalNodes?: number;
  healthyNodes?: number;
  term?: number | string;
  createdAt?: string;
  lastElection?: string;
  metadata?: Record<string, string>;
}

export interface GetClusterStatusResponse {
  cluster?: ClusterInfo;
  localNode?: ClusterNode;
  nodes?: ClusterNode[];
  timestamp?: string;
}

export interface ListClusterNodesResponse {
  nodes?: ClusterNode[];
  total?: number;
}

export interface BootstrapClusterRequest {
  clusterName?: string;
  nodeName?: string;
  bindAddress?: string;
  bindPort?: number;
  advertiseAddress?: string;
  advertisePort?: number;
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

export interface BootstrapClusterResponse {
  status?: ClusterOperationStatus;
  cluster?: ClusterInfo;
  node?: ClusterNode;
}

export interface JoinClusterRequest {
  nodeName?: string;
  bindAddress?: string;
  bindPort?: number;
  advertiseAddress?: string;
  advertisePort?: number;
  seedAddresses: string[];
  labels?: Record<string, string>;
  metadata?: Record<string, string>;
}

export interface JoinClusterResponse {
  status?: ClusterOperationStatus;
  cluster?: ClusterInfo;
  node?: ClusterNode;
}

export interface LeaveClusterRequest {
  nodeId?: string;
  force?: boolean;
  timeoutSeconds?: number;
}

export interface LeaveClusterResponse {
  status?: ClusterOperationStatus;
}

/**
 * Platform ClusterService class (not the quicbaas ClusterService at
 * client.cluster).
 *
 * @example
 * ```typescript
 * const status = await client.platformCluster.getStatus();
 * const nodes = await client.platformCluster.listNodes();
 * await client.platformCluster.join({ seedAddresses: ['10.0.0.1:7946'] });
 * ```
 */
export class PlatformClusterService extends BaseService {
  /**
   * Creates a new cluster service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/cluster');
  }

  /** Get the cluster status, leader and local node. */
  async getStatus(): Promise<ApiResponse<GetClusterStatusResponse>> {
    return this.client.get<GetClusterStatusResponse>(this.buildUrl('/status'));
  }

  /** List every node of the cluster. */
  async listNodes(): Promise<ApiResponse<ListClusterNodesResponse>> {
    return this.client.get<ListClusterNodesResponse>(this.buildUrl('/nodes'));
  }

  /** Bootstrap a new cluster with this node as its first leader. */
  async bootstrap(request: BootstrapClusterRequest): Promise<ApiResponse<BootstrapClusterResponse>> {
    return this.client.post<BootstrapClusterResponse>(this.buildUrl('/bootstrap'), request);
  }

  /** Join this node to an existing cluster through its seed addresses. */
  async join(request: JoinClusterRequest): Promise<ApiResponse<JoinClusterResponse>> {
    return this.client.post<JoinClusterResponse>(this.buildUrl('/join'), request);
  }

  /** Remove a node (this node when nodeId is empty) from the cluster. */
  async leave(request: LeaveClusterRequest = {}): Promise<ApiResponse<LeaveClusterResponse>> {
    return this.client.post<LeaveClusterResponse>(this.buildUrl('/leave'), request);
  }
}
