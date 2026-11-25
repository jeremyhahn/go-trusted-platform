/**
 * QuicBaaS Cluster Service
 *
 * Provides operations for cluster management including status monitoring,
 * node management, and leadership operations.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { Transport } from '../../transport/transport.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService, type ListOptions } from '../base-service.js';
import type {
  ClusterStatusResponse,
  GetNodesResponse,
  AddNodeRequest,
  AddNodeResponse,
  RemoveNodeRequest,
  RemoveNodeResponse,
  GetLeaderResponse,
  TransferLeadershipRequest,
  TransferLeadershipResponse,
} from '../../types/quicbaas/infrastructure-part1.js';

/**
 * QuicBaaS Cluster Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Get cluster status
 * const status = await client.quicbaas.cluster.getStatus();
 * console.log(`Cluster state: ${status.data.state}`);
 *
 * // List all nodes
 * const nodes = await client.quicbaas.cluster.getNodes();
 * nodes.data.nodes.forEach(node => {
 *   console.log(`Node ${node.nodeId}: ${node.state}`);
 * });
 *
 * // Add a new node
 * const newNode = await client.quicbaas.cluster.addNode({
 *   address: '192.168.1.10:7946',
 *   metadata: { rack: 'rack-1' }
 * });
 * ```
 */
export class ClusterService extends BaseService {
  /**
   * Creates a new Cluster service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Get cluster status
   *
   * Returns the current status of the QuicBaaS cluster including
   * health state, node count, and leader information.
   *
   * @returns Cluster status information
   */
  async getStatus(): Promise<ApiResponse<ClusterStatusResponse>> {
    return this.client.get<ClusterStatusResponse>(this.buildUrl('/cluster/status'));
  }

  /**
   * Get all cluster nodes
   *
   * Returns a list of all nodes in the cluster with their current
   * state, role, and health information.
   *
   * @param options - Optional list options for pagination
   * @returns List of cluster nodes
   */
  async getNodes(options?: ListOptions): Promise<ApiResponse<GetNodesResponse>> {
    return this.client.get<GetNodesResponse>(this.buildUrl('/cluster/nodes', options));
  }

  /**
   * Add a node to the cluster
   *
   * Adds a new node to the QuicBaaS cluster. The node will join
   * as a follower and begin synchronizing data.
   *
   * @param request - Node addition request with address and optional metadata
   * @returns Added node information
   */
  async addNode(request: AddNodeRequest): Promise<ApiResponse<AddNodeResponse>> {
    return this.client.post<AddNodeResponse>(this.buildUrl('/cluster/nodes'), request);
  }

  /**
   * Remove a node from the cluster
   *
   * Removes a node from the QuicBaaS cluster. Data will be
   * redistributed to remaining nodes.
   *
   * @param request - Node removal request with node ID
   * @returns Removal confirmation
   */
  async removeNode(request: RemoveNodeRequest): Promise<ApiResponse<RemoveNodeResponse>> {
    const url = this.buildUrl(`/cluster/nodes/${this.encodePathSegment(request.nodeId)}`, {
      filters: {
        force: request.force?.toString(),
      },
    });
    return this.client.delete<RemoveNodeResponse>(url);
  }

  /**
   * Get current cluster leader
   *
   * Returns information about the current cluster leader node
   * including its address and the current Raft term.
   *
   * @returns Leader node information
   */
  async getLeader(): Promise<ApiResponse<GetLeaderResponse>> {
    return this.client.get<GetLeaderResponse>(this.buildUrl('/cluster/leader'));
  }

  /**
   * Transfer cluster leadership
   *
   * Initiates a leadership transfer to a specified target node.
   * This operation is useful for maintenance or load balancing.
   *
   * @param request - Leadership transfer request with target node ID
   * @returns Transfer result with new leader information
   */
  async transferLeadership(request: TransferLeadershipRequest): Promise<ApiResponse<TransferLeadershipResponse>> {
    return this.client.post<TransferLeadershipResponse>(
      this.buildUrl('/cluster/leader/transfer'),
      request
    );
  }
}
