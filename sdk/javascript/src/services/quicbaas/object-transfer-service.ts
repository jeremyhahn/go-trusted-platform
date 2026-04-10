/**
 * QuicBaaS Object Transfer Service
 *
 * Provides operations for peer-to-peer data transfer including
 * initiating, monitoring, and managing transfers between nodes.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  InitiateTransferRequest,
  InitiateTransferResponse,
  GetTransferStatusRequest,
  GetTransferStatusResponse,
  CancelTransferRequest,
  CancelTransferResponse,
  ListTransfersRequest,
  ListTransfersResponse,
} from '../../types/quicbaas/infrastructure-part2.js';

/**
 * QuicBaaS Object Transfer Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Initiate a peer-to-peer transfer
 * const transfer = await client.quicbaas.objectTransfer.initiateTransfer({
 *   direction: 'peer_to_peer',
 *   source: {
 *     nodeId: 'node-1',
 *     address: '192.168.1.10:9000',
 *     bucket: 'source-bucket',
 *     key: 'data/file.bin',
 *   },
 *   destination: {
 *     nodeId: 'node-2',
 *     address: '192.168.1.20:9000',
 *     bucket: 'dest-bucket',
 *     key: 'data/file.bin',
 *   },
 *   maxRetries: 3,
 *   priority: 'high',
 * });
 *
 * // Check transfer status
 * const status = await client.quicbaas.objectTransfer.getTransferStatus({
 *   transferId: transfer.data.transfer.id,
 * });
 *
 * // List all transfers
 * const transfers = await client.quicbaas.objectTransfer.listTransfers({
 *   status: 'in_progress',
 * });
 * ```
 */
export class ObjectTransferService extends BaseService {
  /**
   * Creates a new Object Transfer service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // Transfer Operations
  // =========================================================================

  /**
   * Initiate a new data transfer
   *
   * @param request - Transfer initiation request
   * @returns Created transfer
   */
  async initiateTransfer(request: InitiateTransferRequest): Promise<ApiResponse<InitiateTransferResponse>> {
    return this.client.post<InitiateTransferResponse>(
      this.buildUrl('/transfers'),
      request
    );
  }

  /**
   * Get the status of a transfer
   *
   * @param request - Get transfer status request
   * @returns Transfer status and progress
   */
  async getTransferStatus(request: GetTransferStatusRequest): Promise<ApiResponse<GetTransferStatusResponse>> {
    return this.client.get<GetTransferStatusResponse>(
      this.buildUrl(`/transfers/${this.encodePathSegment(request.transferId)}`)
    );
  }

  /**
   * Cancel an in-progress transfer
   *
   * @param request - Cancel transfer request
   * @returns Cancellation result
   */
  async cancelTransfer(request: CancelTransferRequest): Promise<ApiResponse<CancelTransferResponse>> {
    return this.client.post<CancelTransferResponse>(
      this.buildUrl(`/transfers/${this.encodePathSegment(request.transferId)}/cancel`),
      {}
    );
  }

  /**
   * List all transfers with optional filtering
   *
   * @param request - List transfers request with optional filters
   * @returns List of transfers
   */
  async listTransfers(request?: ListTransfersRequest): Promise<ApiResponse<ListTransfersResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request?.status !== undefined) {
      filters.status = request.status;
    }
    if (request?.direction !== undefined) {
      filters.direction = request.direction;
    }
    if (request?.sourceNodeId !== undefined) {
      filters.sourceNodeId = request.sourceNodeId;
    }
    if (request?.destinationNodeId !== undefined) {
      filters.destinationNodeId = request.destinationNodeId;
    }

    return this.client.get<ListTransfersResponse>(
      this.buildUrl('/transfers', {
        page: request?.page,
        limit: request?.pageSize,
        filters,
      })
    );
  }
}
