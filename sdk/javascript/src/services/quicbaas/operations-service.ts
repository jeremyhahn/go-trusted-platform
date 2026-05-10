/**
 * QuicBaaS Operations Service
 *
 * Provides operations for database maintenance including migrations,
 * upgrades, rebalancing, and compaction.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { Transport } from '../../transport/transport.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  MigrateRequest,
  MigrateResponse,
  UpgradeRequest,
  UpgradeResponse,
  RebalanceRequest,
  RebalanceResponse,
  CompactRequest,
  CompactResponse,
  OperationStatusResponse,
  CancelOperationRequest,
  CancelOperationResponse,
} from '../../types/quicbaas/infrastructure-part1.js';

/**
 * QuicBaaS Operations Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Start a migration
 * const migration = await client.quicbaas.operations.migrate({
 *   targetVersion: '2.0.0',
 *   dryRun: false
 * });
 * console.log(`Migration started: ${migration.data.operationId}`);
 *
 * // Check operation status
 * const status = await client.quicbaas.operations.getOperationStatus(
 *   migration.data.operationId
 * );
 * console.log(`Progress: ${status.data.progress}%`);
 *
 * // Start a rebalance operation
 * const rebalance = await client.quicbaas.operations.rebalance({
 *   maxConcurrent: 4
 * });
 *
 * // Compact the database
 * const compact = await client.quicbaas.operations.compact({
 *   full: true
 * });
 * ```
 */
export class OperationsService extends BaseService {
  /**
   * Creates a new Operations service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Start a database migration
   *
   * Initiates a schema or data migration to a target version.
   * Returns an operation ID that can be used to track progress.
   *
   * @param request - Migration request with target version
   * @returns Migration operation details
   */
  async migrate(request: MigrateRequest): Promise<ApiResponse<MigrateResponse>> {
    return this.client.post<MigrateResponse>(this.buildUrl('/operations/migrate'), request);
  }

  /**
   * Start a database upgrade
   *
   * Initiates an upgrade to a new database version. Supports
   * rolling upgrades for zero-downtime deployments.
   *
   * @param request - Upgrade request with target version and strategy
   * @returns Upgrade operation details
   */
  async upgrade(request: UpgradeRequest): Promise<ApiResponse<UpgradeResponse>> {
    return this.client.post<UpgradeResponse>(this.buildUrl('/operations/upgrade'), request);
  }

  /**
   * Start a cluster rebalance
   *
   * Initiates a data rebalancing operation to redistribute
   * partitions across cluster nodes for better load distribution.
   *
   * @param request - Rebalance request with optional target nodes
   * @returns Rebalance operation details
   */
  async rebalance(request?: RebalanceRequest): Promise<ApiResponse<RebalanceResponse>> {
    return this.client.post<RebalanceResponse>(
      this.buildUrl('/operations/rebalance'),
      request ?? {}
    );
  }

  /**
   * Start a compaction operation
   *
   * Initiates a compaction operation to reclaim disk space
   * and optimize storage layout.
   *
   * @param request - Compaction request with optional targets
   * @returns Compaction operation details
   */
  async compact(request?: CompactRequest): Promise<ApiResponse<CompactResponse>> {
    return this.client.post<CompactResponse>(
      this.buildUrl('/operations/compact'),
      request ?? {}
    );
  }

  /**
   * Get operation status
   *
   * Returns the current status and progress of an ongoing or
   * completed operation.
   *
   * @param operationId - The operation ID to check
   * @returns Operation status and progress
   */
  async getOperationStatus(operationId: string): Promise<ApiResponse<OperationStatusResponse>> {
    return this.client.get<OperationStatusResponse>(
      this.buildUrl(`/operations/${this.encodePathSegment(operationId)}`)
    );
  }

  /**
   * Cancel an operation
   *
   * Attempts to cancel an ongoing operation. Not all operations
   * can be cancelled once started.
   *
   * @param request - Cancel request with operation ID
   * @returns Cancellation result
   */
  async cancelOperation(request: CancelOperationRequest): Promise<ApiResponse<CancelOperationResponse>> {
    const url = this.buildUrl(`/operations/${this.encodePathSegment(request.operationId)}/cancel`, {
      filters: {
        force: request.force?.toString(),
      },
    });
    return this.client.post<CancelOperationResponse>(url, {});
  }
}
