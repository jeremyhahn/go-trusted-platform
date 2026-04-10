/**
 * QuicBaaS Transaction Service
 *
 * Provides transaction support including begin/commit/rollback and
 * compare-and-swap (CAS) operations for optimistic concurrency control.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  BeginTransactionRequest,
  BeginTransactionResponse,
  CommitTransactionRequest,
  CommitTransactionResponse,
  RollbackTransactionRequest,
  RollbackTransactionResponse,
  CompareAndSwapRequest,
  CompareAndSwapResponse,
} from '../../types/quicbaas/core-data.js';

/**
 * QuicBaaS Transaction Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Begin a transaction
 * const beginResult = await client.quicbaas.transaction.begin({
 *   isolationLevel: 'SERIALIZABLE',
 *   timeout: 30,
 * });
 *
 * // Commit with operations
 * const commitResult = await client.quicbaas.transaction.commit({
 *   transactionId: beginResult.data.transactionId,
 *   operations: [
 *     { type: 'PUT', key: 'account/123', value: btoa('{"balance": 100}') },
 *     { type: 'DELETE', key: 'temp/data' },
 *   ],
 * });
 *
 * // Or rollback on error
 * const rollbackResult = await client.quicbaas.transaction.rollback({
 *   transactionId: beginResult.data.transactionId,
 * });
 *
 * // Compare-and-swap for atomic updates
 * const casResult = await client.quicbaas.transaction.compareAndSwap({
 *   conditions: [
 *     { key: 'counter', target: 'VERSION', operator: 'EQ', value: 5 },
 *   ],
 *   onSuccess: [
 *     { type: 'PUT', key: 'counter', value: btoa('6') },
 *   ],
 *   onFailure: [
 *     { type: 'GET', key: 'counter' },
 *   ],
 * });
 * ```
 */
export class TransactionService extends BaseService {
  /**
   * Creates a new Transaction service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Begin a new transaction
   *
   * Starts a new transaction with the specified isolation level and timeout.
   * Returns a transaction ID that must be used for subsequent operations.
   *
   * @param request - Begin transaction request with isolation level and timeout
   * @returns Transaction ID and metadata
   */
  async begin(request?: BeginTransactionRequest): Promise<ApiResponse<BeginTransactionResponse>> {
    return this.client.post<BeginTransactionResponse>(
      this.buildUrl('/transactions'),
      {
        isolationLevel: request?.isolationLevel,
        timeout: request?.timeout,
        readOnly: request?.readOnly,
      }
    );
  }

  /**
   * Commit a transaction
   *
   * Commits all operations in the transaction atomically. Operations can be
   * provided at commit time or can be executed individually during the
   * transaction and then committed.
   *
   * @param request - Commit request with transaction ID and operations
   * @returns Commit result with revision and any GET results
   */
  async commit(request: CommitTransactionRequest): Promise<ApiResponse<CommitTransactionResponse>> {
    return this.client.post<CommitTransactionResponse>(
      this.buildUrl(`/transactions/${this.encodePathSegment(request.transactionId)}/commit`),
      {
        operations: request.operations,
      }
    );
  }

  /**
   * Rollback a transaction
   *
   * Aborts the transaction and discards all operations. This should be called
   * when an error occurs or the transaction should be cancelled.
   *
   * @param request - Rollback request with transaction ID
   * @returns Rollback result with transaction state
   */
  async rollback(request: RollbackTransactionRequest): Promise<ApiResponse<RollbackTransactionResponse>> {
    return this.client.post<RollbackTransactionResponse>(
      this.buildUrl(`/transactions/${this.encodePathSegment(request.transactionId)}/rollback`),
      {}
    );
  }

  /**
   * Compare-and-swap operation
   *
   * Performs an atomic compare-and-swap operation. Conditions are evaluated
   * atomically, and if all conditions are met, the onSuccess operations are
   * executed. Otherwise, the onFailure operations are executed.
   *
   * This is useful for optimistic concurrency control without holding a
   * transaction open.
   *
   * @param request - CAS request with conditions and success/failure operations
   * @returns CAS result with success flag and operation results
   */
  async compareAndSwap(request: CompareAndSwapRequest): Promise<ApiResponse<CompareAndSwapResponse>> {
    return this.client.post<CompareAndSwapResponse>(
      this.buildUrl('/transactions/cas'),
      {
        conditions: request.conditions,
        onSuccess: request.onSuccess,
        onFailure: request.onFailure,
      }
    );
  }
}
