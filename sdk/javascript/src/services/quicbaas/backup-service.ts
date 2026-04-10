/**
 * QuicBaaS Backup Service
 *
 * Provides backup and restore operations for data protection and disaster
 * recovery including full, incremental, and differential backups.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  CreateBackupRequest,
  CreateBackupResponse,
  RestoreBackupRequest,
  RestoreBackupResponse,
  ListBackupsRequest,
  ListBackupsResponse,
  DeleteBackupRequest,
  DeleteBackupResponse,
  GetBackupStatusRequest,
  GetBackupStatusResponse,
} from '../../types/quicbaas/core-data.js';

/**
 * QuicBaaS Backup Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a full backup
 * const createResult = await client.quicbaas.backup.create({
 *   name: 'daily-backup-2024-01-15',
 *   type: 'FULL',
 *   compression: true,
 *   encryptionKeyId: 'key-123',
 *   tags: { schedule: 'daily' },
 * });
 *
 * // Create an incremental backup
 * const incrementalResult = await client.quicbaas.backup.create({
 *   name: 'hourly-backup-2024-01-15-14',
 *   type: 'INCREMENTAL',
 *   baseBackupId: createResult.data.backup.backupId,
 * });
 *
 * // Check backup status
 * const statusResult = await client.quicbaas.backup.getStatus({
 *   backupId: createResult.data.backup.backupId,
 * });
 *
 * // List all backups
 * const listResult = await client.quicbaas.backup.list({
 *   type: 'FULL',
 *   state: 'COMPLETED',
 * });
 *
 * // Restore from backup
 * const restoreResult = await client.quicbaas.backup.restore({
 *   backupId: createResult.data.backup.backupId,
 *   overwrite: false,
 * });
 *
 * // Delete old backup
 * const deleteResult = await client.quicbaas.backup.delete({
 *   backupId: 'backup-old-123',
 * });
 * ```
 */
export class BackupService extends BaseService {
  /**
   * Creates a new Backup service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Create a new backup
   *
   * Initiates a backup operation with the specified type and options.
   * Supports full, incremental, and differential backup types.
   *
   * @param request - Create backup request with name, type, and options
   * @returns Backup metadata including backup ID
   */
  async create(request: CreateBackupRequest): Promise<ApiResponse<CreateBackupResponse>> {
    return this.client.post<CreateBackupResponse>(
      this.buildUrl('/backups'),
      {
        name: request.name,
        type: request.type,
        baseBackupId: request.baseBackupId,
        prefixes: request.prefixes,
        location: request.location,
        compression: request.compression,
        encryptionKeyId: request.encryptionKeyId,
        tags: request.tags,
      }
    );
  }

  /**
   * Restore from a backup
   *
   * Initiates a restore operation from the specified backup. Supports
   * restoring to a different key prefix and overwrite options.
   *
   * @param request - Restore request with backup ID and options
   * @returns Restore progress information
   */
  async restore(request: RestoreBackupRequest): Promise<ApiResponse<RestoreBackupResponse>> {
    return this.client.post<RestoreBackupResponse>(
      this.buildUrl(`/backups/${this.encodePathSegment(request.backupId)}/restore`),
      {
        targetPrefix: request.targetPrefix,
        overwrite: request.overwrite,
        decryptionKeyId: request.decryptionKeyId,
      }
    );
  }

  /**
   * List all backups
   *
   * Retrieves a list of backups with optional filtering by type, state,
   * and time range.
   *
   * @param request - List backups request with filters
   * @returns List of backup metadata
   */
  async list(request?: ListBackupsRequest): Promise<ApiResponse<ListBackupsResponse>> {
    const params: Record<string, string | number | undefined> = {};

    if (request?.type !== undefined) {
      params.type = request.type;
    }

    if (request?.state !== undefined) {
      params.state = request.state;
    }

    if (request?.startTime !== undefined) {
      params.startTime = request.startTime;
    }

    if (request?.endTime !== undefined) {
      params.endTime = request.endTime;
    }

    if (request?.limit !== undefined) {
      params.limit = request.limit;
    }

    if (request?.cursor !== undefined) {
      params.cursor = request.cursor;
    }

    return this.client.get<ListBackupsResponse>(
      this.buildUrl('/backups', { filters: params })
    );
  }

  /**
   * Delete a backup
   *
   * Removes a backup and its associated data. Use force option to delete
   * backups that are the base for other incremental/differential backups.
   *
   * @param request - Delete backup request with backup ID
   * @returns Deletion confirmation
   */
  async delete(request: DeleteBackupRequest): Promise<ApiResponse<DeleteBackupResponse>> {
    const params: Record<string, string | boolean | undefined> = {};

    if (request.force !== undefined) {
      params.force = request.force;
    }

    return this.client.delete<DeleteBackupResponse>(
      this.buildUrl(`/backups/${this.encodePathSegment(request.backupId)}`, {
        filters: params,
      })
    );
  }

  /**
   * Get backup status
   *
   * Retrieves the current status and progress of a backup operation.
   * Includes progress information for in-progress backups.
   *
   * @param request - Get status request with backup ID
   * @returns Backup metadata and progress information
   */
  async getStatus(request: GetBackupStatusRequest): Promise<ApiResponse<GetBackupStatusResponse>> {
    return this.client.get<GetBackupStatusResponse>(
      this.buildUrl(`/backups/${this.encodePathSegment(request.backupId)}/status`)
    );
  }
}
