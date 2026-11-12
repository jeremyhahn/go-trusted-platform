/**
 * Unit tests for BackupService
 *
 * Tests backup and restore operations for data protection and disaster
 * recovery including full, incremental, and differential backups.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BackupService } from '../backup-service.js';
import type { ApiClient } from '../../../client/api-client.js';
import type { ApiResponse } from '../../../types/api.js';

// Mock ApiClient
function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
    interceptors: {
      request: { add: vi.fn(), getAll: vi.fn(() => []) },
      response: { add: vi.fn(), getAll: vi.fn(() => []) },
      error: { add: vi.fn(), getAll: vi.fn(() => []) },
    },
    addRequestInterceptor: vi.fn(),
    addResponseInterceptor: vi.fn(),
    addErrorInterceptor: vi.fn(),
  } as unknown as ApiClient;
}

describe('BackupService', () => {
  let service: BackupService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new BackupService(mockClient);
  });

  // =========================================================================
  // create() tests
  // =========================================================================

  describe('create', () => {
    it('should create a full backup', async () => {
      const mockResponse: ApiResponse<{
        backup: { backupId: string; name: string; type: string; state: string };
      }> = {
        success: true,
        data: {
          backup: {
            backupId: 'backup-123',
            name: 'daily-backup-2024-01-15',
            type: 'FULL',
            state: 'IN_PROGRESS',
          },
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.create({
        name: 'daily-backup-2024-01-15',
        type: 'FULL',
      });

      expect(result.success).toBe(true);
      expect(result.data?.backup.backupId).toBe('backup-123');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups', {
        name: 'daily-backup-2024-01-15',
        type: 'FULL',
        baseBackupId: undefined,
        prefixes: undefined,
        location: undefined,
        compression: undefined,
        encryptionKeyId: undefined,
        tags: undefined,
      });
    });

    it('should create an incremental backup', async () => {
      const mockResponse: ApiResponse<{
        backup: { backupId: string; name: string; type: string };
      }> = {
        success: true,
        data: {
          backup: {
            backupId: 'backup-456',
            name: 'hourly-backup',
            type: 'INCREMENTAL',
          },
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        name: 'hourly-backup',
        type: 'INCREMENTAL',
        baseBackupId: 'backup-123',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups', {
        name: 'hourly-backup',
        type: 'INCREMENTAL',
        baseBackupId: 'backup-123',
        prefixes: undefined,
        location: undefined,
        compression: undefined,
        encryptionKeyId: undefined,
        tags: undefined,
      });
    });

    it('should create a backup with compression', async () => {
      const mockResponse: ApiResponse<{
        backup: { backupId: string; name: string };
      }> = {
        success: true,
        data: { backup: { backupId: 'backup-789', name: 'compressed-backup' } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        name: 'compressed-backup',
        type: 'FULL',
        compression: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups', {
        name: 'compressed-backup',
        type: 'FULL',
        baseBackupId: undefined,
        prefixes: undefined,
        location: undefined,
        compression: true,
        encryptionKeyId: undefined,
        tags: undefined,
      });
    });

    it('should create an encrypted backup', async () => {
      const mockResponse: ApiResponse<{
        backup: { backupId: string; name: string };
      }> = {
        success: true,
        data: { backup: { backupId: 'backup-enc', name: 'encrypted-backup' } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        name: 'encrypted-backup',
        type: 'FULL',
        encryptionKeyId: 'key-123',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups', {
        name: 'encrypted-backup',
        type: 'FULL',
        baseBackupId: undefined,
        prefixes: undefined,
        location: undefined,
        compression: undefined,
        encryptionKeyId: 'key-123',
        tags: undefined,
      });
    });

    it('should create a backup with specific prefixes', async () => {
      const mockResponse: ApiResponse<{
        backup: { backupId: string; name: string };
      }> = {
        success: true,
        data: { backup: { backupId: 'backup-partial', name: 'users-backup' } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        name: 'users-backup',
        type: 'FULL',
        prefixes: ['users/', 'profiles/'],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups', {
        name: 'users-backup',
        type: 'FULL',
        baseBackupId: undefined,
        prefixes: ['users/', 'profiles/'],
        location: undefined,
        compression: undefined,
        encryptionKeyId: undefined,
        tags: undefined,
      });
    });

    it('should create a backup with custom location', async () => {
      const mockResponse: ApiResponse<{
        backup: { backupId: string; name: string };
      }> = {
        success: true,
        data: { backup: { backupId: 'backup-s3', name: 's3-backup' } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        name: 's3-backup',
        type: 'FULL',
        location: 's3://bucket/backups/',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups', {
        name: 's3-backup',
        type: 'FULL',
        baseBackupId: undefined,
        prefixes: undefined,
        location: 's3://bucket/backups/',
        compression: undefined,
        encryptionKeyId: undefined,
        tags: undefined,
      });
    });

    it('should create a backup with tags', async () => {
      const mockResponse: ApiResponse<{
        backup: { backupId: string; name: string };
      }> = {
        success: true,
        data: { backup: { backupId: 'backup-tagged', name: 'tagged-backup' } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        name: 'tagged-backup',
        type: 'FULL',
        tags: { schedule: 'daily', environment: 'production' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups', {
        name: 'tagged-backup',
        type: 'FULL',
        baseBackupId: undefined,
        prefixes: undefined,
        location: undefined,
        compression: undefined,
        encryptionKeyId: undefined,
        tags: { schedule: 'daily', environment: 'production' },
      });
    });

    it('should handle backup creation error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'BACKUP_IN_PROGRESS', message: 'Another backup is already in progress' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.create({
        name: 'duplicate-backup',
        type: 'FULL',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('BACKUP_IN_PROGRESS');
    });
  });

  // =========================================================================
  // restore() tests
  // =========================================================================

  describe('restore', () => {
    it('should restore from a backup', async () => {
      const mockResponse: ApiResponse<{
        restoreId: string;
        state: string;
        progress: number;
      }> = {
        success: true,
        data: {
          restoreId: 'restore-123',
          state: 'IN_PROGRESS',
          progress: 0,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.restore({
        backupId: 'backup-123',
      });

      expect(result.success).toBe(true);
      expect(result.data?.restoreId).toBe('restore-123');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups/backup-123/restore', {
        targetPrefix: undefined,
        overwrite: undefined,
        decryptionKeyId: undefined,
      });
    });

    it('should restore with target prefix', async () => {
      const mockResponse: ApiResponse<{ restoreId: string; state: string }> = {
        success: true,
        data: { restoreId: 'restore-456', state: 'IN_PROGRESS' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.restore({
        backupId: 'backup-123',
        targetPrefix: 'restored/',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups/backup-123/restore', {
        targetPrefix: 'restored/',
        overwrite: undefined,
        decryptionKeyId: undefined,
      });
    });

    it('should restore with overwrite option', async () => {
      const mockResponse: ApiResponse<{ restoreId: string; state: string }> = {
        success: true,
        data: { restoreId: 'restore-789', state: 'IN_PROGRESS' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.restore({
        backupId: 'backup-123',
        overwrite: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups/backup-123/restore', {
        targetPrefix: undefined,
        overwrite: true,
        decryptionKeyId: undefined,
      });
    });

    it('should restore with decryption key', async () => {
      const mockResponse: ApiResponse<{ restoreId: string; state: string }> = {
        success: true,
        data: { restoreId: 'restore-dec', state: 'IN_PROGRESS' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.restore({
        backupId: 'backup-encrypted',
        decryptionKeyId: 'key-456',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/backups/backup-encrypted/restore', {
        targetPrefix: undefined,
        overwrite: undefined,
        decryptionKeyId: 'key-456',
      });
    });

    it('should encode backup ID in URL', async () => {
      const mockResponse: ApiResponse<{ restoreId: string; state: string }> = {
        success: true,
        data: { restoreId: 'restore-special', state: 'IN_PROGRESS' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.restore({
        backupId: 'backup/with/slashes',
      });

      expect(mockClient.post).toHaveBeenCalledWith(
        '/v1/quicbaas/backups/backup%2Fwith%2Fslashes/restore',
        expect.anything()
      );
    });

    it('should handle restore error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'BACKUP_NOT_FOUND', message: 'Backup not found' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.restore({
        backupId: 'nonexistent',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('BACKUP_NOT_FOUND');
    });
  });

  // =========================================================================
  // list() tests
  // =========================================================================

  describe('list', () => {
    it('should list all backups', async () => {
      const mockResponse: ApiResponse<{
        backups: Array<{
          backupId: string;
          name: string;
          type: string;
          state: string;
          createdAt: number;
        }>;
      }> = {
        success: true,
        data: {
          backups: [
            { backupId: 'b1', name: 'backup-1', type: 'FULL', state: 'COMPLETED', createdAt: 1700000000000 },
            { backupId: 'b2', name: 'backup-2', type: 'INCREMENTAL', state: 'COMPLETED', createdAt: 1700003600000 },
          ],
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.list();

      expect(result.success).toBe(true);
      expect(result.data?.backups).toHaveLength(2);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/backups');
    });

    it('should list backups by type', async () => {
      const mockResponse: ApiResponse<{ backups: unknown[] }> = {
        success: true,
        data: { backups: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ type: 'FULL' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('type=FULL')
      );
    });

    it('should list backups by state', async () => {
      const mockResponse: ApiResponse<{ backups: unknown[] }> = {
        success: true,
        data: { backups: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ state: 'COMPLETED' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('state=COMPLETED')
      );
    });

    it('should list backups in time range', async () => {
      const mockResponse: ApiResponse<{ backups: unknown[] }> = {
        success: true,
        data: { backups: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({
        startTime: 1700000000000,
        endTime: 1700086400000,
      });

      const call = vi.mocked(mockClient.get).mock.calls[0]![0];
      expect(call).toContain('startTime=1700000000000');
      expect(call).toContain('endTime=1700086400000');
    });

    it('should list backups with pagination', async () => {
      const mockResponse: ApiResponse<{
        backups: unknown[];
        cursor?: string;
      }> = {
        success: true,
        data: { backups: [], cursor: 'next-page' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ limit: 10, cursor: 'current-page' });

      const call = vi.mocked(mockClient.get).mock.calls[0]![0];
      expect(call).toContain('limit=10');
      expect(call).toContain('cursor=current-page');
    });

    it('should handle list error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INTERNAL_ERROR', message: 'Failed to list backups' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.list();

      expect(result.success).toBe(false);
    });
  });

  // =========================================================================
  // delete() tests
  // =========================================================================

  describe('delete', () => {
    it('should delete a backup', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.delete({
        backupId: 'backup-old-123',
      });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({ deleted: true });
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/backups/backup-old-123');
    });

    it('should delete a backup with force option', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.delete({
        backupId: 'backup-with-deps',
        force: true,
      });

      expect(mockClient.delete).toHaveBeenCalledWith(
        expect.stringContaining('force=true')
      );
    });

    it('should encode backup ID in delete URL', async () => {
      const mockResponse: ApiResponse<{ deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.delete({
        backupId: 'backup/special/id',
      });

      expect(mockClient.delete).toHaveBeenCalledWith(
        expect.stringContaining('backup%2Fspecial%2Fid')
      );
    });

    it('should handle delete error for backup with dependencies', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'HAS_DEPENDENCIES', message: 'Backup has dependent incremental backups' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.delete({
        backupId: 'backup-base',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('HAS_DEPENDENCIES');
    });

    it('should handle delete not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Backup not found' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.delete({
        backupId: 'nonexistent',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // getStatus() tests
  // =========================================================================

  describe('getStatus', () => {
    it('should get backup status', async () => {
      const mockResponse: ApiResponse<{
        backup: {
          backupId: string;
          name: string;
          state: string;
          progress: number;
          sizeBytes: number;
        };
      }> = {
        success: true,
        data: {
          backup: {
            backupId: 'backup-123',
            name: 'daily-backup',
            state: 'IN_PROGRESS',
            progress: 75,
            sizeBytes: 1073741824,
          },
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getStatus({
        backupId: 'backup-123',
      });

      expect(result.success).toBe(true);
      expect(result.data?.backup).toMatchObject({ progress: 75 });
      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/backups/backup-123/status');
    });

    it('should get completed backup status', async () => {
      const mockResponse: ApiResponse<{
        backup: {
          backupId: string;
          state: string;
          progress: number;
          completedAt: number;
        };
      }> = {
        success: true,
        data: {
          backup: {
            backupId: 'backup-done',
            state: 'COMPLETED',
            progress: 100,
            completedAt: 1700003600000,
          },
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getStatus({
        backupId: 'backup-done',
      });

      expect(result.success).toBe(true);
      expect(result.data?.backup.state).toBe('COMPLETED');
    });

    it('should encode backup ID in status URL', async () => {
      const mockResponse: ApiResponse<{ backup: { backupId: string; state: string } }> = {
        success: true,
        data: { backup: { backupId: 'special', state: 'COMPLETED' } },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.getStatus({
        backupId: 'backup/with/special',
      });

      expect(mockClient.get).toHaveBeenCalledWith(
        '/v1/quicbaas/backups/backup%2Fwith%2Fspecial/status'
      );
    });

    it('should handle status error for failed backup', async () => {
      const mockResponse: ApiResponse<{
        backup: {
          backupId: string;
          state: string;
          error: string;
        };
      }> = {
        success: true,
        data: {
          backup: {
            backupId: 'backup-failed',
            state: 'FAILED',
            error: 'Insufficient disk space',
          },
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getStatus({
        backupId: 'backup-failed',
      });

      expect(result.success).toBe(true);
      expect(result.data?.backup.state).toBe('FAILED');
    });

    it('should handle status not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Backup not found' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getStatus({
        backupId: 'nonexistent',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });
});
