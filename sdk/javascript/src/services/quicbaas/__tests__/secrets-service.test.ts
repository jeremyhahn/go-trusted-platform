/**
 * Unit tests for QuicBaaSSecretsService
 *
 * Tests secret storage operations with versioning support including
 * create, read, update, delete, and version management.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QuicBaaSSecretsService } from '../secrets-service.js';
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

describe('QuicBaaSSecretsService', () => {
  let service: QuicBaaSSecretsService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new QuicBaaSSecretsService(mockClient);
  });

  // =========================================================================
  // create() tests
  // =========================================================================

  describe('create', () => {
    it('should create a new secret', async () => {
      const mockResponse: ApiResponse<{
        path: string;
        version: number;
        createdAt: number;
      }> = {
        success: true,
        data: {
          path: 'app/config/database',
          version: 1,
          createdAt: Date.now(),
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.create({
        path: 'app/config/database',
        data: {
          username: 'dbuser',
          password: 'securepassword123',
          host: 'db.example.com',
        },
      });

      expect(result.success).toBe(true);
      expect(result.data?.version).toBe(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/secrets/data', {
        path: 'app/config/database',
        data: {
          username: 'dbuser',
          password: 'securepassword123',
          host: 'db.example.com',
        },
      });
    });

    it('should create a secret with type', async () => {
      const mockResponse: ApiResponse<{
        path: string;
        version: number;
        type: string;
      }> = {
        success: true,
        data: {
          path: 'app/config/database',
          version: 1,
          type: 'database',
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        path: 'app/config/database',
        data: { username: 'user', password: 'pass' },
        type: 'database',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/secrets/data', {
        path: 'app/config/database',
        data: { username: 'user', password: 'pass' },
        type: 'database',
      });
    });

    it('should create a secret with tags', async () => {
      const mockResponse: ApiResponse<{
        path: string;
        version: number;
      }> = {
        success: true,
        data: { path: 'app/config/api', version: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.create({
        path: 'app/config/api',
        data: { apiKey: 'key-123' },
        tags: { environment: 'production', team: 'backend' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/secrets/data', {
        path: 'app/config/api',
        data: { apiKey: 'key-123' },
        tags: { environment: 'production', team: 'backend' },
      });
    });

    it('should handle secret already exists error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'ALREADY_EXISTS', message: 'Secret already exists at this path' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.create({
        path: 'existing/secret',
        data: { key: 'value' },
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ALREADY_EXISTS');
    });

    it('should handle invalid path error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_PATH', message: 'Secret path is invalid' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.create({
        path: '../invalid/path',
        data: { key: 'value' },
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_PATH');
    });
  });

  // =========================================================================
  // get() tests
  // =========================================================================

  describe('get', () => {
    it('should get a secret by path', async () => {
      const mockResponse: ApiResponse<{
        data: Record<string, string>;
        metadata: { version: number; createdAt: number };
      }> = {
        success: true,
        data: {
          data: { username: 'dbuser', password: 'secret' },
          metadata: { version: 1, createdAt: Date.now() },
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.get({
        path: 'app/config/database',
      });

      expect(result.success).toBe(true);
      expect(result.data?.data?.username).toBe('dbuser');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/secrets/data/app%2Fconfig%2Fdatabase');
    });

    it('should get a specific version of a secret', async () => {
      const mockResponse: ApiResponse<{
        data: Record<string, string>;
        metadata: { version: number };
      }> = {
        success: true,
        data: {
          data: { password: 'old-password' },
          metadata: { version: 1 },
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.get({
        path: 'app/config/database',
        version: 1,
      });

      expect(mockClient.get).toHaveBeenCalledWith(
        '/v1/quicbaas/secrets/data/app%2Fconfig%2Fdatabase?version=1'
      );
    });

    it('should handle secret not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Secret not found' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.get({
        path: 'nonexistent/secret',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });

    it('should encode special characters in path', async () => {
      const mockResponse: ApiResponse<{ data: Record<string, string> }> = {
        success: true,
        data: { data: { key: 'value' } },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.get({
        path: 'path/with spaces/key',
      });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('path%2Fwith%20spaces%2Fkey')
      );
    });
  });

  // =========================================================================
  // update() tests
  // =========================================================================

  describe('update', () => {
    it('should update a secret', async () => {
      const mockResponse: ApiResponse<{
        path: string;
        version: number;
        updatedAt: number;
      }> = {
        success: true,
        data: {
          path: 'app/config/database',
          version: 2,
          updatedAt: Date.now(),
        },
      };
      vi.mocked(mockClient.put).mockResolvedValue(mockResponse);

      const result = await service.update({
        path: 'app/config/database',
        data: {
          username: 'dbuser',
          password: 'newpassword456',
        },
      });

      expect(result.success).toBe(true);
      expect(result.data?.version).toBe(2);
      expect(mockClient.put).toHaveBeenCalledWith('/v1/quicbaas/secrets/data/app%2Fconfig%2Fdatabase', {
        data: { username: 'dbuser', password: 'newpassword456' },
        cas: undefined,
      });
    });

    it('should update with CAS (check-and-set)', async () => {
      const mockResponse: ApiResponse<{
        path: string;
        version: number;
      }> = {
        success: true,
        data: { path: 'app/config/api', version: 3 },
      };
      vi.mocked(mockClient.put).mockResolvedValue(mockResponse);

      await service.update({
        path: 'app/config/api',
        data: { apiKey: 'new-key' },
        cas: 2,
      });

      expect(mockClient.put).toHaveBeenCalledWith('/v1/quicbaas/secrets/data/app%2Fconfig%2Fapi', {
        data: { apiKey: 'new-key' },
        cas: 2,
      });
    });

    it('should handle CAS conflict error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'CAS_MISMATCH', message: 'Version mismatch, secret was modified' },
      };
      vi.mocked(mockClient.put).mockResolvedValue(mockResponse);

      const result = await service.update({
        path: 'app/config/database',
        data: { password: 'new' },
        cas: 1,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('CAS_MISMATCH');
    });

    it('should handle update not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Secret not found' },
      };
      vi.mocked(mockClient.put).mockResolvedValue(mockResponse);

      const result = await service.update({
        path: 'nonexistent/secret',
        data: { key: 'value' },
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // delete() tests
  // =========================================================================

  describe('delete', () => {
    it('should soft delete a secret', async () => {
      const mockResponse: ApiResponse<{
        deleted: boolean;
        deletedVersions: number[];
      }> = {
        success: true,
        data: { deleted: true, deletedVersions: [1, 2, 3] },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.delete({
        path: 'app/config/database',
      });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({ deleted: true });
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/quicbaas/secrets/data/app%2Fconfig%2Fdatabase');
    });

    it('should permanently delete a secret', async () => {
      const mockResponse: ApiResponse<{
        deleted: boolean;
        permanent: boolean;
      }> = {
        success: true,
        data: { deleted: true, permanent: true },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.delete({
        path: 'app/config/database',
        permanent: true,
      });

      expect(mockClient.delete).toHaveBeenCalledWith(
        expect.stringContaining('permanent=true')
      );
    });

    it('should delete specific versions', async () => {
      const mockResponse: ApiResponse<{
        deleted: boolean;
        deletedVersions: number[];
      }> = {
        success: true,
        data: { deleted: true, deletedVersions: [1, 2] },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      await service.delete({
        path: 'app/config/database',
        versions: [1, 2],
      });

      expect(mockClient.delete).toHaveBeenCalledWith(
        expect.stringContaining('versions=1%2C2')
      );
    });

    it('should handle delete not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Secret not found' },
      };
      vi.mocked(mockClient.delete).mockResolvedValue(mockResponse);

      const result = await service.delete({
        path: 'nonexistent/secret',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // list() tests
  // =========================================================================

  describe('list', () => {
    it('should list all secrets', async () => {
      const mockResponse: ApiResponse<{
        secrets: Array<{ path: string; type?: string; version: number }>;
        totalCount: number;
      }> = {
        success: true,
        data: {
          secrets: [
            { path: 'app/config/database', type: 'database', version: 2 },
            { path: 'app/config/api', type: 'kv', version: 1 },
          ],
          totalCount: 2,
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.list();

      expect(result.success).toBe(true);
      expect(result.data?.secrets).toHaveLength(2);
      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/v1/quicbaas/secrets/metadata')
      );
    });

    it('should list secrets with path prefix', async () => {
      const mockResponse: ApiResponse<{
        secrets: Array<{ path: string }>;
        totalCount: number;
      }> = {
        success: true,
        data: { secrets: [], totalCount: 0 },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ pathPrefix: 'app/config/' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('pathPrefix=app%2Fconfig%2F')
      );
    });

    it('should list secrets by type', async () => {
      const mockResponse: ApiResponse<{
        secrets: Array<{ path: string; type: string }>;
        totalCount: number;
      }> = {
        success: true,
        data: { secrets: [], totalCount: 0 },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ type: 'database' });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('type=database')
      );
    });

    it('should list secrets with pagination', async () => {
      const mockResponse: ApiResponse<{
        secrets: unknown[];
        totalCount: number;
      }> = {
        success: true,
        data: { secrets: [], totalCount: 100 },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ page: 2, pageSize: 10 });

      const call = vi.mocked(mockClient.get).mock.calls[0]?.[0];
      expect(call).toContain('page=2');
      expect(call).toContain('limit=10');
    });

    it('should list including deleted secrets', async () => {
      const mockResponse: ApiResponse<{
        secrets: unknown[];
        totalCount: number;
      }> = {
        success: true,
        data: { secrets: [], totalCount: 0 },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.list({ includeDeleted: true });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('includeDeleted=true')
      );
    });
  });

  // =========================================================================
  // getVersion() tests
  // =========================================================================

  describe('getVersion', () => {
    it('should get a specific version of a secret', async () => {
      const mockResponse: ApiResponse<{
        data: Record<string, string>;
        version: number;
        createdAt: number;
      }> = {
        success: true,
        data: {
          data: { password: 'old-password' },
          version: 1,
          createdAt: 1700000000000,
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getVersion({
        path: 'app/config/database',
        version: 1,
      });

      expect(result.success).toBe(true);
      expect(result.data).toMatchObject({ version: 1 });
      expect(mockClient.get).toHaveBeenCalledWith(
        '/v1/quicbaas/secrets/data/app%2Fconfig%2Fdatabase/versions/1'
      );
    });

    it('should handle version not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Version not found' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getVersion({
        path: 'app/config/database',
        version: 999,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // listVersions() tests
  // =========================================================================

  describe('listVersions', () => {
    it('should list all versions of a secret', async () => {
      const mockResponse: ApiResponse<{
        versions: Array<{ version: number; createdAt: number; deleted: boolean }>;
        totalCount: number;
      }> = {
        success: true,
        data: {
          versions: [
            { version: 3, createdAt: 1700003600000, deleted: false },
            { version: 2, createdAt: 1700000000000, deleted: false },
            { version: 1, createdAt: 1699996400000, deleted: true },
          ],
          totalCount: 3,
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.listVersions({
        path: 'app/config/database',
      });

      expect(result.success).toBe(true);
      expect(result.data?.versions).toHaveLength(3);
      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/v1/quicbaas/secrets/data/app%2Fconfig%2Fdatabase/versions')
      );
    });

    it('should list versions with pagination', async () => {
      const mockResponse: ApiResponse<{
        versions: unknown[];
        totalCount: number;
      }> = {
        success: true,
        data: { versions: [], totalCount: 50 },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listVersions({
        path: 'app/config/database',
        page: 2,
        pageSize: 10,
      });

      const call = vi.mocked(mockClient.get).mock.calls[0]?.[0];
      expect(call).toContain('page=2');
      expect(call).toContain('limit=10');
    });

    it('should handle list versions not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Secret not found' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.listVersions({
        path: 'nonexistent/secret',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });
  });

  // =========================================================================
  // rotateSecret() tests
  // =========================================================================

  describe('rotateSecret', () => {
    it('should rotate a secret', async () => {
      const mockResponse: ApiResponse<{
        oldVersion: number;
        newVersion: number;
        rotatedAt: number;
      }> = {
        success: true,
        data: {
          oldVersion: 2,
          newVersion: 3,
          rotatedAt: Date.now(),
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.rotateSecret({
        path: 'app/config/database',
      });

      expect(result.success).toBe(true);
      expect(result.data?.newVersion).toBe(3);
      expect(mockClient.post).toHaveBeenCalledWith(
        '/v1/quicbaas/secrets/data/app%2Fconfig%2Fdatabase/rotate',
        { newData: undefined }
      );
    });

    it('should rotate with new data', async () => {
      const mockResponse: ApiResponse<{
        oldVersion: number;
        newVersion: number;
      }> = {
        success: true,
        data: { oldVersion: 1, newVersion: 2 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.rotateSecret({
        path: 'app/config/api',
        newData: { apiKey: 'new-rotated-key' },
      });

      expect(mockClient.post).toHaveBeenCalledWith(
        '/v1/quicbaas/secrets/data/app%2Fconfig%2Fapi/rotate',
        { newData: { apiKey: 'new-rotated-key' } }
      );
    });

    it('should handle rotate not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Secret not found' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.rotateSecret({
        path: 'nonexistent/secret',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });

    it('should handle rotation not supported error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'ROTATION_NOT_SUPPORTED', message: 'Secret type does not support automatic rotation' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.rotateSecret({
        path: 'app/config/static',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('ROTATION_NOT_SUPPORTED');
    });
  });
});
