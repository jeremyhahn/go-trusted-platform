/**
 * Unit tests for TransactionService
 *
 * Tests transaction support including begin/commit/rollback and
 * compare-and-swap (CAS) operations.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TransactionService } from '../transaction-service.js';
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

describe('TransactionService', () => {
  let service: TransactionService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TransactionService(mockClient);
  });

  // =========================================================================
  // begin() tests
  // =========================================================================

  describe('begin', () => {
    it('should begin a transaction with default options', async () => {
      const mockResponse: ApiResponse<{
        transactionId: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          transactionId: 'txn-123',
          expiresAt: Date.now() + 30000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.begin();

      expect(result.success).toBe(true);
      expect(result.data?.transactionId).toBe('txn-123');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions', {
        isolationLevel: undefined,
        timeout: undefined,
        readOnly: undefined,
      });
    });

    it('should begin a transaction with isolation level', async () => {
      const mockResponse: ApiResponse<{
        transactionId: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          transactionId: 'txn-456',
          expiresAt: Date.now() + 30000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.begin({
        isolationLevel: 'SERIALIZABLE',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions', {
        isolationLevel: 'SERIALIZABLE',
        timeout: undefined,
        readOnly: undefined,
      });
    });

    it('should begin a transaction with timeout', async () => {
      const mockResponse: ApiResponse<{
        transactionId: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          transactionId: 'txn-789',
          expiresAt: Date.now() + 60000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.begin({
        timeout: 60,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions', {
        isolationLevel: undefined,
        timeout: 60,
        readOnly: undefined,
      });
    });

    it('should begin a read-only transaction', async () => {
      const mockResponse: ApiResponse<{
        transactionId: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          transactionId: 'txn-readonly',
          expiresAt: Date.now() + 30000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.begin({
        readOnly: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions', {
        isolationLevel: undefined,
        timeout: undefined,
        readOnly: true,
      });
    });

    it('should begin a transaction with all options', async () => {
      const mockResponse: ApiResponse<{
        transactionId: string;
        expiresAt: number;
      }> = {
        success: true,
        data: {
          transactionId: 'txn-all',
          expiresAt: Date.now() + 30000,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.begin({
        isolationLevel: 'READ_COMMITTED',
        timeout: 45,
        readOnly: false,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions', {
        isolationLevel: 'READ_COMMITTED',
        timeout: 45,
        readOnly: false,
      });
    });

    it('should handle transaction limit exceeded error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'TRANSACTION_LIMIT_EXCEEDED', message: 'Too many concurrent transactions' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.begin();

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('TRANSACTION_LIMIT_EXCEEDED');
    });
  });

  // =========================================================================
  // commit() tests
  // =========================================================================

  describe('commit', () => {
    it('should commit a transaction with operations', async () => {
      const mockResponse: ApiResponse<{
        revision: number;
        results?: unknown[];
      }> = {
        success: true,
        data: { revision: 100 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.commit({
        transactionId: 'txn-123',
        operations: [
          { type: 'PUT', key: 'account/123', value: '{"balance": 100}' },
          { type: 'DELETE', key: 'temp/data' },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.data?.revision).toBe(100);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions/txn-123/commit', {
        operations: [
          { type: 'PUT', key: 'account/123', value: '{"balance": 100}' },
          { type: 'DELETE', key: 'temp/data' },
        ],
      });
    });

    it('should commit an empty transaction', async () => {
      const mockResponse: ApiResponse<{ revision: number }> = {
        success: true,
        data: { revision: 101 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.commit({
        transactionId: 'txn-empty',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions/txn-empty/commit', {
        operations: undefined,
      });
    });

    it('should encode transaction ID in URL', async () => {
      const mockResponse: ApiResponse<{ revision: number }> = {
        success: true,
        data: { revision: 102 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.commit({
        transactionId: 'txn/with/slashes',
      });

      expect(mockClient.post).toHaveBeenCalledWith(
        '/v1/quicbaas/transactions/txn%2Fwith%2Fslashes/commit',
        expect.anything()
      );
    });

    it('should handle transaction not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Transaction not found' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.commit({
        transactionId: 'nonexistent',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });

    it('should handle transaction expired error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'TRANSACTION_EXPIRED', message: 'Transaction has expired' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.commit({
        transactionId: 'expired-txn',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('TRANSACTION_EXPIRED');
    });

    it('should handle conflict error on commit', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'CONFLICT', message: 'Transaction conflict detected' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.commit({
        transactionId: 'conflicting-txn',
        operations: [{ type: 'PUT', key: 'shared/key', value: 'data' }],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('CONFLICT');
    });
  });

  // =========================================================================
  // rollback() tests
  // =========================================================================

  describe('rollback', () => {
    it('should rollback a transaction', async () => {
      const mockResponse: ApiResponse<{
        transactionId: string;
        state: string;
      }> = {
        success: true,
        data: { transactionId: 'txn-123', state: 'ABORTED' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.rollback({
        transactionId: 'txn-123',
      });

      expect(result.success).toBe(true);
      expect(result.data?.state).toBe('ABORTED');
      expect(mockClient.post).toHaveBeenCalledWith(
        '/v1/quicbaas/transactions/txn-123/rollback',
        {}
      );
    });

    it('should encode transaction ID in rollback URL', async () => {
      const mockResponse: ApiResponse<{ transactionId: string; state: string }> = {
        success: true,
        data: { transactionId: 'txn/special', state: 'ABORTED' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.rollback({
        transactionId: 'txn/special',
      });

      expect(mockClient.post).toHaveBeenCalledWith(
        '/v1/quicbaas/transactions/txn%2Fspecial/rollback',
        {}
      );
    });

    it('should handle rollback of non-existent transaction', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Transaction not found' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.rollback({
        transactionId: 'nonexistent',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });

    it('should handle rollback of already committed transaction', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_STATE', message: 'Transaction already committed' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.rollback({
        transactionId: 'committed-txn',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_STATE');
    });
  });

  // =========================================================================
  // compareAndSwap() tests
  // =========================================================================

  describe('compareAndSwap', () => {
    it('should execute successful compare-and-swap', async () => {
      const mockResponse: ApiResponse<{
        succeeded: boolean;
        results?: unknown[];
      }> = {
        success: true,
        data: { succeeded: true },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.compareAndSwap({
        conditions: [
          { key: 'counter', target: 'VERSION', operator: 'EQ', value: 5 },
        ],
        onSuccess: [
          { type: 'PUT', key: 'counter', value: '6' },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.data?.succeeded).toBe(true);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions/cas', {
        conditions: [
          { key: 'counter', target: 'VERSION', operator: 'EQ', value: 5 },
        ],
        onSuccess: [
          { type: 'PUT', key: 'counter', value: '6' },
        ],
        onFailure: undefined,
      });
    });

    it('should execute compare-and-swap with onFailure', async () => {
      const mockResponse: ApiResponse<{
        succeeded: boolean;
        results?: Array<{ key: string; value: string }>;
      }> = {
        success: true,
        data: {
          succeeded: false,
          results: [{ key: 'counter', value: '10' }],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.compareAndSwap({
        conditions: [
          { key: 'counter', target: 'VERSION', operator: 'EQ', value: 5 },
        ],
        onSuccess: [
          { type: 'PUT', key: 'counter', value: '6' },
        ],
        onFailure: [
          { type: 'GET', key: 'counter' },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.data?.succeeded).toBe(false);
      expect(result.data?.results).toHaveLength(1);
    });

    it('should handle multiple conditions', async () => {
      const mockResponse: ApiResponse<{ succeeded: boolean }> = {
        success: true,
        data: { succeeded: true },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.compareAndSwap({
        conditions: [
          { key: 'balance/account-1', target: 'VALUE', operator: 'GTE', value: 100 },
          { key: 'balance/account-2', target: 'EXISTS', operator: 'EQ', value: true },
        ],
        onSuccess: [
          { type: 'PUT', key: 'balance/account-1', value: '50' },
          { type: 'PUT', key: 'balance/account-2', value: '150' },
        ],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions/cas', {
        conditions: [
          { key: 'balance/account-1', target: 'VALUE', operator: 'GTE', value: 100 },
          { key: 'balance/account-2', target: 'EXISTS', operator: 'EQ', value: true },
        ],
        onSuccess: [
          { type: 'PUT', key: 'balance/account-1', value: '50' },
          { type: 'PUT', key: 'balance/account-2', value: '150' },
        ],
        onFailure: undefined,
      });
    });

    it('should handle CAS with VERSION target', async () => {
      const mockResponse: ApiResponse<{ succeeded: boolean }> = {
        success: true,
        data: { succeeded: true },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.compareAndSwap({
        conditions: [
          { key: 'doc', target: 'VERSION', operator: 'EQ', value: 42 },
        ],
        onSuccess: [
          { type: 'PUT', key: 'doc', value: 'updated content' },
        ],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/transactions/cas', {
        conditions: [
          { key: 'doc', target: 'VERSION', operator: 'EQ', value: 42 },
        ],
        onSuccess: [
          { type: 'PUT', key: 'doc', value: 'updated content' },
        ],
        onFailure: undefined,
      });
    });

    it('should handle CAS error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_REQUEST', message: 'Invalid CAS conditions' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.compareAndSwap({
        conditions: [],
        onSuccess: [],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_REQUEST');
    });
  });
});
