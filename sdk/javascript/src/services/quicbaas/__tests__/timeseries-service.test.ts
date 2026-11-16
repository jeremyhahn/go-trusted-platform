/**
 * Unit tests for TimeSeriesService
 *
 * Tests time-series data operations including insert, query, aggregation,
 * and range deletion for metrics and telemetry data.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { TimeSeriesService } from '../timeseries-service.js';
import type { ApiClient } from '../../../client/api-client.js';
import type { ApiResponse } from '../../../types/api.js';
import type { TimeBucket } from '../../../types/quicbaas/core-data.js';

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

/** `expect.any` is typed `any`; naming it once keeps the assertions typed. */
const anyNumber = expect.any(Number) as unknown as number;

describe('TimeSeriesService', () => {
  let service: TimeSeriesService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new TimeSeriesService(mockClient);
  });

  // =========================================================================
  // insert() tests
  // =========================================================================

  describe('insert', () => {
    it('should insert time-series data points', async () => {
      const mockResponse: ApiResponse<{ insertedCount: number }> = {
        success: true,
        data: { insertedCount: 2 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const now = Date.now();
      const result = await service.insert({
        metric: 'cpu.usage',
        dataPoints: [
          { timestamp: now, value: 45.2, tags: { host: 'server-1' } },
          { timestamp: now + 1000, value: 52.1, tags: { host: 'server-2' } },
        ],
      });

      expect(result.success).toBe(true);
      expect(result.data?.insertedCount).toBe(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries', {
        metric: 'cpu.usage',
        dataPoints: [
          { timestamp: now, value: 45.2, tags: { host: 'server-1' } },
          { timestamp: now + 1000, value: 52.1, tags: { host: 'server-2' } },
        ],
        retention: undefined,
      });
    });

    it('should insert with retention period', async () => {
      const mockResponse: ApiResponse<{ insertedCount: number }> = {
        success: true,
        data: { insertedCount: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.insert({
        metric: 'cpu.usage',
        dataPoints: [{ timestamp: Date.now(), value: 45.2 }],
        retention: 86400 * 30, // 30 days
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries', {
        metric: 'cpu.usage',
        dataPoints: [{ timestamp: anyNumber, value: 45.2 }],
        retention: 86400 * 30,
      });
    });

    it('should insert data points without tags', async () => {
      const mockResponse: ApiResponse<{ insertedCount: number }> = {
        success: true,
        data: { insertedCount: 1 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.insert({
        metric: 'system.memory',
        dataPoints: [{ timestamp: Date.now(), value: 8192 }],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries', {
        metric: 'system.memory',
        dataPoints: [{ timestamp: anyNumber, value: 8192 }],
        retention: undefined,
      });
    });

    it('should handle insert error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_METRIC', message: 'Invalid metric name' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.insert({
        metric: '',
        dataPoints: [{ timestamp: Date.now(), value: 1 }],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_METRIC');
    });

    it('should handle empty data points error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_REQUEST', message: 'Data points cannot be empty' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.insert({
        metric: 'cpu.usage',
        dataPoints: [],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_REQUEST');
    });
  });

  // =========================================================================
  // query() tests
  // =========================================================================

  describe('query', () => {
    it('should query time-series data', async () => {
      const mockResponse: ApiResponse<{
        dataPoints: Array<{ timestamp: number; value: number; tags?: Record<string, string> }>;
      }> = {
        success: true,
        data: {
          dataPoints: [
            { timestamp: 1700000000000, value: 45.2, tags: { host: 'server-1' } },
            { timestamp: 1700000001000, value: 46.5, tags: { host: 'server-1' } },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.query({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
      });

      expect(result.success).toBe(true);
      expect(result.data?.dataPoints).toHaveLength(2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/query', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
        tags: undefined,
        limit: undefined,
        order: undefined,
      });
    });

    it('should query with tag filter', async () => {
      const mockResponse: ApiResponse<{ dataPoints: unknown[] }> = {
        success: true,
        data: { dataPoints: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
        tags: { host: 'server-1' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/query', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
        tags: { host: 'server-1' },
        limit: undefined,
        order: undefined,
      });
    });

    it('should query with limit', async () => {
      const mockResponse: ApiResponse<{ dataPoints: unknown[] }> = {
        success: true,
        data: { dataPoints: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
        limit: 100,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/query', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
        tags: undefined,
        limit: 100,
        order: undefined,
      });
    });

    it('should query with descending order', async () => {
      const mockResponse: ApiResponse<{ dataPoints: unknown[] }> = {
        success: true,
        data: { dataPoints: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.query({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
        order: 'DESC',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/query', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700003600000,
        tags: undefined,
        limit: undefined,
        order: 'DESC',
      });
    });

    it('should handle query error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'METRIC_NOT_FOUND', message: 'Metric not found' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.query({
        metric: 'nonexistent.metric',
        startTime: 1700000000000,
        endTime: 1700003600000,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('METRIC_NOT_FOUND');
    });
  });

  // =========================================================================
  // aggregate() tests
  // =========================================================================

  describe('aggregate', () => {
    it('should aggregate time-series data', async () => {
      const mockResponse: ApiResponse<{
        buckets: Array<{
          timestamp: number;
          values: Record<string, number>;
        }>;
      }> = {
        success: true,
        data: {
          buckets: [
            { timestamp: 1700000000000, values: { avg: 45.5, max: 52.0 } },
            { timestamp: 1700003600000, values: { avg: 48.2, max: 55.0 } },
          ],
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.aggregate({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'HOUR',
        aggregations: [{ function: 'AVG' }, { function: 'MAX' }],
      });

      expect(result.success).toBe(true);
      expect(result.data).toHaveProperty(['buckets', 'length'], 2);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/aggregate', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'HOUR',
        bucketSize: undefined,
        aggregations: [{ function: 'AVG' }, { function: 'MAX' }],
        tags: undefined,
        groupBy: undefined,
        fill: undefined,
      });
    });

    it('should aggregate with percentile', async () => {
      const mockResponse: ApiResponse<{ buckets: unknown[] }> = {
        success: true,
        data: { buckets: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.aggregate({
        metric: 'latency',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'MINUTE',
        aggregations: [{ function: 'PERCENTILE', percentile: 95 }],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/aggregate', {
        metric: 'latency',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'MINUTE',
        bucketSize: undefined,
        aggregations: [{ function: 'PERCENTILE', percentile: 95 }],
        tags: undefined,
        groupBy: undefined,
        fill: undefined,
      });
    });

    it('should aggregate with groupBy', async () => {
      const mockResponse: ApiResponse<{ buckets: unknown[] }> = {
        success: true,
        data: { buckets: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.aggregate({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'HOUR',
        aggregations: [{ function: 'AVG' }],
        groupBy: ['host', 'datacenter'],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/aggregate', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'HOUR',
        bucketSize: undefined,
        aggregations: [{ function: 'AVG' }],
        tags: undefined,
        groupBy: ['host', 'datacenter'],
        fill: undefined,
      });
    });

    it('should aggregate with fill strategy', async () => {
      const mockResponse: ApiResponse<{ buckets: unknown[] }> = {
        success: true,
        data: { buckets: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.aggregate({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'HOUR',
        aggregations: [{ function: 'AVG' }],
        fill: 'PREVIOUS',
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/aggregate', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'HOUR',
        bucketSize: undefined,
        aggregations: [{ function: 'AVG' }],
        tags: undefined,
        groupBy: undefined,
        fill: 'PREVIOUS',
      });
    });

    it('should aggregate with custom bucket size', async () => {
      const mockResponse: ApiResponse<{ buckets: unknown[] }> = {
        success: true,
        data: { buckets: [] },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.aggregate({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'CUSTOM' as TimeBucket,
        bucketSize: 300000, // 5 minutes
        aggregations: [{ function: 'AVG' }],
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/aggregate', {
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'CUSTOM',
        bucketSize: 300000,
        aggregations: [{ function: 'AVG' }],
        tags: undefined,
        groupBy: undefined,
        fill: undefined,
      });
    });

    it('should handle aggregate error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_AGGREGATION', message: 'Invalid aggregation function' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.aggregate({
        metric: 'cpu.usage',
        startTime: 1700000000000,
        endTime: 1700086400000,
        bucket: 'HOUR',
        aggregations: [],
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_AGGREGATION');
    });
  });

  // =========================================================================
  // deleteRange() tests
  // =========================================================================

  describe('deleteRange', () => {
    it('should delete data in time range', async () => {
      const mockResponse: ApiResponse<{ deletedCount: number }> = {
        success: true,
        data: { deletedCount: 1000 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.deleteRange({
        metric: 'cpu.usage',
        startTime: 0,
        endTime: 1700000000000,
      });

      expect(result.success).toBe(true);
      expect(result.data?.deletedCount).toBe(1000);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/delete', {
        metric: 'cpu.usage',
        startTime: 0,
        endTime: 1700000000000,
        tags: undefined,
      });
    });

    it('should delete data with tag filter', async () => {
      const mockResponse: ApiResponse<{ deletedCount: number }> = {
        success: true,
        data: { deletedCount: 500 },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.deleteRange({
        metric: 'cpu.usage',
        startTime: 0,
        endTime: 1700000000000,
        tags: { host: 'decommissioned-server' },
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/timeseries/delete', {
        metric: 'cpu.usage',
        startTime: 0,
        endTime: 1700000000000,
        tags: { host: 'decommissioned-server' },
      });
    });

    it('should handle delete range error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'PERMISSION_DENIED', message: 'Cannot delete protected metrics' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.deleteRange({
        metric: 'system.critical',
        startTime: 0,
        endTime: Date.now(),
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('PERMISSION_DENIED');
    });

    it('should handle invalid time range error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_REQUEST', message: 'Start time must be before end time' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.deleteRange({
        metric: 'cpu.usage',
        startTime: 2000000000000,
        endTime: 1000000000000,
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_REQUEST');
    });
  });
});
