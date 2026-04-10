/**
 * QuicBaaS Time-Series Service
 *
 * Provides time-series data operations including insert, query, aggregation,
 * and range deletion for metrics and telemetry data.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  TimeSeriesInsertRequest,
  TimeSeriesInsertResponse,
  TimeSeriesQueryRequest,
  TimeSeriesQueryResponse,
  TimeSeriesAggregateRequest,
  TimeSeriesAggregateResponse,
  TimeSeriesDeleteRangeRequest,
  TimeSeriesDeleteRangeResponse,
} from '../../types/quicbaas/core-data.js';

/**
 * QuicBaaS Time-Series Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Insert time-series data points
 * const insertResult = await client.quicbaas.timeseries.insert({
 *   metric: 'cpu.usage',
 *   dataPoints: [
 *     { timestamp: Date.now(), value: 45.2, tags: { host: 'server-1' } },
 *     { timestamp: Date.now(), value: 52.1, tags: { host: 'server-2' } },
 *   ],
 *   retention: 86400 * 30, // 30 days
 * });
 *
 * // Query time-series data
 * const queryResult = await client.quicbaas.timeseries.query({
 *   metric: 'cpu.usage',
 *   startTime: Date.now() - 3600000, // Last hour
 *   endTime: Date.now(),
 *   tags: { host: 'server-1' },
 * });
 *
 * // Aggregate time-series data
 * const aggregateResult = await client.quicbaas.timeseries.aggregate({
 *   metric: 'cpu.usage',
 *   startTime: Date.now() - 86400000, // Last 24 hours
 *   endTime: Date.now(),
 *   bucket: 'HOUR',
 *   aggregations: [
 *     { function: 'AVG' },
 *     { function: 'MAX' },
 *     { function: 'PERCENTILE', percentile: 95 },
 *   ],
 *   groupBy: ['host'],
 * });
 *
 * // Delete old data
 * const deleteResult = await client.quicbaas.timeseries.deleteRange({
 *   metric: 'cpu.usage',
 *   startTime: 0,
 *   endTime: Date.now() - 86400000 * 90, // Older than 90 days
 * });
 * ```
 */
export class TimeSeriesService extends BaseService {
  /**
   * Creates a new Time-Series service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Insert time-series data points
   *
   * Stores multiple data points for a metric with optional tags and retention
   * period. Data points are stored with nanosecond precision.
   *
   * @param request - Insert request with metric, data points, and retention
   * @returns Insert result with count of inserted points
   */
  async insert(request: TimeSeriesInsertRequest): Promise<ApiResponse<TimeSeriesInsertResponse>> {
    return this.client.post<TimeSeriesInsertResponse>(
      this.buildUrl('/timeseries'),
      {
        metric: request.metric,
        dataPoints: request.dataPoints,
        retention: request.retention,
      }
    );
  }

  /**
   * Query time-series data points
   *
   * Retrieves data points for a metric within a time range. Supports filtering
   * by tags and pagination for large result sets.
   *
   * @param request - Query request with metric, time range, and filters
   * @returns Query result with data points
   */
  async query(request: TimeSeriesQueryRequest): Promise<ApiResponse<TimeSeriesQueryResponse>> {
    return this.client.post<TimeSeriesQueryResponse>(
      this.buildUrl('/timeseries/query'),
      {
        metric: request.metric,
        startTime: request.startTime,
        endTime: request.endTime,
        tags: request.tags,
        limit: request.limit,
        order: request.order,
      }
    );
  }

  /**
   * Aggregate time-series data
   *
   * Computes aggregations over time-series data with flexible bucketing and
   * grouping options. Supports multiple aggregation functions including
   * statistical operations.
   *
   * @param request - Aggregate request with metric, time range, and aggregations
   * @returns Aggregation results with bucketed values
   */
  async aggregate(request: TimeSeriesAggregateRequest): Promise<ApiResponse<TimeSeriesAggregateResponse>> {
    return this.client.post<TimeSeriesAggregateResponse>(
      this.buildUrl('/timeseries/aggregate'),
      {
        metric: request.metric,
        startTime: request.startTime,
        endTime: request.endTime,
        bucket: request.bucket,
        bucketSize: request.bucketSize,
        aggregations: request.aggregations,
        tags: request.tags,
        groupBy: request.groupBy,
        fill: request.fill,
      }
    );
  }

  /**
   * Delete time-series data in a time range
   *
   * Removes data points for a metric within a time range. Supports filtering
   * by tags to selectively delete data.
   *
   * @param request - Delete range request with metric, time range, and filters
   * @returns Delete result with count of deleted points
   */
  async deleteRange(request: TimeSeriesDeleteRangeRequest): Promise<ApiResponse<TimeSeriesDeleteRangeResponse>> {
    return this.client.post<TimeSeriesDeleteRangeResponse>(
      this.buildUrl('/timeseries/delete'),
      {
        metric: request.metric,
        startTime: request.startTime,
        endTime: request.endTime,
        tags: request.tags,
      }
    );
  }
}
