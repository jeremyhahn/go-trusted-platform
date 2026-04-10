/**
 * QuicBaaS TimeSeries React Hook
 *
 * Provides access to the QuicBaaS TimeSeries service for time-series
 * data operations including insert, query, aggregation, and deletion.
 *
 * @packageDocumentation
 */

import type { TimeSeriesService } from '../../services/quicbaas/timeseries-service.js';
import { usePlatformClient } from '../context.js';

/**
 * Hook to access the QuicBaaS TimeSeries service
 *
 * Provides methods for time-series data operations including inserting
 * data points, querying time ranges, performing aggregations, and
 * managing time-series data lifecycle.
 *
 * @returns The TimeSeriesService instance from the current client
 *
 * @example
 * ```tsx
 * function TimeSeriesManager() {
 *   const timeseries = useQuicBaaSTimeSeries();
 *
 *   const insertDataPoint = async () => {
 *     const result = await timeseries.insert({
 *       metric: 'cpu_usage',
 *       timestamp: Date.now(),
 *       value: 85.5,
 *       tags: { host: 'server-01', region: 'us-east-1' },
 *     });
 *     console.log('Inserted:', result.data);
 *   };
 *
 *   const queryRange = async () => {
 *     const result = await timeseries.query({
 *       metric: 'cpu_usage',
 *       start: Date.now() - 3600000, // 1 hour ago
 *       end: Date.now(),
 *       tags: { host: 'server-01' },
 *     });
 *     console.log('Data points:', result.data?.points);
 *   };
 *
 *   const aggregate = async () => {
 *     const result = await timeseries.aggregate({
 *       metric: 'cpu_usage',
 *       start: Date.now() - 86400000, // 24 hours ago
 *       end: Date.now(),
 *       aggregation: 'avg',
 *       interval: '1h',
 *     });
 *     console.log('Aggregated:', result.data?.buckets);
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSTimeSeries(): TimeSeriesService {
  const client = usePlatformClient();
  return client.quicBaaSTimeSeries;
}
