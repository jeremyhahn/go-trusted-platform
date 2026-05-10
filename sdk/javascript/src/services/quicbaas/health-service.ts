/**
 * QuicBaaS Health Service
 *
 * Provides health check operations including ping, liveness probes,
 * readiness probes, and metrics collection.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { Transport } from '../../transport/transport.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  PingResponse,
  LivenessResponse,
  ReadinessResponse,
  MetricsResponse,
} from '../../types/quicbaas/infrastructure-part1.js';

/**
 * QuicBaaS Health Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Simple ping check
 * const ping = await client.quicbaas.health.ping();
 * console.log(`Server time: ${ping.data.timestamp}`);
 *
 * // Check liveness (is the service running?)
 * const liveness = await client.quicbaas.health.liveness();
 * if (liveness.data.alive) {
 *   console.log('Service is alive');
 * }
 *
 * // Check readiness (is the service ready to handle requests?)
 * const readiness = await client.quicbaas.health.readiness();
 * if (readiness.data.ready) {
 *   console.log('Service is ready');
 * } else {
 *   readiness.data.checks.forEach(check => {
 *     if (check.status === 'fail') {
 *       console.error(`Check failed: ${check.name} - ${check.message}`);
 *     }
 *   });
 * }
 *
 * // Get metrics
 * const metrics = await client.quicbaas.health.getMetrics();
 * metrics.data.metrics.forEach(metric => {
 *   console.log(`${metric.name}: ${metric.value}`);
 * });
 * ```
 */
export class HealthService extends BaseService {
  /**
   * Creates a new Health service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/quicbaas');
  }

  /**
   * Ping the QuicBaaS service
   *
   * A simple health check that returns immediately if the service
   * is reachable. Useful for basic connectivity testing.
   *
   * @returns Ping response with timestamp and version
   */
  async ping(): Promise<ApiResponse<PingResponse>> {
    return this.client.get<PingResponse>(this.buildUrl('/health/ping'));
  }

  /**
   * Check service liveness
   *
   * Liveness probe for Kubernetes or similar orchestration systems.
   * Returns true if the service is running, even if it's not ready
   * to handle requests.
   *
   * @returns Liveness status
   */
  async liveness(): Promise<ApiResponse<LivenessResponse>> {
    return this.client.get<LivenessResponse>(this.buildUrl('/health/live'));
  }

  /**
   * Check service readiness
   *
   * Readiness probe for Kubernetes or similar orchestration systems.
   * Returns true only if the service is ready to handle requests,
   * including all dependencies being available.
   *
   * @returns Readiness status with individual check results
   */
  async readiness(): Promise<ApiResponse<ReadinessResponse>> {
    return this.client.get<ReadinessResponse>(this.buildUrl('/health/ready'));
  }

  /**
   * Get service metrics
   *
   * Returns current metrics from the QuicBaaS service including
   * counters, gauges, and histograms for monitoring and alerting.
   *
   * @returns Service metrics
   */
  async getMetrics(): Promise<ApiResponse<MetricsResponse>> {
    return this.client.get<MetricsResponse>(this.buildUrl('/health/metrics'));
  }
}
