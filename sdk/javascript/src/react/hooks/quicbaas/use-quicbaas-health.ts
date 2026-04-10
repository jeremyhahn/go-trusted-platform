/**
 * QuicBaaS Health React Hook
 *
 * Provides access to the QuicBaaS Health service for health checks
 * including ping, liveness, readiness probes, and metrics collection.
 *
 * @packageDocumentation
 */

import type { HealthService } from '../../../services/quicbaas/health-service.js';
import { usePlatformClient } from '../../context.js';

/**
 * Hook to access the QuicBaaS Health service
 *
 * Provides methods for health checks suitable for Kubernetes liveness
 * and readiness probes, as well as metrics collection for monitoring.
 *
 * @returns The HealthService instance from the current client
 *
 * @example
 * ```tsx
 * function HealthDashboard() {
 *   const quicBaaSHealth = useQuicBaaSHealth();
 *
 *   const checkPing = async () => {
 *     const result = await quicBaaSHealth.ping();
 *     if (result.data) {
 *       console.log('Server time:', result.data.timestamp);
 *       console.log('Version:', result.data.version);
 *     }
 *   };
 *
 *   const checkLiveness = async () => {
 *     const result = await quicBaaSHealth.liveness();
 *     return result.data?.alive ?? false;
 *   };
 *
 *   const checkReadiness = async () => {
 *     const result = await quicBaaSHealth.readiness();
 *     if (result.data) {
 *       if (!result.data.ready) {
 *         result.data.checks?.forEach(check => {
 *           if (check.status === 'fail') {
 *             console.error(`Check failed: ${check.name} - ${check.message}`);
 *           }
 *         });
 *       }
 *       return result.data.ready;
 *     }
 *     return false;
 *   };
 *
 *   const getMetrics = async () => {
 *     const result = await quicBaaSHealth.getMetrics();
 *     if (result.data) {
 *       result.data.metrics?.forEach(metric => {
 *         console.log(`${metric.name}: ${metric.value}`);
 *       });
 *     }
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSHealth(): HealthService {
  const client = usePlatformClient();
  return client.health;
}
