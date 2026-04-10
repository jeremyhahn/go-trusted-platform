/**
 * QuicBaaS Cache React Hook
 *
 * Provides access to the QuicBaaS Cache service for distributed
 * cache management including get, put, delete, and statistics.
 *
 * @packageDocumentation
 */

import type { CacheService } from '../../../services/quicbaas/cache-service.js';
import { usePlatformClient } from '../../context.js';

/**
 * Hook to access the QuicBaaS Cache service
 *
 * Provides methods for cache operations including storing, retrieving,
 * and deleting cached values with TTL support and statistics.
 *
 * @returns The CacheService instance from the current client
 *
 * @example
 * ```tsx
 * function CacheManager() {
 *   const quicBaaSCache = useQuicBaaSCache();
 *
 *   const cacheValue = async () => {
 *     const result = await quicBaaSCache.put({
 *       key: 'user:123',
 *       value: JSON.stringify({ name: 'John', email: 'john@example.com' }),
 *       valueType: 'json',
 *       ttlSeconds: 3600,
 *     });
 *     console.log('Cached:', result.data?.created);
 *   };
 *
 *   const getCachedValue = async () => {
 *     const result = await quicBaaSCache.get({ key: 'user:123' });
 *     if (result.data?.found) {
 *       const user = JSON.parse(result.data.value);
 *       return user;
 *     }
 *     return null;
 *   };
 *
 *   const getStats = async () => {
 *     const result = await quicBaaSCache.getStats();
 *     if (result.data) {
 *       console.log(`Hit ratio: ${(result.data.hitRatio * 100).toFixed(2)}%`);
 *     }
 *   };
 *
 *   const clearByPattern = async () => {
 *     const result = await quicBaaSCache.clear({ pattern: 'user:*' });
 *     console.log('Cleared entries:', result.data?.clearedCount);
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSCache(): CacheService {
  const client = usePlatformClient();
  return client.cache;
}
