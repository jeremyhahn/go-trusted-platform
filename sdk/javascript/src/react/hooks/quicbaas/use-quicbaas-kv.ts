/**
 * QuicBaaS KV React Hook
 *
 * Provides access to the QuicBaaS Key-Value service for CRUD operations
 * with watch support for real-time updates.
 *
 * @packageDocumentation
 */

import type { KVService } from '../../../services/quicbaas/kv-service.js';
import { usePlatformClient } from '../../context.js';

/**
 * Hook to access the QuicBaaS Key-Value service
 *
 * Provides methods for key-value CRUD operations including get, put,
 * delete, list, and watch functionality.
 *
 * @returns The KVService instance from the current client
 *
 * @example
 * ```tsx
 * function KeyValueManager() {
 *   const quicBaaSKV = useQuicBaaSKV();
 *
 *   const storeValue = async () => {
 *     const result = await quicBaaSKV.put({
 *       key: 'config/app',
 *       value: btoa(JSON.stringify({ theme: 'dark' })),
 *       ttl: 3600,
 *     });
 *     console.log('Stored version:', result.data?.version);
 *   };
 *
 *   const fetchValue = async () => {
 *     const result = await quicBaaSKV.get({ key: 'config/app' });
 *     if (result.data?.kv) {
 *       const config = JSON.parse(atob(result.data.kv.value));
 *       console.log('Config:', config);
 *     }
 *   };
 *
 *   const listKeys = async () => {
 *     const result = await quicBaaSKV.list({ prefix: 'config/' });
 *     console.log('Keys:', result.data?.kvs.map(kv => kv.key));
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSKV(): KVService {
  const client = usePlatformClient();
  return client.kv;
}
