/**
 * QuicBaaS Secrets React Hook
 *
 * Provides access to the QuicBaaS Secrets service for secure secret
 * storage with versioning, rotation, and lifecycle management.
 *
 * @packageDocumentation
 */

import type { QuicBaaSSecretsService } from '../../../services/quicbaas/secrets-service.js';
import { usePlatformClient } from '../../context.js';

/**
 * Hook to access the QuicBaaS Secrets service
 *
 * Provides methods for secret CRUD operations, version management,
 * and secret rotation with support for tagging and expiration.
 *
 * @returns The QuicBaaSSecretsService instance from the current client
 *
 * @example
 * ```tsx
 * function SecretsManager() {
 *   const quicBaaSSecrets = useQuicBaaSSecrets();
 *
 *   const createSecret = async () => {
 *     const result = await quicBaaSSecrets.create({
 *       path: 'app/database/credentials',
 *       data: {
 *         username: 'dbuser',
 *         password: 'securepass123',
 *         host: 'db.example.com',
 *       },
 *       type: 'database',
 *       tags: { environment: 'production' },
 *     });
 *     console.log('Created secret version:', result.data?.metadata.version);
 *   };
 *
 *   const getSecret = async () => {
 *     const result = await quicBaaSSecrets.get({ path: 'app/database/credentials' });
 *     if (result.data?.data) {
 *       console.log('Host:', result.data.data.host);
 *     }
 *   };
 *
 *   const rotateSecret = async () => {
 *     const result = await quicBaaSSecrets.rotateSecret({
 *       path: 'app/database/credentials',
 *       newData: { password: 'newSecurePass456' },
 *     });
 *     console.log('Rotated to version:', result.data?.newVersion);
 *   };
 *
 *   const listVersions = async () => {
 *     const result = await quicBaaSSecrets.listVersions({
 *       path: 'app/database/credentials',
 *     });
 *     return result.data?.versions ?? [];
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSSecrets(): QuicBaaSSecretsService {
  const client = usePlatformClient();
  return client.secrets;
}
