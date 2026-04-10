/**
 * QuicBaaS Vector React Hook
 *
 * Provides access to the QuicBaaS Vector service for similarity search
 * operations including k-NN search and namespace management.
 *
 * @packageDocumentation
 */

import type { VectorService } from '../../../services/quicbaas/vector-service.js';
import { usePlatformClient } from '../../context.js';

/**
 * Hook to access the QuicBaaS Vector service
 *
 * Provides methods for vector similarity search including insert, search,
 * delete vectors, and namespace management for organizing vector indexes.
 *
 * @returns The VectorService instance from the current client
 *
 * @example
 * ```tsx
 * function VectorSearchComponent() {
 *   const quicBaaSVector = useQuicBaaSVector();
 *
 *   const insertVectors = async () => {
 *     const result = await quicBaaSVector.insert({
 *       namespace: 'documents',
 *       vectors: [
 *         { id: 'doc-1', values: [0.1, 0.2, 0.3], metadata: { title: 'Doc 1' } },
 *         { id: 'doc-2', values: [0.4, 0.5, 0.6], metadata: { title: 'Doc 2' } },
 *       ],
 *     });
 *     console.log('Inserted:', result.data?.insertedCount);
 *   };
 *
 *   const searchSimilar = async (queryVector: number[]) => {
 *     const result = await quicBaaSVector.search({
 *       namespace: 'documents',
 *       vector: queryVector,
 *       topK: 10,
 *       includeMetadata: true,
 *     });
 *     return result.data?.results ?? [];
 *   };
 *
 *   const createNamespace = async () => {
 *     const result = await quicBaaSVector.createNamespace({
 *       name: 'embeddings',
 *       dimension: 1536,
 *       metric: 'COSINE',
 *     });
 *     console.log('Created namespace:', result.data?.namespace.name);
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSVector(): VectorService {
  const client = usePlatformClient();
  return client.vector;
}
