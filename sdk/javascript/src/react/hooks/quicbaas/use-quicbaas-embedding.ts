/**
 * QuicBaaS Embedding React Hook
 *
 * Provides access to the QuicBaaS Embedding service for multi-provider
 * embedding generation to convert text into vector representations.
 *
 * @packageDocumentation
 */

import type { EmbeddingService } from '../../../services/quicbaas/embedding-service.js';
import { usePlatformClient } from '../../context.js';

/**
 * Hook to access the QuicBaaS Embedding service
 *
 * Provides methods for generating embeddings using multiple providers
 * including OpenAI, Cohere, HuggingFace, Ollama, Voyage, Jina, and custom providers.
 *
 * @returns The EmbeddingService instance from the current client
 *
 * @example
 * ```tsx
 * function EmbeddingGenerator() {
 *   const quicBaaSEmbedding = useQuicBaaSEmbedding();
 *
 *   const generateEmbedding = async (text: string) => {
 *     const result = await quicBaaSEmbedding.generate({
 *       input: text,
 *       provider: 'OPENAI',
 *       model: 'text-embedding-3-small',
 *     });
 *     return result.data?.embedding.values ?? [];
 *   };
 *
 *   const generateBatch = async (texts: string[]) => {
 *     const result = await quicBaaSEmbedding.generateBatch({
 *       inputs: texts,
 *       provider: 'COHERE',
 *       model: 'embed-english-v3.0',
 *     });
 *     console.log(`Generated ${result.data?.embeddings.length} embeddings`);
 *     return result.data?.embeddings ?? [];
 *   };
 *
 *   const listProviders = async () => {
 *     const result = await quicBaaSEmbedding.listProviders({ activeOnly: true });
 *     return result.data?.providers ?? [];
 *   };
 *
 *   // Convenience methods for specific providers
 *   const embedWithOpenAI = async (text: string) => {
 *     const result = await quicBaaSEmbedding.generateOpenAI(text);
 *     return result.data?.embedding.values ?? [];
 *   };
 *
 *   const embedWithOllama = async (text: string) => {
 *     const result = await quicBaaSEmbedding.generateOllama(text, 'nomic-embed-text');
 *     return result.data?.embedding.values ?? [];
 *   };
 *
 *   // ... render
 * }
 * ```
 */
export function useQuicBaaSEmbedding(): EmbeddingService {
  const client = usePlatformClient();
  return client.embedding;
}
