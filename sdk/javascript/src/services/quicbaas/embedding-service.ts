/**
 * QuicBaaS Embedding Service
 *
 * Provides multi-provider embedding generation for converting text
 * into vector representations suitable for similarity search.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { Transport } from '../../transport/transport.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  EmbeddingProvider,
  GenerateEmbeddingRequest,
  GenerateEmbeddingResponse,
  GenerateBatchEmbeddingRequest,
  GenerateBatchEmbeddingResponse,
  ListEmbeddingProvidersRequest,
  ListEmbeddingProvidersResponse,
  GetEmbeddingProviderInfoRequest,
  GetEmbeddingProviderInfoResponse,
} from '../../types/quicbaas/ai-ml.js';

/**
 * QuicBaaS Embedding Service class
 *
 * Provides multi-provider embedding generation supporting OpenAI, Cohere,
 * HuggingFace, Ollama, Voyage, Jina, and custom providers.
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Generate a single embedding
 * const embedding = await client.quicbaas.embedding.generate({
 *   input: 'Hello, world!',
 *   provider: 'OPENAI',
 *   model: 'text-embedding-3-small',
 * });
 *
 * // Generate batch embeddings
 * const embeddings = await client.quicbaas.embedding.generateBatch({
 *   inputs: ['Document 1 content', 'Document 2 content'],
 *   provider: 'COHERE',
 *   model: 'embed-english-v3.0',
 * });
 *
 * // List available providers
 * const providers = await client.quicbaas.embedding.listProviders({
 *   activeOnly: true,
 * });
 * ```
 */
export class EmbeddingService extends BaseService {
  /**
   * Creates a new Embedding service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/quicbaas/embedding');
  }

  // =========================================================================
  // Embedding Generation
  // =========================================================================

  /**
   * Generate an embedding for a single input text
   *
   * Converts text into a vector representation using the specified
   * provider and model.
   *
   * @param request - Embedding generation request
   * @returns Generated embedding with metadata
   *
   * @example
   * ```typescript
   * const result = await embeddingService.generate({
   *   input: 'The quick brown fox jumps over the lazy dog.',
   *   provider: 'OPENAI',
   *   model: 'text-embedding-3-small',
   * });
   *
   * console.log(`Dimension: ${result.data.embedding.values.length}`);
   * console.log(`Tokens used: ${result.data.embedding.tokenCount}`);
   *
   * // Use the embedding for vector search
   * const searchResults = await vectorService.search({
   *   vector: result.data.embedding.values,
   *   topK: 10,
   * });
   * ```
   */
  async generate(request: GenerateEmbeddingRequest): Promise<ApiResponse<GenerateEmbeddingResponse>> {
    return this.client.post<GenerateEmbeddingResponse>(this.buildUrl('/generate'), request);
  }

  /**
   * Generate embeddings for multiple input texts in batch
   *
   * More efficient than generating embeddings one at a time when
   * processing multiple texts.
   *
   * @param request - Batch embedding generation request
   * @returns Generated embeddings for all inputs
   *
   * @example
   * ```typescript
   * const documents = [
   *   'First document content...',
   *   'Second document content...',
   *   'Third document content...',
   * ];
   *
   * const result = await embeddingService.generateBatch({
   *   inputs: documents,
   *   provider: 'VOYAGE',
   *   model: 'voyage-large-2',
   *   truncate: true,
   * });
   *
   * console.log(`Generated ${result.data.embeddings.length} embeddings`);
   * console.log(`Total tokens: ${result.data.totalTokenCount}`);
   * console.log(`Processing time: ${result.data.processingTimeMs}ms`);
   *
   * // Prepare vectors for insertion
   * const vectors = result.data.embeddings.map((emb, i) => ({
   *   id: `doc-${i}`,
   *   values: emb.values,
   *   metadata: { content: documents[i] },
   * }));
   * ```
   */
  async generateBatch(request: GenerateBatchEmbeddingRequest): Promise<ApiResponse<GenerateBatchEmbeddingResponse>> {
    return this.client.post<GenerateBatchEmbeddingResponse>(this.buildUrl('/generate/batch'), request);
  }

  // =========================================================================
  // Provider Management
  // =========================================================================

  /**
   * List available embedding providers
   *
   * Returns information about all configured embedding providers
   * including their status and available models.
   *
   * @param options - Filter options for providers
   * @returns List of embedding providers
   *
   * @example
   * ```typescript
   * // List all providers
   * const allProviders = await embeddingService.listProviders({});
   *
   * // List only active and configured providers
   * const activeProviders = await embeddingService.listProviders({
   *   configuredOnly: true,
   *   activeOnly: true,
   * });
   *
   * for (const provider of activeProviders.data.providers) {
   *   console.log(`${provider.displayName}: ${provider.models.length} models`);
   *   for (const model of provider.models) {
   *     console.log(`  - ${model.name} (dim: ${model.dimension})`);
   *   }
   * }
   * ```
   */
  async listProviders(options?: ListEmbeddingProvidersRequest): Promise<ApiResponse<ListEmbeddingProvidersResponse>> {
    return this.client.get<ListEmbeddingProvidersResponse>(this.buildUrl('/providers', {
      filters: {
        configuredOnly: options?.configuredOnly?.toString(),
        activeOnly: options?.activeOnly?.toString(),
      },
    }));
  }

  /**
   * Get detailed information about a specific embedding provider
   *
   * Returns configuration, status, and available models for the
   * specified provider.
   *
   * @param request - Request with provider type
   * @returns Provider information and models
   *
   * @example
   * ```typescript
   * const info = await embeddingService.getProviderInfo({
   *   provider: 'OPENAI',
   * });
   *
   * if (info.data.provider.isConfigured) {
   *   console.log('OpenAI is configured');
   *   console.log(`Status: ${info.data.provider.status}`);
   *
   *   for (const model of info.data.provider.models) {
   *     console.log(`Model: ${model.name}`);
   *     console.log(`  Dimension: ${model.dimension}`);
   *     console.log(`  Max tokens: ${model.maxInputTokens}`);
   *     if (model.costPer1kTokens) {
   *       console.log(`  Cost: $${model.costPer1kTokens}/1k tokens`);
   *     }
   *   }
   * }
   * ```
   */
  async getProviderInfo(request: GetEmbeddingProviderInfoRequest): Promise<ApiResponse<GetEmbeddingProviderInfoResponse>> {
    return this.client.get<GetEmbeddingProviderInfoResponse>(
      this.buildUrl(`/providers/${this.encodePathSegment(request.provider)}`)
    );
  }

  // =========================================================================
  // Convenience Methods
  // =========================================================================

  /**
   * Generate embedding using OpenAI
   *
   * Convenience method for generating embeddings with OpenAI provider.
   *
   * @param input - Text to embed
   * @param model - OpenAI model (default: text-embedding-3-small)
   * @returns Generated embedding
   *
   * @example
   * ```typescript
   * const embedding = await embeddingService.generateOpenAI(
   *   'Hello, world!',
   *   'text-embedding-3-large'
   * );
   * ```
   */
  async generateOpenAI(input: string, model: string = 'text-embedding-3-small'): Promise<ApiResponse<GenerateEmbeddingResponse>> {
    return this.generate({
      input,
      provider: 'OPENAI' as EmbeddingProvider,
      model,
    });
  }

  /**
   * Generate embedding using Cohere
   *
   * Convenience method for generating embeddings with Cohere provider.
   *
   * @param input - Text to embed
   * @param model - Cohere model (default: embed-english-v3.0)
   * @returns Generated embedding
   *
   * @example
   * ```typescript
   * const embedding = await embeddingService.generateCohere(
   *   'Hello, world!',
   *   'embed-multilingual-v3.0'
   * );
   * ```
   */
  async generateCohere(input: string, model: string = 'embed-english-v3.0'): Promise<ApiResponse<GenerateEmbeddingResponse>> {
    return this.generate({
      input,
      provider: 'COHERE' as EmbeddingProvider,
      model,
    });
  }

  /**
   * Generate embedding using Ollama (local)
   *
   * Convenience method for generating embeddings with local Ollama provider.
   *
   * @param input - Text to embed
   * @param model - Ollama model (default: nomic-embed-text)
   * @returns Generated embedding
   *
   * @example
   * ```typescript
   * const embedding = await embeddingService.generateOllama(
   *   'Hello, world!',
   *   'mxbai-embed-large'
   * );
   * ```
   */
  async generateOllama(input: string, model: string = 'nomic-embed-text'): Promise<ApiResponse<GenerateEmbeddingResponse>> {
    return this.generate({
      input,
      provider: 'OLLAMA' as EmbeddingProvider,
      model,
    });
  }
}
