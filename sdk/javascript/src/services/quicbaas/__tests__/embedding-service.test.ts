/**
 * Unit tests for EmbeddingService
 *
 * Tests multi-provider embedding generation for converting text
 * into vector representations.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EmbeddingService } from '../embedding-service.js';
import type { ApiClient } from '../../../client/api-client.js';
import type { ApiResponse } from '../../../types/api.js';
import type { EmbeddingProvider } from '../../../types/quicbaas/ai-ml.js';

// Mock ApiClient
function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
    interceptors: {
      request: { add: vi.fn(), getAll: vi.fn(() => []) },
      response: { add: vi.fn(), getAll: vi.fn(() => []) },
      error: { add: vi.fn(), getAll: vi.fn(() => []) },
    },
    addRequestInterceptor: vi.fn(),
    addResponseInterceptor: vi.fn(),
    addErrorInterceptor: vi.fn(),
  } as unknown as ApiClient;
}

describe('EmbeddingService', () => {
  let service: EmbeddingService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new EmbeddingService(mockClient);
  });

  // =========================================================================
  // generate() tests
  // =========================================================================

  describe('generate', () => {
    it('should generate an embedding for text', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: {
          embedding: { values: [0.1, 0.2, 0.3], tokenCount: 10 },
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.generate({
        input: 'Hello, world!',
        provider: 'OPENAI',
        model: 'text-embedding-3-small',
      });

      expect(result.success).toBe(true);
      expect(result.data?.embedding.values).toHaveLength(3);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Hello, world!',
        provider: 'OPENAI',
        model: 'text-embedding-3-small',
      });
    });

    it('should generate embedding with truncate option', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: { embedding: { values: [0.1], tokenCount: 512 } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generate({
        input: 'Very long text...',
        provider: 'COHERE',
        model: 'embed-english-v3.0',
        truncate: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Very long text...',
        provider: 'COHERE',
        model: 'embed-english-v3.0',
        truncate: true,
      });
    });

    it('should handle provider not configured error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'PROVIDER_NOT_CONFIGURED', message: 'OpenAI provider not configured' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.generate({
        input: 'Hello',
        provider: 'OPENAI',
        model: 'text-embedding-3-small',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('PROVIDER_NOT_CONFIGURED');
    });

    it('should handle input too long error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INPUT_TOO_LONG', message: 'Input exceeds maximum token limit' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.generate({
        input: 'x'.repeat(100000),
        provider: 'OPENAI',
        model: 'text-embedding-3-small',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INPUT_TOO_LONG');
    });
  });

  // =========================================================================
  // generateBatch() tests
  // =========================================================================

  describe('generateBatch', () => {
    it('should generate batch embeddings', async () => {
      const mockResponse: ApiResponse<{
        embeddings: Array<{ values: number[]; tokenCount: number }>;
        totalTokenCount: number;
        processingTimeMs: number;
      }> = {
        success: true,
        data: {
          embeddings: [
            { values: [0.1, 0.2], tokenCount: 5 },
            { values: [0.3, 0.4], tokenCount: 6 },
          ],
          totalTokenCount: 11,
          processingTimeMs: 250,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.generateBatch({
        inputs: ['Document 1', 'Document 2'],
        provider: 'VOYAGE',
        model: 'voyage-large-2',
      });

      expect(result.success).toBe(true);
      expect(result.data?.embeddings).toHaveLength(2);
      expect(result.data?.totalTokenCount).toBe(11);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate/batch', {
        inputs: ['Document 1', 'Document 2'],
        provider: 'VOYAGE',
        model: 'voyage-large-2',
      });
    });

    it('should generate batch with truncate option', async () => {
      const mockResponse: ApiResponse<{
        embeddings: Array<{ values: number[] }>;
        totalTokenCount: number;
        processingTimeMs: number;
      }> = {
        success: true,
        data: {
          embeddings: [{ values: [0.1] }],
          totalTokenCount: 100,
          processingTimeMs: 100,
        },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generateBatch({
        inputs: ['Long document...'],
        provider: 'COHERE',
        model: 'embed-english-v3.0',
        truncate: true,
      });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate/batch', {
        inputs: ['Long document...'],
        provider: 'COHERE',
        model: 'embed-english-v3.0',
        truncate: true,
      });
    });

    it('should handle empty inputs error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'INVALID_REQUEST', message: 'Inputs array cannot be empty' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.generateBatch({
        inputs: [],
        provider: 'OPENAI',
        model: 'text-embedding-3-small',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('INVALID_REQUEST');
    });

    it('should handle batch size limit error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'BATCH_TOO_LARGE', message: 'Batch size exceeds limit' },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      const result = await service.generateBatch({
        inputs: Array<string>(1000).fill('text'),
        provider: 'OPENAI',
        model: 'text-embedding-3-small',
      });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('BATCH_TOO_LARGE');
    });
  });

  // =========================================================================
  // listProviders() tests
  // =========================================================================

  describe('listProviders', () => {
    it('should list all embedding providers', async () => {
      const mockResponse: ApiResponse<{
        providers: Array<{
          name: string;
          displayName: string;
          isConfigured: boolean;
          models: Array<{ name: string; dimension: number }>;
        }>;
      }> = {
        success: true,
        data: {
          providers: [
            {
              name: 'OPENAI',
              displayName: 'OpenAI',
              isConfigured: true,
              models: [{ name: 'text-embedding-3-small', dimension: 1536 }],
            },
            {
              name: 'COHERE',
              displayName: 'Cohere',
              isConfigured: true,
              models: [{ name: 'embed-english-v3.0', dimension: 1024 }],
            },
          ],
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.listProviders();

      expect(result.success).toBe(true);
      expect(result.data?.providers).toHaveLength(2);
      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('/v1/quicbaas/embedding/providers')
      );
    });

    it('should filter configured providers only', async () => {
      const mockResponse: ApiResponse<{ providers: unknown[] }> = {
        success: true,
        data: { providers: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listProviders({ configuredOnly: true });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('configuredOnly=true')
      );
    });

    it('should filter active providers only', async () => {
      const mockResponse: ApiResponse<{ providers: unknown[] }> = {
        success: true,
        data: { providers: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listProviders({ activeOnly: true });

      expect(mockClient.get).toHaveBeenCalledWith(
        expect.stringContaining('activeOnly=true')
      );
    });

    it('should combine filter options', async () => {
      const mockResponse: ApiResponse<{ providers: unknown[] }> = {
        success: true,
        data: { providers: [] },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.listProviders({ configuredOnly: true, activeOnly: true });

      const call = vi.mocked(mockClient.get).mock.calls[0]![0];
      expect(call).toContain('configuredOnly=true');
      expect(call).toContain('activeOnly=true');
    });
  });

  // =========================================================================
  // getProviderInfo() tests
  // =========================================================================

  describe('getProviderInfo', () => {
    it('should get provider information', async () => {
      const mockResponse: ApiResponse<{
        provider: {
          name: string;
          displayName: string;
          isConfigured: boolean;
          status: string;
          models: Array<{
            name: string;
            dimension: number;
            maxInputTokens: number;
            costPer1kTokens?: number;
          }>;
        };
      }> = {
        success: true,
        data: {
          provider: {
            name: 'OPENAI',
            displayName: 'OpenAI',
            isConfigured: true,
            status: 'active',
            models: [
              {
                name: 'text-embedding-3-small',
                dimension: 1536,
                maxInputTokens: 8191,
                costPer1kTokens: 0.00002,
              },
            ],
          },
        },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getProviderInfo({ provider: 'OPENAI' });

      expect(result.success).toBe(true);
      expect(result.data?.provider).toMatchObject({ name: 'OPENAI' });
      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/embedding/providers/OPENAI');
    });

    it('should handle provider not found error', async () => {
      const mockResponse: ApiResponse<never> = {
        success: false,
        error: { code: 'NOT_FOUND', message: 'Provider not found' },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      const result = await service.getProviderInfo({ provider: 'UNKNOWN' as EmbeddingProvider });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe('NOT_FOUND');
    });

    it('should encode provider name in URL', async () => {
      const mockResponse: ApiResponse<{ provider: { name: string } }> = {
        success: true,
        data: { provider: { name: 'CUSTOM_PROVIDER' } },
      };
      vi.mocked(mockClient.get).mockResolvedValue(mockResponse);

      await service.getProviderInfo({ provider: 'CUSTOM_PROVIDER' as EmbeddingProvider });

      expect(mockClient.get).toHaveBeenCalledWith('/v1/quicbaas/embedding/providers/CUSTOM_PROVIDER');
    });
  });

  // =========================================================================
  // Convenience method tests
  // =========================================================================

  describe('generateOpenAI', () => {
    it('should generate OpenAI embedding with default model', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: { embedding: { values: [0.1], tokenCount: 5 } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generateOpenAI('Hello, world!');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Hello, world!',
        provider: 'OPENAI',
        model: 'text-embedding-3-small',
      });
    });

    it('should generate OpenAI embedding with custom model', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: { embedding: { values: [0.1], tokenCount: 5 } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generateOpenAI('Hello!', 'text-embedding-3-large');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Hello!',
        provider: 'OPENAI',
        model: 'text-embedding-3-large',
      });
    });
  });

  describe('generateCohere', () => {
    it('should generate Cohere embedding with default model', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: { embedding: { values: [0.1], tokenCount: 5 } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generateCohere('Hello, world!');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Hello, world!',
        provider: 'COHERE',
        model: 'embed-english-v3.0',
      });
    });

    it('should generate Cohere embedding with custom model', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: { embedding: { values: [0.1], tokenCount: 5 } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generateCohere('Hello!', 'embed-multilingual-v3.0');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Hello!',
        provider: 'COHERE',
        model: 'embed-multilingual-v3.0',
      });
    });
  });

  describe('generateOllama', () => {
    it('should generate Ollama embedding with default model', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: { embedding: { values: [0.1], tokenCount: 5 } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generateOllama('Hello, world!');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Hello, world!',
        provider: 'OLLAMA',
        model: 'nomic-embed-text',
      });
    });

    it('should generate Ollama embedding with custom model', async () => {
      const mockResponse: ApiResponse<{
        embedding: { values: number[]; tokenCount: number };
      }> = {
        success: true,
        data: { embedding: { values: [0.1], tokenCount: 5 } },
      };
      vi.mocked(mockClient.post).mockResolvedValue(mockResponse);

      await service.generateOllama('Hello!', 'mxbai-embed-large');

      expect(mockClient.post).toHaveBeenCalledWith('/v1/quicbaas/embedding/generate', {
        input: 'Hello!',
        provider: 'OLLAMA',
        model: 'mxbai-embed-large',
      });
    });
  });
});
