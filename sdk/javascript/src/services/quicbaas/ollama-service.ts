/**
 * QuicBaaS Ollama Service
 *
 * Provides local LLM and embedding generation via Ollama integration,
 * supporting model management and inference operations.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  OllamaModelType,
  OllamaGenerateRequest,
  OllamaGenerateResponse,
  OllamaEmbedRequest,
  OllamaEmbedResponse,
  OllamaChatRequest,
  OllamaChatResponse,
  OllamaListModelsRequest,
  OllamaListModelsResponse,
  OllamaPullModelRequest,
  OllamaPullModelResponse,
  OllamaDeleteModelRequest,
  OllamaDeleteModelResponse,
} from '../../types/quicbaas/ai-ml.js';

/**
 * QuicBaaS Ollama Service class
 *
 * Provides local LLM inference and embedding generation via Ollama.
 * Supports model management including pulling, listing, and deleting models.
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Generate text completion
 * const response = await client.quicbaas.ollama.generate({
 *   model: 'llama3.2',
 *   prompt: 'Explain quantum computing in simple terms.',
 *   options: { temperature: 0.7 },
 * });
 *
 * // Generate embeddings
 * const embeddings = await client.quicbaas.ollama.embed({
 *   model: 'nomic-embed-text',
 *   input: 'Hello, world!',
 * });
 *
 * // Chat conversation
 * const chat = await client.quicbaas.ollama.chat({
 *   model: 'llama3.2',
 *   messages: [
 *     { role: 'system', content: 'You are a helpful assistant.' },
 *     { role: 'user', content: 'What is the capital of France?' },
 *   ],
 * });
 * ```
 */
export class OllamaService extends BaseService {
  /**
   * Creates a new Ollama service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas/ollama');
  }

  // =========================================================================
  // Inference Operations
  // =========================================================================

  /**
   * Generate text completion
   *
   * Generates text completion using the specified model and prompt.
   * Supports system prompts, templates, and various generation options.
   *
   * @param request - Generation request with model, prompt, and options
   * @returns Generated response with performance metrics
   *
   * @example
   * ```typescript
   * const result = await ollamaService.generate({
   *   model: 'llama3.2',
   *   prompt: 'Write a haiku about programming.',
   *   system: 'You are a creative poet.',
   *   options: {
   *     temperature: 0.9,
   *     topP: 0.95,
   *     numPredict: 100,
   *   },
   * });
   *
   * console.log(result.data.response);
   * console.log(`Tokens generated: ${result.data.evalCount}`);
   * ```
   */
  async generate(request: OllamaGenerateRequest): Promise<ApiResponse<OllamaGenerateResponse>> {
    return this.client.post<OllamaGenerateResponse>(this.buildUrl('/generate'), request);
  }

  /**
   * Generate embeddings for text
   *
   * Converts text into vector embeddings using the specified model.
   * Supports single text or batch input.
   *
   * @param request - Embedding request with model and input text(s)
   * @returns Generated embeddings array
   *
   * @example
   * ```typescript
   * // Single text embedding
   * const single = await ollamaService.embed({
   *   model: 'nomic-embed-text',
   *   input: 'Hello, world!',
   * });
   * console.log(`Embedding dimension: ${single.data.embeddings[0].length}`);
   *
   * // Batch embeddings
   * const batch = await ollamaService.embed({
   *   model: 'nomic-embed-text',
   *   input: ['First document', 'Second document', 'Third document'],
   * });
   * console.log(`Generated ${batch.data.embeddings.length} embeddings`);
   * ```
   */
  async embed(request: OllamaEmbedRequest): Promise<ApiResponse<OllamaEmbedResponse>> {
    return this.client.post<OllamaEmbedResponse>(this.buildUrl('/embed'), request);
  }

  /**
   * Chat with a model
   *
   * Conducts a multi-turn conversation with the specified model.
   * Supports system messages, user/assistant history, and multimodal inputs.
   *
   * @param request - Chat request with model and messages
   * @returns Chat response with assistant message
   *
   * @example
   * ```typescript
   * const result = await ollamaService.chat({
   *   model: 'llama3.2',
   *   messages: [
   *     { role: 'system', content: 'You are a helpful coding assistant.' },
   *     { role: 'user', content: 'How do I sort an array in JavaScript?' },
   *   ],
   *   options: {
   *     temperature: 0.7,
   *   },
   * });
   *
   * console.log(`Assistant: ${result.data.message.content}`);
   *
   * // Continue the conversation
   * const followUp = await ollamaService.chat({
   *   model: 'llama3.2',
   *   messages: [
   *     { role: 'system', content: 'You are a helpful coding assistant.' },
   *     { role: 'user', content: 'How do I sort an array in JavaScript?' },
   *     { role: 'assistant', content: result.data.message.content },
   *     { role: 'user', content: 'Can you show me an example with objects?' },
   *   ],
   * });
   * ```
   */
  async chat(request: OllamaChatRequest): Promise<ApiResponse<OllamaChatResponse>> {
    return this.client.post<OllamaChatResponse>(this.buildUrl('/chat'), request);
  }

  // =========================================================================
  // Model Management
  // =========================================================================

  /**
   * List available models
   *
   * Returns information about all locally available Ollama models.
   * Can filter by model type (LLM, embedding, multimodal).
   *
   * @param options - Optional filter by model type
   * @returns List of available models
   *
   * @example
   * ```typescript
   * // List all models
   * const all = await ollamaService.listModels({});
   *
   * for (const model of all.data.models) {
   *   console.log(`${model.name}:${model.tag}`);
   *   console.log(`  Type: ${model.modelType}`);
   *   console.log(`  Size: ${(model.size / 1e9).toFixed(2)} GB`);
   * }
   *
   * // List only embedding models
   * const embeddingModels = await ollamaService.listModels({
   *   modelType: 'EMBEDDING',
   * });
   * ```
   */
  async listModels(options?: OllamaListModelsRequest): Promise<ApiResponse<OllamaListModelsResponse>> {
    return this.client.get<OllamaListModelsResponse>(this.buildUrl('/models', {
      filters: {
        modelType: options?.modelType,
      },
    }));
  }

  /**
   * Pull a model from Ollama registry
   *
   * Downloads and installs a model from the Ollama model library.
   * Returns progress information for tracking the download.
   *
   * @param request - Pull request with model name
   * @returns Pull result with progress information
   *
   * @example
   * ```typescript
   * const result = await ollamaService.pullModel({
   *   name: 'llama3.2',
   * });
   *
   * if (result.data.done) {
   *   console.log(`Model ${result.data.name} is ready`);
   * } else {
   *   const progress = result.data.progress;
   *   if (progress?.total && progress?.completed) {
   *     const pct = (progress.completed / progress.total * 100).toFixed(1);
   *     console.log(`Downloading: ${pct}%`);
   *   }
   * }
   * ```
   */
  async pullModel(request: OllamaPullModelRequest): Promise<ApiResponse<OllamaPullModelResponse>> {
    return this.client.post<OllamaPullModelResponse>(this.buildUrl('/models/pull'), request);
  }

  /**
   * Delete a model
   *
   * Removes a locally installed model from the system.
   *
   * @param request - Delete request with model name
   * @returns Delete result
   *
   * @example
   * ```typescript
   * await ollamaService.deleteModel({
   *   name: 'old-model:v1',
   * });
   * console.log('Model deleted');
   * ```
   */
  async deleteModel(request: OllamaDeleteModelRequest): Promise<ApiResponse<OllamaDeleteModelResponse>> {
    return this.client.delete<OllamaDeleteModelResponse>(
      this.buildUrl(`/models/${this.encodePathSegment(request.name)}`)
    );
  }

  // =========================================================================
  // Convenience Methods
  // =========================================================================

  /**
   * Quick generate with defaults
   *
   * Simple text generation with sensible defaults.
   *
   * @param model - Model name
   * @param prompt - Prompt text
   * @param temperature - Temperature (default: 0.7)
   * @returns Generated response
   *
   * @example
   * ```typescript
   * const response = await ollamaService.quickGenerate(
   *   'llama3.2',
   *   'What is 2 + 2?'
   * );
   * console.log(response.data.response);
   * ```
   */
  async quickGenerate(
    model: string,
    prompt: string,
    temperature: number = 0.7
  ): Promise<ApiResponse<OllamaGenerateResponse>> {
    return this.generate({
      model,
      prompt,
      options: { temperature },
    });
  }

  /**
   * Quick embed with defaults
   *
   * Simple embedding generation with sensible defaults.
   *
   * @param model - Model name
   * @param input - Text to embed
   * @returns Generated embeddings
   *
   * @example
   * ```typescript
   * const embeddings = await ollamaService.quickEmbed(
   *   'nomic-embed-text',
   *   'Hello, world!'
   * );
   * console.log(`Dimension: ${embeddings.data.embeddings[0].length}`);
   * ```
   */
  async quickEmbed(model: string, input: string | string[]): Promise<ApiResponse<OllamaEmbedResponse>> {
    return this.embed({
      model,
      input,
    });
  }

  /**
   * Check if a model is available locally
   *
   * @param modelName - Model name to check
   * @returns Whether the model is available
   *
   * @example
   * ```typescript
   * const hasLlama = await ollamaService.hasModel('llama3.2');
   * if (!hasLlama) {
   *   await ollamaService.pullModel({ name: 'llama3.2' });
   * }
   * ```
   */
  async hasModel(modelName: string): Promise<boolean> {
    const response = await this.listModels({});
    if (!response.success || !response.data) {
      return false;
    }
    return response.data.models.some(
      (m) => m.name === modelName || `${m.name}:${m.tag}` === modelName
    );
  }

  /**
   * List embedding models only
   *
   * Convenience method to list only embedding-capable models.
   *
   * @returns List of embedding models
   *
   * @example
   * ```typescript
   * const embeddingModels = await ollamaService.listEmbeddingModels();
   * console.log('Available embedding models:');
   * for (const model of embeddingModels.data.models) {
   *   console.log(`  - ${model.name}`);
   * }
   * ```
   */
  async listEmbeddingModels(): Promise<ApiResponse<OllamaListModelsResponse>> {
    return this.listModels({ modelType: 'EMBEDDING' as OllamaModelType });
  }

  /**
   * List LLM models only
   *
   * Convenience method to list only LLM (text generation) models.
   *
   * @returns List of LLM models
   *
   * @example
   * ```typescript
   * const llmModels = await ollamaService.listLLMModels();
   * console.log('Available LLM models:');
   * for (const model of llmModels.data.models) {
   *   console.log(`  - ${model.name}`);
   * }
   * ```
   */
  async listLLMModels(): Promise<ApiResponse<OllamaListModelsResponse>> {
    return this.listModels({ modelType: 'LLM' as OllamaModelType });
  }
}
