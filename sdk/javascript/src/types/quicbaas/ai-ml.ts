/**
 * QuicBaaS AI/ML Types
 *
 * Types for AI/ML operations including vector similarity search,
 * embedding generation, and local LLM integration via Ollama.
 */

// =============================================================================
// Common Enums and Types
// =============================================================================

/**
 * Distance metric for vector similarity search
 */
export type DistanceMetric =
  | 'COSINE'
  | 'EUCLIDEAN'
  | 'DOT_PRODUCT'
  | 'MANHATTAN';

/**
 * Embedding provider types
 */
export type EmbeddingProvider =
  | 'OPENAI'
  | 'COHERE'
  | 'HUGGINGFACE'
  | 'OLLAMA'
  | 'VOYAGE'
  | 'JINA'
  | 'CUSTOM';

/**
 * Ollama model type
 */
export type OllamaModelType =
  | 'LLM'
  | 'EMBEDDING'
  | 'MULTIMODAL';

/**
 * Operation status for AI/ML operations
 */
export interface AIMLStatus {
  /** Whether the operation succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details if failed */
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

// =============================================================================
// Vector Service Types
// =============================================================================

/**
 * Vector data structure
 */
export interface Vector {
  /** Unique vector identifier */
  id: string;
  /** Vector values (float array) */
  values: number[];
  /** Optional metadata associated with the vector */
  metadata?: Record<string, unknown>;
  /** Sparse vector indices (for hybrid search) */
  sparseIndices?: number[];
  /** Sparse vector values (for hybrid search) */
  sparseValues?: number[];
}

/**
 * Vector search result
 */
export interface VectorSearchResult {
  /** Vector identifier */
  id: string;
  /** Similarity score */
  score: number;
  /** Vector values (if requested) */
  values?: number[];
  /** Vector metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Vector namespace information
 */
export interface VectorNamespace {
  /** Namespace name */
  name: string;
  /** Vector count in namespace */
  vectorCount: number;
  /** Vector dimension */
  dimension: number;
  /** Distance metric used */
  metric: DistanceMetric;
  /** Creation timestamp (unix epoch) */
  createdAt: number;
  /** Last update timestamp (unix epoch) */
  updatedAt: number;
}

/**
 * Vector index statistics
 */
export interface VectorIndexStats {
  /** Total vector count */
  totalVectorCount: number;
  /** Index size in bytes */
  indexSizeBytes: number;
  /** Dimension of vectors */
  dimension: number;
  /** Distance metric */
  metric: DistanceMetric;
  /** Number of namespaces */
  namespaceCount: number;
  /** Index type (e.g., 'hnsw', 'flat', 'ivf') */
  indexType: string;
  /** Whether index is trained (for IVF) */
  isTrained: boolean;
  /** Index configuration */
  config?: Record<string, unknown>;
}

// -----------------------------------------------------------------------------
// Vector Request Types
// -----------------------------------------------------------------------------

/**
 * Insert vectors request
 */
export interface VectorInsertRequest {
  /** Namespace to insert into */
  namespace?: string;
  /** Vectors to insert */
  vectors: Vector[];
  /** Whether to overwrite existing vectors */
  overwrite?: boolean;
}

/**
 * Vector search request
 */
export interface VectorSearchRequest {
  /** Namespace to search in */
  namespace?: string;
  /** Query vector */
  vector: number[];
  /** Number of results to return (k) */
  topK: number;
  /** Minimum score threshold */
  scoreThreshold?: number;
  /** Include vector values in response */
  includeValues?: boolean;
  /** Include metadata in response */
  includeMetadata?: boolean;
  /** Metadata filter */
  filter?: Record<string, unknown>;
}

/**
 * Similar vectors search request (by ID)
 */
export interface VectorSearchSimilarRequest {
  /** Namespace to search in */
  namespace?: string;
  /** Vector ID to find similar vectors for */
  id: string;
  /** Number of results to return (k) */
  topK: number;
  /** Minimum score threshold */
  scoreThreshold?: number;
  /** Include vector values in response */
  includeValues?: boolean;
  /** Include metadata in response */
  includeMetadata?: boolean;
  /** Metadata filter */
  filter?: Record<string, unknown>;
}

/**
 * Delete vectors request
 */
export interface VectorDeleteRequest {
  /** Namespace to delete from */
  namespace?: string;
  /** Vector IDs to delete */
  ids?: string[];
  /** Delete all vectors matching filter */
  filter?: Record<string, unknown>;
  /** Delete all vectors in namespace */
  deleteAll?: boolean;
}

/**
 * Create namespace request
 */
export interface CreateNamespaceRequest {
  /** Namespace name */
  name: string;
  /** Vector dimension */
  dimension: number;
  /** Distance metric */
  metric?: DistanceMetric;
  /** Index configuration */
  indexConfig?: {
    /** Index type */
    type?: 'hnsw' | 'flat' | 'ivf';
    /** HNSW M parameter */
    hnswM?: number;
    /** HNSW ef construction */
    hnswEfConstruction?: number;
    /** IVF nlist */
    ivfNlist?: number;
  };
}

/**
 * Delete namespace request
 */
export interface DeleteNamespaceRequest {
  /** Namespace name */
  name: string;
  /** Force deletion even if not empty */
  force?: boolean;
}

/**
 * List namespaces request
 */
export interface ListNamespacesRequest {
  /** Maximum number of results */
  limit?: number;
  /** Cursor for pagination */
  cursor?: string;
  /** Filter by prefix */
  prefix?: string;
}

/**
 * Get vector stats request
 */
export interface GetVectorStatsRequest {
  /** Namespace to get stats for (all if not specified) */
  namespace?: string;
}

// -----------------------------------------------------------------------------
// Vector Response Types
// -----------------------------------------------------------------------------

/**
 * Insert vectors response
 */
export interface VectorInsertResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Number of vectors inserted */
  insertedCount: number;
  /** IDs of inserted vectors */
  insertedIds: string[];
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Vector search response
 */
export interface VectorSearchResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Search results */
  results: VectorSearchResult[];
  /** Query processing time in milliseconds */
  queryTimeMs: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Delete vectors response
 */
export interface VectorDeleteResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Number of vectors deleted */
  deletedCount: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Create namespace response
 */
export interface CreateNamespaceResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Created namespace information */
  namespace: VectorNamespace;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Delete namespace response
 */
export interface DeleteNamespaceResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Deleted namespace name */
  name: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List namespaces response
 */
export interface ListNamespacesResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Namespaces */
  namespaces: VectorNamespace[];
  /** Next cursor for pagination */
  nextCursor?: string;
  /** Whether there are more results */
  hasMore: boolean;
  /** Total count */
  totalCount: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get vector stats response
 */
export interface GetVectorStatsResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Index statistics */
  stats: VectorIndexStats;
  /** Per-namespace statistics */
  namespaceStats?: Record<string, VectorIndexStats>;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// Embedding Service Types
// =============================================================================

/**
 * Embedding model information
 */
export interface EmbeddingModel {
  /** Model identifier */
  modelId: string;
  /** Model name */
  name: string;
  /** Provider */
  provider: EmbeddingProvider;
  /** Output dimension */
  dimension: number;
  /** Maximum input tokens */
  maxInputTokens: number;
  /** Whether model supports batching */
  supportsBatch: boolean;
  /** Cost per 1000 tokens (if applicable) */
  costPer1kTokens?: number;
}

/**
 * Embedding provider information
 */
export interface EmbeddingProviderInfo {
  /** Provider type */
  provider: EmbeddingProvider;
  /** Provider display name */
  displayName: string;
  /** Available models */
  models: EmbeddingModel[];
  /** Whether provider is configured */
  isConfigured: boolean;
  /** Provider status */
  status: 'active' | 'inactive' | 'error';
  /** Error message if status is error */
  errorMessage?: string;
}

/**
 * Generated embedding
 */
export interface Embedding {
  /** Input text or identifier */
  input: string;
  /** Embedding vector */
  values: number[];
  /** Token count used */
  tokenCount: number;
}

// -----------------------------------------------------------------------------
// Embedding Request Types
// -----------------------------------------------------------------------------

/**
 * Generate embedding request
 */
export interface GenerateEmbeddingRequest {
  /** Input text to embed */
  input: string;
  /** Model to use */
  model?: string;
  /** Provider to use */
  provider?: EmbeddingProvider;
  /** Encoding format */
  encodingFormat?: 'float' | 'base64';
  /** Truncate input if too long */
  truncate?: boolean;
}

/**
 * Generate batch embeddings request
 */
export interface GenerateBatchEmbeddingRequest {
  /** Input texts to embed */
  inputs: string[];
  /** Model to use */
  model?: string;
  /** Provider to use */
  provider?: EmbeddingProvider;
  /** Encoding format */
  encodingFormat?: 'float' | 'base64';
  /** Truncate inputs if too long */
  truncate?: boolean;
}

/**
 * List providers request
 */
export interface ListEmbeddingProvidersRequest {
  /** Filter by configured status */
  configuredOnly?: boolean;
  /** Filter by active status */
  activeOnly?: boolean;
}

/**
 * Get provider info request
 */
export interface GetEmbeddingProviderInfoRequest {
  /** Provider type */
  provider: EmbeddingProvider;
}

// -----------------------------------------------------------------------------
// Embedding Response Types
// -----------------------------------------------------------------------------

/**
 * Generate embedding response
 */
export interface GenerateEmbeddingResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Generated embedding */
  embedding: Embedding;
  /** Model used */
  model: string;
  /** Provider used */
  provider: EmbeddingProvider;
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Generate batch embeddings response
 */
export interface GenerateBatchEmbeddingResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Generated embeddings */
  embeddings: Embedding[];
  /** Model used */
  model: string;
  /** Provider used */
  provider: EmbeddingProvider;
  /** Total token count */
  totalTokenCount: number;
  /** Processing time in milliseconds */
  processingTimeMs: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List providers response
 */
export interface ListEmbeddingProvidersResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Available providers */
  providers: EmbeddingProviderInfo[];
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Get provider info response
 */
export interface GetEmbeddingProviderInfoResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Provider information */
  provider: EmbeddingProviderInfo;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

// =============================================================================
// Ollama Service Types
// =============================================================================

/**
 * Ollama model information
 */
export interface OllamaModel {
  /** Model name */
  name: string;
  /** Model tag/version */
  tag: string;
  /** Model size in bytes */
  size: number;
  /** Model digest */
  digest: string;
  /** Model type */
  modelType: OllamaModelType;
  /** Model family */
  family?: string;
  /** Parameter count */
  parameterCount?: string;
  /** Quantization level */
  quantizationLevel?: string;
  /** Modified timestamp (unix epoch) */
  modifiedAt: number;
}

/**
 * Ollama generation options
 */
export interface OllamaOptions {
  /** Temperature for generation */
  temperature?: number;
  /** Top-p sampling */
  topP?: number;
  /** Top-k sampling */
  topK?: number;
  /** Repeat penalty */
  repeatPenalty?: number;
  /** Context window size */
  numCtx?: number;
  /** Number of tokens to predict */
  numPredict?: number;
  /** Stop sequences */
  stop?: string[];
  /** Random seed */
  seed?: number;
  /** Mirostat mode (0, 1, or 2) */
  mirostat?: number;
  /** Mirostat tau */
  mirostatTau?: number;
  /** Mirostat eta */
  mirostatEta?: number;
  /** Number of GPU layers */
  numGpu?: number;
  /** Main GPU index */
  mainGpu?: number;
  /** Use memory mapping */
  useMmap?: boolean;
  /** Use memory locking */
  useMlock?: boolean;
  /** Number of threads */
  numThread?: number;
}

/**
 * Chat message
 */
export interface OllamaChatMessage {
  /** Role (system, user, assistant) */
  role: 'system' | 'user' | 'assistant';
  /** Message content */
  content: string;
  /** Images for multimodal models (base64) */
  images?: string[];
}

/**
 * Pull model progress
 */
export interface OllamaPullProgress {
  /** Status message */
  status: string;
  /** Digest being downloaded */
  digest?: string;
  /** Total size in bytes */
  total?: number;
  /** Completed size in bytes */
  completed?: number;
}

// -----------------------------------------------------------------------------
// Ollama Request Types
// -----------------------------------------------------------------------------

/**
 * Ollama generate request
 */
export interface OllamaGenerateRequest {
  /** Model name */
  model: string;
  /** Prompt text */
  prompt: string;
  /** System prompt */
  system?: string;
  /** Template to use */
  template?: string;
  /** Context from previous generation */
  context?: number[];
  /** Generation options */
  options?: OllamaOptions;
  /** Format (e.g., 'json') */
  format?: string;
  /** Images for multimodal models (base64) */
  images?: string[];
  /** Keep model loaded */
  keepAlive?: string;
}

/**
 * Ollama embed request
 */
export interface OllamaEmbedRequest {
  /** Model name */
  model: string;
  /** Input text or texts */
  input: string | string[];
  /** Truncate input if too long */
  truncate?: boolean;
  /** Generation options */
  options?: OllamaOptions;
  /** Keep model loaded */
  keepAlive?: string;
}

/**
 * Ollama chat request
 */
export interface OllamaChatRequest {
  /** Model name */
  model: string;
  /** Chat messages */
  messages: OllamaChatMessage[];
  /** Generation options */
  options?: OllamaOptions;
  /** Format (e.g., 'json') */
  format?: string;
  /** Keep model loaded */
  keepAlive?: string;
}

/**
 * List models request
 */
export interface OllamaListModelsRequest {
  /** Filter by model type */
  modelType?: OllamaModelType;
}

/**
 * Pull model request
 */
export interface OllamaPullModelRequest {
  /** Model name to pull */
  name: string;
  /** Insecure registry */
  insecure?: boolean;
}

/**
 * Delete model request
 */
export interface OllamaDeleteModelRequest {
  /** Model name to delete */
  name: string;
}

// -----------------------------------------------------------------------------
// Ollama Response Types
// -----------------------------------------------------------------------------

/**
 * Ollama generate response
 */
export interface OllamaGenerateResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Model used */
  model: string;
  /** Generated response */
  response: string;
  /** Context for follow-up generation */
  context?: number[];
  /** Whether generation is complete */
  done: boolean;
  /** Reason for completion */
  doneReason?: string;
  /** Total duration in nanoseconds */
  totalDuration?: number;
  /** Load duration in nanoseconds */
  loadDuration?: number;
  /** Prompt evaluation count */
  promptEvalCount?: number;
  /** Prompt evaluation duration in nanoseconds */
  promptEvalDuration?: number;
  /** Evaluation count */
  evalCount?: number;
  /** Evaluation duration in nanoseconds */
  evalDuration?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Ollama embed response
 */
export interface OllamaEmbedResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Model used */
  model: string;
  /** Generated embeddings */
  embeddings: number[][];
  /** Total duration in nanoseconds */
  totalDuration?: number;
  /** Load duration in nanoseconds */
  loadDuration?: number;
  /** Prompt evaluation count */
  promptEvalCount?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Ollama chat response
 */
export interface OllamaChatResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Model used */
  model: string;
  /** Response message */
  message: OllamaChatMessage;
  /** Whether generation is complete */
  done: boolean;
  /** Reason for completion */
  doneReason?: string;
  /** Total duration in nanoseconds */
  totalDuration?: number;
  /** Load duration in nanoseconds */
  loadDuration?: number;
  /** Prompt evaluation count */
  promptEvalCount?: number;
  /** Prompt evaluation duration in nanoseconds */
  promptEvalDuration?: number;
  /** Evaluation count */
  evalCount?: number;
  /** Evaluation duration in nanoseconds */
  evalDuration?: number;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * List models response
 */
export interface OllamaListModelsResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Available models */
  models: OllamaModel[];
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Pull model response
 */
export interface OllamaPullModelResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Model name */
  name: string;
  /** Pull progress */
  progress?: OllamaPullProgress;
  /** Whether pull is complete */
  done: boolean;
  /** Timestamp (unix epoch) */
  timestamp: number;
}

/**
 * Delete model response
 */
export interface OllamaDeleteModelResponse {
  /** Operation status */
  status: AIMLStatus;
  /** Deleted model name */
  name: string;
  /** Timestamp (unix epoch) */
  timestamp: number;
}
