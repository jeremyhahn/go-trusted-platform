/**
 * Client configuration types and defaults
 */

/**
 * Credentials mode for fetch requests
 */
export type CredentialsMode = 'omit' | 'same-origin' | 'include';

/**
 * Retry configuration
 */
export interface RetryConfig {
  /** Maximum number of retry attempts */
  maxRetries: number;
  /** Initial delay between retries in milliseconds */
  initialDelayMs: number;
  /** Maximum delay between retries in milliseconds */
  maxDelayMs: number;
  /** Multiplier for exponential backoff */
  backoffMultiplier: number;
  /** HTTP status codes that should trigger a retry */
  retryableStatuses: readonly number[];
  /** Whether to retry on network errors */
  retryOnNetworkError: boolean;
}

/**
 * Timeout configuration
 */
export interface TimeoutConfig {
  /** Request timeout in milliseconds */
  requestTimeoutMs: number;
  /** Connection timeout in milliseconds */
  connectionTimeoutMs: number;
}

/**
 * API client configuration
 */
export interface ApiClientConfig {
  /** Base URL for API requests */
  baseUrl?: string;

  /** Default headers to include in all requests */
  headers?: Record<string, string>;

  /** Credentials mode for fetch requests */
  credentials?: CredentialsMode;

  /** Timeout configuration */
  timeout?: Partial<TimeoutConfig>;

  /** Retry configuration */
  retry?: Partial<RetryConfig>;

  /** Whether to throw on error responses (default: false) */
  throwOnError?: boolean;

  /** Custom fetch implementation (for testing or SSR) */
  fetch?: typeof fetch;
}

/**
 * Resolved configuration with all defaults applied
 */
export interface ResolvedApiClientConfig {
  baseUrl: string;
  headers: Record<string, string>;
  credentials: CredentialsMode;
  timeout: TimeoutConfig;
  retry: RetryConfig;
  throwOnError: boolean;
  fetch: typeof fetch;
}

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: Readonly<RetryConfig> = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
  retryableStatuses: [408, 429, 500, 502, 503, 504],
  retryOnNetworkError: true,
} as const;

/**
 * Default timeout configuration
 */
export const DEFAULT_TIMEOUT_CONFIG: Readonly<TimeoutConfig> = {
  requestTimeoutMs: 30000,
  connectionTimeoutMs: 10000,
} as const;

/**
 * Gets the default base URL, with SSR-safe environment variable access
 */
export function getDefaultBaseUrl(): string {
  // SSR-safe environment variable access
  if (typeof globalThis !== 'undefined') {
    // Check for Vite-style env
    const viteEnv = (globalThis as Record<string, unknown>).import as
      | { meta?: { env?: Record<string, string> } }
      | undefined;
    if (viteEnv?.meta?.env?.['VITE_API_URL'] !== undefined) {
      return viteEnv.meta.env['VITE_API_URL'];
    }
  }

  // Check for Node.js process.env
  if (typeof process !== 'undefined' && process.env !== undefined) {
    // Next.js style
    const nextPublicUrl = process.env['NEXT_PUBLIC_API_URL'];
    if (nextPublicUrl !== undefined) {
      return nextPublicUrl;
    }

    // Generic API URL
    const apiUrl = process.env['API_URL'];
    if (apiUrl !== undefined) {
      return apiUrl;
    }
  }

  // Default to relative path
  return '/api';
}

/**
 * Gets the default fetch implementation
 *
 * Note: We bind fetch to globalThis to avoid "Illegal invocation" errors
 * that occur when fetch is called without its proper context in browsers.
 */
export function getDefaultFetch(): typeof fetch {
  if (typeof fetch !== 'undefined') {
    // Bind fetch to globalThis to preserve the correct 'this' context
    return fetch.bind(globalThis);
  }
  throw new Error(
    'No fetch implementation available. Please provide a custom fetch function in the client configuration.'
  );
}

/**
 * Resolves partial configuration with defaults
 */
export function resolveConfig(config?: ApiClientConfig): ResolvedApiClientConfig {
  return {
    baseUrl: config?.baseUrl ?? getDefaultBaseUrl(),
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...config?.headers,
    },
    credentials: config?.credentials ?? 'include',
    timeout: {
      ...DEFAULT_TIMEOUT_CONFIG,
      ...config?.timeout,
    },
    retry: {
      ...DEFAULT_RETRY_CONFIG,
      ...config?.retry,
    },
    throwOnError: config?.throwOnError ?? false,
    fetch: config?.fetch ?? getDefaultFetch(),
  };
}

/**
 * Validates configuration
 */
export function validateConfig(config: ResolvedApiClientConfig): void {
  if (config.baseUrl.length === 0) {
    throw new Error('baseUrl cannot be empty');
  }

  if (config.timeout.requestTimeoutMs <= 0) {
    throw new Error('requestTimeoutMs must be positive');
  }

  if (config.retry.maxRetries < 0) {
    throw new Error('maxRetries cannot be negative');
  }
}
