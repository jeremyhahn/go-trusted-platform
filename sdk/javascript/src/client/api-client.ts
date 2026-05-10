/**
 * Core API Client for go-trusted-platform
 *
 * Features:
 * - Automatic JSON serialization/deserialization
 * - Typed error handling with ApiError class
 * - Cookie-based authentication (credentials: 'include')
 * - Configurable base URL from environment or explicit config
 * - Request/response interceptors with full context
 * - Automatic retries with exponential backoff
 * - Request timeout support
 * - SSR-safe design
 */

import { ApiError } from '../errors/api-error.js';
import type { ApiErrorDetails } from '../errors/types.js';
import type { ApiResponse, HttpMethod, QueryParams, RequestBody } from '../types/api.js';
import { appendQueryParams } from '../types/api.js';
import type { Transport } from '../transport/transport.js';
import type { ApiClientConfig, ResolvedApiClientConfig } from './config.js';
import { resolveConfig, validateConfig } from './config.js';
import type {
  ErrorInterceptor,
  InterceptorHandle,
  RequestContext,
  RequestInterceptor,
  ResponseContext,
  ResponseInterceptor,
} from './interceptors.js';
import { InterceptorManager } from './interceptors.js';

/**
 * Request options for individual requests
 */
export interface RequestOptions {
  /** Additional headers for this request */
  headers?: Record<string, string>;
  /** Query parameters */
  params?: QueryParams;
  /** Abort signal for request cancellation */
  signal?: AbortSignal;
  /** Override timeout for this request (ms) */
  timeout?: number;
  /** Override retry config for this request */
  retry?: {
    enabled?: boolean;
    maxRetries?: number;
  };
  /** Custom metadata to pass through interceptors */
  metadata?: Record<string, unknown>;
}

/**
 * API Client class
 *
 * @example
 * ```typescript
 * // Create a client instance
 * const client = new ApiClient({
 *   baseUrl: 'https://api.example.com',
 * });
 *
 * // Make requests
 * const response = await client.get<User[]>('/users');
 * if (response.success) {
 *   console.log(response.data);
 * }
 *
 * // With interceptors
 * client.interceptors.request.add((config, ctx) => {
 *   console.log(`Making request to ${ctx.url}`);
 *   return config;
 * });
 * ```
 */
export class ApiClient implements Transport {
  private readonly config: ResolvedApiClientConfig;

  /** Interceptor managers */
  public readonly interceptors: {
    request: InterceptorManager<RequestInterceptor>;
    response: InterceptorManager<ResponseInterceptor>;
    error: InterceptorManager<ErrorInterceptor>;
  };

  constructor(config?: ApiClientConfig) {
    this.config = resolveConfig(config);
    validateConfig(this.config);

    this.interceptors = {
      request: new InterceptorManager<RequestInterceptor>(),
      response: new InterceptorManager<ResponseInterceptor>(),
      error: new InterceptorManager<ErrorInterceptor>(),
    };
  }

  /**
   * Gets the current base URL
   */
  get baseUrl(): string {
    return this.config.baseUrl;
  }

  /**
   * Add a request interceptor (convenience method)
   */
  addRequestInterceptor(interceptor: RequestInterceptor): InterceptorHandle {
    return this.interceptors.request.add(interceptor);
  }

  /**
   * Add a response interceptor (convenience method)
   */
  addResponseInterceptor(interceptor: ResponseInterceptor): InterceptorHandle {
    return this.interceptors.response.add(interceptor);
  }

  /**
   * Add an error interceptor (convenience method)
   */
  addErrorInterceptor(interceptor: ErrorInterceptor): InterceptorHandle {
    return this.interceptors.error.add(interceptor);
  }

  /**
   * Apply all request interceptors
   */
  private async applyRequestInterceptors(
    requestInit: RequestInit,
    context: RequestContext
  ): Promise<RequestInit> {
    let modifiedConfig = requestInit;
    for (const interceptor of this.interceptors.request.getAll()) {
      modifiedConfig = await interceptor(modifiedConfig, context);
    }
    return modifiedConfig;
  }

  /**
   * Apply all response interceptors
   */
  private async applyResponseInterceptors<T>(
    response: ApiResponse<T>,
    context: ResponseContext<T>
  ): Promise<ApiResponse<T>> {
    let modifiedResponse = response;
    for (const interceptor of this.interceptors.response.getAll()) {
      modifiedResponse = await interceptor(modifiedResponse, context);
    }
    return modifiedResponse;
  }

  /**
   * Apply all error interceptors
   */
  private async applyErrorInterceptors(error: Error, context: RequestContext): Promise<Error> {
    let modifiedError = error;
    for (const interceptor of this.interceptors.error.getAll()) {
      modifiedError = await interceptor(modifiedError, context);
    }
    return modifiedError;
  }

  /**
   * Creates an AbortController with timeout
   */
  private createTimeoutController(timeoutMs: number, existingSignal?: AbortSignal): {
    controller: AbortController;
    cleanup: () => void;
  } {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
      controller.abort(new Error('Request timeout'));
    }, timeoutMs);

    // If there's an existing signal, abort our controller when it aborts
    const existingAbortHandler = existingSignal !== undefined
      ? () => {
          controller.abort(existingSignal.reason);
        }
      : undefined;

    if (existingAbortHandler !== undefined && existingSignal !== undefined) {
      existingSignal.addEventListener('abort', existingAbortHandler);
    }

    return {
      controller,
      cleanup: () => {
        clearTimeout(timeoutId);
        if (existingAbortHandler !== undefined && existingSignal !== undefined) {
          existingSignal.removeEventListener('abort', existingAbortHandler);
        }
      },
    };
  }

  /**
   * Calculates delay for exponential backoff
   */
  private calculateBackoffDelay(attempt: number): number {
    const { initialDelayMs, maxDelayMs, backoffMultiplier } = this.config.retry;
    const delay = initialDelayMs * Math.pow(backoffMultiplier, attempt);
    // Add jitter (10-30% random variance)
    const jitter = delay * (0.1 + Math.random() * 0.2);
    return Math.min(delay + jitter, maxDelayMs);
  }

  /**
   * Determines if a request should be retried.
   *
   * Mutating HTTP verbs (POST, PUT, PATCH, DELETE) are NOT retried on
   * server errors by default — the operation may have partially
   * succeeded server-side, and retrying turns a fast user-visible
   * failure into a 15+ second spinner that ultimately still fails.
   * Read methods (GET, HEAD) keep the legacy retry-on-5xx behaviour.
   * Callers can re-enable mutation retries via
   * `options.retry.retryOnMutation = true`.
   */
  private shouldRetry(
    attempt: number,
    error: ApiError | Error,
    options?: RequestOptions,
    method?: HttpMethod,
  ): boolean {
    // Check if retries are explicitly disabled
    if (options?.retry?.enabled === false) {
      return false;
    }

    const maxRetries = options?.retry?.maxRetries ?? this.config.retry.maxRetries;
    if (attempt >= maxRetries) {
      return false;
    }

    const isMutation = method !== undefined && method !== 'GET' && method !== 'HEAD';
    const allowMutationRetry =
      (options?.retry as { retryOnMutation?: boolean } | undefined)?.retryOnMutation === true;

    if (error instanceof ApiError) {
      // Check if the status code is retryable
      if (error.status !== undefined) {
        if (isMutation && !allowMutationRetry) {
          return false;
        }
        return this.config.retry.retryableStatuses.includes(error.status);
      }
      // Retry network errors (safe even for mutations because no
      // server-side state was modified when the connection failed
      // before reaching the server).
      if (error.isNetworkError() && this.config.retry.retryOnNetworkError) {
        return true;
      }
    }

    // Retry on generic network errors
    if (this.config.retry.retryOnNetworkError) {
      return error.message.includes('network') || error.message.includes('fetch');
    }

    return false;
  }

  /**
   * Waits for the specified delay (uses Promise for non-blocking)
   */
  private async wait(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Core request method with retries
   */
  private async request<T>(
    method: HttpMethod,
    path: string,
    body?: RequestBody,
    options?: RequestOptions
  ): Promise<ApiResponse<T>> {
    const url = appendQueryParams(`${this.config.baseUrl}${path}`, options?.params);
    const startTime = Date.now();

    let attempt = 0;

    while (true) {
      const context: RequestContext = {
        url,
        method,
        headers: { ...this.config.headers, ...options?.headers },
        body,
        attempt,
        metadata: { ...options?.metadata },
      };

      try {
        const response = await this.executeRequest<T>(method, url, body, options, context, startTime);

        // If response is an error and retryable, throw to trigger retry logic
        if (!response.success && response.error !== undefined) {
          const apiError = ApiError.fromResponse(response.error,
            (response as ApiResponse<T> & { _status?: number })._status);

          if (this.shouldRetry(attempt, apiError, options, method)) {
            const delay = this.calculateBackoffDelay(attempt);
            await this.wait(delay);
            attempt++;
            continue;
          }

          // If throwOnError is enabled, throw the error
          if (this.config.throwOnError) {
            throw apiError;
          }
        }

        return response;
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));

        // Apply error interceptors
        const processedError = await this.applyErrorInterceptors(err, context);

        // Check if we should retry
        if (this.shouldRetry(attempt, processedError, options, method)) {
          const delay = this.calculateBackoffDelay(attempt);
          await this.wait(delay);
          attempt++;
          continue;
        }

        // If throwOnError is enabled, throw the error
        if (this.config.throwOnError) {
          throw processedError;
        }

        // Return error response
        const apiError = processedError instanceof ApiError
          ? processedError
          : ApiError.networkError(processedError.message, processedError);

        const errorResponse: ApiResponse<T> = {
          error: {
            code: apiError.code,
            message: apiError.message,
          },
          success: false,
        };

        if (apiError.details !== undefined) {
          errorResponse.error = {
            ...errorResponse.error,
            details: apiError.details,
          } as { code: string; message: string; details: ApiErrorDetails };
        }

        return errorResponse;
      }
    }
  }

  /**
   * Executes a single request (without retry logic)
   */
  private async executeRequest<T>(
    method: HttpMethod,
    url: string,
    body: RequestBody | undefined,
    options: RequestOptions | undefined,
    context: RequestContext,
    startTime: number
  ): Promise<ApiResponse<T>> {
    // Build request config
    const headers: Record<string, string> = {
      ...this.config.headers,
      ...options?.headers,
    };

    let requestInit: RequestInit = {
      method,
      headers,
      credentials: this.config.credentials,
    };

    // Add body if provided
    if (body !== undefined && body !== null) {
      if (body instanceof FormData || body instanceof Blob) {
        requestInit.body = body;
        // Remove Content-Type for FormData to let browser set boundary
        if (body instanceof FormData) {
          delete (requestInit.headers as Record<string, string>)['Content-Type'];
        }
      } else if (typeof body === 'string') {
        requestInit.body = body;
      } else {
        requestInit.body = JSON.stringify(body);
      }
    }

    // Apply request interceptors
    requestInit = await this.applyRequestInterceptors(requestInit, context);

    // Setup timeout
    const timeout = options?.timeout ?? this.config.timeout.requestTimeoutMs;
    const { controller, cleanup } = this.createTimeoutController(timeout, options?.signal);
    requestInit.signal = controller.signal;

    let rawResponse: Response | undefined;

    try {
      // Make the request
      rawResponse = await this.config.fetch(url, requestInit);

      // Parse response
      let data: T | undefined;
      let error: ApiError | undefined;

      const contentType = rawResponse.headers.get('content-type');
      const isJson = contentType?.includes('application/json') ?? false;

      if (isJson) {
        const json = await rawResponse.json();

        if (rawResponse.ok) {
          // The platform REST API wraps every successful response in
          // {code, error, success, payload}. Unwrap so service code can
          // use response.payload fields directly without each page
          // needing to know about the envelope. Plain objects (no
          // success field) are returned as-is.
          if (json && typeof json === 'object' && 'success' in json && 'payload' in json) {
            data = (json.payload ?? {}) as T;
          } else {
            data = json as T;
          }
        } else {
          // The platform error envelope uses `error` (string) instead of
          // `message`. Surface either so callers see the actual cause.
          error = ApiError.fromResponse(
            {
              code: json.code ?? `HTTP_${rawResponse.status}`,
              message: json.message ?? json.error ?? rawResponse.statusText ?? 'An error occurred',
              details: json.details,
            },
            rawResponse.status
          );
        }
      } else if (!rawResponse.ok) {
        const text = await rawResponse.text();
        error = ApiError.fromStatus(
          rawResponse.status,
          text || rawResponse.statusText || 'An error occurred'
        );
      } else {
        // Non-JSON success response
        const text = await rawResponse.text();
        data = text as T;
      }

      // Build response
      let apiResponse: ApiResponse<T>;
      if (error !== undefined) {
        const errorObj: { code: string; message: string; details?: ApiErrorDetails } = {
          code: error.code,
          message: error.message,
        };
        if (error.details !== undefined) {
          errorObj.details = error.details;
        }
        apiResponse = {
          error: errorObj,
          success: false,
        };
      } else if (data !== undefined) {
        apiResponse = {
          data,
          success: true,
        };
      } else {
        // No data and no error - still success but without data
        apiResponse = {
          success: true,
        };
      }

      // Add status for retry logic
      (apiResponse as ApiResponse<T> & { _status?: number })._status = rawResponse.status;

      // Build response context
      const responseContext: ResponseContext<T> = {
        request: context,
        response: apiResponse,
        rawResponse,
        durationMs: Date.now() - startTime,
      };

      // Apply response interceptors
      apiResponse = await this.applyResponseInterceptors(apiResponse, responseContext);

      return apiResponse;
    } finally {
      cleanup();
    }
  }

  /**
   * GET request
   */
  async get<T>(path: string, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>('GET', path, undefined, options);
  }

  /**
   * POST request
   */
  async post<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>('POST', path, body, options);
  }

  /**
   * PUT request
   */
  async put<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>('PUT', path, body, options);
  }

  /**
   * PATCH request
   */
  async patch<T>(path: string, body?: RequestBody, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>('PATCH', path, body, options);
  }

  /**
   * DELETE request
   */
  async delete<T>(path: string, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>('DELETE', path, undefined, options);
  }

  /**
   * HEAD request
   */
  async head(path: string, options?: RequestOptions): Promise<ApiResponse<void>> {
    return this.request<void>('HEAD', path, undefined, options);
  }

  /**
   * OPTIONS request
   */
  async options<T>(path: string, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>('OPTIONS', path, undefined, options);
  }

  /**
   * Generic request method
   */
  async fetch<T>(
    method: HttpMethod,
    path: string,
    options?: RequestOptions & { body?: RequestBody }
  ): Promise<ApiResponse<T>> {
    return this.request<T>(method, path, options?.body, options);
  }
}

/**
 * Creates a new API client instance
 */
export function createApiClient(config?: ApiClientConfig): ApiClient {
  return new ApiClient(config);
}

/**
 * Default API client instance
 */
export const apiClient = new ApiClient();
