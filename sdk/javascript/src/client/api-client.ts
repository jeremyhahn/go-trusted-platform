/**
 * Core API Client for go-trusted-platform
 *
 * Features:
 * - Automatic JSON serialization/deserialization
 * - Typed error handling with ApiError class
 * - Cookie-based authentication (credentials: 'include')
 * - Configurable base URL from environment or explicit config
 * - Request/response interceptors with full context
 * - Automatic retries with exponential backoff (reads; mutations only with an idempotency key or retryOnMutation)
 * - Request timeout support
 * - SSR-safe design
 */

import { ApiError } from '../errors/api-error.js';
import type { ApiErrorDetails, ApiErrorResponse } from '../errors/types.js';
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
    /**
     * Retry a POST, PUT, PATCH or DELETE (on a retryable status or a network error); off by default.
     * An `Idempotency-Key` request header has the same effect.
     */
    retryOnMutation?: boolean;
  };
  /** Custom metadata to pass through interceptors */
  metadata?: Record<string, unknown>;
  /**
   * Resolve `path` against the host root, not under `baseUrl`; for routes
   * mounted outside the API prefix such as OCI `/v2`.
   */
  rootRelative?: boolean;
}

/**
 * Resolve a root-relative `path` against `base`: an absolute `base` (one with
 * a scheme) gives its origin plus `path`; a protocol-relative `base`
 * (`//host/api`) gives its authority plus `path`; a relative `base` (such as
 * the default `/api`) leaves `path` as it is.
 */
function rootUrl(base: string, path: string): string {
  if (/^[a-z][a-z0-9+.-]*:/i.test(base)) {
    return new URL(path, base).toString();
  }
  const protocolRelative = /^\/\/[^/?#]+/.exec(base);
  if (protocolRelative) {
    return `${protocolRelative[0]}${path}`;
  }
  return path;
}

/** Request header (any case) by which the caller states that the server dedupes the request. */
const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';

/**
 * True when any header set carries an `Idempotency-Key` (any case) with a non-blank value:
 * the caller's statement that the server dedupes the request, so a resend is safe.
 */
function hasIdempotencyKey(sentHeaders: Headers | undefined): boolean {
  return idempotencyKeyOf(sentHeaders) !== undefined;
}

/** The non-blank Idempotency-Key a request sent, if any. */
function idempotencyKeyOf(sentHeaders: Headers | undefined): string | undefined {
  const key = sentHeaders?.get(IDEMPOTENCY_KEY_HEADER);
  return typeof key === 'string' && key.trim() !== '' ? key : undefined;
}

/**
 * Merges header sets case-insensitively: a later set's header replaces an
 * earlier one of any case, so a per-request header always wins over a default.
 */
function mergeHeaders(
  ...headerSets: Array<Record<string, string> | undefined>
): Record<string, string> {
  const merged: Record<string, string> = {};
  for (const headers of headerSets) {
    if (headers === undefined) {
      continue;
    }
    for (const [name, value] of Object.entries(headers)) {
      const lower = name.toLowerCase();
      for (const existing of Object.keys(merged)) {
        if (existing.toLowerCase() === lower) {
          delete merged[existing];
        }
      }
      merged[name] = value;
    }
  }
  return merged;
}

/**
 * Lifts the platform error envelope's machine-readable fields into the
 * SDK's `details`.
 *
 * The platform answers errors with `{code, error, success, service,
 * reason, ...}`. `reason` is a stable discriminator (e.g. the REST
 * service registry's `SERVICE_NOT_CONFIGURED`) and `service` names the
 * subsystem; both must survive into `ApiError.details` so callers can
 * branch on them instead of pattern-matching the human-readable
 * message. An explicit `details` object on the envelope wins over the
 * lifted top-level fields.
 */
function mergeEnvelopeDetails(json: Record<string, unknown>): ApiErrorDetails | undefined {
  const lifted: ApiErrorDetails = {};
  if (typeof json.reason === 'string') {
    lifted.reason = json.reason;
  }
  if (typeof json.service === 'string') {
    lifted.service = json.service;
  }
  const supplied = json.details as ApiErrorDetails | undefined;
  if (supplied === undefined || supplied === null) {
    return Object.keys(lifted).length > 0 ? lifted : undefined;
  }
  return { ...lifted, ...supplied };
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
   * A mutating verb (any verb but GET and HEAD) is retried neither on a
   * status nor on a network error unless the caller passes
   * `retry.retryOnMutation: true` or an `Idempotency-Key` header: a
   * response lost after the server acted cannot be told from a connection
   * that never reached it, so a blind resend can repeat the mutation.
   * GET and HEAD keep the retry on the configured statuses and network
   * errors.
   */
  private shouldRetry(
    attempt: number,
    error: ApiError | Error,
    options?: RequestOptions,
    method?: HttpMethod,
    context?: RequestContext,
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
    if (
      isMutation &&
      options?.retry?.retryOnMutation !== true &&
      !hasIdempotencyKey(context?.sentHeaders)
    ) {
      return false;
    }

    if (error instanceof ApiError) {
      // Check if the status code is retryable
      if (error.status !== undefined) {
        return this.config.retry.retryableStatuses.includes(error.status);
      }
      // Network errors: reached only by reads, or by mutations the caller marked safe to resend.
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
    const base = options?.rootRelative
      ? rootUrl(this.config.baseUrl, path)
      : `${this.config.baseUrl}${path}`;
    const url = appendQueryParams(base, options?.params);
    const startTime = Date.now();

    let attempt = 0;
    // The Idempotency-Key the first attempt sent, reused on every resend.
    let idempotencyKey: string | undefined;

    for (;;) {
      const context: RequestContext = {
        url,
        method,
        headers: mergeHeaders(this.config.headers, options?.headers),
        body,
        attempt,
        metadata: { ...options?.metadata },
      };

      try {
        const response = await this.executeRequest<T>(
          method,
          url,
          body,
          options,
          context,
          startTime,
          idempotencyKey
        );

        // If response is an error and retryable, throw to trigger retry logic
        if (!response.success && response.error !== undefined) {
          const apiError = ApiError.fromResponse(response.error,
            (response as ApiResponse<T> & { _status?: number })._status);

          idempotencyKey ??= idempotencyKeyOf(context.sentHeaders);
          if (this.shouldRetry(attempt, apiError, options, method, context)) {
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
        idempotencyKey ??= idempotencyKeyOf(context.sentHeaders);
        if (this.shouldRetry(attempt, processedError, options, method, context)) {
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
    startTime: number,
    idempotencyKey?: string
  ): Promise<ApiResponse<T>> {
    // Build request config
    const headers: Record<string, string> = mergeHeaders(this.config.headers, options?.headers);

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
    // A resend carries the key the first attempt sent, so an interceptor that
    // mints a key per call cannot make the server run the mutation twice.
    if (idempotencyKey !== undefined) {
      const h = new Headers(requestInit.headers);
      h.set(IDEMPOTENCY_KEY_HEADER, idempotencyKey);
      requestInit.headers = h;
    }
    // The retry policy decides on the headers actually sent, interceptors included.
    context.sentHeaders = new Headers(requestInit.headers);

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
        // `unknown`, not the implicit `any` that `Response.json()` hands
        // back. Narrowed ONCE here so neither branch below reads a property
        // off a value that might not have one: `json()` returns `null` for a
        // body of literal `null`, and Go's `json.NewEncoder(w).Encode(x)`
        // emits exactly that for any nil pointer, slice or interface — so an
        // ordinary nil on a Go error path, not hostile input, used to make
        // `json.code` throw. That TypeError was caught by the transport
        // handler below and reported as NETWORK_ERROR with no status, which
        // made a 403 indistinguishable from a network blip and drove callers
        // to retry a decision the server had made deliberately (#245).
        const json: unknown = await rawResponse.json();
        const envelope: Record<string, unknown> =
          json !== null && typeof json === 'object' ? (json as Record<string, unknown>) : {};

        if (rawResponse.ok) {
          // The platform REST API wraps every successful response in
          // {code, error, success, payload}. Unwrap so service code can
          // use response.payload fields directly without each page
          // needing to know about the envelope. Plain objects (no
          // success field) are returned as-is.
          if ('success' in envelope && 'payload' in envelope) {
            data = (envelope.payload ?? {}) as T;
          } else {
            data = json as T;
          }
        } else {
          // The platform error envelope uses `error` (string) instead of
          // `message`. Surface either so callers see the actual cause.
          // Anything that is not a JSON object contributes no fields, and
          // the HTTP status still reaches the caller.
          const code = typeof envelope.code === 'string' ? envelope.code : undefined;
          const message =
            typeof envelope.message === 'string'
              ? envelope.message
              : typeof envelope.error === 'string'
                ? envelope.error
                : undefined;
          // `??` on statusText is not enough: it is the empty string, not
          // undefined, on a response whose status line carries no reason
          // phrase (HTTP/2 has none at all), which would surface a blank
          // message to the caller.
          const errorResponse: ApiErrorResponse = {
            code: code ?? `HTTP_${rawResponse.status}`,
            message:
              message ??
              (rawResponse.statusText.length > 0
                ? rawResponse.statusText
                : 'An error occurred'),
          };
          const envelopeDetails = mergeEnvelopeDetails(envelope);
          if (envelopeDetails !== undefined) {
            errorResponse.details = envelopeDetails;
          }
          error = ApiError.fromResponse(errorResponse, rawResponse.status);
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
        const errorObj: {
          code: string;
          message: string;
          details?: ApiErrorDetails;
          status?: number;
        } = {
          code: error.code,
          message: error.message,
        };
        if (error.details !== undefined) {
          errorObj.details = error.details;
        }
        // Callers receive this plain object, not the ApiError instance,
        // so the HTTP status has to travel with it — without it a caller
        // can only guess at the status from the message text.
        if (error.status !== undefined) {
          errorObj.status = error.status;
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
  async delete<T>(path: string, options?: RequestOptions, body?: RequestBody): Promise<ApiResponse<T>> {
    return this.request<T>('DELETE', path, body, options);
  }

  /**
   * HEAD request
   */
  async head(path: string, options?: RequestOptions): Promise<ApiResponse<void>> {
    return this.request('HEAD', path, undefined, options);
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
