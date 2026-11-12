/**
 * Request and response interceptor types and utilities
 */

import type { ApiResponse } from '../types/api.js';

/**
 * Request context passed to interceptors
 */
export interface RequestContext {
  /** Request URL */
  url: string;
  /** HTTP method */
  method: string;
  /** Request headers */
  headers: Record<string, string>;
  /** Request body (if any) */
  body?: unknown;
  /** Retry attempt number (0 for initial request) */
  attempt: number;
  /** Custom metadata that can be passed between interceptors */
  metadata: Record<string, unknown>;
}

/**
 * Response context passed to interceptors
 */
export interface ResponseContext<T> {
  /** Original request context */
  request: RequestContext;
  /** API response */
  response: ApiResponse<T>;
  /** Raw fetch response (if available) */
  rawResponse?: Response;
  /** Response time in milliseconds */
  durationMs: number;
}

/**
 * Request interceptor function type
 *
 * Can modify the RequestInit before the request is made.
 * Can be async to support operations like token refresh.
 */
export type RequestInterceptor = (
  config: RequestInit,
  context: RequestContext
) => RequestInit | Promise<RequestInit>;

/**
 * Response interceptor function type
 *
 * Can modify or replace the response.
 * Useful for logging, error transformation, etc.
 */
export type ResponseInterceptor = <T>(
  response: ApiResponse<T>,
  context: ResponseContext<T>
) => ApiResponse<T> | Promise<ApiResponse<T>>;

/**
 * Error interceptor function type
 *
 * Called when an error occurs during the request.
 * Can transform or recover from errors.
 */
export type ErrorInterceptor = (error: Error, context: RequestContext) => Error | Promise<Error>;

/**
 * Interceptor registration handle
 */
export interface InterceptorHandle {
  /** Unique identifier for this interceptor */
  id: number;
  /** Removes this interceptor */
  remove: () => void;
}

/**
 * Interceptor manager for handling request/response interceptors
 */
export class InterceptorManager<T> {
  private interceptors: Map<number, T> = new Map();
  private nextId = 0;

  /**
   * Adds an interceptor
   * @returns Handle to remove the interceptor
   */
  add(interceptor: T): InterceptorHandle {
    const id = this.nextId++;
    this.interceptors.set(id, interceptor);

    return {
      id,
      remove: () => {
        this.interceptors.delete(id);
      },
    };
  }

  /**
   * Removes an interceptor by ID
   */
  remove(id: number): boolean {
    return this.interceptors.delete(id);
  }

  /**
   * Clears all interceptors
   */
  clear(): void {
    this.interceptors.clear();
  }

  /**
   * Returns all registered interceptors in order
   */
  getAll(): T[] {
    return Array.from(this.interceptors.values());
  }

  /**
   * Returns the number of registered interceptors
   */
  get size(): number {
    return this.interceptors.size;
  }
}

/**
 * Creates a logging request interceptor
 */
export function createLoggingRequestInterceptor(
  logger: (message: string, data?: unknown) => void = console.log
): RequestInterceptor {
  return (config, context) => {
    logger(`[API Request] ${context.method} ${context.url}`, {
      headers: context.headers,
      body: context.body,
      attempt: context.attempt,
    });
    return config;
  };
}

/**
 * Creates a logging response interceptor
 */
export function createLoggingResponseInterceptor(
  logger: (message: string, data?: unknown) => void = console.log
): ResponseInterceptor {
  return (response, context) => {
    const status = response.success ? 'SUCCESS' : 'ERROR';
    logger(`[API Response] ${status} ${context.request.method} ${context.request.url}`, {
      success: response.success,
      durationMs: context.durationMs,
      error: response.error,
    });
    return response;
  };
}

/**
 * Turns any HeadersInit (a Headers object, an array of pairs or a plain
 * record) into a plain record that can be spread. Plain records keep their
 * key case; the other forms come back with lower-case names.
 */
function normalizeHeaders(init: HeadersInit | undefined): Record<string, string> {
  if (init === undefined || init === null) {
    return {};
  }
  if (init instanceof Headers || Array.isArray(init)) {
    return Object.fromEntries(new Headers(init));
  }
  return init;
}

/**
 * Returns the normalized headers with `name` set to `value`, dropping every
 * existing key that matches `name` case-insensitively first. Fetch joins
 * same-named headers of different case, so a stale value would otherwise
 * travel as "old, new".
 */
function withHeader(init: HeadersInit | undefined, name: string, value: string): Record<string, string> {
  const lower = name.toLowerCase();
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(normalizeHeaders(init))) {
    if (k.toLowerCase() !== lower) {
      out[k] = v;
    }
  }
  out[name] = value;
  return out;
}

/**
 * Creates an authorization header interceptor
 */
export function createAuthInterceptor(getToken: () => string | Promise<string>): RequestInterceptor {
  return async (config, _context) => {
    const token = await getToken();

    return {
      ...config,
      headers: withHeader(config.headers, 'Authorization', `Bearer ${token}`),
    };
  };
}

/**
 * Creates a request ID interceptor
 */
export function createRequestIdInterceptor(generateId: () => string = () => crypto.randomUUID()): RequestInterceptor {
  return (config, context) => {
    const requestId = generateId();
    context.metadata['requestId'] = requestId;

    return {
      ...config,
      headers: withHeader(config.headers, 'X-Request-ID', requestId),
    };
  };
}

/**
 * Creates a retry-after response interceptor
 *
 * Extracts Retry-After header and adds it to the response metadata
 */
export function createRetryAfterInterceptor(): ResponseInterceptor {
  return (response, context) => {
    if (context.rawResponse !== undefined) {
      const retryAfter = context.rawResponse.headers.get('Retry-After');
      if (retryAfter !== null) {
        if (response.error !== undefined) {
          response.error.details = {
            ...response.error.details,
            context: {
              ...response.error.details?.context,
              retryAfterSeconds: Number.isNaN(parseInt(retryAfter, 10)) ? retryAfter : parseInt(retryAfter, 10),
            },
          };
        }
      }
    }
    return response;
  };
}
